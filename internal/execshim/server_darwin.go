//go:build darwin && cgo

/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package execshim

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
	shimv1 "k3sm.io/apis/shim/v1"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/execsession"
	"k3sm.io/runtimed/pkg/supervisor"
)

// ptyTTL bounds how long a handed-off pty slave waits for the Exec stream that
// names it before the shim closes it.
const ptyTTL = 30 * time.Second

// shimServer serves shimv1.ContainerShim for one container.
//
// Concurrency: the identity fields are written once by bringUp before any
// goroutine starts. mu guards exit; exited is closed once, by run, after the
// exit record is persisted. The rings and the log writer carry their own locks.
type shimServer struct {
	shimv1.UnimplementedContainerShimServer

	spec       supervisor.ShimSpec
	self       string
	pid        int
	start      int64
	child      int
	childStart int64

	logw      *crilog.Writer
	out, errs *ring
	pumps     sync.WaitGroup
	fan       fanout
	ptys      *ptyStore
	grpc      *grpc.Server
	execs     atomic.Int32 // exec sessions in flight

	mu     sync.Mutex
	exit   *supervisor.ExitRecord
	exited chan struct{}
}

// assert refuses a request naming another container: the name is the caller's
// proof it reached the shim it meant to.
func (s *shimServer) assert(container string) error {
	if container != s.spec.Container {
		return status.Errorf(codes.NotFound, "this shim hosts container %q, not %q", s.spec.Container, container)
	}
	return nil
}

// isExited reports whether the container's exit has been persisted.
func (s *shimServer) isExited() bool {
	select {
	case <-s.exited:
		return true
	default:
		return false
	}
}

// Status reports the shim's identity, the child's, and the persisted exit.
func (s *shimServer) Status(_ context.Context, req *shimv1.StatusRequest) (*shimv1.StatusResponse, error) {
	if err := s.assert(req.GetContainer()); err != nil {
		return nil, err
	}
	resp := &shimv1.StatusResponse{
		ApiVersion:         shimv1.APIVersion,
		ShimPid:            int32(s.pid),
		ShimStartUnixNano:  s.start,
		ChildPid:           int32(s.child),
		ChildStartUnixNano: s.childStart,
		DroppedBytes:       s.out.Dropped() + s.errs.Dropped(),
	}
	s.mu.Lock()
	if s.exit != nil {
		resp.Exit = &shimv1.ExitStatus{
			ExitCode:   int32(s.exit.ExitCode),
			Signal:     int32(s.exit.Signal),
			FinishedAt: timestamppb.New(time.Unix(0, s.exit.FinishedAtUnixNano)),
		}
	}
	s.mu.Unlock()
	resp.Running = !s.isExited()
	return resp, nil
}

// Signal delivers a signal to the container alone, or to every other member of
// the pod's process group (the shim leads the group and does not signal itself:
// it would only forward the signal to the container a second time).
func (s *shimServer) Signal(_ context.Context, req *shimv1.SignalRequest) (*shimv1.SignalResponse, error) {
	if err := s.assert(req.GetContainer()); err != nil {
		return nil, err
	}
	if s.isExited() {
		return nil, status.Error(codes.FailedPrecondition, "the container has exited")
	}
	sig := unix.Signal(req.GetSignal())
	if !req.GetGroup() {
		if err := unix.Kill(s.child, sig); err != nil && !errors.Is(err, unix.ESRCH) {
			return nil, status.Errorf(codes.Internal, "signal the container: %v", err)
		}
		return &shimv1.SignalResponse{}, nil
	}
	members, ok := supervisor.ProcGroupMembers(s.pid)
	if !ok {
		return nil, status.Error(codes.Internal, "read the pod's process group")
	}
	for _, m := range members {
		if m.Pid == s.pid {
			continue
		}
		if err := unix.Kill(m.Pid, sig); err != nil && !errors.Is(err, unix.ESRCH) {
			return nil, status.Errorf(codes.Internal, "signal pid %d: %v", m.Pid, err)
		}
	}
	return &shimv1.SignalResponse{}, nil
}

// ReopenLog reopens the container's log at its path. The daemon has already
// renamed the old file and created the new one; the shim only opens it (its
// grant appends to that one literal and creates nothing).
func (s *shimServer) ReopenLog(_ context.Context, req *shimv1.ReopenLogRequest) (*shimv1.ReopenLogResponse, error) {
	if err := s.assert(req.GetContainer()); err != nil {
		return nil, err
	}
	if err := s.logw.Reopen(); err != nil {
		return nil, status.Errorf(codes.Internal, "reopen the container log: %v", err)
	}
	return &shimv1.ReopenLogResponse{}, nil
}

// Follow streams live output until the container exits, then its exit as a
// liveness hint (a signal death mirrored as 128+signal; Status is the authority).
func (s *shimServer) Follow(req *shimv1.FollowRequest, stream shimv1.ContainerShim_FollowServer) error {
	if err := s.assert(req.GetContainer()); err != nil {
		return err
	}
	ch, cancel := s.fan.subscribe()
	defer cancel()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-s.exited:
			s.mu.Lock()
			code := int32(0)
			if s.exit != nil {
				code = int32(s.exit.ExitCode)
			}
			s.mu.Unlock()
			return stream.Send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: code}})
		case ent := <-ch:
			if err := stream.Send(attachChunk(ent)); err != nil {
				return err
			}
		}
	}
}

// Exec runs one exec session in the container's context: the container's
// resolved environment and working directory, the pod's rlimit plan and QoS
// band (exec mode), under the shim's own confinement. Sessions keep their own
// session/group exactly as the daemon's do (Setsid+Setctty for a tty, Setpgid
// otherwise) and are torn down with their stream (execsession's invariant).
func (s *shimServer) Exec(stream shimv1.ContainerShim_ExecServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := s.assert(first.GetContainer()); err != nil {
		return err
	}
	s.execs.Add(1)
	defer s.execs.Add(-1)
	if s.isExited() {
		return status.Error(codes.FailedPrecondition, "exec: the container has exited")
	}
	cmdv := first.GetCommand()
	if len(cmdv) == 0 {
		return status.Error(codes.InvalidArgument, "exec: command is required")
	}
	args := append([]string{supervisor.ShimModeExec, s.spec.Launch[3], s.spec.Launch[4]}, cmdv...)
	cmd := exec.CommandContext(stream.Context(), s.self, args...)
	cmd.Env = s.spec.ExecEnv
	cmd.Dir = s.spec.ExecDir
	if !first.GetTty() {
		return execsession.Run(stream, cmd, false, first.GetStdin())
	}
	md, _ := metadata.FromIncomingContext(stream.Context())
	tokens := md.Get(supervisor.ShimPtyTokenKey)
	if len(tokens) != 1 {
		return status.Error(codes.FailedPrecondition, "exec: a tty session needs a handed-off terminal")
	}
	slave := s.ptys.take(tokens[0])
	if slave == nil {
		return status.Error(codes.FailedPrecondition, "exec: no handed-off terminal for this session")
	}
	return execsession.RunOnSlave(stream, cmd, slave)
}

// writeLog drains r into the CRI log and the followers. A dropped-bytes count
// becomes one line of its own, so the gap is visible where it happened. A
// failed log writer keeps the drain going: the container's write(2) must never
// block on it.
func (s *shimServer) writeLog(r *ring, stream crilog.Stream) {
	report := func() {
		if n := r.takeDropped(); n > 0 {
			line := fmt.Sprintf("k3sm-shim: %d bytes of %s were dropped: the log writer fell behind", n, stream)
			_ = s.logw.Write(stream, []byte(line), false)
		}
	}
	_ = crilog.Chunk(r, func(chunk []byte, partial bool) error {
		report()
		_ = s.logw.Write(stream, chunk, partial)
		s.fan.publish(stream, chunk, partial)
		return nil
	})
	report()
}

// acceptPtys receives handed-off pty slaves until the listener closes.
func (s *shimServer) acceptPtys(ln *net.UnixListener) {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			token, f, err := supervisor.RecvPtyHandoff(c)
			if err != nil {
				return
			}
			s.ptys.put(token, f)
		}()
	}
}

// ptyStore holds handed-off slaves until their Exec stream claims them, closing
// any that is not claimed within ptyTTL.
type ptyStore struct {
	mu sync.Mutex
	m  map[string]*os.File
}

func newPtyStore() *ptyStore { return &ptyStore{m: make(map[string]*os.File)} }

func (p *ptyStore) put(token string, f *os.File) {
	p.mu.Lock()
	p.m[token] = f
	p.mu.Unlock()
	time.AfterFunc(ptyTTL, func() {
		if f := p.take(token); f != nil {
			_ = f.Close()
		}
	})
}

func (p *ptyStore) take(token string) *os.File {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := p.m[token]
	delete(p.m, token)
	return f
}
