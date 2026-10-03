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

// handoffTTL bounds how long a handed-off descriptor waits for the RPC that
// claims it before the shim closes it.
const handoffTTL = 30 * time.Second

// maxHandoffs caps the descriptors waiting to be claimed; past it a hand-off is
// refused rather than held.
const maxHandoffs = 16

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
	handoffs  *handoffStore
	grpc      *grpc.Server
	execs     atomic.Int32 // exec sessions in flight
	exitFile  *os.File     // the exit record, opened before confinement

	// reaped is set the moment the container is reaped: from then on its pid
	// may name another process, so neither the signal forwarder nor the Signal
	// RPC signals it.
	reaped atomic.Bool

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
	if s.isExited() || s.reaped.Load() {
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

// ReopenLog switches the container's log to the descriptor the daemon handed
// over (supervisor.ShimLogTokenKey names it): the daemon renamed the old file,
// created and opened the new one, and passed the descriptor. The shim opens no
// log path after confinement, and its profile grants none.
func (s *shimServer) ReopenLog(ctx context.Context, req *shimv1.ReopenLogRequest) (*shimv1.ReopenLogResponse, error) {
	if err := s.assert(req.GetContainer()); err != nil {
		return nil, err
	}
	md, _ := metadata.FromIncomingContext(ctx)
	tokens := md.Get(supervisor.ShimLogTokenKey)
	if len(tokens) != 1 {
		return nil, status.Error(codes.FailedPrecondition, "reopen: no handed-off log descriptor named")
	}
	f := s.handoffs.take(supervisor.HandoffLog, tokens[0])
	if f == nil {
		return nil, status.Error(codes.FailedPrecondition, "reopen: no handed-off log descriptor for this call")
	}
	if err := s.logw.ReopenFrom(f); err != nil {
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
	slave := s.handoffs.take(supervisor.HandoffPty, tokens[0])
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

// acceptHandoffs receives handed-off descriptors until the listener closes.
//
// No server-side peer check: the daemon that hands a descriptor over may be a
// later incarnation than the one that spawned this shim, so its pid is not
// known here, and every pod shares the daemon's uid, so a uid check would admit
// exactly the processes it is meant to keep out. The barrier is the pod
// profile's deny on connect(2) to every shim socket; the daemon's side checks
// the peer (LOCAL_PEERPID) before it hands anything over.
func (s *shimServer) acceptHandoffs(ln *net.UnixListener) {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = supervisor.RecvHandoff(c, s.handoffs.put)
		}()
	}
}

// handoffKey names a waiting descriptor.
type handoffKey struct {
	kind  byte
	token string
}

// handoffStore holds handed-off descriptors until the RPC that names them
// claims them, closing any not claimed within handoffTTL, and holding at most
// maxHandoffs at once.
type handoffStore struct {
	mu sync.Mutex
	m  map[handoffKey]*os.File
}

func newHandoffStore() *handoffStore { return &handoffStore{m: make(map[handoffKey]*os.File)} }

// put keeps f under (kind, token), or refuses when the store is full.
func (h *handoffStore) put(kind byte, token string, f *os.File) bool {
	h.mu.Lock()
	if len(h.m) >= maxHandoffs {
		h.mu.Unlock()
		return false
	}
	h.m[handoffKey{kind, token}] = f
	h.mu.Unlock()
	time.AfterFunc(handoffTTL, func() {
		if f := h.take(kind, token); f != nil {
			_ = f.Close()
		}
	})
	return true
}

// take claims the descriptor of kind under token, or nil.
func (h *handoffStore) take(kind byte, token string) *os.File {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := handoffKey{kind, token}
	f := h.m[k]
	delete(h.m, k)
	return f
}
