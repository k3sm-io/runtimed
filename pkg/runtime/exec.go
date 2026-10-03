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

package runtime

import (
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/execsession"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// pumpChunkSize is the read buffer for streaming a process's output / a forwarded
// connection. Output is streamed as raw byte chunks (not lines) so interactive
// and binary exec output passes through unmangled.
const pumpChunkSize = 32 * 1024

// Exec runs a command inside a pod's existing confinement domain (`kubectl
// exec`). It does not open a privileged shell: it re-enters the same Seatbelt
// profile, the same securityContext uid/gid drop, and the same pod launch spec
// (rlimits + qos) and data-volume cwd as the pod's containers by spawning the
// requested argv through the exec-shim backend — sandbox.Backend.WrapCommand
// produces the k3sm-execshim invocation that runs supervisor.RunLaunchSequence
// (the single source of truth for the launch order) with the user's argv in
// place of the pod entrypoint. An exec is therefore a fresh, equally-confined
// process and cannot escape the pod's sandbox.
//
// The first ExecRequest carries the parameters (pod_id, container, command, tty,
// stdin); subsequent frames carry stdin bytes and tty resize events. stdout and
// stderr stream back as ExecResponse frames and the command's exit code is
// delivered as the terminal ExecResult before the stream closes (a signal-killed
// command maps to 128+signo, matching the supervisor's reaper convention).
func (r *Runtime) Exec(stream runtimev1.Runtime_ExecServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err // includes io.EOF if the client gave up before sending params
	}
	// Route dispatch. A vm pod's containers are guest processes with
	// no host containerProc and no host confinement to re-enter, so the whole
	// host-process body below is meaningless for one: it proxies to the pod's
	// guest agent instead. A pod that is not a vm pod — or an id no pod has —
	// falls through to the byte-unchanged host-process path.
	if p, ok := r.lookupPod(first.GetPodId()); ok && p.isVM() {
		return r.execGuest(stream, p, first)
	}

	p, cp, err := r.lookupContainer(first.GetPodId(), first.GetContainer())
	if err != nil {
		return err
	}
	if p.adopted {
		return status.Errorf(codes.FailedPrecondition, "exec: %v", errAdoptedPod)
	}
	cmdv := first.GetCommand()
	if len(cmdv) == 0 {
		return status.Error(codes.InvalidArgument, "exec: command is required")
	}

	c := cp.spec
	if c == nil {
		c = &runtimev1.Container{}
	}
	cred := resolveCredential(p.box, c)

	// Reuse the pod's confinement: WrapCommand returns the exec-shim invocation
	// that re-applies the pod's profile + drop + rlimit plan + qos band (the full
	// supervisor.LaunchSpec — an exec session gets the POD's limits, one code
	// path). This is the same seam the container spawn (startContainer) and the
	// launch-order tests exercise, so a future profile change
	// automatically covers exec too.
	shimPath, shimArgv, cleanup, err := r.backend.WrapCommand(ctx, p.profile, cmdv, resolveLaunchSpec(p.box, cred))
	if err != nil {
		return status.Errorf(codes.Internal, "exec: wrap command: %v", err)
	}
	defer func() { _ = cleanup() }()

	rootfs, err := r.rootfsPath(p.box)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "exec: %v", err)
	}
	// The container's own working directory and environment, as
	// startContainer resolved them — which for a pulled image includes the
	// image config's WorkingDir and Env (image.MergeRunSpec). An exec session
	// that re-derived them from the container spec alone would run with a
	// different $PATH than the container it is exec'ing into, which is exactly
	// the surprise `kubectl exec` must not produce. The fallback keeps a
	// container spawned before this field existed (and every host-binary route,
	// where the two are identical) working unchanged.
	dir := cp.workingDir
	if dir == "" {
		dir = c.GetWorkingDir()
	}
	if dir == "" {
		dir = rootfs
	}

	cmd := exec.CommandContext(ctx, shimPath)
	cmd.Args = shimArgv
	cmdEnv := cp.env
	if cmdEnv == nil {
		cmdEnv, err = r.containerEnv(p.box, c, nil)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "exec: %v", err)
		}
	}
	cmd.Env = cmdEnv
	cmd.Dir = dir
	return execsession.Run(stream, cmd, first.GetTty(), first.GetStdin())
}

// Attach attaches to an already-running container's streams (`kubectl attach`).
//
// Route dispatch, as Exec does it. A vm pod's containers are GUEST processes
// whose retained stdio lives in the guest's attach hub, so the whole
// host-process body below is meaningless for one and it proxies to the pod's
// guest agent instead (attachGuest, guest.go). The pod is resolved BEFORE
// lookupContainer for that reason: a vm pod has no host containerProc, so the
// host-process lookup cannot answer for one at all.
//
// NATIVE PODS ONLY: a native container is spawned (posix_spawn) with its
// stdout and stderr wired to the log pipes and its stdin not retained — so
// there is no fd to feed new input to a running native process. Interactive
// attach (stdin, or a tty) is therefore reported Unimplemented rather than
// silently dropping the operator's keystrokes; `kubectl exec` is the supported
// interactive path there. Full interactive attach for a NATIVE pod awaits
// stdin-pty retention work; the vm route above has no such limitation, because
// the guest retains the endpoints at spawn.
//
// LIVE-ONLY, deliberately. It follows output written from the moment of the
// attach and REPLAYS NOTHING. That is what CRI attach means upstream — it
// bridges a client to a running container's stdio, not to a history — and it is
// now also the only honest answer: runtimed retains no copy of a container's
// output. Everything the container said before the attach is in its log file,
// which is what `kubectl logs` reads.
//
// The two streams are kept apart (stdout to Stdout, stderr to Stderr) and the
// CRI partial tag decides the delimiter: a chunk that ENDS a logical line gets
// its newline back (the chunker stripped it), while a chunk that continues one
// is forwarded raw, so a 40 KiB line arrives as one line at the terminal rather
// than as three.
func (r *Runtime) Attach(stream runtimev1.Runtime_AttachServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if p, ok := r.lookupPod(first.GetPodId()); ok && p.isVM() {
		return r.attachGuest(stream, p, first)
	}

	_, cp, err := r.lookupContainer(first.GetPodId(), first.GetContainer())
	if err != nil {
		return err
	}
	if first.GetStdin() {
		return status.Error(codes.Unimplemented,
			"interactive attach (stdin/tty) to a running native process is not supported; use `kubectl exec`")
	}
	// Attach follows a PROCESS's output. A container that never started (Waiting
	// because its start failed before the spawn) has none, and cp.proc is nil —
	// which the exit select below would dereference.
	if cp.proc == nil {
		return status.Errorf(codes.FailedPrecondition,
			"attach %s/%s: container has not started", first.GetPodId(), first.GetContainer())
	}

	var sendMu sync.Mutex
	send := func(resp *runtimev1.AttachResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(resp)
	}

	// Follow new output from now. There is deliberately no replay; see the doc
	// comment. A container that never started has no fanout either, which the
	// nil check above has already refused.
	follow, cancel := cp.fanout.subscribe()
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-cp.proc.Done():
			code, _, _ := cp.proc.Wait(ctx)
			return send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: int32(code)}})
		case ent := <-follow:
			if err := send(attachChunk(ent)); err != nil {
				return err
			}
		}
	}
}

// PortForward proxies bytes between the client and a pod-local TCP port
// (`kubectl port-forward`). The pod IP is the darwin-net lo0 alias, so the dial
// is a loopback connection on this node. One stream multiplexes multiple
// forwarded connections by connection_id: the first frame for an id dials the
// pod port and starts a reader that streams pod→client bytes; subsequent frames
// carry client→pod bytes (or a close). All connections + their reader goroutines
// are torn down when the stream ends (client close / context cancellation).
func (r *Runtime) PortForward(stream runtimev1.Runtime_PortForwardServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	r.mu.Lock()
	p, ok := r.pods[first.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "pod %s not found", first.GetPodId())
	}
	podIP := p.podIP
	if podIP == "" {
		return status.Errorf(codes.FailedPrecondition, "pod %s has no IP yet", first.GetPodId())
	}

	var sendMu sync.Mutex
	send := func(resp *runtimev1.PortForwardResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(resp)
	}

	// conns is owned by this (single) recv loop; the per-connection reader
	// goroutines only send (serialized via send) and never touch the map.
	conns := make(map[uint64]net.Conn)
	var wg sync.WaitGroup
	defer func() {
		for _, c := range conns {
			_ = c.Close() // unblocks each reader (Read errors), which then returns
		}
		wg.Wait()
	}()

	handle := func(req *runtimev1.PortForwardRequest) {
		id := req.GetConnectionId()
		conn, ok := conns[id]
		if !ok {
			if req.GetClose() {
				return
			}
			addr := net.JoinHostPort(podIP, strconv.Itoa(int(req.GetPort())))
			var dialer net.Dialer
			c, derr := dialer.DialContext(ctx, "tcp", addr)
			if derr != nil {
				_ = send(&runtimev1.PortForwardResponse{
					ConnectionId: id,
					Close:        true,
					Error:        rpcStatus(codes.Unavailable, "dial pod %s: %v", addr, derr),
				})
				return
			}
			conn = c
			conns[id] = c
			wg.Add(1)
			go func(id uint64, c net.Conn) {
				defer wg.Done()
				buf := make([]byte, pumpChunkSize)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						if serr := send(&runtimev1.PortForwardResponse{ConnectionId: id, Data: append([]byte(nil), buf[:n]...)}); serr != nil {
							return
						}
					}
					if rerr != nil {
						_ = send(&runtimev1.PortForwardResponse{ConnectionId: id, Close: true})
						return
					}
				}
			}(id, c)
		}
		if d := req.GetData(); len(d) > 0 {
			if _, werr := conn.Write(d); werr != nil {
				_ = conn.Close()
				delete(conns, id)
				return
			}
		}
		if req.GetClose() {
			_ = conn.Close()
			delete(conns, id)
		}
	}

	handle(first)
	for {
		req, rerr := stream.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				// The client half-closed its send side; keep proxying pod→client until
				// the stream's context is cancelled (the kubectl-side teardown).
				<-ctx.Done()
				return nil
			}
			return rerr
		}
		handle(req)
	}
}

// lookupContainer resolves a pod + one of its running containers by id/name (an
// empty name selects the sole container), returning a gRPC NotFound status when
// either is absent.
func (r *Runtime) lookupContainer(podID, container string) (*pod, *containerProc, error) {
	r.mu.Lock()
	p, ok := r.pods[podID]
	r.mu.Unlock()
	if !ok {
		return nil, nil, status.Errorf(codes.NotFound, "pod %s not found", podID)
	}
	cp := r.findContainer(p, container)
	if cp == nil {
		return nil, nil, status.Errorf(codes.NotFound, "container %s not found in pod %s", container, podID)
	}
	return p, cp, nil
}

// attachChunk renders one live output chunk as an AttachResponse, on the field
// matching its stream.
//
// A FULL chunk (the CRI F tag) gets its line terminator back: the chunker
// stripped it so the log file could supply its own, and an attached terminal
// that received the bytes without it would run every line together. A PARTIAL
// chunk is forwarded raw — it is the middle of a line that has not ended yet,
// and inserting a newline there would fabricate a line break the container
// never wrote.
func attachChunk(ent logChunk) *runtimev1.AttachResponse {
	out := ent.chunk
	if !ent.partial {
		out = append(append(make([]byte, 0, len(ent.chunk)+1), ent.chunk...), '\n')
	}
	if ent.stream == crilog.StreamStderr {
		return &runtimev1.AttachResponse{Stderr: out}
	}
	return &runtimev1.AttachResponse{Stdout: out}
}
