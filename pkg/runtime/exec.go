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
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// pumpChunkSize is the read buffer for streaming a process's output / a forwarded
// connection. Output is streamed as raw byte chunks (not lines) so interactive
// and binary exec output passes through unmangled.
const pumpChunkSize = 32 * 1024

// Exec runs a command inside a pod's existing confinement domain (`kubectl
// exec`). It does NOT open a privileged shell: it re-enters the SAME Seatbelt
// profile, the SAME securityContext uid/gid drop, and the SAME pod launch spec
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
	p, cp, err := r.lookupContainer(first.GetPodId(), first.GetContainer())
	if err != nil {
		return err
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
	// path). This is the SAME seam the container spawn (startContainer) and the
	// M2.3/B7 launch-order tests exercise, so a future profile change
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
	dir := c.GetWorkingDir()
	if dir == "" {
		dir = rootfs
	}

	cmd := exec.CommandContext(ctx, shimPath)
	cmd.Args = shimArgv
	cmdEnv, err := r.containerEnv(p.box, c)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "exec: %v", err)
	}
	cmd.Env = cmdEnv
	cmd.Dir = dir
	return r.runExec(stream, cmd, first.GetTty(), first.GetStdin())
}

// runExec wires the spawned command's stdio to the bidi stream, runs it to
// completion, and delivers the exit code. stdout/stderr stream back to the
// client; client stdin frames and tty resizes stream to the command. The
// goroutines have bounded lifetimes: the output pumps end when the command's
// output closes (process exit), and the stdin pump ends when the client
// half-closes the stream (io.EOF) or the stream's context is cancelled (handler
// return). gRPC stream.Send is serialized through send (it is not safe to call
// concurrently from the stdout and stderr pumps).
func (r *Runtime) runExec(stream runtimev1.Runtime_ExecServer, cmd *exec.Cmd, tty, wantStdin bool) error {
	var sendMu sync.Mutex
	send := func(resp *runtimev1.ExecResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(resp)
	}

	var (
		wg          sync.WaitGroup
		stdinW      io.Writer // where client stdin bytes are written (pipe or pty master)
		stdinCloser io.Closer // closed on client EOF to signal command stdin EOF (non-tty only)
		ttyMaster   *os.File  // pty master for resize + the closer below (tty only)
	)

	if tty {
		master, slave, err := openPTY()
		if err != nil {
			return status.Errorf(codes.Internal, "exec: allocate tty: %v", err)
		}
		ttyMaster = master
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
		if err := cmd.Start(); err != nil {
			_ = slave.Close()
			_ = master.Close()
			return status.Errorf(codes.Internal, "exec: start: %v", err)
		}
		_ = slave.Close() // the child holds its dup; the parent keeps only the master
		if wantStdin {
			stdinW = master
		}
		// On a tty stdout and stderr are merged onto the line discipline; the master
		// read ends with EIO once the child exits and the kernel closes the slave.
		wg.Add(1)
		go func() {
			defer wg.Done()
			pumpReader(master, func(b []byte) error { return send(&runtimev1.ExecResponse{Stdout: b}) })
		}()
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own pgrp; a client ^C never reaches the daemon
		if wantStdin {
			w, err := cmd.StdinPipe()
			if err != nil {
				return status.Errorf(codes.Internal, "exec: stdin pipe: %v", err)
			}
			stdinW, stdinCloser = w, w
		}
		stdoutR, err := cmd.StdoutPipe()
		if err != nil {
			return status.Errorf(codes.Internal, "exec: stdout pipe: %v", err)
		}
		stderrR, err := cmd.StderrPipe()
		if err != nil {
			return status.Errorf(codes.Internal, "exec: stderr pipe: %v", err)
		}
		if err := cmd.Start(); err != nil {
			return status.Errorf(codes.Internal, "exec: start: %v", err)
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			pumpReader(stdoutR, func(b []byte) error { return send(&runtimev1.ExecResponse{Stdout: b}) })
		}()
		go func() {
			defer wg.Done()
			pumpReader(stderrR, func(b []byte) error { return send(&runtimev1.ExecResponse{Stderr: b}) })
		}()
	}

	// Stdin + resize pump (bounded: ends on the client half-close or stream
	// cancellation). Detached — we never wait on it before returning, since a
	// client that keeps stdin open would otherwise block teardown; gRPC cancels the
	// stream on handler return, which unblocks the Recv and ends this goroutine.
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if stdinCloser != nil {
					_ = stdinCloser.Close() // EOF to the command's stdin
				}
				return
			}
			if d := req.GetStdinData(); len(d) > 0 && stdinW != nil {
				if _, werr := stdinW.Write(d); werr != nil {
					return
				}
			}
			if rs := req.GetResize(); rs != nil && ttyMaster != nil {
				_ = setWinsize(ttyMaster, uint16(rs.GetWidth()), uint16(rs.GetHeight()))
			}
		}
	}()

	// Drain all output BEFORE reaping (os/exec requires pipe reads to complete
	// before Wait; the tty master pump ends on the child's exit), then reap.
	wg.Wait()
	waitErr := cmd.Wait()
	if ttyMaster != nil {
		_ = ttyMaster.Close()
	}

	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if !errors.As(waitErr, &ee) {
			return status.Errorf(codes.Internal, "exec: %v", waitErr)
		}
		exitCode = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			exitCode = 128 + int(ws.Signal())
		}
	}
	return send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: int32(exitCode)}})
}

// Attach attaches to an ALREADY-RUNNING container's streams (`kubectl attach`).
//
// M2 limitation: native pod containers are spawned (posix_spawn) with their
// combined stdout+stderr wired to the log pipe and their stdin NOT retained — so
// there is no fd to feed new input to a running native process. Interactive
// attach (stdin, or a tty) is therefore reported Unimplemented rather than
// silently dropping the operator's keystrokes; `kubectl exec` is the supported
// interactive path. Attach supports the OUTPUT half faithfully: it replays the
// container's buffered combined output and then follows new output live until the
// container exits (delivering its exit code) or the client disconnects. Full
// interactive attach awaits the stdin-pty retention work tracked in PHASES M2.7.
func (r *Runtime) Attach(stream runtimev1.Runtime_AttachServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	_, cp, err := r.lookupContainer(first.GetPodId(), first.GetContainer())
	if err != nil {
		return err
	}
	if first.GetStdin() {
		return status.Error(codes.Unimplemented,
			"interactive attach (stdin/tty) to a running native process is not supported in M2; use `kubectl exec` (see runtimed PHASES M2.7)")
	}

	var sendMu sync.Mutex
	send := func(resp *runtimev1.AttachResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(resp)
	}

	// Follow new output from now; replay the existing buffer first so the operator
	// sees recent context (subscribe before snapshot to avoid missing a line
	// written in between).
	follow, cancel := cp.logs.subscribe()
	defer cancel()
	for _, line := range cp.logs.snapshot(0) {
		if err := send(&runtimev1.AttachResponse{Stdout: appendNewline(line)}); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-cp.proc.Done():
			code, _, _ := cp.proc.Wait(ctx)
			return send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: int32(code)}})
		case line := <-follow:
			if err := send(&runtimev1.AttachResponse{Stdout: appendNewline(line)}); err != nil {
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

// pumpReader copies r in chunks to emit until r returns EOF or an error, or emit
// fails (a dead stream). It is the streaming primitive for exec output.
func pumpReader(r io.Reader, emit func([]byte) error) {
	buf := make([]byte, pumpChunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if e := emit(append([]byte(nil), buf[:n]...)); e != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// appendNewline returns line with a trailing newline (the combined-log buffer
// stores newline-stripped lines; attach re-adds it so the operator sees discrete
// lines).
func appendNewline(line []byte) []byte {
	out := make([]byte, 0, len(line)+1)
	out = append(out, line...)
	return append(out, '\n')
}
