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

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"

	shimv1 "k3sm.io/apis/shim/v1"
)

// ShimLaunch describes a container started beside a resident shim
// (NewShimProcess). The Process's SpawnSpec spawns the shim itself in serve
// mode; Spec is what the shim reads from its stdin.
type ShimLaunch struct {
	// Spec is the shim's launch spec. Its APIVersion is filled in.
	Spec ShimSpec
	// Dialer reaches the shim's socket and reports the peer pid.
	Dialer ShimDialer
	// ProcStart reads a live process's start time (ProcStartTimeNano in
	// production); the shim's is part of the identity ConnectShim checks.
	ProcStart func(pid int) (int64, bool)
	// Kill signals a process group: the bring-up's fail-closed teardown of a
	// shim that did not come up (SignalGroup in production).
	Kill func(pgid int, sig os.Signal) error
	// ReadyTimeout bounds the wait for the shim to serve. Zero means
	// DefaultShimReadyTimeout.
	ReadyTimeout time.Duration
}

// DefaultShimReadyTimeout bounds a shim's bring-up: reading its spec, binding
// its sockets, opening the log, spawning the container and confining itself.
const DefaultShimReadyTimeout = 30 * time.Second

// maxShimDiagBytes bounds what the daemon keeps of a failing shim's
// diagnostics.
const maxShimDiagBytes = 4 << 10

// NewShimProcess builds a Process whose container runs beside a resident shim.
// spec spawns the shim (its Argv is [shim, ShimModeServe]); the spawner must not
// be asked for KeepGroup: the shim leads the pod's new process group and the
// container joins it. sink-less by construction: the shim writes the CRI log.
func NewShimProcess(spawner Spawner, waiter ExitWaiter, spec SpawnSpec, launch ShimLaunch) *Process {
	p := NewProcess(spawner, waiter, spec, nil)
	launch.Spec.APIVersion = shimv1.APIVersion
	p.launch = &launch
	p.shimDir = launch.Spec.Dir
	return p
}

// AdoptShim returns a running Process for a resident shim a previous daemon
// started, reconnected through conn (ConnectShim) with st its first Status. Its
// exit watch runs under ctx through waiter, which for a shim this daemon did not
// spawn is an AdoptedExitWaiter; the exit STATUS still comes from the shim's
// exit record, so it is real. A shim whose container has already exited reports
// the status as soon as the shim itself exits.
func AdoptShim(ctx context.Context, waiter ExitWaiter, conn *ShimConn, st *shimv1.StatusResponse) (*Process, error) {
	if waiter == nil {
		return nil, errors.New("supervisor: adopt needs an exit waiter")
	}
	id := conn.Identity()
	p := &Process{
		waiter:     waiter,
		state:      StateRunning,
		pid:        id.Pid,
		shim:       conn,
		shimDir:    id.Dir,
		childPID:   int(st.GetChildPid()),
		childStart: st.GetChildStartUnixNano(),
		done:       make(chan struct{}),
		drained:    make(chan struct{}),
	}
	go p.reap(ctx, id.Pid)
	return p, nil
}

// AdoptShimByRecord returns a running Process for a live resident shim that
// did not answer (ErrShimUnresponsive): there is no connection, so nothing is
// proxied to it, but its exit is still watched on the recorded shim pid and its
// status still comes from the exit record once it exits. id is the recorded
// identity and child the recorded container pid (0 when unknown).
func AdoptShimByRecord(ctx context.Context, waiter ExitWaiter, id ShimIdentity, child int) (*Process, error) {
	if id.Pid <= 1 || id.Dir == "" {
		return nil, fmt.Errorf("supervisor: refusing to adopt shim pid %d dir %q", id.Pid, id.Dir)
	}
	if waiter == nil {
		return nil, errors.New("supervisor: adopt needs an exit waiter")
	}
	p := &Process{
		waiter:   waiter,
		state:    StateRunning,
		pid:      id.Pid,
		shimDir:  id.Dir,
		childPID: child,
		done:     make(chan struct{}),
		drained:  make(chan struct{}),
	}
	go p.reap(ctx, id.Pid)
	return p, nil
}

// AdoptChild returns a running Process for the container child of a shim that
// died: the degraded path. pgid is the pod group (the dead shim's pid, which
// still names the group while the child lives) and child the container's own
// pid, verified by the caller against its recorded start. The exit is watched
// on the child; with no shim and no exit record its status is unknowable, so
// waiter must be an AdoptedExitWaiter (ErrExitUnknown). There is no output
// stream to resume: the pipes died with the shim.
func AdoptChild(ctx context.Context, waiter ExitWaiter, pgid, child int) (*Process, error) {
	if pgid <= 1 || child <= 1 {
		return nil, fmt.Errorf("supervisor: refusing to adopt pgid %d child %d (both must be > 1)", pgid, child)
	}
	if waiter == nil {
		return nil, errors.New("supervisor: adopt needs an exit waiter")
	}
	p := &Process{
		waiter:   waiter,
		state:    StateRunning,
		pid:      pgid,
		childPID: child,
		done:     make(chan struct{}),
		drained:  make(chan struct{}),
	}
	p.closeDrained()
	go p.reapPID(ctx, child)
	return p, nil
}

// ShimBacked reports whether the process is a resident shim's container (spawned
// or reconnected), the case where the exit status comes from the exit record.
func (p *Process) ShimBacked() bool { return p.shimDir != "" }

// Shim returns the verified connection to the process's shim, or nil.
func (p *Process) Shim() *ShimConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.shim
}

// ChildPID is the CONTAINER's pid: the process to meter, csops and sample. For a
// shim-backed process it is the shim's child; otherwise it is PID(). PID()
// stays the pod group's leader, the target of every group signal.
func (p *Process) ChildPID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.childPID > 0 {
		return p.childPID
	}
	return p.pid
}

// ChildStartUnixNano is the container child's start time as its shim reported
// it (0 when unknown).
func (p *Process) ChildStartUnixNano() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.childStart
}

// NoteKill records that this daemon is about to deliver sig to the process's
// group. A shim the group kill takes down before it persisted the container's
// exit record leaves this as the only account of the death: the exit is then
// reported as that signal rather than as a crashed shim.
func (p *Process) NoteKill(sig syscall.Signal) { p.killSig.Store(int32(sig)) }

// StopSignal returns the signal function a graceful stop drives for this
// process (GracefulStop's signal parameter). group is the group signaller.
//
// For a shim-backed process the termination signal goes to the CONTAINER alone,
// through its shim (the containerd/runc shape: TERM to the init process, KILL to
// all); a shim that does not take the request gets the signal delivered to its
// group instead. Every other signal is a group signal, and a SIGKILL is
// recorded first (NoteKill) because it can take the shim down with the
// container.
func (p *Process) StopSignal(group func(pgid int, sig os.Signal) error) func(int, os.Signal) error {
	return func(pgid int, sig os.Signal) error {
		s, _ := sig.(syscall.Signal)
		if s == syscall.SIGKILL {
			p.NoteKill(s)
		}
		if conn := p.Shim(); conn != nil && s == syscall.SIGTERM {
			err := conn.Signal(context.Background(), int(s), false)
			if err == nil {
				return nil
			}
			slog.Warn("the container's shim did not forward the termination signal; signalling the group",
				"pid", pgid, "err", err)
		}
		return group(pgid, sig)
	}
}

// startShim is Start for a shim-backed process: spawn the shim with its spec on
// stdin and its diagnostics on a pipe, wait for it to serve, verify it, and arm
// the exit watch on the shim.
//
// Readiness is the diagnostics pipe reaching EOF: the shim redirects its stdout
// and stderr to /dev/null once it is confined and serving, and a shim that
// fails before that writes why and exits, which also closes the pipe. Either
// way the daemon then dials; a shim that does not answer is killed with its
// group (the container, if it was launched, is a member) and the start fails
// with what the shim said.
func (p *Process) startShim(ctx context.Context) error {
	l := p.launch
	specR, specW, err := os.Pipe()
	if err != nil {
		p.closeDrained()
		return fmt.Errorf("shim spec pipe: %w", err)
	}
	diagR, diagW, err := os.Pipe()
	if err != nil {
		_, _ = specR.Close(), specW.Close()
		p.closeDrained()
		return fmt.Errorf("shim diagnostics pipe: %w", err)
	}
	spec := p.spec
	spec.StdinFD, spec.StdoutFD, spec.StderrFD = specR.Fd(), diagW.Fd(), diagW.Fd()
	var syncR, syncW *os.File
	if p.execObserver != nil {
		if syncR, syncW, err = os.Pipe(); err == nil {
			spec.ExecSyncFD = syncW.Fd()
		} else {
			slog.Debug("exec-sync pipe unavailable; the exec will not be observed", "path", spec.Path, "err", err)
		}
	}
	l.Spec.ExecSync = syncW != nil
	payload, err := EncodeShimSpec(l.Spec)
	if err != nil {
		_, _, _, _ = specR.Close(), specW.Close(), diagR.Close(), diagW.Close()
		if syncW != nil {
			_, _ = syncR.Close(), syncW.Close()
		}
		p.closeDrained()
		return err
	}
	pid, err := p.spawner.Spawn(ctx, spec)
	// The shim holds its own copies; the parent's must go, or EOF never comes.
	_, _ = specR.Close(), diagW.Close()
	if syncW != nil {
		_ = syncW.Close()
	}
	if err != nil {
		_, _ = specW.Close(), diagR.Close()
		if syncR != nil {
			_ = syncR.Close()
		}
		p.closeDrained()
		return fmt.Errorf("spawn %s: %w", p.spec.Path, err)
	}
	go func() {
		// A shim that dies before reading ends this write with EPIPE.
		_, _ = specW.Write(payload)
		_ = specW.Close()
	}()
	p.mu.Lock()
	p.pid = pid
	p.state = StateRunning
	p.mu.Unlock()

	timeout := l.ReadyTimeout
	if timeout <= 0 {
		timeout = DefaultShimReadyTimeout
	}
	diag, derr := readShimDiag(diagR, timeout)
	_ = diagR.Close()
	var start int64
	if l.ProcStart != nil {
		start, _ = l.ProcStart(pid)
	}
	var conn *ShimConn
	var st *shimv1.StatusResponse
	cerr := derr
	if cerr == nil {
		conn, st, cerr = ConnectShim(ctx, l.Dialer, ShimIdentity{Container: l.Spec.Container, Dir: l.Spec.Dir, Pid: pid, StartUnixNano: start}, nil)
	}
	if cerr != nil {
		p.NoteKill(syscall.SIGKILL)
		if l.Kill != nil {
			_ = l.Kill(pid, syscall.SIGKILL)
		}
		if syncR != nil {
			_ = syncR.Close()
		}
		go p.reap(ctx, pid)
		return fmt.Errorf("the resident shim for %s did not come up: %w (shim output: %q)", l.Spec.Container, cerr, diag)
	}
	p.mu.Lock()
	p.shim = conn
	p.childPID = int(st.GetChildPid())
	p.childStart = st.GetChildStartUnixNano()
	p.mu.Unlock()
	child := p.ChildPID()
	go func() {
		// The exec-sync EOF arrives when the CONTAINER execs its binary: the shim
		// relayed the pipe to it and closed its own copy. The observer asks about
		// the child, which stays unreusable until the shim reaps it.
		if syncR != nil {
			p.awaitExec(syncR, child)
		} else if p.execObserver != nil {
			p.execObserver(child, false)
		}
		p.reap(ctx, pid)
	}()
	return nil
}

// readShimDiag reads r to EOF within timeout and returns what it held, trimmed
// and bounded. A pipe still open at the deadline is an error: the shim neither
// served nor exited.
func readShimDiag(r *os.File, timeout time.Duration) (string, error) {
	if err := r.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("shim diagnostics deadline: %w", err)
	}
	var b strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 && b.Len() < maxShimDiagBytes {
			b.Write(buf[:min(n, maxShimDiagBytes-b.Len())])
		}
		if errors.Is(err, io.EOF) {
			return strings.TrimSpace(b.String()), nil
		}
		if err != nil {
			return strings.TrimSpace(b.String()), fmt.Errorf("the shim did not report ready within %s: %w", timeout, err)
		}
	}
}

// shimExit resolves a shim-backed process's exit once its shim has exited. The
// exit record is the authority; without one, a kill this daemon delivered
// (NoteKill) is the account of the death; without either the shim crashed,
// and the container's status went with it (ErrShimCrashed — the container may
// still be running).
func (p *Process) shimExit(ctx context.Context, code, sig int, err error) (int, int, error) {
	rec, ok, rerr := ReadExitRecord(p.shimDir)
	if ok {
		return rec.ExitCode, rec.Signal, nil
	}
	if rerr != nil {
		slog.Warn("the container's exit record is unreadable", "dir", p.shimDir, "err", rerr)
	}
	if err != nil && ctx.Err() != nil {
		return code, sig, err
	}
	if k := int(p.killSig.Load()); k != 0 {
		return 128 + k, k, nil
	}
	if err != nil {
		return code, sig, fmt.Errorf("%w: %w", ErrShimCrashed, err)
	}
	return code, sig, fmt.Errorf("%w (the shim exited with code %d, signal %d)", ErrShimCrashed, code, sig)
}
