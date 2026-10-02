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
	"sync"
	"time"

	"k3sm.io/runtimed/pkg/crilog"
)

// ErrNotStarted reports an operation on a Process that has not been started.
var ErrNotStarted = errors.New("supervisor: process not started")

// ProcessState is the lifecycle state of a supervised pod process.
type ProcessState int

const (
	// StateInit is the state before Start.
	StateInit ProcessState = iota
	// StateRunning is set once the child is spawned and before it exits.
	StateRunning
	// StateExited is set once the child has been reaped.
	StateExited
)

// String renders the ProcessState.
func (s ProcessState) String() string {
	switch s {
	case StateInit:
		return "init"
	case StateRunning:
		return "running"
	case StateExited:
		return "exited"
	default:
		return "unknown"
	}
}

// LogSink consumes one chunk of a supervised process's output, already split
// into CRI log chunks (crilog.Chunk): stream says which of the child's two
// descriptors produced it, and partial is the CRI P/F tag — true while the
// chunk continues a logical line, false on the chunk that ends one.
//
// CONCURRENCY: it is called from TWO goroutines, one per stream, with no
// serialisation between them. An implementation must be safe for that; the
// production sink (a crilog.Writer) takes one mutex across the whole of a line
// for exactly this reason.
//
// A non-nil return STOPS that stream's pump, which then CLOSES ITS READ END —
// so the child's next write(2) on that descriptor takes EPIPE/SIGPIPE. That is
// containerd's contract and it is deliberate: a pump that swallowed a write
// failure and kept draining would hide the loss, and one that stopped draining
// without closing would block the pod on a full pipe with nothing saying why.
type LogSink func(stream crilog.Stream, chunk []byte, partial bool) error

// Process supervises one native pod process: it spawns it (own process group),
// streams its stdout and stderr to a LogSink, and reaps it via an ExitWaiter
// (the sole reaper). A Process is single-use: Start once, then Wait.
//
// Concurrency: mu guards the lifecycle fields below. The two log-pump
// goroutines and the reap goroutine have clear lifetimes bounded by the process
// exit / ctx; done is closed by the reaper (the sender) when the final status is
// set, and drained is closed once BOTH pumps have finished.
type Process struct {
	spawner Spawner
	spec    SpawnSpec
	waiter  ExitWaiter
	sink    LogSink

	mu       sync.Mutex
	state    ProcessState
	pid      int
	exitCode int
	signal   int
	exitErr  error

	// The two output pipes, parent side. The R ends are read by the pumps and
	// closed by them; the W ends are handed to the child and closed in the
	// parent immediately after the spawn.
	outR, outW *os.File
	errR, errW *os.File

	// pumps counts the live log pumps. The drained edge closes when it reaches
	// zero, never on the first pump to finish — see LogsDrained.
	pumps sync.WaitGroup

	// execObserver and execTimeout are set by ObserveExec before Start and
	// read only by Start (single-use), so they need no lock.
	execObserver func(pid int, observed bool)
	execTimeout  time.Duration

	// capture, when set by CaptureToFiles before Start, routes the child's
	// stdout/stderr into append-only files the pumps tail, instead of pipes.
	// Read only by Start (single-use), so it needs no lock.
	capture *FileCapture

	done      chan struct{} // closed once the process is reaped
	drained   chan struct{} // closed once BOTH log pumps have copied output to EOF
	drainOnce sync.Once     // guards the single close of drained (idempotent, panic-safe)
}

// NewProcess builds a Process. spawner and waiter are the spawn/reap seams; spec
// describes the child; sink (optional) receives its output chunks.
func NewProcess(spawner Spawner, waiter ExitWaiter, spec SpawnSpec, sink LogSink) *Process {
	return &Process{
		spawner: spawner,
		waiter:  waiter,
		spec:    spec,
		sink:    sink,
		state:   StateInit,
		done:    make(chan struct{}),
		drained: make(chan struct{}),
	}
}

// ObserveExec asks the Process to call fn exactly once with the child's pid
// and whether the exec was observed: observed is true once the spawned
// exec-shim has exec'd the pod binary (or exited). It must be called
// before Start. fn runs on the reaper goroutine, BEFORE that goroutine starts
// its exit wait, so it runs concurrently with the caller of Start: fn must do
// its own locking.
//
// Why the wait exists: the spawned process is the exec-shim, which drops
// privilege and applies the sandbox before it execs the pod binary, so a
// question about the POD's image (its code-signing flags, say) asked straight
// after posix_spawn is answered by the shim. The exec-sync pipe (SpawnSpec.
// ExecSyncFD) turns "the shim has exec'd" into an EOF. Why on the reaper
// goroutine: until that goroutine reaps the exit, the pid is at worst a zombie
// and cannot be reused, so fn can never be answered by an unrelated process;
// and Start does not wait, so a container start costs nothing extra.
//
// fn is called with observed false when the pipe cannot be made, has no
// deadline, or EOF does not arrive within timeout (a shim that predates the
// exec-sync protocol holds the descriptor open into the pod), so the caller
// can report an unanswerable question instead of staying silent. A process
// that has already exited when fn asks about it is a zombie, for which csops
// reports ESRCH; that too is the caller's to classify.
func (p *Process) ObserveExec(fn func(pid int, observed bool), timeout time.Duration) {
	p.execObserver = fn
	p.execTimeout = timeout
}

// CaptureToFiles routes the child's stdout and stderr into the two append-only
// files c names instead of pipes, and makes the log pumps TAIL them into the
// sink from the offset persisted beside each file (see rawTail). It must be
// called before Start, and only matters with a sink.
//
// Why files: a pipe's read end lives in this daemon, so when the daemon dies the
// child's next write takes EPIPE and — SIGPIPE's default action — the child dies
// with it. A file descriptor has no reader to lose: the child keeps writing, and
// the next daemon resumes the tail where the last one stopped (AdoptProcess).
func (p *Process) CaptureToFiles(c FileCapture) {
	p.capture = &c
}

// openCaptureFiles opens both capture files for the child and stamps them on
// the spec, unwinding the first if the second fails (openPipes' shape).
func (p *Process) openCaptureFiles() error {
	outW, err := openCaptureFile(p.capture.Stdout)
	if err != nil {
		return err
	}
	errW, err := openCaptureFile(p.capture.Stderr)
	if err != nil {
		_ = outW.Close()
		return err
	}
	p.outW, p.errW = outW, errW
	p.spec.StdoutFD = outW.Fd()
	p.spec.StderrFD = errW.Fd()
	return nil
}

// startTails launches the two capture tails, and the join that closes drained.
func (p *Process) startTails() {
	p.pumps.Add(2)
	go p.tailLogs(p.capture.Stdout, crilog.StreamStdout)
	go p.tailLogs(p.capture.Stderr, crilog.StreamStderr)
	go func() {
		p.pumps.Wait()
		p.closeDrained()
	}()
}

// tailLogs is pumpLogs for a capture file: it tails path into the sink until the
// process is reaped, then drains to the end of the file and returns.
func (p *Process) tailLogs(path string, stream crilog.Stream) {
	defer p.pumps.Done()
	t := &rawTail{path: path, stream: stream, sink: p.sink, maxBytes: RawCaptureMaxBytes, poll: rawTailPoll}
	if err := t.run(context.Background(), p.done); err != nil {
		// Nothing reads the capture file from here on, so nothing truncates it
		// at the size bound either: the child's output accumulates on disk until
		// the pod is deleted. Say so, so the growth has a visible cause.
		slog.Warn("container log tail stopped (the log sink refused a chunk or the capture file is unreadable); the capture file will now grow without bound until the pod is deleted",
			"pid", p.PID(), "path", path, "stream", string(stream), "err", err)
	}
}

// openExecSync creates the exec-sync pipe and returns the spawn spec carrying
// its write end plus the read end, or (spec, nil) when there is no observer or
// the pipe cannot be made.
func (p *Process) openExecSync() (SpawnSpec, *os.File, *os.File) {
	spec := p.spec
	if p.execObserver == nil {
		return spec, nil, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		slog.Debug("exec-sync pipe unavailable; the exec will not be observed", "path", spec.Path, "err", err)
		return spec, nil, nil
	}
	spec.ExecSyncFD = w.Fd()
	// A nil Env means "inherit this process's environment" to the spawner, so
	// the variable is appended to that, never to an empty list.
	base := spec.Env
	if base == nil {
		base = os.Environ()
	}
	spec.Env = append(append([]string{}, base...), fmt.Sprintf("%s=%d", ExecSyncFDEnv, ExecSyncChildFD))
	return spec, r, w
}

// awaitExec blocks until r reaches EOF (the child exec'd or exited) or the
// timeout passes, then calls the observer with observed true on EOF and false
// otherwise. It closes r.
func (p *Process) awaitExec(r *os.File, pid int) {
	defer func() { _ = r.Close() }()
	if err := r.SetReadDeadline(time.Now().Add(p.execTimeout)); err != nil {
		slog.Debug("exec-sync pipe has no deadline; the exec is not observed", "pid", pid, "err", err)
		p.execObserver(pid, false)
		return
	}
	var b [1]byte
	for {
		_, err := r.Read(b[:])
		if errors.Is(err, io.EOF) {
			p.execObserver(pid, true)
			return
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			slog.Debug("exec-sync wait hit its bound; the exec is not observed",
				"pid", pid, "timeout", p.execTimeout)
			p.execObserver(pid, false)
			return
		}
		if err != nil {
			slog.Debug("exec-sync wait ended without an exec; the exec is not observed", "pid", pid, "err", err)
			p.execObserver(pid, false)
			return
		}
	}
}

// Start creates the two output pipes, spawns the child in its own process
// group, and launches the log-pump and reaper goroutines. It returns once the
// child pid is known. Calling Start twice is an error.
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.state != StateInit {
		p.mu.Unlock()
		return fmt.Errorf("supervisor: already started (state %s)", p.state)
	}
	p.mu.Unlock()

	// One pipe per stream: the child writes fd 1 into outW and fd 2 into errW;
	// the parent reads each R end and pumps it to the sink under its own label.
	if p.sink != nil {
		open := p.openPipes
		if p.capture != nil {
			open = p.openCaptureFiles
		}
		if err := open(); err != nil {
			// No pump will ever run on this Process — close the drain edge so a
			// LogsDrained() waiter is not wedged forever by a failed Start.
			p.closeDrained()
			return err
		}
	}

	spec, syncR, syncW := p.openExecSync()
	pid, err := p.spawner.Spawn(ctx, spec)
	if syncW != nil {
		// The child holds its own dup; the parent's write end must go or the
		// read end never reaches EOF.
		_ = syncW.Close()
	}
	if err != nil {
		if syncR != nil {
			_ = syncR.Close()
		}
		p.closePipes()
		// Spawn failed: no pump and no reaper start, so nothing else will ever
		// close drained. Close it here (idempotent) so LogsDrained() never blocks.
		p.closeDrained()
		return fmt.Errorf("spawn %s: %w", p.spec.Path, err)
	}

	p.mu.Lock()
	p.pid = pid
	p.state = StateRunning
	p.mu.Unlock()

	// Parent no longer needs either write end; the child holds its dups. They
	// must go before the pumps read: while the parent holds a write end open,
	// the pipe never reaches EOF even after the child exits.
	p.closeWriteEnds()

	if p.sink != nil && p.capture != nil {
		p.startTails()
	} else if p.sink != nil {
		outR, errR := p.outR, p.errR
		p.pumps.Add(2)
		go p.pumpLogs(outR, crilog.StreamStdout)
		go p.pumpLogs(errR, crilog.StreamStderr)
		go func() {
			p.pumps.Wait()
			p.closeDrained()
		}()
	} else {
		// No sink → no log pumps → nothing to drain; make the edge immediately
		// observable so LogsDrained() never blocks a waiter on a sink-less process.
		p.closeDrained()
	}
	// The exec observation runs at the START of the reaper goroutine, before
	// its exit wait: Start returns at once (a pod start is never serialized
	// behind it), and the pid cannot be reused until this same goroutine
	// reaps it. See ObserveExec.
	go func() {
		if syncR != nil {
			p.awaitExec(syncR, pid)
		} else if p.execObserver != nil {
			// The exec-sync pipe could not be made: the exec goes unobserved.
			p.execObserver(pid, false)
		}
		p.reap(ctx, pid)
	}()
	return nil
}

// openPipes creates both output pipes and stamps their write ends on the spec.
// It unwinds the FIRST pipe if the second fails: a half-created pair would leak
// two descriptors per failed start in a daemon that starts every pod on the
// node, and would leave a spec carrying a stdout fd the child would inherit
// with no reader.
func (p *Process) openPipes() error {
	outR, outW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return fmt.Errorf("stderr pipe: %w", err)
	}
	p.outR, p.outW = outR, outW
	p.errR, p.errW = errR, errW
	p.spec.StdoutFD = outW.Fd()
	p.spec.StderrFD = errW.Fd()
	return nil
}

// pumpLogs streams one of the child's output pipes to the sink until EOF (the
// child closed that fd / exited) or the sink refuses a chunk. It is the sole
// reader of r and CLOSES IT on return — which is what makes a sink failure
// visible to the container as an EPIPE rather than as a silent hang on a pipe
// nobody drains (see LogSink).
//
// Splitting is crilog's: a line longer than crilog.MaxLineBytes is emitted as P
// chunks and nothing is dropped, so one pathological line can neither end a
// container's log delivery nor lose its content — the two failure modes the
// earlier scanner-based and truncating pumps had in turn.
func (p *Process) pumpLogs(r *os.File, stream crilog.Stream) {
	defer p.pumps.Done()
	defer func() { _ = r.Close() }()

	err := crilog.Chunk(r, func(chunk []byte, partial bool) error {
		return p.sink(stream, chunk, partial)
	})
	if err != nil {
		// Only a SINK error reaches here (crilog.Chunk swallows the ordinary
		// read end-of-stream), and it has already stopped this stream. One line,
		// naming the stream and the cause, is the operator's whole signal that a
		// container's output is no longer being recorded.
		slog.Warn("container log pump stopped: the log sink refused a chunk",
			"pid", p.PID(), "path", p.spec.Path, "stream", string(stream), "err", err)
	}
}

// reap waits for the child to exit via the ExitWaiter (the sole reaper), records
// the final status, and closes done. It is the only place that observes the
// exit, so there is no double-reap race.
func (p *Process) reap(ctx context.Context, pid int) {
	code, sig, err := p.waiter.WaitExit(ctx, pid)
	p.mu.Lock()
	p.exitCode = code
	p.signal = sig
	p.exitErr = err
	p.state = StateExited
	p.mu.Unlock()
	close(p.done)
}

// Wait blocks until the process is reaped (or ctx is done) and returns its exit
// code and terminating signal (0 if none). It is safe to call repeatedly.
func (p *Process) Wait(ctx context.Context) (exitCode int, signal int, err error) {
	p.mu.Lock()
	started := p.state != StateInit
	p.mu.Unlock()
	if !started {
		return 0, 0, ErrNotStarted
	}
	select {
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	case <-p.done:
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitCode, p.signal, p.exitErr
}

// PID returns the child pid (0 before Start).
func (p *Process) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// Done returns a channel closed once the process has been reaped (the single
// kqueue reaper observed its exit and recorded the final status). It is a
// broadcast signal safe for multiple observers — e.g. Wait and the
// graceful-stop timer both select on it — and is never used to wait4: the kqueue
// reaper stays the sole reaper. The channel exists from NewProcess; it is only
// closed after Start → reap.
func (p *Process) Done() <-chan struct{} { return p.done }

// LogsDrained returns a channel closed once BOTH log pumps have copied the
// child's stdout and stderr to EOF (the child closed its write ends) and flushed
// every chunk to the sink. It is the observable "logs fully drained" edge: the
// runtime waits on it before finalizing a terminated container, so the final,
// most-diagnostic output (a panic / stack trace, which a runtime commonly writes
// to stderr) is not lost to the pump-vs-reaper race — the pumps drain the dying
// child's bytes INDEPENDENTLY of the kqueue reaper that unblocks Wait.
//
// BOTH, not either: a sync.Once guards a single closing event, so closing on the
// first pump's EOF would report "drained" while the other stream — usually the
// interesting one — was still in flight. The pumps are joined through a
// WaitGroup and the edge closes when the count reaches zero.
//
// Like Done it is broadcast-safe for multiple observers and exists from
// NewProcess; it is only closed after Start (immediately when the process has no
// sink → no pumps).
func (p *Process) LogsDrained() <-chan struct{} { return p.drained }

// State returns the current lifecycle state.
func (p *Process) State() ProcessState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// closeDrained closes the drained edge exactly once. It is the single owner of
// that close: the pump JOIN (both pumps at EOF), the no-sink Start branch, and
// the failed-Start returns all funnel through it, so a Process whose Start never
// reached the pumps (pipe/spawn error) still releases LogsDrained() waiters —
// and a retried Start after such a failure can never double-close.
func (p *Process) closeDrained() {
	p.drainOnce.Do(func() { close(p.drained) })
}

// closeWriteEnds closes the parent's copies of both pipe write ends after the
// spawn. The child holds its dups; while the parent held one open the pipe
// would never reach EOF and the pump would never drain.
func (p *Process) closeWriteEnds() {
	if p.outW != nil {
		_ = p.outW.Close()
		p.outW = nil
	}
	if p.errW != nil {
		_ = p.errW.Close()
		p.errW = nil
	}
}

// closePipes closes every open pipe end (used on spawn failure, where no pump
// will ever run to close a read end itself).
func (p *Process) closePipes() {
	p.closeWriteEnds()
	if p.outR != nil {
		_ = p.outR.Close()
		p.outR = nil
	}
	if p.errR != nil {
		_ = p.errR.Close()
		p.errR = nil
	}
}
