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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
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

// LogSink consumes combined stdout+stderr lines from a supervised process. It is
// called from a dedicated goroutine; implementations must be safe for that and
// must not block indefinitely.
type LogSink func(line []byte)

// Process supervises one native pod process: it spawns it (own process group),
// streams its combined output to a LogSink, and reaps it via an ExitWaiter (the
// sole reaper). A Process is single-use: Start once, then Wait.
//
// Concurrency: mu guards the lifecycle fields below. The log-pump and reap
// goroutines have clear lifetimes bounded by the process exit / ctx; done is
// closed by the reaper (the sender) when the final status is set.
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

	logR *os.File // read end of the combined-log pipe (parent side)
	logW *os.File // write end handed to the child (closed in parent after spawn)

	done    chan struct{} // closed once the process is reaped
	drained chan struct{} // closed once the log pump has copied output to EOF
}

// NewProcess builds a Process. spawner and waiter are the spawn/reap seams; spec
// describes the child; sink (optional) receives combined-output lines.
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

// Start creates the combined-log pipe, spawns the child in its own process
// group, and launches the log-pump and reaper goroutines. It returns once the
// child pid is known. Calling Start twice is an error.
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.state != StateInit {
		p.mu.Unlock()
		return fmt.Errorf("supervisor: already started (state %s)", p.state)
	}
	p.mu.Unlock()

	// Combined stdout+stderr pipe: the child writes both fds into logW; the
	// parent reads logR and pumps to the sink.
	if p.sink != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return fmt.Errorf("log pipe: %w", err)
		}
		p.logR, p.logW = r, w
		p.spec.LogFD = w.Fd()
	}

	pid, err := p.spawner.Spawn(ctx, p.spec)
	if err != nil {
		p.closePipes()
		return fmt.Errorf("spawn %s: %w", p.spec.Path, err)
	}

	p.mu.Lock()
	p.pid = pid
	p.state = StateRunning
	p.mu.Unlock()

	// Parent no longer needs the write end; the child holds its dup.
	if p.logW != nil {
		_ = p.logW.Close()
		p.logW = nil
	}

	if p.sink != nil {
		go p.pumpLogs()
	} else {
		// No sink → no log pump → nothing to drain; make the edge immediately
		// observable so LogsDrained() never blocks a waiter on a sink-less process.
		close(p.drained)
	}
	go p.reap(ctx, pid)
	return nil
}

// pumpLogs streams the combined-output pipe to the sink until EOF (child closed
// its fds / exited). It is the sole reader of logR and closes it on return, then
// closes drained to signal that every byte the child emitted has reached the sink
// (the "logs drained" edge LogsDrained exposes).
func (p *Process) pumpLogs() {
	defer close(p.drained)
	defer p.logR.Close()
	sc := bufio.NewScanner(p.logR)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		buf := make([]byte, len(line))
		copy(buf, line)
		p.sink(buf)
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
// broadcast signal safe for multiple observers — e.g. Wait and the M2.4
// graceful-stop timer both select on it — and is NEVER used to wait4: the kqueue
// reaper stays the sole reaper. The channel exists from NewProcess; it is only
// closed after Start → reap.
func (p *Process) Done() <-chan struct{} { return p.done }

// LogsDrained returns a channel closed once the log pump has copied the child's
// combined stdout+stderr to EOF (the child closed its write end) and flushed every
// line to the sink. It is the observable "logs fully drained" edge: the runtime
// waits on it before snapshotting a terminated container's log tail for the
// FallbackToLogsOnError termination message, so the final, most-diagnostic lines
// (a panic / stack trace) are not lost to the pump-vs-reaper race — the pump drains
// the dying child's bytes INDEPENDENTLY of the kqueue reaper that unblocks Wait.
// Like Done it is broadcast-safe for multiple observers and exists from NewProcess;
// it is only closed after Start (immediately when the process has no sink → no pump).
func (p *Process) LogsDrained() <-chan struct{} { return p.drained }

// State returns the current lifecycle state.
func (p *Process) State() ProcessState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// closePipes closes any open pipe ends (used on spawn failure).
func (p *Process) closePipes() {
	if p.logR != nil {
		_ = p.logR.Close()
		p.logR = nil
	}
	if p.logW != nil {
		_ = p.logW.Close()
		p.logW = nil
	}
}
