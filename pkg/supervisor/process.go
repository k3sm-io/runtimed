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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"unicode/utf8"
)

const (
	// logPumpBufBytes is the pump's read buffer. A line that fits it is delivered
	// with a single copy; a longer one is streamed through it fragment by
	// fragment, so this sizes the pump's steady-state footprint, not the largest
	// line it can survive.
	logPumpBufBytes = 64 * 1024

	// maxLogLineBytes is the most of one line the pump delivers to the sink. It
	// is a TRUNCATION bound, not an acceptance bound: a longer line is delivered
	// truncated and the pump keeps going (readLogLine), so this number chooses
	// how much of a pathological line survives — it is never a cliff past which
	// output stops. Left at the 1 MiB the pre-B164 scanner used: raising it would
	// only move a cliff that no longer exists, at a per-pod memory cost in the
	// daemon that supervises every pod on the node.
	maxLogLineBytes = 1024 * 1024
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

	done      chan struct{} // closed once the process is reaped
	drained   chan struct{} // closed once the log pump has copied output to EOF
	drainOnce sync.Once     // guards the single close of drained (idempotent, panic-safe)
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
			// No pump will ever run on this Process — close the drain edge so a
			// LogsDrained() waiter is not wedged forever by a failed Start.
			p.closeDrained()
			return fmt.Errorf("log pipe: %w", err)
		}
		p.logR, p.logW = r, w
		p.spec.LogFD = w.Fd()
	}

	pid, err := p.spawner.Spawn(ctx, p.spec)
	if err != nil {
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
		p.closeDrained()
	}
	go p.reap(ctx, pid)
	return nil
}

// pumpLogs streams the combined-output pipe to the sink until EOF (child closed
// its fds / exited). It is the sole reader of logR and closes it on return, then
// closes drained to signal that every byte the child emitted has reached the sink
// (the "logs drained" edge LogsDrained exposes).
//
// A line longer than maxLogLineBytes is delivered truncated to its tail and the
// pump CONTINUES — one pathological line must never end a container's log
// delivery, which is what the pre-B164 bufio.Scanner did silently (Scan() stops
// on an over-cap token and its Err() was never checked), taking kubectl logs and
// the FallbackToLogsOnError termination message with it for the life of the
// container.
func (p *Process) pumpLogs() {
	defer p.closeDrained()
	defer p.logR.Close()

	br := bufio.NewReaderSize(p.logR, logPumpBufBytes)
	warned := false // the truncation warning is once per process, not per line
	for {
		line, dropped, ok, err := readLogLine(br, maxLogLineBytes)
		if ok {
			if dropped > 0 && !warned {
				warned = true
				slog.Warn("container log line exceeded the pump limit; truncated to its tail",
					"pid", p.PID(), "path", p.spec.Path,
					"max_line_bytes", maxLogLineBytes, "dropped_bytes", dropped)
			}
			p.sink(line)
		}
		if err != nil {
			// io.EOF is the normal end (the child closed its write end). Anything
			// else ends the pump too — the pipe is unreadable, so there is nothing
			// left to pump — but unlike the pre-B164 scanner it is REPORTED rather
			// than swallowed, which is the whole point of this loop.
			if !errors.Is(err, io.EOF) {
				slog.Warn("container log pump stopped on a read error",
					"pid", p.PID(), "path", p.spec.Path, "err", err)
			}
			return
		}
	}
}

// readLogLine reads one newline-terminated line from br, returning at most
// maxBytes of its TAIL. ok reports whether a line was produced (false only at a
// clean end of stream); dropped is how many bytes of an oversized line were
// discarded; err is the terminating read error (io.EOF at a normal end), which
// may accompany a final unterminated line.
//
// An oversized line is truncated rather than dropped, and truncated to its tail
// rather than its head, for two reasons. Truncating keeps SOME of a pathological
// line — the diagnostic case is a stack trace or a JSON blob emitted without
// newlines, where losing the line entirely loses the incident. Keeping the TAIL
// matches logBuffer.write and terminationMessageFromLogs in pkg/runtime, whose
// bias is that the most recent bytes are the most diagnostic; keeping the head
// here would make those two truncations compose into a slice out of the MIDDLE
// of the line, which is nobody's intent. The pump never buffers more than
// maxBytes+logPumpBufBytes of a line however long the line is, so an unbounded
// line is a bounded cost.
func readLogLine(br *bufio.Reader, maxBytes int) (line []byte, dropped int, ok bool, err error) {
	frag, ferr := br.ReadSlice('\n')
	if !errors.Is(ferr, bufio.ErrBufferFull) {
		// Fast path: the whole line fit the read buffer (the overwhelming case).
		// A partial line held when a read fails is still delivered — those bytes
		// exist and are the last thing the container said.
		if len(frag) == 0 {
			return nil, 0, false, ferr
		}
		// The bound is applied here too. With the shipped sizes a line that fit
		// the read buffer cannot exceed max, but readLogLine must honor its own
		// contract at any maxBytes rather than inherit it from a sibling constant.
		line, dropped = truncateTail(trimEOL(bytes.Clone(frag)), maxBytes)
		return line, dropped, true, ferr
	}

	// Slow path: the line is longer than the read buffer. Retain trailing
	// fragments and discard leading ones, so memory stays bounded by
	// maxBytes+logPumpBufBytes no matter how long the line runs.
	var (
		kept  [][]byte
		keptN int
	)
	for {
		if len(frag) > 0 {
			cp := bytes.Clone(frag)
			kept = append(kept, cp)
			keptN += len(cp)
			for len(kept) > 1 && keptN-len(kept[0]) >= maxBytes {
				keptN -= len(kept[0])
				dropped += len(kept[0])
				kept[0] = nil // release the fragment before reslicing
				kept = kept[1:]
			}
		}
		if !errors.Is(ferr, bufio.ErrBufferFull) {
			break
		}
		frag, ferr = br.ReadSlice('\n')
	}

	buf := make([]byte, 0, keptN)
	for _, f := range kept {
		buf = append(buf, f...)
	}
	buf, cut := truncateTail(trimEOL(buf), maxBytes)
	return buf, dropped + cut, true, ferr
}

// truncateTail returns the last maxBytes of b rounded up to a rune boundary,
// with the number of bytes it discarded.
func truncateTail(b []byte, maxBytes int) (line []byte, dropped int) {
	if len(b) <= maxBytes {
		return b, 0
	}
	tail := utf8TailBytes(b, maxBytes)
	return tail, len(b) - len(tail)
}

// trimEOL strips the line terminator, matching bufio.ScanLines: the newline and
// a carriage return immediately before it (or at end of input).
func trimEOL(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// utf8TailBytes returns the last n bytes of b, advanced to the next UTF-8 rune
// start so the result never begins with orphan continuation bytes (this only
// ever trims, so the n-byte bound still holds). It is a deliberate twin of the
// identical helper in pkg/runtime: that package imports this one, so a shared
// home would need a new internal package for eight lines of byte arithmetic.
func utf8TailBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	b = b[len(b)-n:]
	for len(b) > 0 && !utf8.RuneStart(b[0]) {
		b = b[1:]
	}
	return b
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
// graceful-stop timer both select on it — and is never used to wait4: the kqueue
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

// closeDrained closes the drained edge exactly once. It is the single owner of
// that close: the log pump (at EOF), the no-sink Start branch, and the failed-Start
// returns all funnel through it, so a Process whose Start never reached the pump
// (pipe/spawn error) still releases LogsDrained() waiters — and a retried Start
// after such a failure can never double-close.
func (p *Process) closeDrained() {
	p.drainOnce.Do(func() { close(p.drained) })
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
