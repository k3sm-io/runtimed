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

package guestagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// DefaultMaxLineBytes bounds ONE retained entry, and with it the partial line a
// writer may hold in guest RAM while waiting for a newline that may never come.
//
// It is a separate bound from the ring's two because it constrains a different
// thing: the ring bounds what is RETAINED, this bounds what is BUFFERED before
// anything is retained at all. A container emitting one endless line with no
// newline would otherwise grow an unbounded partial in the pump, which the ring's
// caps never see and therefore never evict.
const DefaultMaxLineBytes = 16 << 10

// ErrNoCapture reports that no output was captured for a container. It is
// distinct from an empty stream, which asserts the container produced nothing;
// this asserts the guest was never wired to listen.
var ErrNoCapture = errors.New("guestagent: no output is captured for this container")

// truncationNotice is the one-line, in-band notice a reader gets when retention
// has dropped output — the pkg/vmhost CappedWriter idiom (consoleTruncationNotice)
// applied to a ring rather than to a cap: a truncated log and a container that
// simply went quiet look identical without it, and they call for opposite operator
// actions. The direction differs because the mechanism does — the console stops
// writing at its cap, the ring evicts OLDEST-first — so this names earlier output,
// not later.
func truncationNotice(dropped int) []byte {
	return []byte(fmt.Sprintf(
		"[k3sm-guest] log truncated: %d earlier entries were dropped to stay inside this container's retention bound",
		dropped))
}

// Capture is the guest's per-container output capture and the Logs seam over it.
//
// It exists because a vm pod's containers used to inherit PID 1's stdio: their
// output went to the VM console and `kubectl logs` could only report that there
// was no per-container buffer to serve from. Each container now gets its own pipes
// (cmd/k3sm-guest-init), and each pipe is pumped into that container's Ring
// through a Writer from here.
//
// BOUNDED, because the guest has no disk. Its rootfs upper is a tmpfs in the VM's
// RAM, which is the pod's hypervisor-enforced memory ceiling, so an unbounded log
// buffer is a way for a chatty workload to OOM its own guest and have the kill
// attributed to the workload's real memory use. Every container's retention is
// therefore capped twice over (entries and bytes, see Ring) with oldest dropped,
// each entry is capped once more (DefaultMaxLineBytes), and what the bounds
// discard is reported in band rather than left as a silent gap.
//
// The zero value is not usable; construct one with NewCapture.
type Capture struct {
	maxEntries int
	maxBytes   int
	maxLine    int

	mu    sync.Mutex
	rings map[string]*Ring
	// raws are the per-container RAW replay buffers `kubectl attach` streams
	// from, kept alongside the line rings rather than in a registry of their
	// own because they are the same fact about the same container, ended by the
	// same Close on the same reap path. What differs is the GRANULARITY, and it
	// differs because the consumers do: `kubectl logs --tail` needs lines,
	// while an attached terminal needs the bytes a program actually wrote —
	// including the newline-less ones (a shell prompt, a pty's keystroke echo)
	// that a line writer holds until a delimiter arrives that may never come.
	raws map[string]*ByteRing
}

// NewCapture builds a capture whose per-container rings take the given bounds;
// non-positive values take DefaultRingEntries / DefaultRingBytes /
// DefaultMaxLineBytes.
func NewCapture(maxEntries, maxBytes, maxLine int) *Capture {
	if maxLine <= 0 {
		maxLine = DefaultMaxLineBytes
	}
	return &Capture{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		maxLine:    maxLine,
		rings:      map[string]*Ring{},
		raws:       map[string]*ByteRing{},
	}
}

// Raw returns the container's raw replay buffer, creating it on first use.
//
// The guest's output pump TEES each read into this and into the container's
// line ring (cmd/k3sm-guest-init's consoleTee), so the two hold the same output
// at the two granularities their consumers need. Calling it registers the
// container, exactly as Writer does, so an attach to a container that has
// produced nothing yet streams empty rather than reporting ErrNoCapture —
// "nothing yet" and "never wired" are different answers.
func (c *Capture) Raw(container string) *ByteRing {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.raws[container]
	if !ok {
		r = NewByteRing(0, 0)
		c.raws[container] = r
	}
	return r
}

// RawStream implements the RawOutput seam: a subscription over the container's
// raw output, carrying the bytes retained at registration and the ones written
// after, with no gap and no duplicate between them (ByteRing.Subscribe).
//
// A container with no raw buffer is ErrNoCapture — the same distinction Stream
// draws, and for the same reason: it asserts the guest was never wired to
// listen, which is a different fact from a container that has been quiet.
func (c *Capture) RawStream(container string) (*ByteSubscription, error) {
	c.mu.Lock()
	ring := c.raws[container]
	c.mu.Unlock()
	if ring == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoCapture, container)
	}
	return ring.Subscribe(0), nil
}

// ring returns the container's ring, creating it on first use.
func (c *Capture) ring(container string) *Ring {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.rings[container]
	if !ok {
		r = NewRing(c.maxEntries, c.maxBytes)
		c.rings[container] = r
	}
	return r
}

// lookup returns the container's ring without creating one.
func (c *Capture) lookup(container string) *Ring {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rings[container]
}

// Writer returns the sink for one of a container's two output streams. The
// caller pumps the container's pipe into it and MUST Close it at EOF, which
// flushes any final line that arrived without a trailing newline.
//
// Calling Writer registers the container, so a container that has produced no
// output yet streams empty rather than reporting ErrNoCapture — "nothing yet" and
// "never wired" are different answers and an operator acts differently on each.
func (c *Capture) Writer(container string, kind LogStreamKind) io.WriteCloser {
	return &lineWriter{ring: c.ring(container), kind: kind, maxLine: c.maxLine}
}

// Close ends every follower of a container's stream, at BOTH granularities. It
// is called when the container exits: a `kubectl logs -f` reader and an
// attached terminal must each see end-of-stream rather than hang on a process
// that will never write again.
//
// Retained output survives on both rings, so a reader arriving after the exit
// still gets what the container said before it.
func (c *Capture) Close(container string) {
	if r := c.lookup(container); r != nil {
		r.Close()
	}
	c.mu.Lock()
	raw := c.raws[container]
	c.mu.Unlock()
	if raw != nil {
		raw.Close()
	}
}

// CloseAll closes every container's streams, for guest shutdown.
func (c *Capture) CloseAll() {
	c.mu.Lock()
	rings := make([]*Ring, 0, len(c.rings))
	for _, r := range c.rings {
		rings = append(rings, r)
	}
	raws := make([]*ByteRing, 0, len(c.raws))
	for _, r := range c.raws {
		raws = append(raws, r)
	}
	c.mu.Unlock()
	for _, r := range rings {
		r.Close()
	}
	for _, r := range raws {
		r.Close()
	}
}

// Stream implements the Logs seam: the container's retained entries matching sel,
// then — with sel.Follow — its live ones, until ctx ends or the container exits.
//
// Every Selector field is either honoured or REFUSED, never ignored. TailLines,
// SinceTime and Follow are applied (the first two by Ring.Snapshot, in upstream's
// order); Previous is refused with a stated reason, because this init starts a
// container exactly once and the host recreates the whole pod on failure, so there
// is no earlier instance in this guest to have retained. Silently serving the
// current instance for a `--previous` request would answer a question about a
// crash with output from the process that replaced it.
func (c *Capture) Stream(ctx context.Context, container string, sel Selector) (<-chan LogEntry, func(), error) {
	ring := c.lookup(container)
	if ring == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrNoCapture, container)
	}
	if sel.Previous {
		return nil, nil, errors.New("this guest retains no output from a previous container instance")
	}

	out := make(chan LogEntry, 64)
	live, unsubscribe := ring.Subscribe(0)
	done := make(chan struct{})
	go func() {
		defer close(out)
		defer unsubscribe()

		// The snapshot and the drop count are read together, under the ring's
		// own lock, so the notice describes exactly the gap that precedes the
		// entries being sent — not a count that moved between two reads.
		retained, dropped := ring.SnapshotWithDropped(sel)
		reported := dropped
		send := func(e LogEntry) bool {
			select {
			case out <- e:
				return true
			case <-ctx.Done():
				return false
			case <-done:
				return false
			}
		}
		if dropped > 0 {
			if !send(noticeEntry(dropped)) {
				return
			}
		}
		for _, e := range retained {
			if !send(e) {
				return
			}
		}
		if !sel.Follow {
			return
		}
		for {
			select {
			case e, ok := <-live:
				if !ok {
					return
				}
				// Retention can keep evicting while a follower reads, so the
				// notice is re-issued when the count grows. Same notice, same
				// idiom — a follower must not be shown a gap it was never told
				// about just because it arrived before the drop.
				if now := ring.Dropped(); now > reported {
					if !send(noticeEntry(now)) {
						return
					}
					reported = now
				}
				if !send(e) {
					return
				}
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return out, func() { once.Do(func() { close(done) }) }, nil
}

// noticeEntry wraps the truncation notice as an entry. It is labelled stderr
// because it is the runtime speaking, not the container: `kubectl logs` merges
// the two, and a consumer that split them would otherwise read a k3sm diagnostic
// as the workload's own output.
func noticeEntry(dropped int) LogEntry {
	return LogEntry{At: time.Now(), Line: truncationNotice(dropped), Stream: StreamStderr}
}

// lineWriter turns a container's raw pipe bytes into one ring entry per LINE.
//
// Line granularity is what makes Selector.TailLines mean what its name says and
// what `kubectl logs --tail` means. A chunk-per-read granularity would make "the
// last 10 entries" depend on how the workload happened to flush, which is not
// something a user can reason about.
//
// The delimiter is STRIPPED (and a preceding CR with it): pkg/runtime's
// logEmitter budgets "the rendered line plus its newline delimiter", so an entry
// that carried its own newline would be double-delimited on the way out.
//
// A line longer than maxLine is emitted in maxLine-sized pieces rather than
// buffered whole — see DefaultMaxLineBytes for why the unbounded alternative is an
// OOM in a guest whose only storage is RAM.
type lineWriter struct {
	ring    *Ring
	kind    LogStreamKind
	maxLine int

	mu  sync.Mutex
	buf []byte
}

// Write splits p into entries at newlines, retaining any trailing partial for the
// next Write. It never reports a short write: the caller is the pump draining a
// container's pipe, and a short write there stops the pump, fills the pipe, and
// blocks the workload on its own stdout.
func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emitLocked(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	// No newline in sight and the partial is over the bound: emit what is held
	// rather than keep growing it.
	for len(w.buf) > w.maxLine {
		w.emitLocked(w.buf[:w.maxLine])
		w.buf = w.buf[w.maxLine:]
	}
	// Re-slice onto a fresh array once the retained partial is small relative to
	// the array behind it, so a burst of large writes does not pin its capacity.
	if len(w.buf) == 0 && cap(w.buf) > w.maxLine {
		w.buf = nil
	}
	return len(p), nil
}

// Close flushes a final line that arrived with no trailing newline — the common
// shape of a container's last write before it exits.
func (w *lineWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.emitLocked(w.buf)
		w.buf = nil
	}
	return nil
}

// emitLocked appends one line to the ring, stripping a trailing CR so a workload
// writing CRLF does not leave a stray carriage return at the end of every entry.
// The caller holds w.mu; Ring.Append copies the bytes, so the slice may alias the
// writer's buffer.
func (w *lineWriter) emitLocked(line []byte) {
	line = bytes.TrimSuffix(line, []byte("\r"))
	w.ring.Append(LogEntry{At: time.Now(), Line: line, Stream: w.kind})
}
