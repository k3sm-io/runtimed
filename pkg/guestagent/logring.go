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
	"sync"
	"time"
)

// DefaultRingEntries and DefaultRingBytes bound one container's retained output.
//
// both bounds are needed, and neither implies the other: an entry cap alone lets a
// container hold a gigabyte in a thousand enormous lines, and a byte cap alone lets
// it hold a million empty ones. The guest has no disk of its own — the ring is in
// the VM's RAM, which is the pod's hypervisor-enforced memory ceiling — so an
// unbounded log buffer is a way for a chatty workload to OOM its own guest and have
// the kill attributed to the workload's real memory use.
const (
	DefaultRingEntries = 4096
	DefaultRingBytes   = 4 << 20
)

// LogStreamKind distinguishes a container's two output streams. It is an
// agent-local type rather than the runtime/v1 enum so this file stays free of
// proto imports and remains a plain, table-testable buffer; the server maps it at
// the boundary.
type LogStreamKind int

// The two streams a container writes.
const (
	// StreamStdout is the container's standard output.
	StreamStdout LogStreamKind = iota
	// StreamStderr is the container's standard error. It is kept separate all the
	// way through: `kubectl logs` presents them together, but a consumer that
	// asked for the split and got a merge cannot recover it.
	StreamStderr
)

// LogEntry is one chunk of a container's output as the ring retains it.
type LogEntry struct {
	// At is when the guest observed the write.
	At time.Time
	// Line is the raw bytes. It may be a partial line: a container writing more
	// than one buffer's worth in one call produces several entries, and joining
	// them would mean holding an unbounded partial line in memory.
	Line []byte
	// Stream is which of the container's two outputs produced it.
	Stream LogStreamKind
}

// size is the entry's charge against the ring's byte budget.
func (e LogEntry) size() int { return len(e.Line) }

// Selector is the SELECTION half of a guest/v1 Logs request — the part only the
// guest can answer, because only the guest holds the output.
//
// The PRESENTATION half (timestamps, limit_bytes) is deliberately absent: the host
// applies those on its own side of the boundary, because an agent that ignored
// limit_bytes and streamed forever must not be able to flood a client. Carrying
// them here would suggest this side enforces them, and it does not.
type Selector struct {
	// TailLines, if > 0, starts from the last N entries.
	TailLines int64
	// SinceTime, if non-zero, filters to entries at or after it.
	SinceTime time.Time
	// Follow keeps the stream open for new entries after the retained ones.
	Follow bool
	// Previous asks for the previous terminated instance's output rather than the
	// live one.
	Previous bool
}

// Ring is one container's bounded retained output, plus the subscriber set that
// `kubectl logs -f` reads from.
//
// Locking discipline: mu guards every field. Subscriber channels are BUFFERED and
// SENT TO non-BLOCKINGLY while mu is held, so a slow or abandoned follower can
// never block the container's writer — which, in a guest, is the pod's own process
// pump. A follower that cannot keep up loses entries; it does not stop the
// workload.
//
// The zero value is not usable; construct one with NewRing.
type Ring struct {
	maxEntries int
	maxBytes   int

	mu      sync.Mutex
	entries []LogEntry
	bytes   int
	// dropped counts entries evicted by the bounds, so a reader can be told the
	// output is incomplete rather than silently shown a gap.
	dropped int
	subs    map[chan LogEntry]struct{}
	closed  bool
}

// NewRing builds a bounded ring. Non-positive bounds take the defaults.
func NewRing(maxEntries, maxBytes int) *Ring {
	if maxEntries <= 0 {
		maxEntries = DefaultRingEntries
	}
	if maxBytes <= 0 {
		maxBytes = DefaultRingBytes
	}
	return &Ring{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		subs:       map[chan LogEntry]struct{}{},
	}
}

// Append records an entry, evicting oldest-first until both bounds hold, and
// delivers it to every live follower.
//
// The entry's bytes are COPIED. The caller is a read pump reusing one buffer, so
// retaining the slice would make every stored entry alias whatever that buffer
// last held — the classic form of this bug, where old log lines mutate.
func (r *Ring) Append(e LogEntry) {
	cp := make([]byte, len(e.Line))
	copy(cp, e.Line)
	e.Line = cp

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.entries = append(r.entries, e)
	r.bytes += e.size()
	for len(r.entries) > r.maxEntries || (r.bytes > r.maxBytes && len(r.entries) > 1) {
		r.bytes -= r.entries[0].size()
		r.entries = r.entries[1:]
		r.dropped++
	}
	for ch := range r.subs {
		select {
		case ch <- e:
		default:
			// The follower is behind. Dropping is the only option that does not
			// block the workload's own output; see the type doc.
		}
	}
}

// Snapshot returns the retained entries matching sel, oldest first.
//
// The order of the two filters is the upstream one and it is not interchangeable:
// since_time narrows first, then tail_lines takes the last N of what remains. The
// other order would return the last N entries overall and then drop the ones
// before since_time, which for a container that went quiet returns nothing at all
// where upstream returns its last N lines since that time.
func (r *Ring) Snapshot(sel Selector) []LogEntry {
	entries, _ := r.SnapshotWithDropped(sel)
	return entries
}

// SnapshotWithDropped is Snapshot plus the eviction count, read in the SAME
// critical section.
//
// The two must be read together or not at all: a reader that takes the entries
// and then asks Dropped separately can be told about a gap that did not precede
// what it was given, or shown a gap it was never told about, because the writer
// evicts between the two calls. The in-band truncation notice is only honest if
// the count describes exactly the entries being served.
func (r *Ring) SnapshotWithDropped(sel Selector) ([]LogEntry, int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]LogEntry, 0, len(r.entries))
	for _, e := range r.entries {
		if !sel.SinceTime.IsZero() && e.At.Before(sel.SinceTime) {
			continue
		}
		out = append(out, e)
	}
	if sel.TailLines > 0 && int64(len(out)) > sel.TailLines {
		out = out[int64(len(out))-sel.TailLines:]
	}
	return out, r.dropped
}

// Subscribe registers a follower and returns its channel plus an unsubscribe func.
//
// The channel is buffered so a brief scheduling delay does not cost entries, and
// the unsubscribe func is idempotent: a follow stream can end from the client side
// or the pod side, and both paths call it.
func (r *Ring) Subscribe(buffer int) (<-chan LogEntry, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan LogEntry, buffer)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	r.subs[ch] = struct{}{}
	r.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, ch)
			r.mu.Unlock()
		})
	}
}

// Close ends every follow stream. It is called when the container exits: a
// follower must see end-of-stream rather than hang on a container that will never
// write again.
func (r *Ring) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for ch := range r.subs {
		close(ch)
		delete(r.subs, ch)
	}
}

// Dropped reports how many entries the bounds evicted. It exists so "the log
// starts mid-stream" can be a stated fact rather than something a reader has to
// infer from a line that begins in the middle of a word.
func (r *Ring) Dropped() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}
