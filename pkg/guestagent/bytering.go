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

import "sync"

// DefaultByteRingBytes and DefaultByteRingChunks bound one container's RAW
// replay buffer — the source `kubectl attach` streams from.
//
// # Why there are two bounds, and why neither implies the other
//
// The byte cap is the memory bound: the guest has no disk (its rootfs upper is
// a tmpfs inside the pod's hypervisor-enforced memory ceiling), so an unbounded
// buffer is a way for a chatty workload to OOM its own guest and have the kill
// attributed to its real memory use.
//
// The CHUNK cap is not a smaller version of it — it bounds a different thing,
// and this source needs it far more than the line ring does. A terminal echoes
// keystrokes ONE BYTE AT A TIME, so an interactive session appends thousands of
// one-byte chunks; the byte cap alone would happily hold 65536 of them, and the
// slice headers describing them cost an order of magnitude more than the bytes
// they point at. The chunk cap is what keeps the overhead proportional.
//
// 64 KiB is roughly two screenfuls of a full-screen TUI's redraw, which is what
// a client attaching mid-session needs to see something coherent rather than a
// fragment.
const (
	DefaultByteRingBytes  = 64 << 10
	DefaultByteRingChunks = 4096
)

// ByteChunk is one write a container made, exactly as it made it.
//
// It is NOT a LogEntry, and the difference is the entire reason this type
// exists. A LogEntry is a LINE: the capture's writer splits on \n, strips the
// delimiter and holds a trailing partial until a newline arrives. That is right
// for `kubectl logs --tail`, and it is wrong for `kubectl attach`, whose client
// is a terminal — a shell prompt, a password query and every keystroke a pty
// echoes back are newline-less, so a line-granular source holds exactly the
// bytes an interactive session is waiting for. This carries the pump's read
// verbatim.
type ByteChunk struct {
	// Data is the raw bytes, unmodified: no delimiter added, none removed, no
	// re-chunking. A terminal's escape sequences and its CRLFs pass through as
	// the workload wrote them.
	Data []byte

	// Stream is which of the container's outputs produced it. A tty container
	// has only StreamStdout — the line discipline merged the two before either
	// reached the master — but a non-tty one writes both, and the split is kept
	// because AttachResponse has a field for each and a merge here could not be
	// undone downstream.
	Stream LogStreamKind
}

// ByteRing is one container's bounded raw output plus the subscriber set an
// attach reads from.
//
// # Locking discipline
//
// mu guards every field. Append RECORDS and FANS OUT in one critical section,
// and Subscribe SNAPSHOTS and REGISTERS in one critical section — which
// together give the property guest.proto asks for: for any chunk C and any
// subscriber S, either C's append completed before S registered (C is in S's
// snapshot, and was fanned out to a subscriber set that did not contain S) or
// it completed after (C is not in the snapshot, and IS delivered to S). There
// is no interleaving in which S sees C twice or misses it.
//
// That is strictly better than the line ring's two-step subscribe-then-snapshot
// (Capture.Stream), which loses nothing but does deliver a duplicate to a
// chunk landing between its two lock acquisitions. A duplicated log line is
// harmless; a duplicated escape sequence is a corrupted screen, so the atomic
// form is the one attach gets.
//
// # Slow subscribers: DROP AND TELL, never block
//
// Subscriber channels are BUFFERED and sent to NON-BLOCKINGLY while mu is held.
// The writer is the container's own output pump, so blocking it fills the pty
// or the pipe and then blocks the workload on its own stdout — a slow
// `kubectl attach` client must never be able to stop the program it is
// watching.
//
// A subscriber that cannot keep up therefore loses bytes, and is TOLD how many:
// a gap in a terminal stream is not a missing line, it is a half-drawn screen
// with no way for the reader to know it. The count lets the attach handler put
// one in-band notice in front of the user, who redraws with ^L. That notice is
// itself visible noise, and it is the cheaper of the two mistakes.
//
// The zero value is not usable; construct one with NewByteRing.
type ByteRing struct {
	maxBytes  int
	maxChunks int

	mu     sync.Mutex
	chunks []ByteChunk
	bytes  int
	subs   map[*byteSub]struct{}
	closed bool
}

// byteSub is one subscriber's queue plus the bytes the bounds cost it.
type byteSub struct {
	ch chan ByteChunk
	// dropped counts BYTES, not chunks. A reader is told how much of the
	// terminal it is missing; "3 chunks" would mean nothing to it, since a
	// chunk is however much the pump happened to read.
	dropped int
}

// NewByteRing builds a bounded raw ring. Non-positive bounds take the defaults.
func NewByteRing(maxBytes, maxChunks int) *ByteRing {
	if maxBytes <= 0 {
		maxBytes = DefaultByteRingBytes
	}
	if maxChunks <= 0 {
		maxChunks = DefaultByteRingChunks
	}
	return &ByteRing{
		maxBytes:  maxBytes,
		maxChunks: maxChunks,
		subs:      map[*byteSub]struct{}{},
	}
}

// Append records p and delivers it to every live subscriber, never blocking.
//
// The bytes are COPIED. The caller is the container's output pump reusing one
// read buffer, so retaining the slice would make every stored chunk alias
// whatever that buffer last held — the classic form of this bug, where the
// replay buffer mutates under the reader.
//
// An empty write is dropped rather than recorded: io.Copy can produce one, and
// a zero-length chunk costs a slice header to say nothing.
func (b *ByteRing) Append(stream LogStreamKind, p []byte) {
	if len(p) == 0 {
		return
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	chunk := ByteChunk{Data: cp, Stream: stream}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.chunks = append(b.chunks, chunk)
	b.bytes += len(cp)
	b.evictLocked()
	for s := range b.subs {
		select {
		case s.ch <- chunk:
		default:
			s.dropped += len(cp)
		}
	}
}

// evictLocked trims the ring back inside both bounds, oldest first.
//
// The byte bound is honoured EXACTLY, by trimming the oldest chunk in place
// rather than discarding it whole. Discarding it whole would be simpler and
// would throw away up to a full read's worth of terminal output for the sake of
// one byte over the cap — and the retained tail is what an attaching client
// redraws from, so its most recent bytes are the ones worth keeping. Trimming
// preserves the chunk's stream label, so a partially evicted chunk is still
// attributed correctly.
//
// The caller holds b.mu.
func (b *ByteRing) evictLocked() {
	for len(b.chunks) > b.maxChunks {
		b.bytes -= len(b.chunks[0].Data)
		b.chunks = b.chunks[1:]
	}
	for b.bytes > b.maxBytes && len(b.chunks) > 0 {
		over := b.bytes - b.maxBytes
		head := b.chunks[0]
		if len(head.Data) > over {
			b.chunks[0].Data = head.Data[over:]
			b.bytes -= over
			return
		}
		b.bytes -= len(head.Data)
		b.chunks = b.chunks[1:]
	}
}

// ByteSubscription is one attach client's view of a container's raw output: the
// bytes retained when it arrived, and the ones written after.
//
// Snapshot MUST be sent before C() is drained, or a live chunk overtakes the
// retained bytes that precede it and the client's terminal receives the
// session out of order. Same rule, same reason, as Events.SubscribeWithSnapshot.
type ByteSubscription struct {
	ring     *ByteRing
	sub      *byteSub
	snapshot []ByteChunk
	once     sync.Once
}

// Snapshot returns the chunks retained at the instant this subscription was
// registered, oldest first. It is safe to call more than once and always
// returns the same bytes.
func (s *ByteSubscription) Snapshot() []ByteChunk { return s.snapshot }

// C is the subscriber's live channel. It is closed when the ring closes, which
// the guest does when the container exits — an attached client must see end of
// stream rather than hang on a process that will never write again.
func (s *ByteSubscription) C() <-chan ByteChunk { return s.sub.ch }

// DroppedBytes reports how many bytes the bounds cost THIS subscriber because
// it fell behind. It is monotone, so a caller reports only the growth.
func (s *ByteSubscription) DroppedBytes() int {
	s.ring.mu.Lock()
	defer s.ring.mu.Unlock()
	return s.sub.dropped
}

// Close unsubscribes. It is idempotent: an attach can end from the client side
// or because the container exited, and both paths call it.
//
// It ends THIS client's subscription and nothing else — it does not close the
// ring, and a container with two attached clients keeps serving the other.
func (s *ByteSubscription) Close() {
	s.once.Do(func() {
		s.ring.mu.Lock()
		delete(s.ring.subs, s.sub)
		s.ring.mu.Unlock()
	})
}

// Subscribe registers a follower and returns it together with the ring's
// current contents, taken in the SAME critical section as the registration.
//
// queue is the subscriber's chunk backlog; non-positive takes a default deep
// enough that a brief scheduling delay costs no bytes.
func (b *ByteRing) Subscribe(queue int) *ByteSubscription {
	if queue <= 0 {
		queue = 512
	}
	sub := &byteSub{ch: make(chan ByteChunk, queue)}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		close(sub.ch)
		return &ByteSubscription{ring: b, sub: sub, snapshot: b.snapshotLocked()}
	}
	b.subs[sub] = struct{}{}
	snapshot := b.snapshotLocked()
	b.mu.Unlock()
	return &ByteSubscription{ring: b, sub: sub, snapshot: snapshot}
}

// Snapshot returns the retained chunks, oldest first, WITHOUT subscribing.
//
// It exists for the closed ring's replay and for the test that shows why
// Subscribe does both at once: a caller that snapshots and then subscribes as
// two separate operations loses every byte written in between.
func (b *ByteRing) Snapshot() []ByteChunk {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

// snapshotLocked copies the retained chunks. The chunk slice is copied so a
// later eviction cannot re-slice the caller's view; the byte slices inside are
// shared, which is safe because nothing ever mutates a stored chunk's data —
// evictLocked only re-slices the ring's own header.
//
// The caller holds b.mu.
func (b *ByteRing) snapshotLocked() []ByteChunk {
	if len(b.chunks) == 0 {
		return nil
	}
	out := make([]ByteChunk, len(b.chunks))
	copy(out, b.chunks)
	return out
}

// Close ends every subscription. It is called when the container exits, and the
// RETAINED bytes survive it: a client attaching after the exit still gets the
// snapshot, and then the terminal exit frame.
func (b *ByteRing) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for s := range b.subs {
		close(s.ch)
		delete(b.subs, s)
	}
}
