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
	"io"
	"sync"
)

// ring is one output stream's bounded buffer between the container's pipe and
// the shim's log writer. Write never blocks: past capacity it drops the OLDEST
// bytes and counts them (containerd's slow-sink posture), so a stalled log
// writer or follower can cost the container output but never block its
// write(2). Read blocks until there is data, and returns io.EOF once the ring is
// closed and drained.
//
// It is circular: the bytes live in buf[start:start+n] modulo len(buf), so a
// write once the ring is full costs the bytes written, not the limit. buf grows
// geometrically up to limit and is then fixed, so an idle stream holds little.
//
// Concurrency: mu guards every field; cond signals data or close to a blocked
// Read. One writer (the pipe reader) and one reader (the log writer) per ring.
type ring struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	start, n int
	limit    int
	closed   bool
	dropped  uint64 // total bytes dropped
	pending  uint64 // bytes dropped since the last takeDropped
}

// newRing returns a ring holding at most limit bytes.
func newRing(limit int) *ring {
	r := &ring{limit: limit}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// Write appends p, dropping the oldest bytes beyond the limit. It never blocks
// and never fails while the ring is open.
func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	written := len(p)
	if len(p) >= r.limit {
		// p alone fills the ring: everything buffered and p's head are dropped.
		r.drop(r.n + len(p) - r.limit)
		p = p[len(p)-r.limit:]
		r.grow(r.limit)
		r.start, r.n = 0, 0
	} else if over := r.n + len(p) - r.limit; over > 0 {
		r.drop(over)
		r.start = (r.start + over) % len(r.buf)
		r.n -= over
	}
	r.grow(r.n + len(p))
	at := (r.start + r.n) % len(r.buf)
	k := copy(r.buf[at:], p)
	copy(r.buf, p[k:])
	r.n += len(p)
	r.cond.Signal()
	return written, nil
}

// drop counts k dropped bytes.
func (r *ring) drop(k int) {
	r.dropped += uint64(k)
	r.pending += uint64(k)
}

// grow makes buf hold at least need bytes (need <= limit), linearizing the
// contents; it only ever runs before buf reaches limit.
func (r *ring) grow(need int) {
	if need <= len(r.buf) {
		return
	}
	size := max(need, 2*len(r.buf), 4<<10)
	size = min(size, r.limit)
	nb := make([]byte, size)
	if r.n > 0 {
		k := copy(nb, r.buf[r.start:min(r.start+r.n, len(r.buf))])
		copy(nb[k:], r.buf[:r.n-k])
	}
	r.buf, r.start = nb, 0
}

// Read copies buffered bytes into p, blocking while the ring is empty and open.
func (r *ring) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.n == 0 && !r.closed {
		r.cond.Wait()
	}
	if r.n == 0 {
		return 0, io.EOF
	}
	end := min(r.start+r.n, len(r.buf))
	k := copy(p, r.buf[r.start:end])
	r.start = (r.start + k) % len(r.buf)
	r.n -= k
	return k, nil
}

// Close ends the stream: Read drains what is buffered and then reports io.EOF.
func (r *ring) Close() {
	r.mu.Lock()
	r.closed = true
	r.cond.Broadcast()
	r.mu.Unlock()
}

// takeDropped returns the bytes dropped since the last call and resets that
// count; the total keeps growing (Dropped).
func (r *ring) takeDropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.pending
	r.pending = 0
	return n
}

// Dropped is the total number of bytes this ring has dropped.
func (r *ring) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}
