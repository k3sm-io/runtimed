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
// Concurrency: mu guards every field; cond signals data or close to a blocked
// Read. One writer (the pipe reader) and one reader (the log writer) per ring.
type ring struct {
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	limit   int
	closed  bool
	dropped uint64 // total bytes dropped
	pending uint64 // bytes dropped since the last takeDropped
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
	r.buf = append(r.buf, p...)
	if over := len(r.buf) - r.limit; over > 0 {
		r.buf = append(r.buf[:0:0], r.buf[over:]...)
		r.dropped += uint64(over)
		r.pending += uint64(over)
	}
	r.cond.Signal()
	return len(p), nil
}

// Read copies buffered bytes into p, blocking while the ring is empty and open.
func (r *ring) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.buf) == 0 && !r.closed {
		r.cond.Wait()
	}
	if len(r.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
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
