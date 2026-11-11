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

package image

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// ErrLayerBodyStalled is returned (wrapped) when a layer body delivers no byte
// for a whole stall window. The fetch is aborted by closing the body; the error
// is an ordinary fetch failure, and a retry of the pull starts the layer over.
var ErrLayerBodyStalled = errors.New("image: layer body stalled")

// defaultLayerStallWindow is how long a layer body may deliver nothing before
// the fetch is aborted. It sits above the transport's 30s dial, 10s TLS
// handshake and 90s idle-connection timeouts: a registry that is merely slow
// keeps sending bytes and is never cut, while a body that has stopped moving no
// longer hangs until the caller's context ends.
const defaultLayerStallWindow = 2 * time.Minute

// stallReader is a progress watchdog on one layer body. Every Read that returns
// at least one byte pushes the deadline out by window; when the deadline passes
// with no byte delivered, the timer closes the body, which unblocks the pending
// Read, and that Read reports ErrLayerBodyStalled.
//
// Lifetime: the timer is a time.AfterFunc, so no goroutine exists until it
// fires, and Close stops it. Close and the timer share one sync.Once around
// the body's Close, so Close returns only after any in-flight timer close has
// finished: nothing this reader started outlives its Close.
type stallReader struct {
	body    io.ReadCloser
	window  time.Duration
	timer   *time.Timer
	stalled atomic.Bool
	once    sync.Once
	err     error
}

// newStallReader wraps body with a watchdog of the given window, armed now.
func newStallReader(body io.ReadCloser, window time.Duration) *stallReader {
	s := &stallReader{body: body, window: window}
	s.timer = time.AfterFunc(window, s.fire)
	return s
}

// fire runs on the timer's goroutine when window passed with no byte.
func (s *stallReader) fire() {
	s.stalled.Store(true)
	s.closeBody()
}

// closeBody closes the body exactly once, from whichever side gets there first.
func (s *stallReader) closeBody() {
	s.once.Do(func() { s.err = s.body.Close() })
}

// Read reads from the body, re-arming the watchdog on progress.
func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.body.Read(p)
	if s.stalled.Load() {
		return n, fmt.Errorf("no byte for %s: %w", s.window, ErrLayerBodyStalled)
	}
	if n > 0 {
		s.timer.Reset(s.window)
	}
	return n, err
}

// Close stops the watchdog and closes the body.
func (s *stallReader) Close() error {
	s.timer.Stop()
	s.closeBody()
	return s.err
}
