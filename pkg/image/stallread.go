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

// stallReader is a progress watchdog on one layer body. It times only the
// body: the timer is armed on entry to each body.Read and stopped before Read
// returns, so time the consumer spends between Reads (writing the bytes to a
// slow disk on a loaded host) never counts. When one body.Read runs a whole
// window without returning, the timer closes the body, which unblocks that
// Read, and Read reports ErrLayerBodyStalled with the read's error as the cause.
//
// Lifetime: the timer is a time.AfterFunc (made through afterFunc, which tests
// replace with a hand-fired fake), so no goroutine exists until it fires, and it is stopped whenever no body.Read is in flight. Close stops it,
// and Close and the timer share one sync.Once around the body's Close, so Close
// returns only after any in-flight timer close has finished: nothing this
// reader started outlives its Close.
type stallReader struct {
	body      io.ReadCloser
	window    time.Duration
	afterFunc func(time.Duration, func()) stallTimer
	timer     stallTimer
	stalled   atomic.Bool
	once      sync.Once
	err       error
}

// stallTimer is the part of *time.Timer the watchdog uses; it is the seam a
// test drives by hand instead of waiting out a real window.
type stallTimer interface {
	Reset(d time.Duration) bool
	Stop() bool
}

// timeAfterFunc is the production afterFunc: a real time.AfterFunc.
func timeAfterFunc(d time.Duration, f func()) stallTimer { return time.AfterFunc(d, f) }

// newStallReader wraps body with a watchdog of the given window. The timer is
// created stopped; each Read arms it for the duration of one body.Read.
func newStallReader(body io.ReadCloser, window time.Duration) *stallReader {
	return (&stallReader{body: body, window: window, afterFunc: timeAfterFunc}).start()
}

// start creates the watchdog timer through s.afterFunc, stopped, and returns s.
func (s *stallReader) start() *stallReader {
	s.timer = s.afterFunc(s.window, s.fire)
	s.timer.Stop()
	return s
}

// fire runs on the timer's goroutine when one body.Read ran a whole window. It
// marks the reader stalled before closing the body, so a read failure the close
// causes always observes the flag.
func (s *stallReader) fire() {
	s.stalled.Store(true)
	s.closeBody()
}

// closeBody closes the body exactly once, from whichever side gets there first.
func (s *stallReader) closeBody() {
	s.once.Do(func() { s.err = s.body.Close() })
}

// stallError is the error Read reports once the watchdog has closed the body;
// cause is the body.Read error that close produced, or nil.
func (s *stallReader) stallError(cause error) error {
	if cause == nil {
		return fmt.Errorf("no byte for %s: %w", s.window, ErrLayerBodyStalled)
	}
	return fmt.Errorf("no byte for %s: %w (%v)", s.window, ErrLayerBodyStalled, cause)
}

// Read reads from the body with the watchdog armed only while body.Read runs.
// Bytes the body delivered are always returned, with a nil error if the
// watchdog fired in the same instant (the next Read reports the stall). A read
// that failed after the watchdog closed the body reports ErrLayerBodyStalled
// with the read's error as the cause; any other error is returned unchanged.
func (s *stallReader) Read(p []byte) (int, error) {
	if s.stalled.Load() {
		return 0, s.stallError(nil)
	}
	s.timer.Reset(s.window)
	n, err := s.body.Read(p)
	s.timer.Stop()
	if !s.stalled.Load() {
		return n, err
	}
	if errors.Is(err, io.EOF) {
		// The body ended as the watchdog fired: it is complete, not stalled.
		return n, err
	}
	if n > 0 {
		return n, nil
	}
	return 0, s.stallError(err)
}

// Close stops the timer and closes the body, once in all: whichever of Close
// and the watchdog gets there first closes it, and every Close returns that one
// body.Close error. Stopping the timer only prevents a firing that has not
// started; a timer callback already running is not waited for beyond the shared
// once around the body's Close.
func (s *stallReader) Close() error {
	s.timer.Stop()
	s.closeBody()
	return s.err
}
