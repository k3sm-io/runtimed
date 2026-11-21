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
// and Close and the timer share one sync.Once around the body's Close.
// Close returns after any callback that has entered the shared once has
// finished; a callback scheduled but not yet running may finish after Close,
// where it finds its window stale and does nothing.
//
// Stale fires: a callback that had already started when Read's timer.Stop ran
// (Stop returned false) runs after that Read returned, perhaps while a later
// Read is in flight. So each window carries a generation: Read bumps gen under
// mu and arms a fresh timer whose callback captures that value, and every Read
// return and Close bumps gen again. fire acts only if its captured generation
// is still the live one, so a fire can cut only the Read that armed it. One
// reused timer cannot do this: with Reset the callback is fixed at creation and
// cannot tell which window it belongs to.
//
// Read must not be called concurrently: one caller at a time, as io.Copy does.
// Overlapping Reads would make an earlier Read's window stale while it is still
// in flight, so its stall would go undetected.
type stallReader struct {
	body      io.ReadCloser
	window    time.Duration
	afterFunc func(time.Duration, func()) stallTimer
	stalled   atomic.Bool
	once      sync.Once
	err       error

	// mu guards timer and gen.
	mu sync.Mutex
	// timer is the window of the Read in flight, or a stopped one.
	timer stallTimer
	// gen is the live window's generation; a fire whose generation differs is stale.
	gen uint64
}

// stallTimer is the part of *time.Timer the watchdog uses; it is the seam a
// test drives by hand instead of waiting out a real window.
type stallTimer interface {
	Reset(d time.Duration) bool
	Stop() bool
}

// timeAfterFunc is the production afterFunc: a real time.AfterFunc.
func timeAfterFunc(d time.Duration, f func()) stallTimer { return time.AfterFunc(d, f) }

// newStallReader wraps body with a watchdog of the given window, its timers
// made by afterFunc (nil means timeAfterFunc). The timer is created stopped;
// each Read arms a fresh one for the duration of one body.Read.
func newStallReader(body io.ReadCloser, window time.Duration, afterFunc func(time.Duration, func()) stallTimer) *stallReader {
	if afterFunc == nil {
		afterFunc = timeAfterFunc
	}
	return (&stallReader{body: body, window: window, afterFunc: afterFunc}).start()
}

// start creates the watchdog timer through s.afterFunc, stopped, and returns s.
// Its callback carries generation 0, which no Read ever arms, so it is inert.
func (s *stallReader) start() *stallReader {
	s.timer = s.afterFunc(s.window, func() { s.fire(0) })
	s.timer.Stop()
	return s
}

// arm starts a fresh window for one body.Read, tied to a new generation.
func (s *stallReader) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	g := s.gen
	s.timer = s.afterFunc(s.window, func() { s.fire(g) })
}

// disarm ends the live window: it stops the timer and bumps gen, so a callback
// Stop was too late to prevent finds its generation stale.
func (s *stallReader) disarm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	s.timer.Stop()
}

// fire runs on the timer's goroutine when the window of generation g ran out.
// A stale g (its Read returned, or Close ran) does nothing. Otherwise it marks
// the reader stalled before closing the body, so a read failure the close
// causes always observes the flag.
func (s *stallReader) fire(g uint64) {
	s.mu.Lock()
	live := g == s.gen
	if live {
		s.stalled.Store(true)
	}
	s.mu.Unlock()
	if live {
		s.closeBody()
	}
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
	s.arm()
	n, err := s.body.Read(p)
	s.disarm()
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
	s.disarm()
	s.closeBody()
	return s.err
}
