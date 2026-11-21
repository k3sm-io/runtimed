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
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// readResult is one Read's return values, carried off a goroutine.
type readResult struct {
	n   int
	err error
}

// readAsync runs one Read of s on a goroutine and returns where its result
// lands. Callers receive from it with no timer: a Read that never returns is
// caught by go test -timeout.
func readAsync(s *stallReader) <-chan readResult {
	done := make(chan readResult, 1)
	go func() {
		n, err := s.Read(make([]byte, 8))
		done <- readResult{n, err}
	}()
	return done
}

// countingCloser is a pipe reader whose Close is counted and returns err, so a
// test can see the body closed exactly once and every Close report that one error.
type countingCloser struct {
	*io.PipeReader
	closes atomic.Int32
	err    error
}

func (c *countingCloser) Close() error {
	c.closes.Add(1)
	_ = c.PipeReader.Close()
	return c.err
}

// TestStallReaderRealTimer runs the watchdog on the production timer
// (newStallReader, a real time.AfterFunc) under -race: a body.Read that blocks
// is cut with the sentinel, the stall stays reported, and Close afterwards
// returns the one body.Close error without closing the body twice. The window
// is short and the wait on the outcome has no timer; nothing asserts how fast
// the watchdog fired.
func TestStallReaderRealTimer(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	closeErr := errors.New("body close")
	body := &countingCloser{PipeReader: pr, err: closeErr}
	s := newStallReader(body, 5*time.Millisecond, nil)

	// The body blocks until it is closed, so only the watchdog can end this
	// Read; how soon it fires changes nothing the test asserts.
	r := <-readAsync(s)
	if r.n != 0 || !errors.Is(r.err, ErrLayerBodyStalled) {
		t.Fatalf("Read = %d, %v; want 0, ErrLayerBodyStalled", r.n, r.err)
	}
	if _, err := s.Read(make([]byte, 8)); !errors.Is(err, ErrLayerBodyStalled) {
		t.Fatalf("Read after stall = %v, want ErrLayerBodyStalled", err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Close(); err != closeErr {
			t.Fatalf("Close %d = %v, want the body's close error", i, err)
		}
	}
	if got := body.closes.Load(); got != 1 {
		t.Fatalf("body closed %d times, want 1", got)
	}
}

// TestStallReaderStaleFire pins that a watchdog deadline belongs to the one
// body.Read that armed it: once that Read has returned, the window it armed can
// no longer cut the body, and every Read starts a fresh window, so time that
// passes outside a Read, or across Reads that each finish inside the window,
// never aborts the next Read.
func TestStallReaderStaleFire(t *testing.T) {
	const window = time.Minute
	tests := []struct {
		name string
		// between runs after each successful Read, before the next one.
		between func(ft *fakeTimer) bool
		// step is how much fake time each body.Read takes while armed.
		step time.Duration
	}{
		{
			name:    "the deadline a returned Read armed passes before the next Read",
			between: func(ft *fakeTimer) bool { return ft.advance(window) },
		},
		{
			name:    "many windows pass between Reads",
			between: func(ft *fakeTimer) bool { return ft.advance(10 * window) },
		},
		{
			name: "each Read takes almost a window, the Reads together many windows",
			step: window - time.Nanosecond,
		},
		{
			name:    "part of a window inside a Read, the rest after it",
			step:    window / 2,
			between: func(ft *fakeTimer) bool { return ft.advance(window / 2) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeTimer()
			want := bytes.Repeat([]byte("k3sm"), 3)
			body := &clockedReader{data: want, step: tt.step, ft: ft}
			s := newFakeStallReader(body, window, ft)
			defer s.Close()
			var got []byte
			buf := make([]byte, 4)
			for {
				n, err := s.Read(buf)
				got = append(got, buf[:n]...)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Read after %d bytes: %v", len(got), err)
				}
				if tt.between != nil && tt.between(ft) {
					t.Fatalf("a window armed by a returned Read fired after %d bytes", len(got))
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("read %q, want %q", got, want)
			}
		})
	}
}

// TestStallReaderClose pins Close against everything that can meet it: a
// second Close, a watchdog firing, a Read in flight. In every interleaving the
// body is closed exactly once, every Close returns that one body.Close error,
// a blocked Read is released, no goroutine the test started is left behind,
// and -race sees no data race.
func TestStallReaderClose(t *testing.T) {
	const window = time.Minute
	closeErr := errors.New("body close")
	tests := []struct {
		name string
		// run drives the interleaving; it returns the error of the Read it ran
		// in flight, or nil if it ran none.
		run func(t *testing.T, s *stallReader, ft *fakeTimer) error
		// readErrs lists the errors the in-flight Read may report, matched with
		// errors.Is; empty means run started no Read.
		readErrs []error
	}{
		{
			name: "double Close",
			run: func(t *testing.T, s *stallReader, ft *fakeTimer) error {
				return nil
			},
		},
		{
			name: "Close after the watchdog fired",
			run: func(t *testing.T, s *stallReader, ft *fakeTimer) error {
				done := readAsync(s)
				waitArmed(ft)
				if !ft.advance(window) {
					t.Fatal("watchdog did not fire at a whole window")
				}
				return (<-done).err
			},
			readErrs: []error{ErrLayerBodyStalled},
		},
		{
			name: "Close racing a fire",
			run: func(t *testing.T, s *stallReader, ft *fakeTimer) error {
				done := readAsync(s)
				waitArmed(ft)
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); ft.advance(window) }()
				go func() { defer wg.Done(); _ = s.Close() }()
				wg.Wait()
				return (<-done).err
			},
			// Close first: the timer is stopped and the Read sees the closed
			// body; the fire first: the Read reports the stall.
			readErrs: []error{ErrLayerBodyStalled, io.ErrClosedPipe},
		},
		{
			name: "Close racing a Read in flight",
			run: func(t *testing.T, s *stallReader, ft *fakeTimer) error {
				done := readAsync(s)
				waitArmed(ft)
				if err := s.Close(); err != closeErr {
					t.Fatalf("Close = %v, want the body's close error", err)
				}
				r := <-done
				if ft.advance(10 * window) {
					t.Fatal("watchdog fired after Close stopped it")
				}
				return r.err
			},
			// Close is not a stall: the Read reports the closed body as it is.
			readErrs: []error{io.ErrClosedPipe},
		},
		{
			name: "Close racing a Read as it starts",
			run: func(t *testing.T, s *stallReader, ft *fakeTimer) error {
				done := readAsync(s)
				if err := s.Close(); err != closeErr {
					t.Fatalf("Close = %v, want the body's close error", err)
				}
				return (<-done).err
			},
			readErrs: []error{io.ErrClosedPipe},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeTimer()
			pr, pw := io.Pipe()
			defer pw.Close()
			body := &countingCloser{PipeReader: pr, err: closeErr}
			s := newFakeStallReader(body, window, ft)
			waitArmed(ft)

			readErr := tt.run(t, s, ft)
			if len(tt.readErrs) > 0 && !isOneOf(readErr, tt.readErrs) {
				t.Fatalf("in-flight Read error = %v, want one of %v", readErr, tt.readErrs)
			}
			if errors.Is(readErr, ErrLayerBodyStalled) && strings.Contains(readErr.Error(), closeErr.Error()) {
				t.Fatalf("stall error %q names the body's close error, want the read's", readErr)
			}
			for i := 0; i < 2; i++ {
				if err := s.Close(); err != closeErr {
					t.Fatalf("Close %d = %v, want the body's close error", i, err)
				}
			}
			if got := body.closes.Load(); got != 1 {
				t.Fatalf("body closed %d times, want 1", got)
			}
		})
	}

	t.Run("the window runs out while a Read unwinds from Close", func(t *testing.T) {
		// Close stops the timer before it closes the body, so a whole window
		// passing between the close and the Read returning is not a stall.
		ft := newFakeTimer()
		body := &unwindingReader{ft: ft, window: window, closed: make(chan struct{})}
		s := newFakeStallReader(body, window, ft)
		waitArmed(ft)
		done := readAsync(s)
		waitArmed(ft)
		if err := s.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		r := <-done
		if body.fired.Load() {
			t.Fatal("the watchdog fired after Close: Close did not stop the timer")
		}
		if !errors.Is(r.err, io.ErrClosedPipe) || errors.Is(r.err, ErrLayerBodyStalled) {
			t.Fatalf("Read error = %v, want io.ErrClosedPipe and no stall", r.err)
		}
	})
}

// unwindingReader blocks a Read until Close, then lets a whole window of fake
// time pass, with the watchdog still armed, before the Read returns.
type unwindingReader struct {
	ft     *fakeTimer
	window time.Duration
	once   sync.Once
	closed chan struct{}
	fired  atomic.Bool
}

func (u *unwindingReader) Read([]byte) (int, error) {
	<-u.closed
	u.fired.Store(u.ft.advance(u.window))
	return 0, io.ErrClosedPipe
}

func (u *unwindingReader) Close() error {
	u.once.Do(func() { close(u.closed) })
	return nil
}

// isOneOf reports whether err matches any of want with errors.Is.
func isOneOf(err error, want []error) bool {
	for _, w := range want {
		if errors.Is(err, w) {
			return true
		}
	}
	return false
}

// TestLayerPullRetryAfterStall pins that a stall leaves nothing behind: a pull
// whose layer body stalls fails with ErrLayerBodyStalled and commits nothing,
// and a second pull of the same reference through the same Puller and cache
// fetches the layer again, commits it, and leaves no partial blob.
func TestLayerPullRetryAfterStall(t *testing.T) {
	release := make(chan struct{})
	var gets atomic.Int32
	sent := make(chan struct{})
	var sentOnce sync.Once
	ref := layerBodyServer(t, func(w http.ResponseWriter, r *http.Request, layer []byte) {
		if gets.Add(1) > 1 {
			_, _ = w.Write(layer)
			return
		}
		// The first fetch delivers a few bytes, then holds the connection.
		_, _ = w.Write(layer[:16])
		w.(http.Flusher).Flush()
		sentOnce.Do(func() { close(sent) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	// Registered after the server's cleanups, so it runs first.
	t.Cleanup(func() { close(release) })
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := mustPullerIndex(t, cache, RemoteFetch, NoLocalIndex{})

	ft := newFakeTimer()
	p.stallAfterFunc = ft.afterFunc

	got := pullFiringStalls(t, p, ref, ft, sent)
	res, err := got.res, got.err
	if res != nil && res.Lease != nil {
		res.Lease.Release()
	}
	if !errors.Is(err, ErrLayerBodyStalled) {
		t.Fatalf("first Pull error = %v, want ErrLayerBodyStalled", err)
	}
	// The server flushed the first bytes before the pull failed. As in
	// TestLayerPullStalledBodyAborts this shows only the server side, but it does
	// tell a pull that failed before the server handled the layer GET apart.
	select {
	case <-sent:
	default:
		t.Fatal("first Pull failed before the server flushed the 16 body bytes")
	}
	assertNoPartialBlobs(t, cache)

	// The retry runs on the same fake timer, never advanced, so a loaded host
	// never cuts the healthy body; the code path is the same watchdog in the
	// same fetch.
	res, err = p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if err != nil {
		t.Fatalf("retry Pull after a stall: %v", err)
	}
	if res.Lease != nil {
		defer res.Lease.Release()
	}
	if got := gets.Load(); got != 2 {
		t.Fatalf("layer fetched %d times, want 2 (the stall, then the retry)", got)
	}
	if len(res.Manifest.Layers) != 1 {
		t.Fatalf("retry manifest has %d layers, want 1", len(res.Manifest.Layers))
	}
	if d := res.Manifest.Layers[0].Digest; !cache.Has(d) {
		t.Fatalf("layer %s not committed after the retry", d)
	}
	if res.CacheHit {
		t.Fatal("retry reported a cache hit: it did not write the layer the stall left uncommitted")
	}
	assertNoPartialBlobs(t, cache)
}

// assertNoPartialBlobs fails if any CommitBlob temp file is left in the blob store.
func assertNoPartialBlobs(t *testing.T, cache *Cache) {
	t.Helper()
	err := filepath.WalkDir(cache.BlobStoreDir(), func(path string, d os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".blob-") {
			t.Errorf("partial blob left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk blob store: %v", err)
	}
}

// drainArmed empties the fake timer's armed signals, so the next waitArmed
// waits for an arm that has not happened yet.
func drainArmed(ft *fakeTimer) {
	for {
		select {
		case <-ft.armed:
		default:
			return
		}
	}
}

// TestStallReaderLostStopRace pins that a watchdog fire belongs to the Read
// that armed it even when Read's Stop lost the race: the callback had already
// started, so it runs after that Read returned bytes. Run then, or while a
// later Read is in flight, it must neither close the body nor mark the reader
// stalled; the later Read is cut only by its own window.
func TestStallReaderLostStopRace(t *testing.T) {
	const window = time.Minute
	// readOne runs one Read that the pipe satisfies with b and returns the
	// callback that Read armed.
	readOne := func(t *testing.T, s *stallReader, ft *fakeTimer, pw *io.PipeWriter, b string) func() {
		t.Helper()
		drainArmed(ft)
		done := readAsync(s)
		waitArmed(ft)
		stale := ft.lastCallback()
		go func() { _, _ = pw.Write([]byte(b)) }()
		if r := <-done; r.n != len(b) || r.err != nil {
			t.Fatalf("Read = %d, %v; want %d, nil", r.n, r.err, len(b))
		}
		return stale
	}

	t.Run("the fire runs after its Read returned", func(t *testing.T) {
		ft := newFakeTimer()
		pr, pw := io.Pipe()
		defer pw.Close()
		body := &countingCloser{PipeReader: pr}
		s := newFakeStallReader(body, window, ft)
		defer s.Close()

		stale := readOne(t, s, ft, pw, "ab")
		stale()
		if got := body.closes.Load(); got != 0 {
			t.Fatalf("a stale fire closed the body %d times, want 0", got)
		}
		readOne(t, s, ft, pw, "cd")
	})

	// A fire that arrives after Close is stale: Close bumped the generation, so
	// the body is closed once (by Close) and later Reads see the closed body, not
	// a stall. The generation bump in Close matters while a Read is still in
	// flight, so that case uses a body whose Read outlives its Close.
	t.Run("the fire runs after Close, its Read having returned", func(t *testing.T) {
		ft := newFakeTimer()
		pr, pw := io.Pipe()
		defer pw.Close()
		body := &countingCloser{PipeReader: pr}
		s := newFakeStallReader(body, window, ft)

		stale := readOne(t, s, ft, pw, "ab")
		if err := s.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		stale()
		if got := body.closes.Load(); got != 1 {
			t.Fatalf("body closed %d times, want 1 (by Close)", got)
		}
		if _, err := s.Read(make([]byte, 8)); errors.Is(err, ErrLayerBodyStalled) || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Read after Close and a stale fire = %v, want io.ErrClosedPipe and no stall", err)
		}
	})

	t.Run("the fire runs after Close, its Read still in flight", func(t *testing.T) {
		ft := newFakeTimer()
		body := &lingeringBody{release: make(chan struct{})}
		s := newFakeStallReader(body, window, ft)
		waitArmed(ft)

		drainArmed(ft)
		done := readAsync(s)
		waitArmed(ft)
		stale := ft.lastCallback()
		if err := s.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		stale()
		close(body.release)
		<-done
		if got := body.closes.Load(); got != 1 {
			t.Fatalf("body closed %d times, want 1 (by Close)", got)
		}
		if _, err := s.Read(make([]byte, 8)); errors.Is(err, ErrLayerBodyStalled) || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Read after Close and a stale fire = %v, want io.ErrClosedPipe and no stall", err)
		}
	})

	t.Run("the fire runs while a later Read is in flight", func(t *testing.T) {
		ft := newFakeTimer()
		pr, pw := io.Pipe()
		defer pw.Close()
		body := &countingCloser{PipeReader: pr}
		s := newFakeStallReader(body, window, ft)
		defer s.Close()

		stale := readOne(t, s, ft, pw, "ab")
		drainArmed(ft)
		done := readAsync(s)
		waitArmed(ft)
		stale()
		if got := body.closes.Load(); got != 0 {
			t.Fatalf("a stale fire closed the body under a later Read %d times, want 0", got)
		}
		go func() { _, _ = pw.Write([]byte("cd")) }()
		if r := <-done; r.n != 2 || r.err != nil {
			t.Fatalf("in-flight Read = %d, %v; want 2, nil", r.n, r.err)
		}

		// The later Read's own window still cuts it.
		drainArmed(ft)
		done = readAsync(s)
		waitArmed(ft)
		if !ft.advance(window) {
			t.Fatal("the third Read's own window did not fire")
		}
		if r := <-done; r.n != 0 || !errors.Is(r.err, ErrLayerBodyStalled) {
			t.Fatalf("stalled Read = %d, %v; want 0, ErrLayerBodyStalled", r.n, r.err)
		}
		if got := body.closes.Load(); got != 1 {
			t.Fatalf("body closed %d times by its own window, want 1", got)
		}
	})
}

// lingeringBody is a body whose in-flight Read outlives its Close: Read
// returns only once release is closed, and a Read on a closed body reports
// io.ErrClosedPipe, as a pipe does.
type lingeringBody struct {
	release chan struct{}
	closes  atomic.Int32
}

func (l *lingeringBody) Read([]byte) (int, error) {
	<-l.release
	return 0, io.ErrClosedPipe
}

func (l *lingeringBody) Close() error {
	l.closes.Add(1)
	return nil
}
