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
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// layerBodyServer is a registry that serves one layer blob through body, which
// writes the layer's bytes however the row wants; every other path is the real
// in-process registry.
func layerBodyServer(t *testing.T, body func(w http.ResponseWriter, r *http.Request, layer []byte)) string {
	t.Helper()
	img := testImage(t, "darwin", "arm64", "")
	layers, err := img.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("layers: %d, %v", len(layers), err)
	}
	ld, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	layer, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}

	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blobs/"+ld.String()) {
			w.Header().Set("Content-Length", strconv.Itoa(len(layer)))
			w.Header().Set("Docker-Content-Digest", ld.String())
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-done:
			default:
				body(w, r, layer)
			}
			return
		}
		store.ServeHTTP(w, r)
	}))
	// Cleanups run last-in first-out: release any held handler, then close.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(done) })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(u.Host + "/stall/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return ref.String()
}

// TestLayerPullStalledBodyAborts is the gate for the layer-body watchdog end
// to end: a layer whose body stops after a few bytes while the server holds the
// connection fails the pull with ErrLayerBodyStalled (see pullFiringStalls for
// what the fire order does and does not show). The watchdog runs on the
// fake timer through the Puller's seam, so the test never waits on the wall
// clock; a pull whose body is not watched never returns, and go test -timeout
// fails it. That a body which keeps delivering is never cut is pinned in
// TestStallReader.
func TestLayerPullStalledBodyAborts(t *testing.T) {
	// The server holds the connection, sending nothing more, until the test
	// releases it; nothing here depends on how long the stall lasts.
	release := make(chan struct{})
	sent := make(chan struct{})
	var sentOnce sync.Once // a retried GET reruns the handler; close(sent) must not panic
	ref := layerBodyServer(t, func(w http.ResponseWriter, r *http.Request, layer []byte) {
		_, _ = w.Write(layer[:16])
		w.(http.Flusher).Flush()
		sentOnce.Do(func() { close(sent) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	// Registered after the server's cleanups, so it runs first and frees the
	// held handler before the server closes.
	t.Cleanup(func() { close(release) })
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := mustPullerIndex(t, cache, RemoteFetch, NoLocalIndex{})
	ft := newFakeTimer()
	p.stallAfterFunc = ft.afterFunc
	got := pullFiringStalls(t, p, ref, ft, sent)
	if got.res != nil && got.res.Lease != nil {
		got.res.Lease.Release()
	}
	if !errors.Is(got.err, ErrLayerBodyStalled) {
		t.Fatalf("Pull error = %v, want ErrLayerBodyStalled", got.err)
	}
	// The server wrote and flushed the 16 bytes before the pull failed. This
	// shows only the server side: the test has no non-test-code view of what the
	// client's reader received, so it cannot prove the abort came from silence
	// after data rather than a stall before the bytes arrived.
	select {
	case <-sent:
	default:
		t.Fatal("Pull failed before the server flushed the 16 body bytes")
	}
}

// pullResult is one Pull's return values, carried off a goroutine.
type pullResult struct {
	res *PullResult
	err error
}

// pullFiringStalls runs one Pull of ref on p, whose stallAfterFunc is
// ft.afterFunc, and returns its result. Once sent is closed (the server has
// flushed the bytes it sends before holding the body), every watchdog window a
// body Read arms is run out on the fake clock, so a held body is cut at once.
// sent is a server-side signal only: a fire may land on a Read that had not yet
// received the flushed bytes, so this helper shows that a watched body is cut,
// not that the cut came after the client read data. That bytes-then-silence
// case is pinned client-side by TestPullResumeStalledBodyKeepsPartial. Nothing
// waits on the wall clock: a Pull that never returns, because nothing watches
// the body, is caught by go test -timeout.
func pullFiringStalls(t *testing.T, p *Puller, ref string, ft *fakeTimer, sent <-chan struct{}) pullResult {
	t.Helper()
	done := make(chan pullResult, 1)
	go func() {
		res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		done <- pullResult{res, err}
	}()
	select {
	case got := <-done:
		return got
	case <-sent:
	}
	for {
		select {
		case got := <-done:
			return got
		case <-ft.armed:
			ft.advance(p.stallWindow())
		}
	}
}

// errReadCloser is a body whose every Read fails with err.
type errReadCloser struct{ err error }

func (e errReadCloser) Read([]byte) (int, error) { return 0, e.err }
func (e errReadCloser) Close() error             { return nil }

// fakeTimer is a hand-driven stallTimer on a virtual clock: advance moves the
// clock and runs the callback if the timer is armed and its deadline passed.
// armed receives a value on every Reset so a test can wait for a Read to be in
// flight without sleeping.
type fakeTimer struct {
	mu       sync.Mutex
	f        func()
	fs       []func()
	now      time.Duration
	deadline time.Duration
	running  bool
	armed    chan struct{}
}

func newFakeTimer() *fakeTimer { return &fakeTimer{armed: make(chan struct{}, 64)} }

// afterFunc is the stallReader.afterFunc the fake stands in for.
func (ft *fakeTimer) afterFunc(d time.Duration, f func()) stallTimer {
	ft.mu.Lock()
	ft.f = f
	ft.fs = append(ft.fs, f)
	ft.mu.Unlock()
	ft.Reset(d)
	return ft
}

func (ft *fakeTimer) Reset(d time.Duration) bool {
	ft.mu.Lock()
	was := ft.running
	ft.deadline, ft.running = ft.now+d, true
	ft.mu.Unlock()
	select {
	case ft.armed <- struct{}{}:
	default:
	}
	return was
}

func (ft *fakeTimer) Stop() bool {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	was := ft.running
	ft.running = false
	return was
}

// advance moves the virtual clock by d and reports whether the timer fired.
func (ft *fakeTimer) advance(d time.Duration) bool {
	ft.mu.Lock()
	ft.now += d
	fire := ft.running && ft.now >= ft.deadline
	if fire {
		ft.running = false
	}
	f := ft.f
	ft.mu.Unlock()
	if fire {
		f()
	}
	return fire
}

// lastCallback returns the callback the most recent afterFunc was given, so a
// test can run it late, as a fire that had already started when Stop ran.
func (ft *fakeTimer) lastCallback() func() {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.fs[len(ft.fs)-1]
}

// waitArmed waits for the fake timer to be armed. There is no timer on the
// wait: a hang is caught by go test -timeout, whose goroutine dump shows the
// caller's line.
func waitArmed(ft *fakeTimer) { <-ft.armed }

// newFakeStallReader is newStallReader with ft in place of time.AfterFunc.
func newFakeStallReader(body io.ReadCloser, window time.Duration, ft *fakeTimer) *stallReader {
	return newStallReader(body, window, ft.afterFunc)
}

// clockedReader delivers one byte of data per Read, each taking step of the
// fake clock while the watchdog is armed.
type clockedReader struct {
	data []byte
	step time.Duration
	ft   *fakeTimer
}

func (c *clockedReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	if c.ft.advance(c.step) {
		return 0, errors.New("clockedReader: watchdog fired mid-read")
	}
	n := copy(p[:1], c.data)
	c.data = c.data[n:]
	return n, nil
}

func (c *clockedReader) Close() error { return nil }

// firingReader fires the watchdog from inside its Read, with the timer armed,
// then returns the scripted result: the watchdog and the read land in the same
// instant, with no sleep.
type firingReader struct {
	ft   *fakeTimer
	fire bool
	n    int
	err  error
}

func (f *firingReader) Read(p []byte) (int, error) {
	if f.fire {
		f.ft.advance(time.Hour)
	}
	for i := 0; i < f.n; i++ {
		p[i] = 'x'
	}
	return f.n, f.err
}

func (f *firingReader) Close() error { return nil }

// TestStallReaderSameInstant pins the rules for the watchdog firing in the same
// instant as a body.Read returning: delivered bytes and a clean EOF always win,
// a read that delivered nothing is a stall, and a read the watchdog did not
// race is passed through untouched.
func TestStallReaderSameInstant(t *testing.T) {
	const window = time.Minute
	boom := errors.New("read failed")
	tests := []struct {
		name      string
		fire      bool
		n         int
		err       error
		wantN     int
		wantErr   error // matched with errors.Is; nil means exactly nil
		wantCause bool  // the stall error names boom
		nextStall bool  // the following Read reports the stall
	}{
		{name: "no fire, data", n: 3, wantN: 3},
		{name: "no fire, error", err: boom, wantErr: boom},
		{name: "fire, data", fire: true, n: 3, wantN: 3, nextStall: true},
		{name: "fire, data with error", fire: true, n: 3, err: boom, wantN: 3, nextStall: true},
		{name: "fire, data with EOF", fire: true, n: 3, err: io.EOF, wantN: 3, wantErr: io.EOF},
		{name: "fire, bare EOF", fire: true, err: io.EOF, wantErr: io.EOF},
		{name: "fire, error", fire: true, err: boom, wantErr: ErrLayerBodyStalled, wantCause: true, nextStall: true},
		{name: "fire, nothing", fire: true, wantErr: ErrLayerBodyStalled, nextStall: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeTimer()
			body := &firingReader{ft: ft, fire: tt.fire, n: tt.n, err: tt.err}
			s := newFakeStallReader(body, window, ft)
			defer s.Close()
			n, err := s.Read(make([]byte, 8))
			if n != tt.wantN {
				t.Fatalf("Read n = %d, want %d", n, tt.wantN)
			}
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("Read error = %v, want nil", err)
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Fatalf("Read error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantCause && !strings.Contains(err.Error(), boom.Error()) {
				t.Fatalf("stall error %q does not name the cause %q", err, boom)
			}
			if tt.nextStall {
				if _, next := s.Read(make([]byte, 8)); !errors.Is(next, ErrLayerBodyStalled) {
					t.Fatalf("next Read error = %v, want ErrLayerBodyStalled", next)
				}
			}
		})
	}
}

// TestStallReader pins the watchdog at the reader level on a fake timer: it
// times only the body.Read, never the consumer between Reads; a stall reports
// the sentinel with the read's error as the cause and stays reported; bytes that
// keep flowing are never cut; and an error the watchdog did not cause is
// returned unchanged.
func TestStallReader(t *testing.T) {
	const window = 2 * time.Minute

	t.Run("a slow consumer is never reported as a stall", func(t *testing.T) {
		ft := newFakeTimer()
		want := bytes.Repeat([]byte("k3sm"), 4)
		s := newFakeStallReader(io.NopCloser(bytes.NewReader(want)), window, ft)
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
			// A slow CommitBlob write between Reads: three windows pass.
			if ft.advance(3 * window) {
				t.Fatalf("watchdog fired between Reads after %d bytes", len(got))
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("read %q, want %q", got, want)
		}
	})

	t.Run("a body.Read that blocks a window reports the sentinel and stays stalled", func(t *testing.T) {
		ft := newFakeTimer()
		pr, pw := io.Pipe()
		defer pw.Close()
		s := newFakeStallReader(pr, window, ft)
		defer s.Close()
		waitArmed(ft)
		type result struct {
			n   int
			err error
		}
		done := make(chan result, 1)
		go func() {
			n, err := s.Read(make([]byte, 8))
			done <- result{n, err}
		}()
		waitArmed(ft)
		if ft.advance(window - time.Nanosecond) {
			t.Fatal("watchdog fired before a whole window")
		}
		if !ft.advance(time.Nanosecond) {
			t.Fatal("watchdog did not fire at a whole window")
		}
		// A Read that never returns (the body was never closed) is caught by go
		// test -timeout.
		r := <-done
		if r.n != 0 || !errors.Is(r.err, ErrLayerBodyStalled) {
			t.Fatalf("Read = %d, %v; want 0, ErrLayerBodyStalled", r.n, r.err)
		}
		if !strings.Contains(r.err.Error(), io.ErrClosedPipe.Error()) {
			t.Fatalf("stall error %q does not name the cause %q", r.err, io.ErrClosedPipe)
		}
		for i := 0; i < 3; i++ {
			if _, err := s.Read(make([]byte, 8)); !errors.Is(err, ErrLayerBodyStalled) {
				t.Fatalf("Read %d after stall = %v, want ErrLayerBodyStalled", i, err)
			}
		}
	})

	t.Run("bytes that keep flowing are never cut", func(t *testing.T) {
		// A byte every eighth of a window, five windows in all.
		ft := newFakeTimer()
		want := bytes.Repeat([]byte("k3sm"), 10)
		body := &clockedReader{data: want, step: window / 8, ft: ft}
		s := newFakeStallReader(body, window, ft)
		defer s.Close()
		got, err := io.ReadAll(s)
		if err != nil {
			t.Fatalf("ReadAll of a flowing body: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("read %q, want %q", got, want)
		}
		ft.mu.Lock()
		elapsed := ft.now
		ft.mu.Unlock()
		if elapsed < 4*window {
			t.Fatalf("flow ran %s of fake time, want at least %s", elapsed, 4*window)
		}
	})

	t.Run("an error the watchdog did not cause is returned unchanged", func(t *testing.T) {
		cause := errors.New("connection reset by peer")
		s := newFakeStallReader(errReadCloser{cause}, window, newFakeTimer())
		defer s.Close()
		if _, err := s.Read(make([]byte, 8)); err != cause {
			t.Fatalf("Read error = %v, want the body's error unchanged", err)
		}
	})
}
