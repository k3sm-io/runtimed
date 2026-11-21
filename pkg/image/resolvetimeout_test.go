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
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// setResolveSeams replaces the resolve timer with ft and the header timeout
// with header for the rest of the test.
func setResolveSeams(t *testing.T, ft *fakeTimer, header time.Duration) {
	t.Helper()
	oldAfter, oldHeader := resolveAfterFunc, headerTimeout
	resolveAfterFunc, headerTimeout = ft.afterFunc, header
	t.Cleanup(func() { resolveAfterFunc, headerTimeout = oldAfter, oldHeader })
}

// hangingManifestRegistry is the in-process registry with img seeded at
// <host>/ok/app:v1 and <host>/hang/app:v1, except that a manifest GET under
// hang/ is accepted and never answered: reached is closed when the first one
// arrives, and the handler is held until the client goes away or the test ends.
func hangingManifestRegistry(t *testing.T) (host string, reached <-chan struct{}) {
	t.Helper()
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	release := make(chan struct{})
	reach := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/hang/") && strings.Contains(r.URL.Path, "/manifests/") {
			once.Do(func() { close(reach) })
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		store.ServeHTTP(w, r)
	}))
	// Cleanups run last-in first-out: release any held handler, then close.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	img := testImage(t, "darwin", "arm64", "")
	for _, repo := range []string{"ok/app:v1", "hang/app:v1"} {
		ref, err := name.ParseReference(u.Host + "/" + repo)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Write(ref, img); err != nil {
			t.Fatalf("seed %s: %v", repo, err)
		}
	}
	return u.Host, reach
}

// TestResolveTimeoutIsPullFailure is the gate for the resolve bound: a
// registry that accepts the manifest request and never answers fails the pull
// with ErrResolveTimeout once the bound runs out (a hand-fired fake timer, so
// nothing waits on the wall clock), a caller's own cancellation stays a context
// error, and a resolve that finishes leaves the context the image fetches its
// layers with uncancelled, even when the timer's callback runs late. The header
// timeout is set far above anything here, so the resolve bound is what fires.
func TestResolveTimeoutIsPullFailure(t *testing.T) {
	t.Run("a manifest that never answers times out the resolve", func(t *testing.T) {
		ft := newFakeTimer()
		setResolveSeams(t, ft, time.Hour)
		host, reached := hangingManifestRegistry(t)
		errc := make(chan error, 1)
		go func() {
			_, err := RemoteFetch(context.Background(), host+"/hang/app:v1", nil, nativePolicy())
			errc <- err
		}()
		<-reached
		if !ft.advance(resolveTimeout) {
			t.Fatal("the resolve timer was not armed while the manifest request was held")
		}
		err := <-errc
		if !errors.Is(err, ErrResolveTimeout) {
			t.Fatalf("err = %v, want ErrResolveTimeout", err)
		}
		if errors.Is(err, context.Canceled) {
			t.Errorf("err = %v carries a context error; a resolve timeout is a pull failure", err)
		}
		if !strings.HasPrefix(err.Error(), `pull "`) {
			t.Errorf("err = %q, want the pull %%q: message shape", err)
		}
		if strings.Contains(err.Error(), "http://") || strings.Contains(err.Error(), "/v2/") {
			t.Errorf("err = %q names the request URL; the cancelled request's error must be dropped", err)
		}
	})

	t.Run("a caller cancellation stays a context error", func(t *testing.T) {
		ft := newFakeTimer()
		setResolveSeams(t, ft, time.Hour)
		host, reached := hangingManifestRegistry(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := RemoteFetch(ctx, host+"/hang/app:v1", nil, nativePolicy())
			errc <- err
		}()
		<-reached
		cancel()
		err := <-errc
		if errors.Is(err, ErrResolveTimeout) {
			t.Fatalf("err = %v, want no ErrResolveTimeout for a caller cancellation", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("a finished resolve never cancels the layer fetch context", func(t *testing.T) {
		ft := newFakeTimer()
		setResolveSeams(t, ft, time.Hour)
		host, _ := hangingManifestRegistry(t)
		img, err := RemoteFetch(context.Background(), host+"/ok/app:v1", nil, nativePolicy())
		if err != nil {
			t.Fatalf("RemoteFetch: %v", err)
		}
		if ft.Stop() {
			t.Fatal("the resolve timer is still armed after the resolve finished")
		}
		if ft.advance(resolveTimeout) {
			t.Fatal("a stopped resolve timer fired")
		}
		// A callback that had already started when Stop ran: it must find the
		// resolve finished and cancel nothing.
		ft.lastCallback()()
		layers, err := img.Layers()
		if err != nil || len(layers) != 1 {
			t.Fatalf("layers: %d, %v", len(layers), err)
		}
		rc, err := layers[0].Compressed()
		if err != nil {
			t.Fatalf("fetch layer after resolve: %v", err)
		}
		defer rc.Close()
		if _, err := io.Copy(io.Discard, rc); err != nil {
			t.Fatalf("read layer after resolve: %v", err)
		}
	})
}

// silentListener accepts connections on 127.0.0.1:0 and never writes to them,
// holding each one open until the test ends. It returns the listener's address.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// assertHeaderTimeout round-trips a GET to addr over tr and asserts it fails
// with the transport's own timeout, not a context error.
func assertHeaderTimeout(t *testing.T, tr http.RoundTripper, addr string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("round trip to a server that never answers succeeded")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a transport timeout", err)
	}
	// net/http's header timeout matches context.DeadlineExceeded under
	// errors.Is, so the proof it is the transport's bound is that the
	// request's own context never ended.
	if req.Context().Err() != nil || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v is a context error, want the response-header timeout", err)
	}
	if !strings.Contains(err.Error(), "timeout awaiting response headers") {
		t.Fatalf("err = %v, want the response-header timeout", err)
	}
}

// TestFlatTransportHeaderTimeout pins the header bound on the flat registry's
// transport, which ArtifactTransport shares.
func TestFlatTransportHeaderTimeout(t *testing.T) {
	old := headerTimeout
	headerTimeout = 50 * time.Millisecond
	t.Cleanup(func() { headerTimeout = old })

	addr := silentListener(t)
	tr := endpointTransport(addr, RegistryEndpoint{Addr: addr}, nil)
	if tr.ResponseHeaderTimeout != headerTimeout {
		t.Fatalf("ResponseHeaderTimeout = %s, want %s", tr.ResponseHeaderTimeout, headerTimeout)
	}
	assertHeaderTimeout(t, tr, addr)

	art, _, err := ArtifactTransport(FlatRegistry{Host: flatHost, Endpoint: RegistryEndpoint{Addr: addr}})
	if err != nil {
		t.Fatalf("ArtifactTransport: %v", err)
	}
	at, ok := art.(*http.Transport)
	if !ok {
		t.Fatalf("ArtifactTransport returned %T, want *http.Transport", art)
	}
	if at.ResponseHeaderTimeout != headerTimeout {
		t.Fatalf("ArtifactTransport ResponseHeaderTimeout = %s, want %s", at.ResponseHeaderTimeout, headerTimeout)
	}
}

// TestExternalTransportHeaderTimeout pins the header bound on the external
// registry transport: a cached clone of ggcr's default transport that keeps
// its proxy, TLS and HTTP/2 settings, and that honours a swapped default.
func TestExternalTransportHeaderTimeout(t *testing.T) {
	old := headerTimeout
	headerTimeout = 50 * time.Millisecond
	t.Cleanup(func() { headerTimeout = old })

	base, ok := remote.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("remote.DefaultTransport is %T, want *http.Transport", remote.DefaultTransport)
	}
	got := registryTransport()
	tr, ok := got.(*http.Transport)
	if !ok {
		t.Fatalf("registryTransport returned %T, want *http.Transport", got)
	}
	if tr == base {
		t.Fatal("registryTransport returned ggcr's default transport itself, want a clone")
	}
	if tr.ResponseHeaderTimeout != headerTimeout {
		t.Errorf("ResponseHeaderTimeout = %s, want %s", tr.ResponseHeaderTimeout, headerTimeout)
	}
	if reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(base.Proxy).Pointer() {
		t.Error("Proxy differs from remote.DefaultTransport's")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig, base.TLSClientConfig) {
		t.Error("TLSClientConfig differs from remote.DefaultTransport's")
	}
	if tr.ForceAttemptHTTP2 != base.ForceAttemptHTTP2 || tr.MaxIdleConnsPerHost != base.MaxIdleConnsPerHost ||
		tr.TLSHandshakeTimeout != base.TLSHandshakeTimeout || tr.IdleConnTimeout != base.IdleConnTimeout {
		t.Error("HTTP/2, idle or TLS handshake settings differ from remote.DefaultTransport's")
	}
	if again := registryTransport(); again != got {
		t.Error("registryTransport built a new transport on a repeated call; connections would not be reused")
	}
	assertHeaderTimeout(t, got, silentListener(t))

	t.Run("a swapped default transport is honoured", func(t *testing.T) {
		swapped := base.Clone()
		remote.DefaultTransport = swapped
		t.Cleanup(func() { remote.DefaultTransport = base })
		st, ok := registryTransport().(*http.Transport)
		if !ok || st == tr || st == swapped || st.ResponseHeaderTimeout != headerTimeout {
			t.Fatalf("registryTransport after a swap = %p, want a fresh clone of the swapped transport", st)
		}
	})

	t.Run("a default that is not an *http.Transport is returned unchanged", func(t *testing.T) {
		var custom http.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("unused")
		})
		remote.DefaultTransport = custom
		t.Cleanup(func() { remote.DefaultTransport = base })
		if got := registryTransport(); reflect.ValueOf(got).Pointer() != reflect.ValueOf(custom).Pointer() {
			t.Fatal("registryTransport did not return a non-*http.Transport default unchanged")
		}
	})
}

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
