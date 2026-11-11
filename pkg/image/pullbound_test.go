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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// silentServer accepts every request and never writes a byte of response; a
// handler is held until the client goes away or the test ends. It returns the
// server's host:port.
func silentServer(t *testing.T) string {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(done) })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// setDuration overrides *v for the test and restores it after.
// The overrides are unsynchronised, so a test that calls remoteFetch must not use t.Parallel.
func setDuration(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

// TestResolveTimeoutIsPullFailure pins the resolve bound: a registry that never
// answers fails the resolve with ErrPullResolveTimeout within the bound, a
// cancelled caller stays a cancellation, and the bound does not reach the layer
// fetches of an image that resolved in time.
func TestResolveTimeoutIsPullFailure(t *testing.T) {
	t.Run("silent registry", func(t *testing.T) {
		setDuration(t, &resolveTimeout, 50*time.Millisecond)
		host := silentServer(t)
		start := time.Now()
		_, err := RemoteFetch(context.Background(), host+"/silent/app:v1", nil, nativePolicy())
		if !errors.Is(err, ErrPullResolveTimeout) {
			t.Fatalf("RemoteFetch error = %v, want ErrPullResolveTimeout", err)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RemoteFetch error = %v wraps a context error", err)
		}
		if el := time.Since(start); el > 30*time.Second {
			t.Fatalf("RemoteFetch took %s, want about the 50ms bound", el)
		}
	})
	t.Run("parent cancel", func(t *testing.T) {
		setDuration(t, &resolveTimeout, time.Minute)
		host := silentServer(t)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		_, err := RemoteFetch(ctx, host+"/silent/app:v1", nil, nativePolicy())
		if err == nil || errors.Is(err, ErrPullResolveTimeout) {
			t.Fatalf("RemoteFetch error = %v, want a cancellation, not ErrPullResolveTimeout", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RemoteFetch error = %v, want context.Canceled", err)
		}
	})
	t.Run("layer fetch after the bound", func(t *testing.T) {
		setDuration(t, &resolveTimeout, 2*time.Second)
		ref := layerBodyServer(t, func(w http.ResponseWriter, _ *http.Request, layer []byte) {
			_, _ = w.Write(layer)
		})
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if err != nil {
			t.Fatalf("RemoteFetch: %v", err)
		}
		time.Sleep(resolveTimeout + 100*time.Millisecond)
		layers, err := img.Layers()
		if err != nil || len(layers) != 1 {
			t.Fatalf("layers: %d, %v", len(layers), err)
		}
		rc, err := layers[0].Compressed()
		if err != nil {
			t.Fatalf("Compressed after the resolve bound: %v", err)
		}
		defer rc.Close()
		if _, err := io.Copy(io.Discard, rc); err != nil {
			t.Fatalf("read layer after the resolve bound: %v", err)
		}
	})
}

// TestFlatTransportHeaderTimeout pins the header bound on the flat registry's
// transport without loosening its dial restriction.
func TestFlatTransportHeaderTimeout(t *testing.T) {
	setDuration(t, &responseHeaderTimeout, 50*time.Millisecond)
	const host = "flat.test:5000"
	tr := endpointTransport(host, RegistryEndpoint{Addr: silentServer(t)}, nil)
	t.Cleanup(tr.CloseIdleConnections)
	if tr.ResponseHeaderTimeout != 50*time.Millisecond {
		t.Fatalf("ResponseHeaderTimeout = %s, want 50ms", tr.ResponseHeaderTimeout)
	}
	if tr.Proxy != nil {
		t.Fatal("flat transport has a proxy function")
	}
	c := &http.Client{Transport: tr}

	start := time.Now()
	resp, err := c.Get("http://" + host + "/v2/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("GET on a silent endpoint succeeded")
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Fatalf("GET took %s, want about the 50ms bound", el)
	}
	if !strings.Contains(err.Error(), "timeout awaiting response headers") {
		t.Fatalf("GET error = %v, want a response header timeout", err)
	}

	resp, err = c.Get("http://other.test:5000/v2/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("GET on another host succeeded")
	}
	if !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("GET other host error = %v, want a refused dial", err)
	}
}

// countingTransport counts the round trips it carries.
type countingTransport struct {
	n    atomic.Int64
	next http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return c.next.RoundTrip(r)
}

// TestExternalTransportHeaderTimeout pins the external registry transport: a
// header-bounded clone of http.DefaultTransport that leaves the global alone,
// and that a caller's own transport option overrides.
func TestExternalTransportHeaderTimeout(t *testing.T) {
	def := http.DefaultTransport.(*http.Transport)
	before := def.ResponseHeaderTimeout
	tr := newExternalTransport(50 * time.Millisecond)
	if tr == nil {
		t.Fatal("newExternalTransport = nil with a stock http.DefaultTransport")
	}
	t.Cleanup(tr.CloseIdleConnections)
	if tr == def {
		t.Fatal("newExternalTransport returned http.DefaultTransport itself")
	}
	if tr.Proxy == nil {
		t.Fatal("clone dropped the proxy function")
	}
	if tr.ResponseHeaderTimeout != 50*time.Millisecond {
		t.Fatalf("ResponseHeaderTimeout = %s, want 50ms", tr.ResponseHeaderTimeout)
	}
	if tr.DialContext == nil {
		t.Fatal("clone dropped the dialer: no dial timeout")
	}
	if tr.MaxIdleConnsPerHost != externalMaxIdleConnsPerHost || externalMaxIdleConnsPerHost != 50 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 50", tr.MaxIdleConnsPerHost)
	}
	if tr.TLSHandshakeTimeout != def.TLSHandshakeTimeout {
		t.Fatalf("TLSHandshakeTimeout = %s, want the default's %s", tr.TLSHandshakeTimeout, def.TLSHandshakeTimeout)
	}
	if def.ResponseHeaderTimeout != before {
		t.Fatalf("http.DefaultTransport ResponseHeaderTimeout mutated to %s", def.ResponseHeaderTimeout)
	}

	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Get("http://" + silentServer(t) + "/v2/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("GET on a silent registry succeeded")
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Fatalf("GET took %s, want about the 50ms bound", el)
	}
	if !strings.Contains(err.Error(), "timeout awaiting response headers") {
		t.Fatalf("GET error = %v, want a response header timeout", err)
	}

	// Order: the caller's transport option comes after the default one, so it
	// carries every round trip of the pull.
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := name.ParseReference(u.Host + "/order/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, testImage(t, "darwin", "arm64", "")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	inner := &http.Transport{}
	t.Cleanup(inner.CloseIdleConnections)
	rec := &countingTransport{next: inner}
	if _, err := remoteFetch(context.Background(), r, r.String(), nil, nativePolicy(), remote.WithTransport(rec)); err != nil {
		t.Fatalf("remoteFetch: %v", err)
	}
	if rec.n.Load() == 0 {
		t.Fatal("the caller's transport carried no round trip: the default transport option overrode it")
	}
}

// freshExternalTransport makes remoteFetch build its external transport anew
// (so it reads the current header bound) and restores the shared one after.
func freshExternalTransport(t *testing.T) {
	t.Helper()
	old := externalTransport
	next := onceExternalTransport()
	externalTransport = next
	t.Cleanup(func() {
		externalTransport = old
		if tr, ok := next().(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	})
}

// TestExternalTransportHeaderTimeoutThroughPull pins that remoteFetch, with no
// caller transport, carries its round trips on the header-bounded transport: a
// registry that never writes headers fails on the header bound, long before the
// resolve bound, and http.DefaultTransport is left as it was.
func TestExternalTransportHeaderTimeoutThroughPull(t *testing.T) {
	def := http.DefaultTransport.(*http.Transport)
	beforeHeader := def.ResponseHeaderTimeout
	beforeProxy := fmt.Sprintf("%p", def.Proxy)
	beforeDial := fmt.Sprintf("%p", def.DialContext)

	setDuration(t, &responseHeaderTimeout, 50*time.Millisecond)
	setDuration(t, &resolveTimeout, 5*time.Second)
	freshExternalTransport(t)

	r, err := name.ParseReference(silentServer(t) + "/silent/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = remoteFetch(context.Background(), r, r.String(), nil, nativePolicy())
	el := time.Since(start)
	if err == nil {
		t.Fatal("remoteFetch on a silent registry succeeded")
	}
	if errors.Is(err, ErrPullResolveTimeout) {
		t.Fatalf("remoteFetch error = %v, want the header bound, not the resolve bound", err)
	}
	if !strings.Contains(err.Error(), "timeout awaiting response headers") {
		t.Fatalf("remoteFetch error = %v, want a response header timeout", err)
	}
	if el > 30*time.Second {
		t.Fatalf("remoteFetch took %s, want no hang (guard 30s); the error type and text prove the bound", el)
	}

	tr, ok := externalTransport().(*http.Transport)
	if !ok {
		t.Fatal("external transport is not an *http.Transport")
	}
	if tr.ResponseHeaderTimeout != 50*time.Millisecond || tr.DialContext == nil {
		t.Fatalf("external transport: header timeout %s, dialer set %t", tr.ResponseHeaderTimeout, tr.DialContext != nil)
	}
	if tr.MaxIdleConnsPerHost != 50 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 50", tr.MaxIdleConnsPerHost)
	}
	if def.ResponseHeaderTimeout != beforeHeader {
		t.Fatalf("http.DefaultTransport ResponseHeaderTimeout mutated to %s", def.ResponseHeaderTimeout)
	}
	if got := fmt.Sprintf("%p", def.Proxy); got != beforeProxy {
		t.Fatalf("http.DefaultTransport Proxy changed: %s, was %s", got, beforeProxy)
	}
	if got := fmt.Sprintf("%p", def.DialContext); got != beforeDial {
		t.Fatalf("http.DefaultTransport DialContext changed: %s, was %s", got, beforeDial)
	}
}

// timeoutNetError is a net.Error that reports a timeout.
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

// TestMirrorFallbackResolveAndHeaderTimeouts pins what the mirror fallback does
// today with the two bounds' errors: a resolve-bound failure is not eligible,
// a transport timeout (the header bound's kind of error) is.
func TestMirrorFallbackResolveAndHeaderTimeouts(t *testing.T) {
	resolve := fmt.Errorf("pull %q: %w after %s: %v", "r/app:v1", ErrPullResolveTimeout, time.Minute, context.Canceled)
	if mirrorFallbackEligible(resolve) {
		t.Errorf("mirrorFallbackEligible(%v) = true, want false", resolve)
	}
	var ne net.Error = timeoutNetError{}
	header := fmt.Errorf("pull %q: %w", "r/app:v1", ne)
	if !mirrorFallbackEligible(header) {
		t.Errorf("mirrorFallbackEligible(%v) = false, want true", header)
	}
}
