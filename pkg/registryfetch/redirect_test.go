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

package registryfetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hit is what one server saw on one blob request.
type hit struct{ auth, rng string }

// recorder notes the Authorization and Range of each blob request.
type recorder struct {
	mu   sync.Mutex
	hits []hit
}

func (r *recorder) note(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, hit{req.Header.Get("Authorization"), req.Header.Get("Range")})
}

func (r *recorder) seen() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hit(nil), r.hits...)
}

// redirectSetup shapes the two hosts serveRedirectWith starts.
type redirectSetup struct {
	// bHost is the host name B is reached by; A is always "127.0.0.1".
	bHost string
	// bearer makes A answer the /v2/ ping with a Bearer challenge whose realm
	// is A's own /token endpoint, and redirect a blob GET only when it carries
	// that token; otherwise A answers the ping with 200.
	bearer bool
}

// redirectToken is the token A's /token endpoint issues.
const redirectToken = "tok-redirect"

// serveRedirect starts origin A, which answers the /v2/ ping itself and every
// blob GET with a 307 to the same path on a second host B, served by b. B is
// reached as "localhost", A as "127.0.0.1", so the two differ by host name.
func serveRedirect(t *testing.T, b http.Handler) (reg *Registry, ref string, a, bseen *recorder) {
	t.Helper()
	return serveRedirectWith(t, b, redirectSetup{bHost: "localhost"})
}

// serveRedirectWith is serveRedirect with B's host name and A's auth scheme
// chosen by s.
func serveRedirectWith(t *testing.T, b http.Handler, s redirectSetup) (reg *Registry, ref string, a, bseen *recorder) {
	t.Helper()
	a, bseen = &recorder{}, &recorder{}
	bsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bseen.note(req)
		b.ServeHTTP(w, req)
	}))
	t.Cleanup(bsrv.Close)
	bURL := strings.Replace(bsrv.URL, "127.0.0.1", s.bHost, 1)
	asrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		challenge := func() {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="http://`+req.Host+`/token",service="redirect-test"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
		switch {
		case req.URL.Path == "/v2/" && s.bearer:
			challenge()
			return
		case req.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
			return
		case req.URL.Path == "/token" && s.bearer:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"`+redirectToken+`"}`)
			return
		}
		a.note(req)
		if s.bearer && req.Header.Get("Authorization") != "Bearer "+redirectToken {
			challenge()
			return
		}
		http.Redirect(w, req, bURL+req.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(asrv.Close)
	host := strings.TrimPrefix(asrv.URL, "http://")
	return &Registry{Transport: http.DefaultTransport, PlainHTTP: true}, host + "/models/tiny:v1", a, bseen
}

var redirectCred = &Credential{Username: "alice", Password: "pw-redirect"}

// checkHops: A saw one request with an Authorization header, B saw one with
// none, and both carried wantRange.
func checkHops(t *testing.T, a, b *recorder, wantRange string) {
	t.Helper()
	ah, bh := a.seen(), b.seen()
	if len(ah) != 1 || ah[0].auth == "" || ah[0].rng != wantRange {
		t.Fatalf("origin saw %q, want one request with Authorization and Range %q", ah, wantRange)
	}
	if len(bh) != 1 || bh[0].auth != "" || bh[0].rng != wantRange {
		t.Fatalf("second host saw %q, want one request with no Authorization and Range %q", bh, wantRange)
	}
}

// checkOneHopEach: A issued exactly one redirect and B received exactly one
// blob request.
func checkOneHopEach(t *testing.T, a, b *recorder) {
	t.Helper()
	if ah, bh := a.seen(), b.seen(); len(ah) != 1 || len(bh) != 1 {
		t.Fatalf("origin saw %q and second host saw %q, want one blob request each", ah, bh)
	}
}

// TestBlobRedirectDropsAuthorization: a 307 to another host carries no
// Authorization there; the origin did get one.
func TestBlobRedirectDropsAuthorization(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirect(t, &fakeRegistry{data: data})
	body, start, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	checkHops(t, a, b, "")
	if got, err := io.ReadAll(body); start != 0 || err != nil || !bytes.Equal(got, data) {
		t.Fatalf("start %d, %d bytes, err %v; want the whole blob from 0", start, len(got), err)
	}
}

// TestBlobRedirectKeepsRangeDropsAuthorization: a ranged GET keeps its Range
// across the redirect and still sends no Authorization to the second host.
func TestBlobRedirectKeepsRangeDropsAuthorization(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirect(t, &fakeRegistry{data: data})
	body, _, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	checkHops(t, a, b, "bytes=300-")
}

// TestBlobRedirectRangeAnsweredWith200RestartsAtZero: the second host
// ignores the Range and sends the whole blob; Blob reports start 0.
func TestBlobRedirectRangeAnsweredWith200RestartsAtZero(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirect(t, &fakeRegistry{data: data, rangeStatus: http.StatusOK})
	body, start, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	checkOneHopEach(t, a, b)
	if got, err := io.ReadAll(body); start != 0 || err != nil || !bytes.Equal(got, data) {
		t.Fatalf("start %d, %d bytes, err %v; want the whole blob from 0", start, len(got), err)
	}
}

// TestBlobRedirectWrongContentRangeIsRefused: the second host's 206 with a
// Content-Range other than the one asked for is ErrBlobRange.
func TestBlobRedirectWrongContentRangeIsRefused(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirect(t, &fakeRegistry{data: data, contentRange: "bytes 0-999/1000"})
	body, _, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err == nil {
		body.Close()
		t.Fatal("a wrong Content-Range from the second host was accepted")
	}
	if !errors.Is(err, ErrBlobRange) {
		t.Fatalf("err = %v, want ErrBlobRange", err)
	}
	checkOneHopEach(t, a, b)
}

// TestBlobRedirectPartialContentReturnsFromOffset: the second host's 206 with
// the asked Content-Range is the body from the offset.
func TestBlobRedirectPartialContentReturnsFromOffset(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirect(t, &fakeRegistry{data: data})
	body, start, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	checkOneHopEach(t, a, b)
	if got, err := io.ReadAll(body); start != 300 || err != nil || !bytes.Equal(got, data[300:]) {
		t.Fatalf("start %d, %d bytes, err %v; want 300 and the blob from 300", start, len(got), err)
	}
}

// TestBlobRedirectBearerTokenStaysOnOrigin: A demands a bearer token from its
// own token endpoint; the blob GET to A carries it, and the 307 to another
// host carries no Authorization at all.
func TestBlobRedirectBearerTokenStaysOnOrigin(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirectWith(t, &fakeRegistry{data: data}, redirectSetup{bHost: "localhost", bearer: true})
	body, _, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	if ah := a.seen(); len(ah) != 1 || ah[0].auth != "Bearer "+redirectToken {
		t.Fatalf("origin saw %q, want one request with Authorization %q", ah, "Bearer "+redirectToken)
	}
	if bh := b.seen(); len(bh) != 1 || bh[0].auth != "" {
		t.Fatalf("second host saw %q, want one request with no Authorization", bh)
	}
}

// TestBlobRedirectToOtherPortDropsAuthorization: B is the same host name as A
// (both 127.0.0.1) on a different port, and still gets no Authorization.
func TestBlobRedirectToOtherPortDropsAuthorization(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, a, b := serveRedirectWith(t, &fakeRegistry{data: data}, redirectSetup{bHost: "127.0.0.1"})
	body, _, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	checkHops(t, a, b, "")
}
