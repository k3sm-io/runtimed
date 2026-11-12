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

// serveRedirect starts origin A, which answers the /v2/ ping itself and every
// blob GET with a 307 to the same path on a second host B, served by b. B is
// reached as "localhost", A as "127.0.0.1", so the two differ by host name.
func serveRedirect(t *testing.T, b http.Handler) (reg *Registry, ref string, a, bseen *recorder) {
	t.Helper()
	a, bseen = &recorder{}, &recorder{}
	bsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bseen.note(req)
		b.ServeHTTP(w, req)
	}))
	t.Cleanup(bsrv.Close)
	bURL := strings.Replace(bsrv.URL, "127.0.0.1", "localhost", 1)
	asrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		a.note(req)
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
	reg, ref, _, _ := serveRedirect(t, &fakeRegistry{data: data, rangeStatus: http.StatusOK})
	body, start, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if got, err := io.ReadAll(body); start != 0 || err != nil || !bytes.Equal(got, data) {
		t.Fatalf("start %d, %d bytes, err %v; want the whole blob from 0", start, len(got), err)
	}
}

// TestBlobRedirectWrongContentRangeIsRefused: the second host's 206 with a
// Content-Range other than the one asked for is ErrBlobRange.
func TestBlobRedirectWrongContentRangeIsRefused(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, _, _ := serveRedirect(t, &fakeRegistry{data: data, contentRange: "bytes 0-999/1000"})
	body, _, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err == nil {
		body.Close()
		t.Fatal("a wrong Content-Range from the second host was accepted")
	}
	if !errors.Is(err, ErrBlobRange) {
		t.Fatalf("err = %v, want ErrBlobRange", err)
	}
}

// TestBlobRedirectPartialContentReturnsFromOffset: the second host's 206 with
// the asked Content-Range is the body from the offset.
func TestBlobRedirectPartialContentReturnsFromOffset(t *testing.T) {
	data, digest := blobData(1000)
	reg, ref, _, _ := serveRedirect(t, &fakeRegistry{data: data})
	body, start, err := reg.Blob(context.Background(), ref, redirectCred, digest, 1000, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if got, err := io.ReadAll(body); start != 300 || err != nil || !bytes.Equal(got, data[300:]) {
		t.Fatalf("start %d, %d bytes, err %v; want 300 and the blob from 300", start, len(got), err)
	}
}
