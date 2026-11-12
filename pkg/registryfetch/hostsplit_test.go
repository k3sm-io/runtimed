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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// credSeen is the Authorization and Cookie one server saw on one request.
type credSeen struct{ auth, cookie string }

// credLog records the credential headers of each request a server sees.
type credLog struct {
	mu   sync.Mutex
	reqs []credSeen
}

func (l *credLog) note(req *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, credSeen{req.Header.Get("Authorization"), req.Header.Get("Cookie")})
}

func (l *credLog) seen() []credSeen {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]credSeen(nil), l.reqs...)
}

// stampingAuth stands in for the authenticating transport: it attaches an
// Authorization and a Cookie to every request it sees and records its URL.
type stampingAuth struct {
	inner http.RoundTripper
	mu    sync.Mutex
	urls  []string
}

func (s *stampingAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.urls = append(s.urls, req.URL.String())
	s.mu.Unlock()
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("Cookie", "session=x")
	return s.inner.RoundTrip(req)
}

func (s *stampingAuth) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.urls...)
}

// stampAuth replaces newAuthTransport for the test with a stampingAuth over
// the inner transport Session passes, and returns it.
func stampAuth(t *testing.T) *stampingAuth {
	t.Helper()
	s := &stampingAuth{}
	prev := newAuthTransport
	newAuthTransport = func(_ context.Context, _ name.Registry, _ authn.Authenticator, inner http.RoundTripper, _ []string) (http.RoundTripper, error) {
		s.inner = inner
		return s, nil
	}
	t.Cleanup(func() { newAuthTransport = prev })
	return s
}

// serveOK starts a server that records each request and answers 200.
func serveOK(t *testing.T) (*httptest.Server, *credLog) {
	t.Helper()
	log := &credLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.note(req)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

// serveRedirectTo starts origin A, which records each request and answers it
// with a 307 to target plus the request path.
func serveRedirectTo(t *testing.T, target string) (*httptest.Server, *credLog) {
	t.Helper()
	log := &credLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.note(req)
		http.Redirect(w, req, target+req.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

// getVia opens a Session for a repository on origin and GETs path on it.
func getVia(t *testing.T, inner http.RoundTripper, origin, path string) (*http.Response, error) {
	t.Helper()
	host := strings.TrimPrefix(origin, "http://")
	reg := &Registry{Transport: inner, PlainHTTP: true}
	_, client, err := reg.Session(context.Background(), host+"/models/tiny:v1", redirectCred)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client.Do(req)
}

// TestSessionCheckRedirectStripsCredentials: the authenticating transport
// stamps an Authorization and a Cookie on every request it sees; A gets both,
// and A's 307 to another host B reaches B with neither, because B's request
// never passes through the authenticating transport.
func TestSessionCheckRedirectStripsCredentials(t *testing.T) {
	stamp := stampAuth(t)
	b, blog := serveOK(t)
	bURL := strings.Replace(b.URL, "127.0.0.1", "localhost", 1)
	a, alog := serveRedirectTo(t, bURL)
	resp, err := getVia(t, http.DefaultTransport, a.URL, "/v2/models/tiny/blobs/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ah := alog.seen(); len(ah) != 1 || ah[0].auth != "Bearer x" || ah[0].cookie != "session=x" {
		t.Fatalf("origin saw %q, want one request with Authorization and Cookie", ah)
	}
	if bh := blog.seen(); len(bh) != 1 || bh[0].auth != "" || bh[0].cookie != "" {
		t.Fatalf("second host saw %q, want one request with no Authorization and no Cookie", bh)
	}
	if got := stamp.seen(); len(got) != 1 || !strings.HasPrefix(got[0], a.URL) {
		t.Fatalf("authenticating transport saw %q, want only the origin request", got)
	}
}

// TestSessionRedirectToOtherPortIsAnotherHost: B is A's host name on another
// port; the redirect there passes the authenticating transport by.
func TestSessionRedirectToOtherPortIsAnotherHost(t *testing.T) {
	stamp := stampAuth(t)
	b, blog := serveOK(t)
	a, alog := serveRedirectTo(t, b.URL)
	resp, err := getVia(t, http.DefaultTransport, a.URL, "/v2/models/tiny/blobs/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ah := alog.seen(); len(ah) != 1 || ah[0].auth != "Bearer x" {
		t.Fatalf("origin saw %q, want one request with Authorization", ah)
	}
	if bh := blog.seen(); len(bh) != 1 || bh[0].auth != "" || bh[0].cookie != "" {
		t.Fatalf("other port saw %q, want one request with no credential", bh)
	}
	if got := stamp.seen(); len(got) != 1 {
		t.Fatalf("authenticating transport saw %q, want only the origin request", got)
	}
}

// plainRecorder is the registry's plain transport: it records each URL and
// answers https requests itself with a 200 (no TLS server shares A's port),
// passing the rest to http.DefaultTransport.
type plainRecorder struct {
	mu   sync.Mutex
	urls []string
	reqs []credSeen
}

func (p *plainRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.urls = append(p.urls, req.URL.String())
	p.reqs = append(p.reqs, credSeen{req.Header.Get("Authorization"), req.Header.Get("Cookie")})
	p.mu.Unlock()
	if req.URL.Scheme == "https" {
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: req,
		}, nil
	}
	return http.DefaultTransport.RoundTrip(req)
}

// TestSessionRedirectToOtherSchemeIsAnotherHost: A redirects to its own
// host:port under https. httptest cannot serve two schemes on one port, so
// the plain transport answers the https request itself; the point is that it,
// not the authenticating transport, receives it, with no credential.
func TestSessionRedirectToOtherSchemeIsAnotherHost(t *testing.T) {
	stamp := stampAuth(t)
	plain := &plainRecorder{}
	log := &credLog{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.note(req)
		target := strings.Replace(srv.URL, "http://", "https://", 1)
		http.Redirect(w, req, target+req.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	resp, err := getVia(t, plain, srv.URL, "/v2/models/tiny/blobs/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ah := log.seen(); len(ah) != 1 || ah[0].auth != "Bearer x" {
		t.Fatalf("origin saw %q, want one request with Authorization", ah)
	}
	if got := stamp.seen(); len(got) != 1 || !strings.HasPrefix(got[0], "http://") {
		t.Fatalf("authenticating transport saw %q, want only the http origin request", got)
	}
	plain.mu.Lock()
	defer plain.mu.Unlock()
	var https []credSeen
	for i, u := range plain.urls {
		if strings.HasPrefix(u, "https://") {
			https = append(https, plain.reqs[i])
		}
	}
	if len(https) != 1 || https[0].auth != "" || https[0].cookie != "" {
		t.Fatalf("plain transport saw https requests %q (urls %q), want one with no credential", https, plain.urls)
	}
}

// routeRecorder records that it was asked and answers 204.
type routeRecorder struct{ n int }

func (r *routeRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.n++
	return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
}

// TestHostSplitRoutes: scheme and host:port decide the route, with default
// ports filled in and host names compared case-insensitively.
func TestHostSplitRoutes(t *testing.T) {
	for _, tc := range []struct {
		scheme, host, url string
		auth              bool
	}{
		{"https", "registry.example", "https://registry.example/v2/", true},
		{"https", "registry.example", "https://registry.example:443/v2/", true},
		{"https", "registry.example:443", "https://REGISTRY.example/v2/", true},
		{"http", "registry.example", "http://registry.example:80/v2/", true},
		{"https", "registry.example", "http://registry.example/v2/", false},
		{"https", "registry.example", "http://registry.example:443/v2/", false},
		{"https", "registry.example", "https://registry.example:5000/v2/", false},
		{"https", "registry.example", "https://blobs.example/v2/", false},
		{"https", "registry.example", "https://registry.example.evil/v2/", false},
	} {
		auth, plain := &routeRecorder{}, &routeRecorder{}
		h := &hostSplit{scheme: tc.scheme, host: canonicalHost(tc.scheme, tc.host), auth: auth, plain: plain}
		req, err := http.NewRequest(http.MethodGet, tc.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := h.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := auth.n == 1 && plain.n == 0; got != tc.auth {
			t.Errorf("registry %s://%s, request %s: auth %d plain %d, want auth route %v",
				tc.scheme, tc.host, tc.url, auth.n, plain.n, tc.auth)
		}
	}
}

// TestBlobRedirectChallengeScopeDoesNotReachToken: with the real
// authenticating transport, A demands a bearer token and redirects the blob
// GET to B, whose 401 challenge asks for scope "repository:evil/x:push". A's
// token endpoint is asked exactly once, and only for the original pull scope.
func TestBlobRedirectChallengeScopeDoesNotReachToken(t *testing.T) {
	_, digest := blobData(1000)
	blog := &credLog{}
	var asrv *httptest.Server
	bsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blog.note(req)
		// The realm is A's own token endpoint, so only the scope is foreign.
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="`+asrv.URL+`/token",service="redirect-test",scope="repository:evil/x:push"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(bsrv.Close)
	bURL := strings.Replace(bsrv.URL, "127.0.0.1", "localhost", 1)
	var (
		mu     sync.Mutex
		scopes [][]string
	)
	asrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		challenge := func() {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+req.Host+`/token",service="redirect-test"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
		switch {
		case req.URL.Path == "/v2/":
			challenge()
		case req.URL.Path == "/token":
			mu.Lock()
			scopes = append(scopes, req.URL.Query()["scope"])
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"`+redirectToken+`"}`)
		case req.Header.Get("Authorization") != "Bearer "+redirectToken:
			challenge()
		default:
			http.Redirect(w, req, bURL+req.URL.Path, http.StatusTemporaryRedirect)
		}
	}))
	t.Cleanup(asrv.Close)
	host := strings.TrimPrefix(asrv.URL, "http://")
	reg := &Registry{Transport: http.DefaultTransport, PlainHTTP: true}
	body, _, err := reg.Blob(context.Background(), host+"/models/tiny:v1", redirectCred, digest, 1000, 0)
	if err == nil {
		body.Close()
		t.Fatal("a 401 from the second host was accepted as the blob")
	}
	if bh := blog.seen(); len(bh) != 1 || bh[0].auth != "" {
		t.Fatalf("second host saw %q, want one request with no Authorization", bh)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "repository:models/tiny:pull"
	if len(scopes) != 1 || len(scopes[0]) != 1 || scopes[0][0] != want {
		t.Fatalf("origin token endpoint saw scopes %q, want exactly one request for [%q]", scopes, want)
	}
}
