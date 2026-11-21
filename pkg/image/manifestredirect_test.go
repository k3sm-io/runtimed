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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// TestManifestFetchRedirectDoesNotReachTokenLogic pins that a manifest GET the
// registry redirects to another host is fetched off the credential path: the
// other host gets no Authorization header, and its 401 challenge (asking for a
// push scope at the registry's own token realm) never becomes a token request.
// The second row makes the registry's /v2/ ping always answer 401, so the
// authenticating layer go-containerregistry stacks on top is a bearer one too.
func TestManifestFetchRedirectDoesNotReachTokenLogic(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pingAlways401 bool
	}{
		{name: "ping succeeds with a token"},
		{name: "ping always challenges", pingAlways401: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu       sync.Mutex
				scopes   []string
				foreignA []string
				bHits    int
			)
			b := httptest.NewServer(nil)
			defer b.Close()
			a := httptest.NewServer(nil)
			defer a.Close()
			challenge := `Bearer realm="` + a.URL + `/token",service="x"`
			a.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authed := r.Header.Get("Authorization") == "Bearer good"
				switch {
				case r.URL.Path == "/token":
					mu.Lock()
					scopes = append(scopes, r.URL.Query()["scope"]...)
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"token":"good"}`))
				case r.URL.Path == "/v2/":
					if !authed || tc.pingAlways401 {
						w.Header().Set("WWW-Authenticate", challenge)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.WriteHeader(http.StatusOK)
				case strings.HasPrefix(r.URL.Path, "/v2/repo/x/manifests/"):
					if !authed {
						w.Header().Set("WWW-Authenticate", challenge+`,scope="repository:repo/x:pull"`)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					http.Redirect(w, r, b.URL+"/elsewhere", http.StatusTemporaryRedirect)
				default:
					http.NotFound(w, r)
				}
			})
			b.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				bHits++
				mu.Unlock()
				if h := r.Header.Get("Authorization"); h != "" {
					mu.Lock()
					foreignA = append(foreignA, h)
					mu.Unlock()
				}
				w.Header().Set("WWW-Authenticate",
					`Bearer realm="`+a.URL+`/token",service="x",scope="repository:evil/x:push"`)
				w.WriteHeader(http.StatusUnauthorized)
			})

			ref := strings.TrimPrefix(a.URL, "http://") + "/repo/x:tag"
			cred := &RegistryCredential{Username: "u", Password: "p"}
			if _, err := RemoteFetch(context.Background(), ref, cred, nativePolicy()); err == nil {
				t.Fatal("RemoteFetch succeeded; want the redirect target's 401 as an error")
			}

			mu.Lock()
			defer mu.Unlock()
			if bHits == 0 {
				t.Error("redirect target was never reached; the fetch failed before the redirect")
			}
			if len(foreignA) != 0 {
				t.Errorf("redirect target received Authorization %q; want none", foreignA)
			}
			if len(scopes) == 0 {
				t.Fatal("token endpoint never hit; the push-scope check is vacuous")
			}
			for _, s := range scopes {
				if strings.Contains(s, "push") {
					t.Errorf("token endpoint asked for scope %q; want no push scope (all: %q)", s, scopes)
				}
			}
		})
	}
}

// downgradeTransport stands in for an https registry, registry.example,
// whose manifest GETs redirect to plain http on blobs.example. It records
// every plain http request it is asked to send.
type downgradeTransport struct {
	mu    sync.Mutex
	plain []string
}

func (d *downgradeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res := &http.Response{Header: http.Header{}, Body: http.NoBody, Request: req}
	switch {
	case req.URL.Scheme == "http":
		d.mu.Lock()
		d.plain = append(d.plain, req.URL.Host)
		d.mu.Unlock()
		res.StatusCode = http.StatusNotFound
	case req.URL.Path == "/v2/":
		res.StatusCode = http.StatusOK
	case strings.HasPrefix(req.URL.Path, "/v2/repo/x/manifests/"):
		res.StatusCode = http.StatusTemporaryRedirect
		res.Header.Set("Location", "http://blobs.example/x")
	default:
		res.StatusCode = http.StatusNotFound
	}
	return res, nil
}

// TestManifestFetchRefusesDowngrade pins that a manifest GET an https
// registry redirects to plain http is refused with
// registryfetch.ErrRedirectDowngrade before the http request is sent.
// go-containerregistry's own redirect check allows a redirect to any public
// host, whatever the scheme. (net/http's url.Error around the refusal still
// carries the full target URL, as it does for Session's checkRedirect.)
func TestManifestFetchRefusesDowngrade(t *testing.T) {
	ref := "registry.example/repo/x:tag"
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if r.Context().Registry.Scheme() != "https" {
		t.Fatalf("registry scheme %q; the row needs https", r.Context().Registry.Scheme())
	}
	tr := &downgradeTransport{}
	_, err = splitFetch(context.Background(), r, ref, &RegistryCredential{Username: "u", Password: "p"},
		nativePolicy(), tr)
	if !errors.Is(err, registryfetch.ErrRedirectDowngrade) {
		t.Fatalf("splitFetch: err %v, want ErrRedirectDowngrade", err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.plain) != 0 {
		t.Errorf("plain http requests sent to %q; want none", tr.plain)
	}
}
