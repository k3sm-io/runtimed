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
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// challengeTransport answers GET /v2/ with a Basic challenge (so the
// authenticating layer is built) and every other request with 200 plus a
// WWW-Authenticate header. registryfetch's host split strips that header from
// a response it routed past the credential transport, so its presence on a
// response tells the test which side the request took.
type challengeTransport struct {
	mu   sync.Mutex
	auth []string
}

func (c *challengeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := http.Header{"Www-Authenticate": {`Basic realm="x"`}}
	status := http.StatusOK
	if req.URL.Path == "/v2/" {
		status = http.StatusUnauthorized
	}
	c.mu.Lock()
	c.auth = append(c.auth, req.Header.Get("Authorization"))
	c.mu.Unlock()
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// TestHostCompareCredentialTransport pins how the transport the manifest and
// blob fetches use (registryfetch.Registry.OriginSplit, the hostSplit in
// pkg/registryfetch/registry.go) decides a request is for the registry's own
// origin. It compares the lower-cased scheme exactly, and the host name
// (lower-cased) and port, with the scheme's default port filled in when none
// is written. A trailing dot, a suffix or a prefix is another host. Rows
// marked "bare" give an IPv6 host without brackets, the form a hand-built
// URL can carry. creds says whether the request went through the
// authenticating transport.
func TestHostCompareCredentialTransport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		registry string // the reference's registry, as name parses it
		insecure bool   // name.Insecure: scheme http
		scheme   string // the request URL's scheme
		host     string // the request URL's host
		creds    bool
	}{
		{name: "same host same port", registry: "registry.example:5000", scheme: "https", host: "registry.example:5000", creds: true},
		{name: "same host other port", registry: "registry.example:5000", scheme: "https", host: "registry.example:5001"},
		{name: "same host and port, scheme https to http", registry: "registry.example:5000", scheme: "http", host: "registry.example:5000"},
		{name: "same host and port, scheme http to https", registry: "registry.example:5000", insecure: true, scheme: "https", host: "registry.example:5000"},
		{name: "scheme in upper case", registry: "registry.example", scheme: "HTTPS", host: "registry.example", creds: true},
		{name: "host letter case, request upper", registry: "registry.example", scheme: "https", host: "Registry.Example", creds: true},
		{name: "host letter case, registry upper", registry: "Registry.Example", scheme: "https", host: "registry.example", creds: true},
		{name: "trailing dot on request", registry: "registry.example", scheme: "https", host: "registry.example."},
		{name: "trailing dot on registry", registry: "registry.example.", scheme: "https", host: "registry.example"},
		{name: "ipv6 bracketed both", registry: "[::1]:5000", insecure: true, scheme: "http", host: "[::1]:5000", creds: true},
		{name: "ipv6 bracketed other port", registry: "[::1]:5000", insecure: true, scheme: "http", host: "[::1]:5001"},
		{name: "ipv6 bracketed default port omitted", registry: "[::1]", insecure: true, scheme: "http", host: "[::1]:80", creds: true},
		{name: "ipv6 bare request, bracketed registry", registry: "[::1]:5000", insecure: true, scheme: "http", host: "::1"},
		// The standard library reads the unbracketed host "::1:5000" as hostname
		// "::1" and port "5000" (asserted in the test body), the same endpoint
		// as "[::1]:5000". Credentials sent there go to the registry itself.
		{name: "ipv6 bare request with port form", registry: "[::1]:5000", insecure: true, scheme: "http", host: "::1:5000", creds: true},
		{name: "default port written on request", registry: "registry.example", scheme: "https", host: "registry.example:443", creds: true},
		{name: "default port written on registry", registry: "registry.example:443", scheme: "https", host: "registry.example", creds: true},
		{name: "http default port is not the https one", registry: "registry.example", scheme: "https", host: "registry.example:80"},
		{name: "suffix lookalike", registry: "registry.example", scheme: "https", host: "registry.example.evil.test"},
		{name: "prefix lookalike", registry: "registry.example", scheme: "https", host: "evilregistry.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.host == "::1:5000" {
				u := &url.URL{Host: tc.host}
				if u.Hostname() != "::1" || u.Port() != "5000" {
					t.Fatalf("url.URL{Host: %q}: Hostname %q, Port %q; want %q and %q",
						tc.host, u.Hostname(), u.Port(), "::1", "5000")
				}
			}
			var opts []name.Option
			if tc.insecure {
				opts = append(opts, name.Insecure)
			}
			repo, err := name.NewRepository(tc.registry+"/team/app", opts...)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.registry, err)
			}
			inner := &challengeTransport{}
			reg := registryfetch.Registry{Transport: inner}
			rt, err := reg.OriginSplit(context.Background(), repo, &registryfetch.Credential{Username: "u", Password: "p"})
			if err != nil {
				t.Fatalf("OriginSplit: %v", err)
			}
			req := (&http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Scheme: tc.scheme, Host: tc.host, Path: "/v2/team/app/blobs/x"},
				Header: http.Header{},
			}).WithContext(context.Background())
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			resp.Body.Close()
			// The final (non-ping) request is the last one the inner transport saw.
			inner.mu.Lock()
			lastAuth := inner.auth[len(inner.auth)-1]
			inner.mu.Unlock()
			// The library's basic-auth layer attaches the header only when the
			// request host string equals the registry string exactly, so a row
			// the split routes to the credential transport by canonical form
			// (case, default port) still carries no header. The header is
			// therefore required only for an exact textual match.
			sent := lastAuth != ""
			if sent && !tc.creds {
				t.Errorf("registry %q, request %s://%s: sends credentials to another origin (Authorization %q)",
					tc.registry, tc.scheme, tc.host, lastAuth)
			}
			if !sent && tc.creds && tc.host == repo.RegistryStr() {
				t.Errorf("registry %q, request %s://%s: withholds credentials from the registry's own origin",
					tc.registry, tc.scheme, tc.host)
			}
			// A response that kept its challenge went through the credential
			// transport; the plain route strips it.
			if got := resp.Header.Get("Www-Authenticate") != ""; got != tc.creds {
				t.Errorf("registry %q (scheme %s), request %s://%s: credential transport = %v, want %v",
					tc.registry, repo.Registry.Scheme(), tc.scheme, tc.host, got, tc.creds)
			}
		})
	}
}
