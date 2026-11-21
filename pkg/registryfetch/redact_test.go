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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

// queryMarker stands in for a presigned signature in a redirect target's
// query.
const queryMarker = "sig-marker-5d1c"

// closedURL is an http URL on a loopback port nothing listens on: a dial to
// it is refused.
func closedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr
}

// redirectFailure is one way a redirect to a target whose query holds
// queryMarker fails.
type redirectFailure struct {
	name string
	// tls starts the registry over https.
	tls bool
	// target is where the registry redirects a request for path, given the
	// registry's own URL.
	target func(t *testing.T, self, path string) string
	// is is the cause the error must still match, if any.
	is error
}

func redirectFailures() []redirectFailure {
	return []redirectFailure{
		{
			name: "refused downgrade", tls: true, is: ErrRedirectDowngrade,
			target: func(t *testing.T, _, path string) string {
				return closedURL(t) + path + "?X-Amz-Signature=" + queryMarker
			},
		},
		{
			name: "dial error",
			target: func(t *testing.T, _, path string) string {
				return closedURL(t) + path + "?X-Amz-Signature=" + queryMarker
			},
		},
		{
			name: "too many redirects",
			target: func(_ *testing.T, self, path string) string {
				return self + path + "?X-Amz-Signature=" + queryMarker
			},
		},
	}
}

// serveFailing starts a registry that answers the /v2/ ping and redirects
// every other request as f says.
func serveFailing(t *testing.T, f redirectFailure) *httptest.Server {
	t.Helper()
	var self string
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, req, f.target(t, self, req.URL.Path), http.StatusTemporaryRedirect)
	})
	var srv *httptest.Server
	if f.tls {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	self = srv.URL
	return srv
}

// registryHost is the host name a TLS registry is reached by: go-containerregistry
// names a loopback registry http whatever is asked, and httptest's certificate
// names example.com.
const registryHost = "example.com"

// reach returns the host a reference names srv by and a transport that
// reaches it: for a TLS registry, registryHost on srv's port, dialled to srv.
func reach(srv *httptest.Server, tls bool) (host, base string, rt http.RoundTripper) {
	addr := srv.Listener.Addr().String()
	if !tls {
		return addr, srv.URL, srv.Client().Transport
	}
	_, port, _ := net.SplitHostPort(addr)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	dial := tr.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	tr.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
		if a == net.JoinHostPort(registryHost, port) {
			a = addr
		}
		return dial(ctx, network, a)
	}
	host = net.JoinHostPort(registryHost, port)
	return host, "https://" + host, tr
}

// checkNoQuery fails when err is nil, names queryMarker in any rendering, no
// longer matches f.is, or holds no *url.Error whose URL kept its path.
func checkNoQuery(t *testing.T, f redirectFailure, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err)} {
		if strings.Contains(s, queryMarker) {
			t.Fatalf("error %s names the redirect target's query", s)
		}
	}
	if f.is != nil && !errors.Is(err, f.is) {
		t.Fatalf("err = %v, want it to match %v", err, f.is)
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("err = %v, want a *url.Error in its chain", err)
	}
	if strings.Contains(ue.URL, queryMarker) || !strings.Contains(ue.URL, "/v2/models/tiny/") {
		t.Fatalf("url.Error URL %q, want the path without the query", ue.URL)
	}
}

// TestRedirectErrorOmitsTargetQuery: a redirect to a URL whose query holds a
// marker fails three ways (an https registry's redirect to http, a dial to a
// closed port, a redirect loop), through Blob over Session's client and
// through a plain client over OriginSplit's transport, as the remote package
// stacks one. No error names the marker, and each still matches its cause.
func TestRedirectErrorOmitsTargetQuery(t *testing.T) {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	for _, f := range redirectFailures() {
		t.Run("Blob/"+f.name, func(t *testing.T) {
			host, _, rt := reach(serveFailing(t, f), f.tls)
			reg := &Registry{Transport: rt, PlainHTTP: !f.tls, newAuth: (&stampingAuth{}).newAuth}
			_, _, err := reg.Blob(context.Background(), host+"/models/tiny:v1", redirectCred, digest, 10, 0)
			checkNoQuery(t, f, err)
		})
		t.Run("OriginSplit/"+f.name, func(t *testing.T) {
			host, base, tr := reach(serveFailing(t, f), f.tls)
			reg := &Registry{Transport: tr, newAuth: (&stampingAuth{}).newAuth}
			var opts []name.Option
			if !f.tls {
				opts = append(opts, name.Insecure)
			}
			repo, err := name.NewRepository(host+"/models/tiny", opts...)
			if err != nil {
				t.Fatal(err)
			}
			rt, err := reg.OriginSplit(context.Background(), repo, redirectCred)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/v2/models/tiny/manifests/v1", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{Transport: rt}).Do(req)
			if err == nil {
				resp.Body.Close()
			}
			checkNoQuery(t, f, RedactURLError(err))
		})
	}
}

// TestReduceURL: only scheme, host and path survive a URL that parses; one
// that does not, or an opaque one, keeps its scheme and nothing past it when
// it holds an '@' anywhere, and is a fixed placeholder when it has no valid
// scheme. No result holds the row's secret, a '?' or a '#'.
func TestReduceURL(t *testing.T) {
	for _, tc := range []struct{ in, want, secret string }{
		{"https://blobs.example/a/b?X-Amz-Signature=s#frag", "https://blobs.example/a/b", "X-Amz-Signature"},
		{"https://u:p@blobs.example:8443/a%2Fb?q=1", "https://blobs.example:8443/a%2Fb", "u:p"},
		{"http://blobs.example", "http://blobs.example", "@"},
		{"https://blobs.example/%zz?sig=s", "https://blobs.example/%zz", "sig="},
		{"https://u:p@blobs.example/%zz?sig=s", "https://redacted", "u:p"},
		{"mailto:x?sig=s", "redacted", "sig="},
		{"https://u:p/w@blobs.example/%zz?sig=s", "https://redacted", "u:p"},
		{"https://u:p?ss@blobs.example/%zz?sig=s", "https://redacted", "u:p"},
		{"https://u:p?x@host/path", "https://redacted", "u:p"},
		{"https://blobs.example/a/%zz/b?sig=s#frag", "https://blobs.example/a/%zz/b", "sig="},
		{"//user:pw@host/%zz", "redacted", "user:pw"},
		{"user:pw@host/%zz", "redacted", "pw@"},
		{"https:user:pw@host/p", "redacted", "user:pw"},
		{"https://user:pa?ss/word@host/p%zz", "https://redacted", "user:pa"},
		{"foo?sig=S://h\x7f", "redacted", "sig=S"},
		{"https://blobs.example/%zz?email=a@b.com&sig=S", "https://redacted", "a@b.com"},
	} {
		got := reduceURL(tc.in)
		if got != tc.want {
			t.Errorf("reduceURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, tc.secret) || strings.ContainsAny(got, "?#") {
			t.Errorf("reduceURL(%q) = %q, holds %q, '?' or '#'", tc.in, got, tc.secret)
		}
	}
}

// TestRedactURLErrorKeepsCause: the rebuilt chain still matches its cause
// and keeps url.Error's Op; nil and other errors pass through unchanged.
func TestRedactURLErrorKeepsCause(t *testing.T) {
	cause := errors.New("cause")
	err := RedactURLError(bound(&url.Error{Op: "Get", URL: "https://h/p?sig=" + queryMarker, Err: cause}))
	if !errors.Is(err, cause) || strings.Contains(err.Error(), queryMarker) {
		t.Fatalf("err = %v, want the cause without the query", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) || ue.Op != "Get" || ue.URL != "https://h/p" {
		t.Fatalf("url.Error = %+v, want Op Get and URL https://h/p", ue)
	}
	if RedactURLError(nil) != nil {
		t.Fatal("RedactURLError(nil) is not nil")
	}
	if got := RedactURLError(cause); got != cause {
		t.Fatalf("RedactURLError(cause) = %v, want cause itself", got)
	}
}

// TestRedactURLErrorScrubsRenderedURL: a wrapper that has already rendered a
// URL into its text (go-containerregistry's refused token-server redirect
// does) loses the URL's query and fragment, and still reaches its cause.
func TestRedactURLErrorScrubsRenderedURL(t *testing.T) {
	cause := errors.New("cause")
	inner := fmt.Errorf("refusing token-server redirect to %q: %w", "https://t.example/token?sig="+queryMarker+"#f", cause)
	err := RedactURLError(&url.Error{Op: "Get", URL: "https://r.example/v2/", Err: inner})
	msg := err.Error()
	if strings.Contains(msg, queryMarker) || strings.Contains(msg, "#f") || !strings.Contains(msg, `"https://t.example/token"`) {
		t.Fatalf("err = %s, want the rendered URL without its query or fragment", msg)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want it to reach the cause", err)
	}
	if again := RedactURLError(err); again.Error() != msg {
		t.Fatalf("second pass = %s, want %s", again, msg)
	}
	for _, text := range []string{
		`json: "https://t.example/x?a=1\u0026X-Amz-Signature=` + queryMarker + `"`,
		`quoted: "https://t.example/x?a=\"` + queryMarker + `\"" after`,
		"single: 'https://t.example/x?a=1'" + queryMarker + "<b>",
	} {
		if got := RedactURLError(errors.New(text)).Error(); strings.Contains(got, queryMarker) || !strings.Contains(got, "https://t.example/x") {
			t.Errorf("scrub(%s) = %s, want the URL without any of its query", text, got)
		}
	}
	plain := errors.New("no URL here: https://h.example/p")
	if got := RedactURLError(plain); got != plain {
		t.Fatalf("RedactURLError(%v) = %v, want it unchanged", plain, got)
	}
}

// failingRoute is a round tripper whose every request fails with a
// *url.Error naming the request's URL, as a client inside a transport (the
// authenticating transport's token fetch) fails.
type failingRoute struct{}

func (failingRoute) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: errors.New("refused")}
}

// TestHostSplitRedactsRouteErrors: an error either route returns reaches
// hostSplit's caller without the request's query.
func TestHostSplitRedactsRouteErrors(t *testing.T) {
	h := &hostSplit{scheme: "https", host: canonicalHost("https", "registry.example"), auth: failingRoute{}, plain: failingRoute{}}
	for _, u := range []string{
		"https://registry.example/v2/x?sig=" + queryMarker,
		"https://blobs.example/x?sig=" + queryMarker,
	} {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.RoundTrip(req)
		if err == nil || strings.Contains(err.Error(), queryMarker) {
			t.Fatalf("%s: err = %v, want an error without the query", u, err)
		}
	}
}
