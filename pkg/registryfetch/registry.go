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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

var (
	// ErrInvalidReference reports a reference that does not parse.
	ErrInvalidReference = errors.New("registryfetch: reference does not parse")
	// ErrTransportRequired reports a Registry without a Transport.
	ErrTransportRequired = errors.New("registryfetch: transport is required")
	// ErrBlobRange reports a ranged answer that is not the bytes asked for
	// (a Content-Range other than offset to the end of the blob), or an
	// offset outside the blob's size.
	ErrBlobRange = errors.New("registryfetch: blob range is not the one asked for")
	// ErrBlobOverrun reports a blob body longer than the size it was opened
	// for; it is returned by the body's Read.
	ErrBlobOverrun = errors.New("registryfetch: blob body is longer than its size")
	// ErrRedirectDowngrade reports an https registry redirecting a request to
	// plain http; the Session client refuses to follow it.
	ErrRedirectDowngrade = errors.New("registryfetch: redirect from https to http")
)

// ReferenceError is the error for a reference that does not parse. It
// matches ErrInvalidReference under errors.Is; Err is the bounded parse error.
type ReferenceError struct{ Err error }

func (e *ReferenceError) Error() string { return ErrInvalidReference.Error() + ": " + e.Err.Error() }

// Is reports target == ErrInvalidReference.
func (e *ReferenceError) Is(target error) bool { return target == ErrInvalidReference }

// Unwrap returns the parse error.
func (e *ReferenceError) Unwrap() error { return e.Err }

// Credential is a registry login. A nil *Credential is anonymous.
type Credential struct {
	// Username and Password are basic-auth credentials.
	Username string
	// Password pairs with Username.
	Password string
	// Auth is the base64("username:password") form a docker config stores.
	Auth string
	// IdentityToken is an OAuth2 refresh/identity token.
	IdentityToken string
	// RegistryToken is a bearer token sent directly to the registry.
	RegistryToken string
}

// String redacts: it names the username and which secret fields are set,
// never their values, so %v, %+v and %s cannot leak a login.
func (c Credential) String() string {
	return fmt.Sprintf("Credential{Username:%q Password:%s Auth:%s IdentityToken:%s RegistryToken:%s}",
		c.Username, present(c.Password), present(c.Auth), present(c.IdentityToken), present(c.RegistryToken))
}

// GoString is the %#v form; it is String, redacted the same way.
func (c Credential) GoString() string { return c.String() }

// LogValue redacts for slog: the username and the set/unset state of each
// secret field.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("username", c.Username),
		slog.String("password", present(c.Password)),
		slog.String("auth", present(c.Auth)),
		slog.String("identity_token", present(c.IdentityToken)),
		slog.String("registry_token", present(c.RegistryToken)),
	)
}

func present(s string) string {
	if s == "" {
		return "unset"
	}
	return "set"
}

// Registry reaches one registry over Transport, which the caller scopes (the
// dial target, the trusted CA); PlainHTTP is that hop's scheme.
type Registry struct {
	Transport http.RoundTripper
	PlainHTTP bool

	// newAuth builds the authenticating transport for one repository; nil
	// means transport.NewWithContext. It is a field, not a package variable,
	// so a test sets it on its own Registry and mutates no shared state.
	newAuth func(ctx context.Context, reg name.Registry, auth authn.Authenticator, t http.RoundTripper, scopes []string) (http.RoundTripper, error)
}

func (g *Registry) parse(ref string) (name.Reference, error) {
	opts := []name.Option{name.StrictValidation}
	if g.PlainHTTP {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return nil, &ReferenceError{Err: bound(err)}
	}
	return r, nil
}

func authenticator(cred *Credential) authn.Authenticator {
	if cred == nil {
		return authn.Anonymous
	}
	return authn.FromConfig(authn.AuthConfig{
		Username: cred.Username, Password: cred.Password, Auth: cred.Auth,
		IdentityToken: cred.IdentityToken, RegistryToken: cred.RegistryToken,
	})
}

// Session parses ref and returns an authenticated client for its repository,
// scoped to pull, over the registry's transport.
//
// The client splits requests by origin: one whose scheme and host:port are
// the registry's goes through the authenticating transport, and any other
// goes straight to the registry's plain Transport. Real registries redirect
// blob GETs to object storage on another host; that host must get no
// credential, and its 401 challenges must never reach the token logic.
func (g *Registry) Session(ctx context.Context, ref string, cred *Credential) (name.Reference, *http.Client, error) {
	if g.Transport == nil {
		return nil, nil, ErrTransportRequired
	}
	r, err := g.parse(ref)
	if err != nil {
		return nil, nil, err
	}
	split, err := g.OriginSplit(ctx, r.Context(), cred)
	if err != nil {
		return nil, nil, err
	}
	return r, &http.Client{Transport: split, CheckRedirect: checkRedirect(g.PlainHTTP)}, nil
}

// OriginSplit returns the round tripper Session's client uses for repo: a
// request whose scheme and host:port are repo's registry's goes through an
// authenticating transport scoped to pull, and any other goes to the plain
// Transport. A response from another origin reaches the caller without its
// WWW-Authenticate challenges, so an authenticating layer a caller stacks on
// top (go-containerregistry's remote package always adds one) cannot turn a
// redirect target's 401 into a token request. Pass it to remote.WithTransport
// without remote.WithAuth.
func (g *Registry) OriginSplit(ctx context.Context, repo name.Repository, cred *Credential) (http.RoundTripper, error) {
	if g.Transport == nil {
		return nil, ErrTransportRequired
	}
	newAuth := g.newAuth
	if newAuth == nil {
		newAuth = transport.NewWithContext
	}
	rt, err := newAuth(ctx, repo.Registry, authenticator(cred), g.Transport,
		[]string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, fmt.Errorf("registry auth: %w", bound(err))
	}
	return &hostSplit{
		scheme: repo.Registry.Scheme(),
		host:   canonicalHost(repo.Registry.Scheme(), repo.RegistryStr()),
		auth:   rt,
		plain:  g.Transport,
	}, nil
}

// maxRedirects is net/http's own default redirect limit.
const maxRedirects = 10

// crossOriginHeaders are the headers net/http drops on a redirect to another
// domain, plus Proxy-Authorization; checkRedirect drops them on any change of
// origin.
var crossOriginHeaders = []string{"Authorization", "Proxy-Authorization", "Www-Authenticate", "Cookie", "Cookie2"}

// checkRedirect returns the Session client's CheckRedirect. net/http copies a
// caller's headers to a redirect target whose host name matches, whatever its
// port or scheme; the returned func removes the credential headers whenever
// the target's scheme or host:port differs from the first request's, and
// keeps net/http's ten-redirect limit. An https to http redirect is refused
// unless the registry is plain http itself: the bytes on such a hop could be
// replaced on the path, even though no credential goes with them.
func checkRedirect(plainHTTP bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		first := via[0].URL
		fs, ts := strings.ToLower(first.Scheme), strings.ToLower(req.URL.Scheme)
		if fs == "https" && ts == "http" && !plainHTTP {
			// Scheme and host only: a redirect target's query can carry a
			// presigned signature.
			return fmt.Errorf("%w: to %s://%s", ErrRedirectDowngrade, req.URL.Scheme, req.URL.Host)
		}
		if fs != ts || canonicalHost(fs, first.Host) != canonicalHost(ts, req.URL.Host) {
			for _, h := range crossOriginHeaders {
				req.Header.Del(h)
			}
		}
		return nil
	}
}

// hostSplit routes a request to auth when its scheme and host:port are the
// registry's, and to plain otherwise, so the authenticating transport never
// sees a request for another origin. A plain response loses its
// WWW-Authenticate header, so no layer above can act on its challenge. A
// plain http request for an https registry is refused with
// ErrRedirectDowngrade: it can only be a redirect, and a client stacked on
// top (go-containerregistry's remote package builds its own) has no
// checkRedirect of Session's to refuse it first.
type hostSplit struct {
	scheme, host string
	auth, plain  http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (h *hostSplit) RoundTrip(req *http.Request) (*http.Response, error) {
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme == h.scheme && canonicalHost(scheme, req.URL.Host) == h.host {
		return h.auth.RoundTrip(req)
	}
	if h.scheme == "https" && scheme == "http" {
		// Scheme and host only, as checkRedirect: the query can carry a
		// presigned signature.
		if req.Body != nil {
			_ = req.Body.Close() // a RoundTripper closes the body, even on error
		}
		return nil, fmt.Errorf("%w: to %s://%s", ErrRedirectDowngrade, req.URL.Scheme, req.URL.Host)
	}
	res, err := h.plain.RoundTrip(req)
	if res != nil {
		res.Header.Del("WWW-Authenticate")
	}
	return res, err
}

// canonicalHost is host lower-cased with the scheme's default port filled in
// when it names none.
func canonicalHost(scheme, host string) string {
	u := url.URL{Host: host}
	name, port := strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return net.JoinHostPort(name, port)
}

// Blob opens the size-byte blob digest in ref's repository from offset, with
// a Range request when offset > 0. A 200 restarts at 0; a 206 is accepted only
// with exactly one Content-Range of "bytes <offset>-<size-1>/<size>" (see
// parseContentRange); a 416 is retried once without a Range, and that retry
// must be a 200 or a 206 of the whole object from 0. start is the offset the
// body begins at.
//
// The body yields at most size-start bytes: a Read that would go past them
// returns the bytes up to the size and an error matching ErrBlobOverrun, never
// a silent cut. Each request sends Accept-Encoding: identity, so the bytes
// counted are the stored blob's, not a transfer coding's; the caller's
// Transport is not modified.
func (g *Registry) Blob(ctx context.Context, ref string, cred *Credential, digest string, size, offset int64) (body io.ReadCloser, start int64, err error) {
	if size < 0 || offset < 0 || offset > size {
		return nil, 0, fmt.Errorf("blob %s: offset %d of size %d: %w", quoteBounded(digest, 128), offset, size, ErrBlobRange)
	}
	r, client, err := g.Session(ctx, ref, cred)
	if err != nil {
		return nil, 0, err
	}
	repo := r.Context()
	blobURL := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", repo.Registry.Scheme(), repo.RegistryStr(), repo.RepositoryStr(), digest)
	get := func(from int64) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
		if err != nil {
			return nil, err
		}
		if from > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-")
		}
		req.Header.Set("Accept-Encoding", "identity")
		return client.Do(req)
	}
	resp, err := get(offset)
	if err != nil {
		return nil, 0, bound(err)
	}
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && offset > 0 {
		resp.Body.Close()
		offset = 0
		if resp, err = get(0); err != nil {
			return nil, 0, bound(err)
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return ceiling(resp.Body, digest, size, 0), 0, nil
	case http.StatusPartialContent:
		crs := resp.Header.Values("Content-Range")
		var cr string
		if len(crs) == 1 {
			cr = crs[0]
		}
		first, last, total, ok := parseContentRange(cr)
		if !ok || first != offset || last != size-1 || total != size {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("blob %s: Content-Range %s is not bytes %d-%d/%d: %w",
				digest, quoteBounded(strings.Join(crs, ", "), 128), offset, size-1, size, ErrBlobRange)
		}
		return ceiling(resp.Body, digest, size, first), first, nil
	}
	defer resp.Body.Close()
	if err := transport.CheckError(resp, http.StatusOK, http.StatusPartialContent); err != nil {
		return nil, 0, fmt.Errorf("blob %s: %w", digest, bound(err))
	}
	return nil, 0, fmt.Errorf("blob %s: status %d", digest, resp.StatusCode)
}

// ceilingBody is a blob body that may yield left more bytes; one more is
// ErrBlobOverrun from Read.
type ceilingBody struct {
	rc     io.ReadCloser
	digest string
	size   int64
	left   int64
	err    error // sticky overrun
}

func ceiling(rc io.ReadCloser, digest string, size, start int64) *ceilingBody {
	return &ceilingBody{rc: rc, digest: digest, size: size, left: size - start}
}

// Read reads at most left+1 bytes, so a body of exactly left bytes ends with
// the source's own EOF and one byte past it is seen as an overrun.
func (c *ceilingBody) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.left < int64(len(p)) {
		p = p[:c.left+1]
	}
	n, err := c.rc.Read(p)
	if int64(n) > c.left {
		n = int(c.left)
		c.left = 0
		c.err = fmt.Errorf("blob %s: body longer than %d bytes: %w", c.digest, c.size, ErrBlobOverrun)
		return n, c.err
	}
	c.left -= int64(n)
	return n, err
}

// Close closes the response body.
func (c *ceilingBody) Close() error { return c.rc.Close() }

// parseContentRange parses exactly "bytes <first>-<last>/<total>": the
// lowercase unit, one space, and three ASCII decimals with no sign and no
// leading zero (a lone 0 aside), each within int64, with first <= last <
// total as RFC 9110 section 14.4 requires of a satisfied range. Anything else
// (an unsatisfied "*", a missing part, trailing text, a disordered range) is
// refused. Blob still compares the numbers with what it asked for.
func parseContentRange(v string) (first, last, total int64, ok bool) {
	rest, ok := strings.CutPrefix(v, "bytes ")
	if !ok {
		return 0, 0, 0, false
	}
	a, rest, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, 0, 0, false
	}
	b, c, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, 0, 0, false
	}
	var oks [3]bool
	first, oks[0] = decimal(a)
	last, oks[1] = decimal(b)
	total, oks[2] = decimal(c)
	if !oks[0] || !oks[1] || !oks[2] || first > last || last >= total {
		return 0, 0, 0, false
	}
	return first, last, total, true
}

// decimal parses a canonical non-negative ASCII decimal that fits an int64.
func decimal(s string) (int64, bool) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// maxForeignErrBytes bounds foreign (registry, transport) error text carried
// in an error this package returns.
const maxForeignErrBytes = 512

// boundedError renders a foreign error bounded and ASCII-quoted, keeping the
// cause visible to errors.Is.
type boundedError struct{ err error }

func (e *boundedError) Error() string { return quoteBounded(e.err.Error(), maxForeignErrBytes) }
func (e *boundedError) Unwrap() error { return e.err }

func bound(err error) error {
	if err == nil {
		return nil
	}
	return &boundedError{err: err}
}

// quoteBounded ASCII-quotes at most max bytes of s, marking a cut with "...".
func quoteBounded(s string, max int) string {
	if len(s) > max {
		return strconv.QuoteToASCII(s[:max]) + "..."
	}
	return strconv.QuoteToASCII(s)
}
