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
	"net/http"
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

// Registry reaches one registry over Transport, which the caller scopes (the
// dial target, the trusted CA); PlainHTTP is that hop's scheme.
type Registry struct {
	Transport http.RoundTripper
	PlainHTTP bool
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
func (g *Registry) Session(ctx context.Context, ref string, cred *Credential) (name.Reference, *http.Client, error) {
	if g.Transport == nil {
		return nil, nil, ErrTransportRequired
	}
	r, err := g.parse(ref)
	if err != nil {
		return nil, nil, err
	}
	repo := r.Context()
	rt, err := transport.NewWithContext(ctx, repo.Registry, authenticator(cred), g.Transport,
		[]string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, nil, fmt.Errorf("registry auth: %w", bound(err))
	}
	return r, &http.Client{Transport: rt}, nil
}

// Blob opens the size-byte blob digest in ref's repository from offset, with
// a Range request when offset > 0. A 200 restarts at 0; a 206 is accepted only
// with exactly one Content-Range of "bytes <offset>-<size-1>/<size>" (see
// parseContentRange); a 416 is retried once without a Range, and that retry
// must be a 200 or a 206 of the whole object from 0. start is the offset the
// body begins at.
func (g *Registry) Blob(ctx context.Context, ref string, cred *Credential, digest string, size, offset int64) (body io.ReadCloser, start int64, err error) {
	if size < 0 || offset < 0 || offset > size {
		return nil, 0, fmt.Errorf("blob %s: offset %d of size %d: %w", quoteBounded(digest, 128), offset, size, ErrBlobRange)
	}
	r, client, err := g.Session(ctx, ref, cred)
	if err != nil {
		return nil, 0, err
	}
	repo := r.Context()
	url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", repo.Registry.Scheme(), repo.RegistryStr(), repo.RepositoryStr(), digest)
	get := func(from int64) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if from > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-")
		}
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
		return resp.Body, 0, nil
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
		return resp.Body, first, nil
	}
	defer resp.Body.Close()
	if err := transport.CheckError(resp, http.StatusOK, http.StatusPartialContent); err != nil {
		return nil, 0, fmt.Errorf("blob %s: %w", digest, bound(err))
	}
	return nil, 0, fmt.Errorf("blob %s: status %d", digest, resp.StatusCode)
}

// parseContentRange parses exactly "bytes <first>-<last>/<total>": the
// lowercase unit, one space, and three ASCII decimals with no sign and no
// leading zero (a lone 0 aside), each within int64. Anything else (an
// unsatisfied "*", a missing part, trailing text) is refused. It checks the
// grammar only; Blob compares the numbers with what it asked for.
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
	if !oks[0] || !oks[1] || !oks[2] {
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
