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
	"net/url"
	"strings"
)

// RedactURLError returns err with each *url.Error it holds rebuilt so that
// the error's URL keeps only its scheme, host and path: no user info, query
// or fragment. net/http wraps every failure of a request, a refused or
// failed redirect included, in a *url.Error naming the full URL of the
// request that failed, and a redirect target's query can carry a presigned
// signature for object storage.
//
// It rebuilds a *url.Error at the top of err, or under this package's
// bounded wrapper, and the *url.Error inside that, so errors.Is and
// errors.As still reach the cause. Any other error is returned as it is: a
// wrapper that has already rendered a *url.Error into its text cannot be
// rebuilt, so a caller passes an error through here before it wraps it.
//
// Every error Blob returns has been through it, and so has every error from
// the round tripper OriginSplit returns. A caller of Session's client,
// or of a client stacked on OriginSplit's transport, passes the error from
// Do through it: the *url.Error is built by that client, above this package.
func RedactURLError(err error) error {
	switch e := err.(type) {
	case *url.Error:
		return &url.Error{Op: e.Op, URL: reduceURL(e.URL), Err: RedactURLError(e.Err)}
	case *boundedError:
		return &boundedError{err: RedactURLError(e.err)}
	}
	return err
}

// reduceURL is raw with only its scheme, host and path. A raw URL that does
// not parse, or an opaque one, is cut at its first '?' or '#' instead, and
// loses any user info before its host.
func reduceURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Opaque == "" {
		r := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
		return r.String()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		if at := strings.LastIndex(strings.SplitN(rest, "/", 2)[0], "@"); at >= 0 {
			raw = scheme + "://" + rest[at+1:]
		}
	}
	return raw
}
