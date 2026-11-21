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
	"regexp"
	"strings"
)

// RedactURLError returns err with every URL it names reduced to its scheme,
// host and path: no user info, query or fragment. net/http wraps every
// failure of a request, a refused or failed redirect included, in a
// *url.Error naming the full URL of the request that failed, and a redirect
// target's query can carry a presigned signature for object storage.
//
// A *url.Error at the top of err, or under this package's bounded wrapper,
// is rebuilt with its URL reduced, and so is the *url.Error inside that. Any
// other error whose text names a URL with a query or fragment (a wrapper
// that has already rendered one into its message) is wrapped so that its
// text loses them. errors.Is and errors.As still reach the cause; a
// *url.Error held under such a wrapper keeps its own URL field, so a caller
// passes an error through here before it wraps it.
//
// Every error Blob returns has been through it, and so has every error from
// the round tripper OriginSplit returns. A caller of Session's client, or of
// a client stacked on OriginSplit's transport, passes the error from Do
// through it: the *url.Error is built by that client, above this package.
func RedactURLError(err error) error {
	switch e := err.(type) {
	case nil:
		return nil
	case *url.Error:
		return &url.Error{Op: e.Op, URL: reduceURL(e.URL), Err: RedactURLError(e.Err)}
	case *boundedError:
		return &boundedError{err: RedactURLError(e.err)}
	case *scrubbedError:
		return e
	}
	msg := err.Error()
	if scrubbed := scrubURLs(msg); scrubbed != msg {
		return &scrubbedError{msg: scrubbed, err: err}
	}
	return err
}

// scrubbedError is an error whose text named a URL's query or fragment,
// rendered without them.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// urlInText matches an http or https URL in error text up to a quote, a
// space or a control byte, so a %q-quoted URL ends at its closing quote.
var urlInText = regexp.MustCompile(`(?i)https?://[^\s"'<>\\]+`)

// scrubURLs reduces every http or https URL in s with reduceURL.
func scrubURLs(s string) string {
	return urlInText.ReplaceAllStringFunc(s, reduceURL)
}

// reduceURL is raw with only its scheme, host and path. A raw URL that does
// not parse, or an opaque one, is cut at its first '?' or '#' instead, and
// loses everything up to the last '@' after its scheme, so no user info
// survives (a path holding '@' loses more than it must).
func reduceURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Opaque == "" {
		r := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
		return r.String()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			raw = scheme + "://" + rest[at+1:]
		}
	}
	return raw
}
