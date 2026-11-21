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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestBoundErrOmitsURLQuery: a remote fetch's *url.Error, bounded and then
// wrapped as remoteFetch wraps it, names the URL's path but not its query,
// and errors.Is and errors.As still reach the cause.
func TestBoundErrOmitsURLQuery(t *testing.T) {
	cause := errors.New("stopped after 10 redirects")
	err := fmt.Errorf("pull %q: %w", "example.com/x:v1", boundErr(&url.Error{
		Op: "Get", URL: "https://blobs.example/v2/x/manifests/v1?X-Amz-Signature=sig-marker-77", Err: cause,
	}))
	if msg := err.Error(); strings.Contains(msg, "sig-marker-77") || !strings.Contains(msg, "/v2/x/manifests/v1") {
		t.Fatalf("err = %s, want the path without the query", msg)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want it to reach the cause", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) || strings.Contains(ue.URL, "sig-marker-77") {
		t.Fatalf("url.Error = %+v, want its URL without the query", ue)
	}
}
