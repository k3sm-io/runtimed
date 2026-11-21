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

package artifact

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestBoundOmitsURLQuery: a manifest fetch's *url.Error, bounded and wrapped
// as Manifest wraps it, names the URL's path but not its query, and still
// reaches the cause.
func TestBoundOmitsURLQuery(t *testing.T) {
	cause := errors.New("stopped after 10 redirects")
	err := fmt.Errorf("manifest: %w", bound(&url.Error{
		Op: "Get", URL: "https://blobs.example/v2/x/manifests/v1?X-Amz-Signature=sig-marker-91", Err: cause,
	}))
	if msg := err.Error(); strings.Contains(msg, "sig-marker-91") || !strings.Contains(msg, "/v2/x/manifests/v1") {
		t.Fatalf("err = %s, want the path without the query", msg)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want it to reach the cause", err)
	}
}
