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
	"strings"
	"testing"
)

// TestPathCollisionMessage pins the client text of a collision: the pair and
// the remedy, never the probe error, and found through any wrapping while the
// full Error stays as it was.
func TestPathCollisionMessage(t *testing.T) {
	const probe = "/var/k3sm/PROBE-DETAIL: boom"
	const remedy = "sudo k3sm install --data-volume"
	for _, tc := range []struct {
		name     string
		err      error
		want     []string
		fullHas  string
		withheld string
	}{
		{"case", collisionError("usr/Foo", "usr/foo", nil), []string{`"usr/Foo"`, `"usr/foo"`, "differ only by case", remedy}, "", ""},
		{"case unmeasured", collisionError("usr/Foo", "usr/foo", errors.New(probe)),
			[]string{`"usr/Foo"`, `"usr/foo"`, "could not be measured", remedy}, "PROBE-DETAIL", "PROBE-DETAIL"},
		{"normalization", collisionError("café", "café", nil), []string{"Unicode normalization", "rebuild the image"}, "", ""},
	} {
		wrapped := fmt.Errorf("materialize into /var/k3sm/pods/HOST-DETAIL/rootfs: %w", tc.err)
		msg, ok := PathCollisionMessage(wrapped)
		if !ok {
			t.Fatalf("%s: no collision found in %v", tc.name, wrapped)
		}
		if !errors.Is(wrapped, ErrPathCollision) {
			t.Errorf("%s: ErrPathCollision is unreachable", tc.name)
		}
		if !strings.HasPrefix(msg, ErrPathCollision.Error()+": ") {
			t.Errorf("%s: message %q does not start with the sentinel", tc.name, msg)
		}
		for _, w := range tc.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: message %q lacks %q", tc.name, msg, w)
			}
		}
		if strings.Contains(msg, "HOST-DETAIL") || (tc.withheld != "" && strings.Contains(msg, tc.withheld)) {
			t.Errorf("%s: message %q carries host detail", tc.name, msg)
		}
		if tc.fullHas != "" && !strings.Contains(tc.err.Error(), tc.fullHas) {
			t.Errorf("%s: full error %q lost %q", tc.name, tc.err, tc.fullHas)
		}
	}
	if _, ok := PathCollisionMessage(errors.New("other")); ok {
		t.Error("a non-collision error has a collision message")
	}
}
