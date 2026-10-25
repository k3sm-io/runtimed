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
	"strings"
	"testing"
)

// TestRepoDigest pins the digested reference a container's image_id is built
// from: containerd's normalization of the repository (Docker Hub for a name
// with no registry, a registry port never read as a tag), the pinned digest
// over the resolved one, and refusal of a malformed digest.
func TestRepoDigest(t *testing.T) {
	resolved := "sha256:" + strings.Repeat("b", 64)
	pinned := "sha256:" + strings.Repeat("4", 64)
	cases := []struct {
		name, ref, resolved, want string
		ok                        bool
	}{
		{"registry with a port keeps its host", "registry-k3sm:6450/ois/app:v1", resolved, "registry-k3sm:6450/ois/app@" + resolved, true},
		{"untagged registry reference", "registry-k3sm:6450/ois/app", resolved, "registry-k3sm:6450/ois/app@" + resolved, true},
		{"dotted registry keeps its host", "ghcr.io/k3sm-io/app:v1", resolved, "ghcr.io/k3sm-io/app@" + resolved, true},
		{"bare official image is docker.io/library", "alpine:3.20", resolved, "docker.io/library/alpine@" + resolved, true},
		{"bare untagged official image", "nginx", resolved, "docker.io/library/nginx@" + resolved, true},
		{"user repository is docker.io/<user>", "user/app", resolved, "docker.io/user/app@" + resolved, true},
		{"explicit docker.io is spelled docker.io", "docker.io/library/nginx:1.27", resolved, "docker.io/library/nginx@" + resolved, true},
		{"index.docker.io is spelled docker.io", "index.docker.io/user/app:v1", resolved, "docker.io/user/app@" + resolved, true},
		{"localhost with a port keeps its host", "localhost:5000/app:v1", resolved, "localhost:5000/app@" + resolved, true},
		{"pinned digest wins over the resolved one", "registry-k3sm:6450/ois/app@" + pinned, resolved, "registry-k3sm:6450/ois/app@" + pinned, true},
		{"tag and digest keep the pin and drop the tag", "example.com/ns/app:v1@" + pinned, resolved, "example.com/ns/app@" + pinned, true},
		{"bare pinned reference is normalized", "alpine@" + pinned, resolved, "docker.io/library/alpine@" + pinned, true},
		{"empty resolved digest", "example.com/app:v1", "", "", false},
		{"digest without an algorithm", "example.com/app:v1", strings.Repeat("b", 64), "", false},
		{"digest with non-hex body", "example.com/app:v1", "sha256:" + strings.Repeat("z", 64), "", false},
		{"digest of the wrong length", "example.com/app:v1", "sha256:abcd", "", false},
		{"reference that does not parse", "Example.com/UPPER/app:v1", resolved, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := RepoDigest(tc.ref, tc.resolved)
			if got != tc.want || ok != tc.ok {
				t.Errorf("RepoDigest(%q, %q) = (%q, %v), want (%q, %v)", tc.ref, tc.resolved, got, ok, tc.want, tc.ok)
			}
		})
	}
}
