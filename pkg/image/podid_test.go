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
	"strings"
	"testing"
)

// TestPodRootfsRejectsTraversal is B136's named gate.
//
// It pins the REJECTION half of the contract: a pod id that is not a legal path
// component yields no PodID, and therefore no path — the derivation is
// unreachable rather than checked-after-the-fact. The artifact half (that a
// rejected id creates nothing on disk) is pinned by
// pkg/runtime.TestCreatePodRejectsTraversingPodID, because Cache.PodRootfs is a
// pure string function that touches no filesystem: asserting "no artifact" here
// would be trivially true even against the unfixed code, which is precisely the
// vacuity the blob-store review warned about.
func TestPodRootfsRejectsTraversal(t *testing.T) {
	c, outside := deepCache(t)
	before := treeOf(t, outside)

	reject := []struct{ name, id string }{
		{"parent traversal", ".."},
		{"current dir", "."},
		{"empty", ""},
		// The case that reaches the control-plane state tree: it stays inside the
		// daemon root, so a bare prefix check on the root admits it.
		{"escape to a sibling of the pods tree", "../server"},
		// The case that escapes the root entirely to a directory whose name merely
		// starts with the root's — the classic prefix-check bypass.
		{"escape to a same-prefix sibling root", "../../k3sm-evil/x"},
		{"separator", "a/b"},
		{"absolute", "/abs"},
		{"trailing separator", "pod-1/"},
		{"dot-slash prefix", "./pod-1"},
		{"leading dot", ".hidden"},
		{"nul byte", "pod\x00evil"},
		{"space", "pod 1"},
		{"tilde", "~"},
		// Aliasing, not traversal: the default APFS volume is case-insensitive
		// while the daemon's pod registry is keyed by the raw string, so admitting
		// case would let two live pods share one on-disk directory.
		{"uppercase", "POD-1"},
		{"mixed case", "Pod-A"},
		{"non-ascii", "pöd-1"},
		{"too long", strings.Repeat("a", 129)},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			id, err := ParsePodID(tc.id)
			if !errors.Is(err, ErrInvalidPodID) {
				t.Fatalf("ParsePodID(%q) error = %v, want ErrInvalidPodID", tc.id, err)
			}
			if id.String() != "" {
				t.Errorf("ParsePodID(%q) returned a usable id %q; a rejected id must yield no path material", tc.id, id.String())
			}
		})
	}

	// The whole tree containing the cache root must be byte-identical: no
	// rejected id may have created, moved or removed anything anywhere.
	if got := treeOf(t, outside); !equalTrees(before, got) {
		t.Errorf("rejected ids mutated the filesystem\nbefore: %v\nafter:  %v", before, got)
	}

	// positive CONTROL. Without it this table cannot distinguish "the class is
	// correct" from "the class rejects everything" — and a class that rejected a
	// real pod id would break every pod on the node, a fail-closed regression as
	// bad operationally as the hole itself.
	accept := []struct{ name, id string }{
		{"apiserver uuid", "5f8a1c2d-3e4b-4a6c-8d9e-0f1a2b3c4d5e"},
		{"short test id", "p"},
		{"hyphenated", "pod-clbo-mem"},
		{"trailing hyphen", "pod-"},
		{"underscore", "pod_1"},
		{"interior dot", "pod.1"},
		{"digits", "12345"},
		{"max length", strings.Repeat("a", 128)},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			id, err := ParsePodID(tc.id)
			if err != nil {
				t.Fatalf("ParsePodID(%q) = %v, want accepted", tc.id, err)
			}
			if id.String() != tc.id {
				t.Errorf("ParsePodID(%q).String() = %q, want the input unchanged", tc.id, id.String())
			}
			// An accepted id must produce a path strictly inside the cache root.
			got := c.PodRootfs(id)
			wantPrefix := c.Root() + "/pods/"
			if !strings.HasPrefix(got, wantPrefix) {
				t.Errorf("PodRootfs(%q) = %q, want it under %q", tc.id, got, wantPrefix)
			}
			if dir := c.PodDir(id); !strings.HasPrefix(dir, wantPrefix) {
				t.Errorf("PodDir(%q) = %q, want it under %q", tc.id, dir, wantPrefix)
			}
		})
	}
}
