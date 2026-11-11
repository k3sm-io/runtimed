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
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestSymlinkChainCannotEscapeTree is the gate for a symlink whose target is
// contained as a STRING but not on the tree: the kernel follows a link before
// it applies the ".." after it, so two links that each pass a string check can
// compose into one that resolves above the tree.
//
// Both chains are driven through the real layer-apply path under the native
// dialect (no chroot, so an escape there reaches the host), and each must be
// refused with ErrLayerEscapes before the second link exists on disk.
func TestSymlinkChainCannotEscapeTree(t *testing.T) {
	cases := []struct {
		name string
		// specs is one layer. Its first entry is a link that is genuinely
		// contained (a/b/l resolves to the tree root); the last is the one that
		// escapes through it.
		specs []tarSpec
		// escaper is the tree-relative name of the escaping link, as spelled
		// in the archive.
		escaper string
	}{
		{
			// x/e -> ../a/b/l/../.. joins to "a" as a string, but on the tree
			// a/b/l is the root, so the two trailing ".." climb two levels
			// above it.
			name: "dotdot_after_a_link_in_the_target",
			specs: []tarSpec{
				{name: "a/b/l", typ: tar.TypeSymlink, link: "../.."},
				{name: "x/e", typ: tar.TypeSymlink, link: "../a/b/l/../.."},
			},
			escaper: "x/e",
		},
		{
			// a/b/l/x/y -> ../../../.. joins to "." as a string, but its parent
			// is created THROUGH a/b/l, so the link really lives at x/y and
			// the four ".." climb three levels above the tree.
			name: "link_whose_parent_crosses_a_link",
			specs: []tarSpec{
				{name: "a/b/l", typ: tar.TypeSymlink, link: "../.."},
				{name: "a/b/l/x/y", typ: tar.TypeSymlink, link: "../../../.."},
			},
			escaper: "x/y",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, _, err := applyInto(t, ApplyLimits{}, tc.specs)
			if !errors.Is(err, ErrLayerEscapes) {
				t.Fatalf("Apply error = %v, want ErrLayerEscapes", err)
			}
			if fi, serr := os.Lstat(filepath.Join(tree, filepath.FromSlash(tc.escaper))); serr == nil {
				t.Fatalf("apply left the escaping link %s in the tree (mode %v)", tc.escaper, fi.Mode())
			}
		})
	}
}
