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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestLayerEntryNameLengthIsBounded pins the cap that bounds every walk of an
// entry name: a name over maxLayerEntryPathLen is refused before it reaches
// the filesystem, and a name exactly at it — with a climbing symlink at the
// bottom, so the ancestor check walks every component of the name —
// still applies.
//
// The name at the limit is 32 components of 127-128 bytes rather than 2048
// one-byte ones: each component stays under NAME_MAX, and the tree stays
// cheap enough to create and remove in a unit test.
func TestLayerEntryNameLengthIsBounded(t *testing.T) {
	atLimit := strings.Repeat(strings.Repeat("d", 127)+"/", 31) + strings.Repeat("l", 128)
	if len(atLimit) != maxLayerEntryPathLen {
		t.Fatalf("test name is %d bytes, want %d", len(atLimit), maxLayerEntryPathLen)
	}

	t.Run("over_the_limit_is_refused", func(t *testing.T) {
		over := atLimit + "x"
		if _, err := layerEntryPath(over); !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("layerEntryPath(%d bytes) error = %v, want ErrLayerMalformed", len(over), err)
		}
		_, _, err := applyInto(t, ApplyLimits{}, []tarSpec{{name: over, typ: tar.TypeSymlink, link: ".."}})
		if !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("Apply error = %v, want ErrLayerMalformed", err)
		}
	})

	t.Run("deep_name_at_the_limit_applies", func(t *testing.T) {
		parent := path.Dir(atLimit)
		tree, _, err := applyInto(t, ApplyLimits{}, []tarSpec{
			{name: parent, typ: tar.TypeDir, mode: 0o755},
			{name: atLimit, typ: tar.TypeSymlink, link: ".."},
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		root, err := os.OpenRoot(tree)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		got, err := root.Readlink(atLimit)
		if err != nil || got != ".." {
			t.Fatalf("Readlink = %q, %v; want \"..\"", got, err)
		}
	})
}

// TestLayerEntryDepthIsBounded pins the component-count cap: a name one
// component over maxLayerEntryDepth is refused before it reaches the
// filesystem, and a name exactly at it applies a climbing symlink whose every
// ancestor already exists — the case where the ancestor check walks the whole
// name, which is the most expensive entry the cap admits.
func TestLayerEntryDepthIsBounded(t *testing.T) {
	atLimit := strings.Repeat("d/", maxLayerEntryDepth-1) + "l"

	t.Run("one_over_the_limit_is_refused", func(t *testing.T) {
		over := "d/" + atLimit
		if _, err := layerEntryPath(over); !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("layerEntryPath(%d components) error = %v, want ErrLayerMalformed",
				maxLayerEntryDepth+1, err)
		}
		_, _, err := applyInto(t, ApplyLimits{}, []tarSpec{{name: over, typ: tar.TypeSymlink, link: ".."}})
		if !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("Apply error = %v, want ErrLayerMalformed", err)
		}
	})

	t.Run("at_the_limit_applies", func(t *testing.T) {
		if _, err := layerEntryPath(atLimit); err != nil {
			t.Fatalf("layerEntryPath(%d components): %v", maxLayerEntryDepth, err)
		}
		tree, _, err := applyInto(t, ApplyLimits{}, []tarSpec{
			{name: path.Dir(atLimit), typ: tar.TypeDir, mode: 0o755},
			{name: atLimit, typ: tar.TypeSymlink, link: ".."},
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		root, err := os.OpenRoot(tree)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if got, err := root.Readlink(atLimit); err != nil || got != ".." {
			t.Fatalf("Readlink = %q, %v; want \"..\"", got, err)
		}
	})
}

// TestClimbingLinksInADeepChainApplyQuickly pins the cost of the ancestor walk
// in symlinkParentIsReal: it must be linear per entry, not quadratic. The layer
// is 200 climbing symlinks at the bottom of one real chain at the
// maxLayerEntryDepth limit, so each link's walk inspects 127 ancestors. With
// each prefix resolved from the root the layer took about a minute; the bound
// is generous so that only a quadratic walk trips it.
func TestClimbingLinksInADeepChainApplyQuickly(t *testing.T) {
	const links = 200
	chain := strings.Repeat("d/", maxLayerEntryDepth-1)
	specs := make([]tarSpec, 0, links)
	for i := range links {
		specs = append(specs, tarSpec{name: fmt.Sprintf("%sl%d", chain, i), typ: tar.TypeSymlink, link: "../x"})
	}
	start := time.Now()
	tree, _, err := applyInto(t, ApplyLimits{}, specs)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Logf("%d climbing links in a %d-component chain applied in %v", links, maxLayerEntryDepth, elapsed)
	if bound := 20 * time.Second; elapsed > bound {
		t.Fatalf("Apply took %v, want under %v: the ancestor walk is not linear", elapsed, bound)
	}
	last := filepath.Join(tree, filepath.FromSlash(fmt.Sprintf("%sl%d", chain, links-1)))
	if fi, serr := os.Lstat(last); serr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat(last link) = %v, %v; want a symlink", fi, serr)
	}
}
