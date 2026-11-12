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
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// outsideSentinel creates a directory OUTSIDE any tree, holding the files
// "keep" and "sub/keep", and returns its absolute path. assertSentinelIntact
// fails if anything under it changed.
func sentinelOutside(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"keep", "sub/keep"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("host"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func assertSentinelIntact(t *testing.T, dir string) {
	t.Helper()
	var got []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk outside dir: %v", err)
	}
	want := []string{".", "keep", "sub", "sub/keep"}
	if len(got) != len(want) {
		t.Fatalf("outside dir now holds %q, want %q: the apply reached outside the tree", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("outside dir now holds %q, want %q: the apply reached outside the tree", got, want)
		}
	}
	for _, p := range []string{"keep", "sub/keep"} {
		if b, err := os.ReadFile(filepath.Join(dir, p)); err != nil || string(b) != "host" {
			t.Fatalf("outside file %s = %q (%v), want untouched", p, b, err)
		}
	}
}

// assertTreeLinksContained resolves every symlink in tree with the fuzz
// target's independent resolver and fails on any that resolves above the root.
func assertTreeLinksContained(t *testing.T, tree string, linux bool) {
	t.Helper()
	err := filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		rel, err := filepath.Rel(tree, p)
		if err != nil {
			return err
		}
		if why := resolveFromTree(tree, filepath.ToSlash(rel), linux); why != "" {
			t.Errorf("tree holds %s, which %s", rel, why)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk tree: %v", err)
	}
}

// applyLayers applies each layer in order into a fresh tree and returns the
// tree and the per-layer apply errors (nil for a layer that applied).
func applyLayers(t *testing.T, policy UnpackPolicy, layers ...[]tarSpec) (string, []error) {
	t.Helper()
	tree := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tree)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	a, err := NewLayerApplier(root, policy, ApplyLimits{})
	if err != nil {
		t.Fatal(err)
	}
	errs := make([]error, len(layers))
	for i, specs := range layers {
		errs[i] = a.Apply(context.Background(), bytes.NewReader(buildTar(t, specs)))
	}
	return tree, errs
}

func bothDialects(t *testing.T, fn func(t *testing.T, policy UnpackPolicy, linux bool)) {
	t.Run("native", func(t *testing.T) { fn(t, NativeUnpackPolicy(), false) })
	t.Run("linux", func(t *testing.T) { fn(t, LinuxUnpackPolicy(), true) })
}

// TestApplyLayerDirReplacedBySymlink pins the assumption the symlink
// containment argument rests on: a later layer that REPLACES a populated
// directory with a symlink leaves none of the directory's children behind, a
// climbing link written under the replaced name afterwards is refused (its
// parent is now a link), and nothing outside the tree is touched.
func TestApplyLayerDirReplacedBySymlink(t *testing.T) {
	bothDialects(t, func(t *testing.T, policy UnpackPolicy, linux bool) {
		outside := sentinelOutside(t)
		tree, errs := applyLayers(t, policy,
			[]tarSpec{
				{name: "real", typ: tar.TypeDir, mode: 0o755},
				{name: "d", typ: tar.TypeDir, mode: 0o755},
				{name: "d/child", mode: 0o644, data: "lower"},
				{name: "d/sub", typ: tar.TypeDir, mode: 0o755},
				{name: "d/sub/x", mode: 0o644, data: "lower"},
				{name: "d/sub/l", typ: tar.TypeSymlink, link: "../child"},
			},
			[]tarSpec{{name: "d", typ: tar.TypeSymlink, link: "real"}},
			// Written after the replacement, through the new link: a climbing
			// link whose parent is the replaced name must be refused.
			[]tarSpec{{name: "d/esc", typ: tar.TypeSymlink, link: "../.."}},
			// A non-climbing link and a file through the link are still fine.
			[]tarSpec{
				{name: "d/f", mode: 0o644, data: "upper"},
				{name: "d/ok", typ: tar.TypeSymlink, link: "f"},
			},
		)
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("lower/replacing layers: %v / %v", errs[0], errs[1])
		}
		if !errors.Is(errs[2], ErrLayerEscapes) {
			t.Fatalf("climbing link under the replaced name: err = %v, want ErrLayerEscapes", errs[2])
		}
		if errs[3] != nil {
			t.Fatalf("non-climbing entries through the link: %v", errs[3])
		}
		fi, err := os.Lstat(filepath.Join(tree, "d"))
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("d is %v (%v), want the replacing symlink", fi, err)
		}
		for _, gone := range []string{"real/child", "real/sub", "real/esc"} {
			if _, err := os.Lstat(filepath.Join(tree, gone)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s survived (err %v): the replaced directory's children must be gone", gone, err)
			}
		}
		// Nothing named after a lower child exists anywhere in the tree.
		_ = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err == nil && (d.Name() == "child" || d.Name() == "x" || d.Name() == "esc") {
				t.Errorf("tree still holds %s", p)
			}
			return nil
		})
		if b, err := os.ReadFile(filepath.Join(tree, "real/f")); err != nil || string(b) != "upper" {
			t.Errorf("real/f = %q (%v), want the file written through the link", b, err)
		}
		assertTreeLinksContained(t, tree, linux)
		assertSentinelIntact(t, outside)
	})
}

// TestApplyLayerSymlinkReplacedByDir is the reverse: a later layer that
// replaces a symlink with a directory replaces the LINK, not its target. The
// target's contents survive, new children land in the new directory, and a
// climbing link under the new (real) directory is judged by the string check.
func TestApplyLayerSymlinkReplacedByDir(t *testing.T) {
	bothDialects(t, func(t *testing.T, policy UnpackPolicy, linux bool) {
		outside := sentinelOutside(t)
		tree, errs := applyLayers(t, policy,
			[]tarSpec{
				{name: "real", typ: tar.TypeDir, mode: 0o755},
				{name: "real/child", mode: 0o644, data: "lower"},
				{name: "d", typ: tar.TypeSymlink, link: "real"},
			},
			[]tarSpec{
				{name: "d", typ: tar.TypeDir, mode: 0o755},
				{name: "d/n", mode: 0o644, data: "upper"},
				{name: "d/l", typ: tar.TypeSymlink, link: "../real/child"},
			},
			[]tarSpec{{name: "d/esc", typ: tar.TypeSymlink, link: "../.."}},
		)
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("layers: %v / %v", errs[0], errs[1])
		}
		if !errors.Is(errs[2], ErrLayerEscapes) {
			t.Fatalf("d/esc -> ../..: err = %v, want ErrLayerEscapes", errs[2])
		}
		fi, err := os.Lstat(filepath.Join(tree, "d"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("d is %v (%v), want a real directory", fi, err)
		}
		if b, err := os.ReadFile(filepath.Join(tree, "real/child")); err != nil || string(b) != "lower" {
			t.Errorf("real/child = %q (%v): replacing the link must not touch its target", b, err)
		}
		for _, absent := range []string{"real/n", "real/l", "d/child", "d/esc"} {
			if _, err := os.Lstat(filepath.Join(tree, absent)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s exists (err %v), want absent", absent, err)
			}
		}
		assertTreeLinksContained(t, tree, linux)
		assertSentinelIntact(t, outside)
	})
}

// TestApplyLayerWhiteoutThroughSymlinkStaysInTree covers whiteout and opaque
// markers that name a path under a symlinked directory. A linux-dialect link
// may hold an ABSOLUTE target (the guest chroots), and here it names a real
// host directory: on the host, a whiteout or opaque marker reached through it
// must remove nothing there. The in-tree variant must likewise leave the
// outside untouched and the tree's links contained.
func TestApplyLayerWhiteoutThroughSymlinkStaysInTree(t *testing.T) {
	t.Run("absolute link to a host directory", func(t *testing.T) {
		outside := sentinelOutside(t)
		cases := map[string][]tarSpec{
			"whiteout file":       {{name: "d/.wh.keep", mode: 0o644}},
			"whiteout nested dir": {{name: "d/.wh.sub", mode: 0o644}},
			"whiteout under sub":  {{name: "d/sub/.wh.keep", mode: 0o644}},
			"opaque marker":       {{name: "d/.wh..wh..opq", mode: 0o644}},
			"opaque nested":       {{name: "d/sub/.wh..wh..opq", mode: 0o644}},
			"file through link":   {{name: "d/new", mode: 0o644, data: "x"}},
			"dir through link":    {{name: "d/newdir", typ: tar.TypeDir, mode: 0o755}},
		}
		for name, upper := range cases {
			t.Run(name, func(t *testing.T) {
				tree, errs := applyLayers(t, LinuxUnpackPolicy(),
					[]tarSpec{{name: "d", typ: tar.TypeSymlink, link: outside}},
					upper,
				)
				if errs[0] != nil {
					t.Fatalf("lower layer: %v", errs[0])
				}
				// os.Root refuses to follow an absolute link off the anchor,
				// so the marker fails closed rather than acting on the host.
				if errs[1] == nil {
					t.Errorf("upper layer applied through a link to a host directory; want it refused")
				}
				assertSentinelIntact(t, outside)
				assertTreeLinksContained(t, tree, true)
			})
		}
	})
	t.Run("in-tree link", func(t *testing.T) {
		bothDialects(t, func(t *testing.T, policy UnpackPolicy, linux bool) {
			outside := sentinelOutside(t)
			tree, errs := applyLayers(t, policy,
				[]tarSpec{
					{name: "real", typ: tar.TypeDir, mode: 0o755},
					{name: "real/a", mode: 0o644, data: "lower"},
					{name: "real/sub", typ: tar.TypeDir, mode: 0o755},
					{name: "real/sub/b", mode: 0o644, data: "lower"},
					{name: "d", typ: tar.TypeSymlink, link: "real"},
				},
				[]tarSpec{
					{name: "d/.wh.a", mode: 0o644},
					{name: "d/sub/.wh..wh..opq", mode: 0o644},
				},
			)
			if errs[0] != nil {
				t.Fatalf("lower layer: %v", errs[0])
			}
			t.Logf("upper layer: %v", errs[1])
			if fi, err := os.Lstat(filepath.Join(tree, "d")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				t.Errorf("d is %v (%v), want the symlink kept", fi, err)
			}
			assertTreeLinksContained(t, tree, linux)
			assertSentinelIntact(t, outside)
		})
	})
}

// TestUnpackDiscardsATreeARefusedLayerLeftPartial is the fail-closed contract
// at the applier's only production caller (Unpacker.applyStaged, reached
// through Unpack and MaterializeTree). The FIRST layer applies and the second
// is refused mid-layer by the parent-is-real check, after one of its entries
// already landed, so the staging tree is genuinely partial when the refusal
// returns. Nothing usable may remain: no committed tree, no staging directory
// in either store, and MaterializeTree must not create or fill the pod
// rootfs a later step would clone, sign or inventory.
func TestUnpackDiscardsATreeARefusedLayerLeftPartial(t *testing.T) {
	layers := func(t *testing.T) []tarSpec {
		return []tarSpec{
			{name: "partial", mode: 0o644, data: "written before the refusal"},
			{name: "a/l", typ: tar.TypeSymlink, link: ".."},
		}
	}
	lower := []tarSpec{
		{name: "b", typ: tar.TypeDir, mode: 0o755},
		{name: "a", typ: tar.TypeSymlink, link: "b"},
		{name: "ok", mode: 0o644, data: "ok"},
	}
	for _, tc := range []struct {
		name   string
		policy UnpackPolicy
		linux  bool
	}{
		{"native", NativeUnpackPolicy(), false},
		{"linux", LinuxUnpackPolicy(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, u := newTestUnpacker(t)
			img := imageFrom(t, layerFrom(t, lower), layerFrom(t, layers(t)))
			if tc.linux {
				img = linuxImageFrom(t, layerFrom(t, lower), layerFrom(t, layers(t)))
			}
			mfst := commitImage(t, c, img)

			if _, err := u.Unpack(context.Background(), mfst, tc.policy); !errors.Is(err, ErrLayerEscapes) {
				t.Fatalf("Unpack error = %v, want ErrLayerEscapes", err)
			}
			assertStoresEmpty(t, c)

			dst := filepath.Join(t.TempDir(), "pod", "rootfs")
			if _, err := u.MaterializeTree(context.Background(), mfst, tc.policy, dst); !errors.Is(err, ErrLayerEscapes) {
				t.Fatalf("MaterializeTree error = %v, want ErrLayerEscapes", err)
			}
			if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("MaterializeTree created the pod rootfs %s (err %v) for a refused image", dst, err)
			}
			assertStoresEmpty(t, c)
		})
	}
}

// assertStoresEmpty fails if either tree store holds any entry: a committed
// tree or a leftover ".tree-*" staging directory.
func assertStoresEmpty(t *testing.T, c *Cache) {
	t.Helper()
	for _, store := range []string{c.UnpackedRoot(), c.SnapshotsRoot()} {
		entries, err := os.ReadDir(store)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("read store %s: %v", store, err)
		}
		for _, e := range entries {
			t.Errorf("store %s holds %q after a refused layer", store, e.Name())
		}
	}
}
