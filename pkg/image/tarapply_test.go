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
	"strings"
	"testing"
)

// tarSpec is one entry of a synthetic layer tar.
type tarSpec struct {
	name string
	typ  byte
	mode int64
	data string
	link string
	// uid, gid and pax are the LINUX dialect's inputs: the ownership sidecar
	// records the first two, and pax carries PAX extended attributes (the
	// "SCHILY.xattr." records archive/tar and every OCI builder use).
	uid int
	gid int
	pax map[string]string
}

// buildTar renders specs as an UNCOMPRESSED tar. The applier consumes a
// decompressed stream, so these tests exercise it directly with no gzip layer in
// the way.
func buildTar(t *testing.T, specs []tarSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, s := range specs {
		typ := s.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     s.name,
			Typeflag: typ,
			Mode:     s.mode,
			Linkname: s.link,
			Size:     int64(len(s.data)),
			Uid:      s.uid,
			Gid:      s.gid,
		}
		if len(s.pax) > 0 {
			// PAXRecords need the PAX format explicitly; the writer's USTAR
			// default would silently drop them and the xattr rows would then
			// pass with zero xattr handling present.
			hdr.PAXRecords = s.pax
			hdr.Format = tar.FormatPAX
		}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", s.name, err)
		}
		if typ == tar.TypeReg && s.data != "" {
			if _, err := tw.Write([]byte(s.data)); err != nil {
				t.Fatalf("write body %q: %v", s.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// applyInto applies specs into a fresh tree under t.TempDir and returns the tree
// path, the accumulated stats, and the apply error, under the NATIVE dialect.
func applyInto(t *testing.T, limits ApplyLimits, layers ...[]tarSpec) (string, ApplyStats, error) {
	t.Helper()
	tree, _, stats, err := applyIntoApplier(t, NativeUnpackPolicy(), limits, layers...)
	return tree, stats, err
}

// applyIntoApplier is applyInto under an explicit dialect, returning the applier
// as well so a Linux-dialect test can read the ownership records the apply built.
func applyIntoApplier(t *testing.T, policy UnpackPolicy, limits ApplyLimits, layers ...[]tarSpec) (string, *LayerApplier, ApplyStats, error) {
	t.Helper()
	dir := t.TempDir()
	tree := filepath.Join(dir, "rootfs")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tree)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	a, err := NewLayerApplier(root, policy, limits)
	if err != nil {
		t.Fatalf("NewLayerApplier: %v", err)
	}
	for _, specs := range layers {
		if err := a.Apply(context.Background(), bytes.NewReader(buildTar(t, specs))); err != nil {
			return tree, a, a.Stats(), err
		}
	}
	return tree, a, a.Stats(), nil
}

// TestLayerEntryPath pins the FIRST of the unpacker's two independent
// containment controls: the name sanitizer, which refuses a traversal outright
// rather than cleaning it away (a cleaned name writes to a different file than
// the archive asked for, silently).
func TestLayerEntryPath(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{"plain", "usr/bin/app", "usr/bin/app", nil},
		{"dot_slash_prefix", "./usr/bin/app", "usr/bin/app", nil},
		{"trailing_slash_dir", "usr/bin/", "usr/bin", nil},
		{"single_component", "app", "app", nil},

		{"absolute", "/etc/passwd", "", ErrLayerEscapes},
		{"leading_dotdot", "../etc/passwd", "", ErrLayerEscapes},
		{"interior_dotdot", "usr/../../etc/passwd", "", ErrLayerEscapes},
		{"trailing_dotdot", "usr/bin/..", "", ErrLayerEscapes},
		{"bare_dotdot", "..", "", ErrLayerEscapes},

		{"empty", "", "", ErrLayerMalformed},
		{"dot", ".", "", ErrLayerMalformed},
		{"dot_slash_only", "./", "", ErrLayerMalformed},
		{"double_slash", "usr//bin", "", ErrLayerMalformed},
		{"interior_dot", "usr/./bin", "", ErrLayerMalformed},
		{"nul", "usr/bi\x00n", "", ErrLayerMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := layerEntryPath(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("layerEntryPath(%q) error = %v, want %v", tc.in, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("layerEntryPath(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("layerEntryPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSymlinkTargetContained pins the rule that makes the NATIVE dialect safe
// without a chroot: a link's target must be relative and must not resolve above
// the tree, because the tree is cloned verbatim into a pod rootfs that the host
// root sits directly above.
func TestSymlinkTargetContained(t *testing.T) {
	cases := []struct {
		name    string
		link    string
		target  string
		wantErr error
	}{
		{"sibling", "usr/bin/sh", "busybox", nil},
		{"up_then_down_in_tree", "usr/bin/sh", "../lib/busybox", nil},
		{"deep_relative", "a/b/c/l", "../../d/e", nil},
		{"self_dir", "a/l", ".", nil},

		{"absolute_root", "usr/bin/sh", "/bin/sh", ErrLayerEscapes},
		{"absolute_etc", "l", "/etc/passwd", ErrLayerEscapes},
		{"escapes_one", "l", "../outside", ErrLayerEscapes},
		{"escapes_deep", "a/b/l", "../../../outside", ErrLayerEscapes},
		{"escapes_exactly_root_parent", "a/l", "../..", ErrLayerEscapes},

		{"empty", "l", "", ErrLayerMalformed},
		{"nul", "l", "a\x00b", ErrLayerMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := symlinkTargetContained(tc.link, tc.target, false)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("symlinkTargetContained(%q, %q): %v", tc.link, tc.target, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("symlinkTargetContained(%q, %q) error = %v, want %v", tc.link, tc.target, err, tc.wantErr)
			}
		})
	}
}

// TestApplyLayerRefusesEscape drives the refusals through the whole applier
// (not just the sanitizer) and proves the refusal is fatal to the layer: the
// escape target must not exist on disk afterwards.
//
// The witness file is placed as a SIBLING of the tree, which is where every one
// of these entries is aiming.
func TestApplyLayerRefusesEscape(t *testing.T) {
	cases := []struct {
		name string
		spec tarSpec
	}{
		{"absolute_regular", tarSpec{name: "/escape.txt", mode: 0o644, data: "no"}},
		{"dotdot_regular", tarSpec{name: "../escape.txt", mode: 0o644, data: "no"}},
		{"dotdot_dir", tarSpec{name: "../escape.txt", typ: tar.TypeDir, mode: 0o755}},
		{"absolute_symlink", tarSpec{name: "link", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		{"escaping_symlink", tarSpec{name: "link", typ: tar.TypeSymlink, link: "../escape.txt"}},
		{"escaping_symlink_deep", tarSpec{name: "a/b/link", typ: tar.TypeSymlink, link: "../../../escape.txt"}},
		{"absolute_hardlink", tarSpec{name: "link", typ: tar.TypeLink, link: "/etc/passwd"}},
		{"dotdot_hardlink", tarSpec{name: "link", typ: tar.TypeLink, link: "../escape.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, _, err := applyInto(t, ApplyLimits{}, []tarSpec{tc.spec})
			if !errors.Is(err, ErrLayerEscapes) {
				t.Fatalf("Apply error = %v, want ErrLayerEscapes", err)
			}
			// Nothing may have been created beside the tree.
			if _, serr := os.Lstat(filepath.Join(filepath.Dir(tree), "escape.txt")); serr == nil {
				t.Fatalf("apply created %s outside the tree", filepath.Join(filepath.Dir(tree), "escape.txt"))
			}
			// And no link may survive inside it either.
			if fi, serr := os.Lstat(filepath.Join(tree, "link")); serr == nil {
				t.Fatalf("apply left %s inside the tree (mode %v)", filepath.Join(tree, "link"), fi.Mode())
			}
		})
	}
}

// TestApplyLayerNodeTypes covers the closed typeflag set: what is created, what
// is skipped-and-counted, and what is refused.
func TestApplyLayerNodeTypes(t *testing.T) {
	t.Run("creates_dirs_files_links", func(t *testing.T) {
		tree, stats, err := applyInto(t, ApplyLimits{}, []tarSpec{
			{name: "usr", typ: tar.TypeDir, mode: 0o755},
			{name: "usr/bin", typ: tar.TypeDir, mode: 0o755},
			{name: "usr/bin/busybox", mode: 0o755, data: "BUSYBOX"},
			{name: "usr/bin/sh", typ: tar.TypeSymlink, link: "busybox"},
			{name: "usr/bin/ash", typ: tar.TypeLink, link: "usr/bin/busybox"},
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if stats.Dirs != 2 || stats.Files != 1 || stats.Symlinks != 1 || stats.Hardlinks != 1 {
			t.Errorf("stats = %+v, want 2 dirs / 1 file / 1 symlink / 1 hardlink", stats)
		}
		if got := readTree(t, tree, "usr/bin/busybox"); got != "BUSYBOX" {
			t.Errorf("busybox = %q", got)
		}
		// The symlink must be a LINK, not a copy — "links recorded as links".
		fi, err := os.Lstat(filepath.Join(tree, "usr/bin/sh"))
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("usr/bin/sh mode = %v, err %v; want a symlink", fi.Mode(), err)
		}
		if target, _ := os.Readlink(filepath.Join(tree, "usr/bin/sh")); target != "busybox" {
			t.Errorf("usr/bin/sh -> %q, want %q", target, "busybox")
		}
		// The hard link must share the target's inode.
		a, err := os.Stat(filepath.Join(tree, "usr/bin/busybox"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.Stat(filepath.Join(tree, "usr/bin/ash"))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(a, b) {
			t.Error("hard link does not share the target's inode")
		}
	})

	t.Run("skips_and_counts_special_nodes", func(t *testing.T) {
		tree, stats, err := applyInto(t, ApplyLimits{}, []tarSpec{
			{name: "dev", typ: tar.TypeDir, mode: 0o755},
			{name: "dev/null", typ: tar.TypeChar, mode: 0o666},
			{name: "dev/loop0", typ: tar.TypeBlock, mode: 0o660},
			{name: "dev/initctl", typ: tar.TypeFifo, mode: 0o600},
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if stats.SkippedSpecial != 3 {
			t.Errorf("SkippedSpecial = %d, want 3", stats.SkippedSpecial)
		}
		for _, n := range []string{"dev/null", "dev/loop0", "dev/initctl"} {
			if _, err := os.Lstat(filepath.Join(tree, n)); err == nil {
				t.Errorf("%s was created; special nodes must be skipped", n)
			}
		}
	})

	t.Run("refuses_unknown_typeflag", func(t *testing.T) {
		_, _, err := applyInto(t, ApplyLimits{}, []tarSpec{{name: "weird", typ: 'Z', mode: 0o644}})
		if !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("Apply error = %v, want ErrLayerMalformed", err)
		}
	})

	t.Run("refuses_hardlink_to_absent_target", func(t *testing.T) {
		_, _, err := applyInto(t, ApplyLimits{}, []tarSpec{
			{name: "alias", typ: tar.TypeLink, link: "not/written/yet"},
		})
		if !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("Apply error = %v, want ErrLayerMalformed", err)
		}
	})

	t.Run("refuses_hardlink_to_a_symlink", func(t *testing.T) {
		// A hard link whose target is a SYMLINK would alias the link itself; the
		// applier requires a regular file so a link can never stand in for a node
		// the layer did not supply.
		_, _, err := applyInto(t, ApplyLimits{}, []tarSpec{
			{name: "real", mode: 0o644, data: "x"},
			{name: "sym", typ: tar.TypeSymlink, link: "real"},
			{name: "alias", typ: tar.TypeLink, link: "sym"},
		})
		if !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("Apply error = %v, want ErrLayerMalformed", err)
		}
	})
}

// TestApplyLayerOrdering pins the OCI apply rule the multi-layer path depends
// on: a later layer wins, including when it replaces a node with one of a
// different kind, and an earlier layer's untouched files survive.
func TestApplyLayerOrdering(t *testing.T) {
	t.Run("later_file_wins", func(t *testing.T) {
		tree, _, err := applyInto(t, ApplyLimits{},
			[]tarSpec{
				{name: "app", mode: 0o755, data: "V1"},
				{name: "keep.txt", mode: 0o644, data: "KEEP"},
			},
			[]tarSpec{{name: "app", mode: 0o755, data: "V2"}},
		)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := readTree(t, tree, "app"); got != "V2" {
			t.Errorf("app = %q, want V2 (the later layer)", got)
		}
		if got := readTree(t, tree, "keep.txt"); got != "KEEP" {
			t.Errorf("keep.txt = %q, want KEEP (untouched by the later layer)", got)
		}
	})

	t.Run("later_file_replaces_a_symlink_rather_than_writing_through_it", func(t *testing.T) {
		tree, _, err := applyInto(t, ApplyLimits{},
			[]tarSpec{
				{name: "target.txt", mode: 0o644, data: "ORIGINAL"},
				{name: "app", typ: tar.TypeSymlink, link: "target.txt"},
			},
			[]tarSpec{{name: "app", mode: 0o755, data: "V2"}},
		)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := readTree(t, tree, "app"); got != "V2" {
			t.Errorf("app = %q, want V2", got)
		}
		// Writing through the link would have clobbered the target.
		if got := readTree(t, tree, "target.txt"); got != "ORIGINAL" {
			t.Errorf("target.txt = %q, want ORIGINAL — the layer wrote through the symlink", got)
		}
		fi, err := os.Lstat(filepath.Join(tree, "app"))
		if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
			t.Errorf("app mode = %v, err %v; want a regular file", fi.Mode(), err)
		}
	})

	t.Run("later_file_replaces_a_populated_directory", func(t *testing.T) {
		tree, _, err := applyInto(t, ApplyLimits{},
			[]tarSpec{
				{name: "thing", typ: tar.TypeDir, mode: 0o755},
				{name: "thing/inner", mode: 0o644, data: "INNER"},
			},
			[]tarSpec{{name: "thing", mode: 0o644, data: "NOW A FILE"}},
		)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := readTree(t, tree, "thing"); got != "NOW A FILE" {
			t.Errorf("thing = %q", got)
		}
	})

	t.Run("later_dir_keeps_earlier_contents", func(t *testing.T) {
		tree, _, err := applyInto(t, ApplyLimits{},
			[]tarSpec{
				{name: "d", typ: tar.TypeDir, mode: 0o755},
				{name: "d/keep", mode: 0o644, data: "KEEP"},
			},
			[]tarSpec{{name: "d", typ: tar.TypeDir, mode: 0o700}},
		)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := readTree(t, tree, "d/keep"); got != "KEEP" {
			t.Errorf("d/keep = %q, want KEEP — a re-declared directory must not be emptied", got)
		}
	})
}

// TestApplyLayerModeDiscipline pins entryPerm's two documented divergences from
// the tar header: setuid/setgid/sticky are always stripped (and counted), and
// the OWNER bits are widened so an unprivileged daemon can read back what it
// wrote. Group and other bits must be untouched.
func TestApplyLayerModeDiscipline(t *testing.T) {
	tree, stats, err := applyInto(t, ApplyLimits{}, []tarSpec{
		{name: "suid", mode: 0o4755, data: "x"},
		{name: "sgid", mode: 0o2755, data: "x"},
		{name: "sticky_dir", typ: tar.TypeDir, mode: 0o1777},
		{name: "mode_zero", mode: 0, data: "x"},
		{name: "group_readable", mode: 0o640, data: "x"},
		{name: "plain_dir", typ: tar.TypeDir, mode: 0o755},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if stats.StrippedSetIDs != 3 {
		t.Errorf("StrippedSetIDs = %d, want 3", stats.StrippedSetIDs)
	}
	cases := []struct {
		name string
		want fs.FileMode
	}{
		{"suid", 0o755},           // setuid gone, owner already rwx
		{"sgid", 0o755},           // setgid gone
		{"sticky_dir", 0o777},     // sticky gone
		{"mode_zero", 0o600},      // owner minimum applied
		{"group_readable", 0o640}, // group bit preserved, owner already rw
		{"plain_dir", 0o755},      // unchanged
	}
	for _, tc := range cases {
		fi, err := os.Lstat(filepath.Join(tree, tc.name))
		if err != nil {
			t.Fatalf("lstat %s: %v", tc.name, err)
		}
		if got := fi.Mode().Perm(); got != tc.want {
			t.Errorf("%s mode = %#o, want %#o", tc.name, got, tc.want)
		}
		if fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
			t.Errorf("%s retained a set-id/sticky bit (mode %v)", tc.name, fi.Mode())
		}
	}
}

// TestApplyLayerLimits pins the two resource guards. They are guards, not
// integrity checks: an over-limit layer is refused with ErrUnpackTooLarge rather
// than truncated into something that would then fail its diffID check with a
// misleading verdict.
func TestApplyLayerLimits(t *testing.T) {
	t.Run("entries", func(t *testing.T) {
		_, _, err := applyInto(t, ApplyLimits{MaxEntries: 2}, []tarSpec{
			{name: "a", mode: 0o644, data: "a"},
			{name: "b", mode: 0o644, data: "b"},
			{name: "c", mode: 0o644, data: "c"},
		})
		if !errors.Is(err, ErrUnpackTooLarge) {
			t.Fatalf("Apply error = %v, want ErrUnpackTooLarge", err)
		}
	})

	t.Run("bytes_within_one_layer", func(t *testing.T) {
		_, _, err := applyInto(t, ApplyLimits{MaxBytes: 8}, []tarSpec{
			{name: "big", mode: 0o644, data: strings.Repeat("x", 9)},
		})
		if !errors.Is(err, ErrUnpackTooLarge) {
			t.Fatalf("Apply error = %v, want ErrUnpackTooLarge", err)
		}
	})

	t.Run("bytes_accumulate_across_layers", func(t *testing.T) {
		// The guard is per-TREE, not per-layer: two layers each under the cap
		// must still trip it together.
		_, _, err := applyInto(t, ApplyLimits{MaxBytes: 8},
			[]tarSpec{{name: "a", mode: 0o644, data: strings.Repeat("x", 5)}},
			[]tarSpec{{name: "b", mode: 0o644, data: strings.Repeat("y", 5)}},
		)
		if !errors.Is(err, ErrUnpackTooLarge) {
			t.Fatalf("Apply error = %v, want ErrUnpackTooLarge", err)
		}
	})

	t.Run("exactly_at_the_cap_is_admitted", func(t *testing.T) {
		if _, _, err := applyInto(t, ApplyLimits{MaxBytes: 8}, []tarSpec{
			{name: "a", mode: 0o644, data: strings.Repeat("x", 8)},
		}); err != nil {
			t.Fatalf("Apply at exactly the cap: %v", err)
		}
	})

	t.Run("negative_bound_is_refused", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := NewLayerApplier(root, NativeUnpackPolicy(), ApplyLimits{MaxBytes: -1}); err == nil {
			t.Fatal("NewLayerApplier accepted a negative limit")
		}
	})
}

// TestNewLayerApplierRequiresAValidPolicy pins the fail-closed dialect check: an
// unset or unknown LayerSemantics never falls through to the native rules.
// "linux" is a real dialect since M11.2-d1, so the unknown-value rows name
// values no dialect will ever claim.
func TestNewLayerApplierRequiresAValidPolicy(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, p := range []UnpackPolicy{{}, {Semantics: "windows"}, {Semantics: "NATIVE"}, {Semantics: "LINUX"}} {
		if _, err := NewLayerApplier(root, p, ApplyLimits{}); err == nil {
			t.Errorf("NewLayerApplier accepted policy %+v", p)
		}
	}
}

// TestApplyLayerHonorsContext proves a cancelled create abandons a layer instead
// of applying it to the end.
func TestApplyLayerHonorsContext(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	a, err := NewLayerApplier(root, NativeUnpackPolicy(), ApplyLimits{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = a.Apply(ctx, bytes.NewReader(buildTar(t, []tarSpec{{name: "a", mode: 0o644, data: "a"}})))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply error = %v, want context.Canceled", err)
	}
	if _, serr := os.Lstat(filepath.Join(dir, "a")); serr == nil {
		t.Error("a cancelled Apply still wrote an entry")
	}
}

// readTree reads a file out of an applied tree.
func readTree(t *testing.T, tree, rel string) string {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join(tree, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(buf)
}

// TestApplyLayerAcceptsTheRootEntry pins the buildkit/docker "./" root entry as
// a NO-OP rather than a fault, and pins the carve-out's exact width.
//
// The bug this replaces was live and total: a `docker build`/buildkit export of
// any debian-derived base emits a `./` directory entry as its first entry, so
// every such image failed to materialize with "entry name \"./\" names the tree
// root itself". Alpine-derived images happen not to carry one, which is why a
// green test table coexisted with an unrunnable standard image — the fixtures
// were all alpine-shaped.
//
// The second half of the table is the part that keeps the fix honest. A
// carve-out for "." is only safe if it is a carve-out for "." and nothing
// adjacent, so the traversal and absolute-name refusals are re-asserted here
// rather than left to the sanitizer's own table: those are the cases a
// too-permissive "just clean the name" fix would silently admit.
func TestApplyLayerAcceptsTheRootEntry(t *testing.T) {
	// The shape a real buildkit layer has: the root entry first, then content.
	buildkitLayer := func(root string) []tarSpec {
		return []tarSpec{
			{name: root, typ: tar.TypeDir, mode: 0o755},
			{name: "etc", typ: tar.TypeDir, mode: 0o755},
			{name: "etc/hostname", mode: 0o644, data: "box"},
		}
	}

	for _, spelling := range []string{"./", ".", "./."} {
		t.Run("root_entry_"+spelling+"_is_skipped", func(t *testing.T) {
			tree, stats, err := applyInto(t, ApplyLimits{}, buildkitLayer(spelling))
			if err != nil {
				t.Fatalf("Apply of a layer whose first entry is %q = %v; a root entry is legal and must be a no-op", spelling, err)
			}
			if stats.RootEntries != 1 {
				t.Errorf("stats.RootEntries = %d, want 1 (the skip must be counted, not silent)", stats.RootEntries)
			}
			// Skipped means skipped: the root entry created nothing and was not
			// counted as a directory the layer made.
			if stats.Dirs != 1 {
				t.Errorf("stats.Dirs = %d, want 1 (only etc/); the root entry must not be counted as a created dir", stats.Dirs)
			}
			// ...and the rest of the layer landed, which is the whole point.
			if got := readTree(t, tree, "etc/hostname"); got != "box" {
				t.Errorf("etc/hostname = %q, want %q", got, "box")
			}
		})
	}

	t.Run("a_root_entry_alone_applies_cleanly", func(t *testing.T) {
		_, stats, err := applyInto(t, ApplyLimits{}, []tarSpec{{name: "./", typ: tar.TypeDir, mode: 0o755}})
		if err != nil {
			t.Fatalf("Apply of a root-entry-only layer = %v, want nil", err)
		}
		if stats.RootEntries != 1 || stats.Dirs != 0 || stats.Files != 0 {
			t.Errorf("stats = %+v, want exactly one skipped root entry and nothing created", stats)
		}
	})

	// The carve-out's width, asserted from the outside. Each of these differs
	// from "./" by one character class, and each must still be refused.
	t.Run("the_carve_out_admits_nothing_adjacent", func(t *testing.T) {
		cases := []struct {
			name    string
			spec    tarSpec
			wantErr error
		}{
			{"dotdot_dir", tarSpec{name: "../", typ: tar.TypeDir, mode: 0o755}, ErrLayerEscapes},
			{"dotdot_prefixed_dir", tarSpec{name: "../escape", typ: tar.TypeDir, mode: 0o755}, ErrLayerEscapes},
			{"absolute_root", tarSpec{name: "/", typ: tar.TypeDir, mode: 0o755}, ErrLayerEscapes},
			{"absolute_dir", tarSpec{name: "/etc", typ: tar.TypeDir, mode: 0o755}, ErrLayerEscapes},
			{"interior_dot_component", tarSpec{name: "etc/./passwd", mode: 0o644, data: "no"}, ErrLayerMalformed},
			{"empty_name", tarSpec{name: "", typ: tar.TypeDir, mode: 0o755}, ErrLayerMalformed},
			// A hardlink cannot target the tree root: layerEntryPath keeps its
			// root refusal for the Linkname call site, which the carve-out in
			// applyEntry deliberately does not reach.
			{"hardlink_to_the_root", tarSpec{name: "link", typ: tar.TypeLink, link: "./"}, ErrLayerMalformed},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, stats, err := applyInto(t, ApplyLimits{}, []tarSpec{tc.spec})
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Apply(%q) error = %v, want %v", tc.spec.name, err, tc.wantErr)
				}
				if stats.RootEntries != 0 {
					t.Errorf("stats.RootEntries = %d for %q; only the cleaned-\".\" name is the root entry",
						stats.RootEntries, tc.spec.name)
				}
			})
		}
	})
}
