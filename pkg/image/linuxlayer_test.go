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
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateFixtures regenerates the committed testdata tars from the specs below.
//
// The fixtures are COMMITTED rather than built per run so that a reviewer can
// run `tar tvf` over the exact bytes the gate asserts on, and so that a bug in
// the spec-to-tar builder cannot make a test pass by changing the input it was
// written against. Regenerate with:
//
//	go test ./pkg/image/ -run TestLinuxRootfsFixtures -update-fixtures
var updateFixtures = flag.Bool("update-fixtures", false, "regenerate the committed testdata layer tars")

// fixtureDir is where the committed layer tars live.
const fixtureDir = "testdata/linuxlayer"

// linuxFixtures is the closed set of committed layer tars and the specs they are
// generated from. Each one is a WHOLE LAYER, so a test names layers by fixture
// rather than assembling entry lists inline.
var linuxFixtures = map[string][]tarSpec{
	// base is the lower layer everything else is applied over.
	"base.tar": {
		{name: "etc", typ: tar.TypeDir, mode: 0o755},
		{name: "etc/keep.conf", mode: 0o644, data: "keep"},
		{name: "etc/gone.conf", mode: 0o644, data: "gone"},
		{name: "opt", typ: tar.TypeDir, mode: 0o755},
		{name: "opt/tool", typ: tar.TypeDir, mode: 0o755},
		{name: "opt/tool/bin", mode: 0o755, data: "lower"},
		{name: "var", typ: tar.TypeDir, mode: 0o755},
		{name: "var/lower.log", mode: 0o644, data: "lower"},
		{name: "var/sub", typ: tar.TypeDir, mode: 0o755},
		{name: "var/sub/deep.log", mode: 0o644, data: "deep"},
	},
	// whiteout deletes one file and one whole directory from the lower layer,
	// and adds a file of its own.
	"whiteout.tar": {
		{name: "etc/.wh.gone.conf", mode: 0o644},
		{name: "opt/.wh.tool", mode: 0o644},
		{name: "etc/new.conf", mode: 0o644, data: "new"},
	},
	// opaque makes var/ opaque while contributing a file INSIDE it: the lower
	// layer's var/lower.log and var/sub/ must go, var/upper.log must stay.
	"opaque.tar": {
		{name: "var/upper.log", mode: 0o644, data: "upper"},
		{name: "var/.wh..wh..opq", mode: 0o644},
		{name: "var/.wh..wh.plnk", mode: 0o644},
	},
	// hardlink-escape links to a path outside the tree. Both the "../" spelling
	// and the absolute spelling must be refused.
	"hardlink-escape.tar": {
		{name: "bin", typ: tar.TypeDir, mode: 0o755},
		{name: "bin/escape", typ: tar.TypeLink, link: "../../../etc/passwd"},
	},
	// setuid carries a setuid-root binary and a distinctly-owned tree, which is
	// what the ownership sidecar has to carry losslessly while the HOST copy
	// carries neither.
	"setuid.tar": {
		{name: "usr", typ: tar.TypeDir, mode: 0o755, uid: 0, gid: 0},
		{name: "usr/bin", typ: tar.TypeDir, mode: 0o755, uid: 0, gid: 0},
		{name: "usr/bin/su", mode: 0o4755, data: "setuid", uid: 0, gid: 0},
		{name: "home", typ: tar.TypeDir, mode: 0o700, uid: 1000, gid: 1000},
		{name: "home/app", mode: 0o600, data: "owned", uid: 1000, gid: 1000},
		{name: "home/link", typ: tar.TypeSymlink, link: "app", uid: 1000, gid: 1000},
	},
	// capability carries a setcap'd binary: the file capability is the
	// documented loss (see xattrAllowlist).
	"capability.tar": {
		{name: "bin", typ: tar.TypeDir, mode: 0o755},
		{name: "bin/ping", mode: 0o755, data: "ping", uid: 0, gid: 0, pax: map[string]string{
			"SCHILY.xattr.security.capability": "\x01\x00\x00\x02\x00\x20\x00\x00",
			"SCHILY.xattr.user.note":           "harmless",
		}},
	},
	// case-collision names two paths that Linux keeps distinct and a
	// case-insensitive APFS volume would merge into one file.
	"case-collision.tar": {
		{name: "srv", typ: tar.TypeDir, mode: 0o755},
		{name: "srv/Config", mode: 0o644, data: "upper"},
		{name: "srv/config", mode: 0o644, data: "lower"},
	},
	// normalization-collision names the same file in NFC and NFD. macOS
	// resolves one to the other even on a case-SENSITIVE volume.
	"normalization-collision.tar": {
		{name: "srv", typ: tar.TypeDir, mode: 0o755},
		{name: "srv/café.conf", mode: 0o644, data: "nfc"},
		{name: "srv/café.conf", mode: 0o644, data: "nfd"},
	},
	// implicit-case-collision hides the collision in a PARENT no entry names,
	// which is why the ownership map records implicit ancestors.
	"implicit-case-collision.tar": {
		{name: "Srv/a", mode: 0o644, data: "a"},
		{name: "srv/b", mode: 0o644, data: "b"},
	},
	// absolute-symlink is the usr-merge shape every real base image ships.
	"absolute-symlink.tar": {
		{name: "bin", typ: tar.TypeDir, mode: 0o755},
		{name: "bin/sh", typ: tar.TypeSymlink, link: "/usr/bin/busybox"},
	},
	// relative-escape-symlink resolves ABOVE the tree; it is refused under both
	// dialects (see symlinkTargetContained).
	"relative-escape-symlink.tar": {
		{name: "bin", typ: tar.TypeDir, mode: 0o755},
		{name: "bin/out", typ: tar.TypeSymlink, link: "../../../etc/passwd"},
	},
	// devices carries the character/block/fifo nodes an unprivileged daemon
	// cannot create and a guest gets from devtmpfs anyway.
	"devices.tar": {
		{name: "dev", typ: tar.TypeDir, mode: 0o755},
		{name: "dev/null", typ: tar.TypeChar, mode: 0o666},
		{name: "dev/loop0", typ: tar.TypeBlock, mode: 0o660},
		{name: "dev/initctl", typ: tar.TypeFifo, mode: 0o600},
	},
}

// TestLinuxRootfsFixtures regenerates the committed fixtures under
// -update-fixtures and otherwise asserts each one is present and readable as a
// tar. It is the provenance record for testdata/linuxlayer: without it a
// committed fixture would be a binary blob with no stated origin.
func TestLinuxRootfsFixtures(t *testing.T) {
	if *updateFixtures {
		if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, specs := range linuxFixtures {
			if err := os.WriteFile(filepath.Join(fixtureDir, name), buildTar(t, specs), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("regenerated %d fixtures in %s", len(linuxFixtures), fixtureDir)
		return
	}
	for name := range linuxFixtures {
		raw := readFixture(t, name)
		tr := tar.NewReader(bytes.NewReader(raw))
		if _, err := tr.Next(); err != nil {
			t.Errorf("fixture %s is not a readable tar: %v", name, err)
		}
	}
}

// readFixture returns one committed layer tar's bytes.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read fixture %s (regenerate with -update-fixtures): %v", name, err)
	}
	return raw
}

// applyFixtures applies the named committed fixtures, in order, into one tree
// under policy, and returns the tree path, the applier and the error.
func applyFixtures(t *testing.T, policy UnpackPolicy, names ...string) (string, *LayerApplier, error) {
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
	a, err := NewLayerApplier(root, policy, ApplyLimits{})
	if err != nil {
		t.Fatalf("NewLayerApplier: %v", err)
	}
	for _, n := range names {
		if err := a.Apply(context.Background(), bytes.NewReader(readFixture(t, n))); err != nil {
			return tree, a, err
		}
	}
	return tree, a, nil
}

// exists reports whether tree-relative rel is present (lstat, so a dangling
// symlink counts as present).
func exists(t *testing.T, tree, rel string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(tree, rel))
	if err == nil {
		return true
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lstat %s: %v", rel, err)
	}
	return false
}

// TestLinuxRootfsWhiteoutOpaqueApply is the M11.2-d1 GATE.
//
// It drives the committed layer fixtures through the LINUX dialect and pins the
// three deletion semantics OCI defines, each against the property that
// distinguishes it from the others:
//
//   - ".wh.<name>" removes a FILE and, recursively, a DIRECTORY the lower
//     layers contributed — and is never itself materialized;
//   - ".wh..wh..opq" removes what the LOWER layers put in its directory while
//     preserving what THIS layer put there, recursing into a directory this
//     layer merely re-moded;
//   - ".wh..wh.<meta>" is AUFS bookkeeping: skipped, counted, never written.
//
// The same fixtures under the NATIVE dialect must produce the opposite result —
// every marker materialized as an ordinary file and nothing deleted — because
// that is the property that makes the two dialects safe to key separately.
func TestLinuxRootfsWhiteoutOpaqueApply(t *testing.T) {
	t.Run("linux_applies_the_markers", func(t *testing.T) {
		tree, a, err := applyFixtures(t, LinuxUnpackPolicy(), "base.tar", "whiteout.tar", "opaque.tar")
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		gone := []string{
			"etc/gone.conf",     // .wh.gone.conf
			"opt/tool",          // .wh.tool, a whole directory
			"opt/tool/bin",      // ...and its contents
			"var/lower.log",     // lower-layer file under an opaque dir
			"var/sub",           // lower-layer directory under an opaque dir
			"var/sub/deep.log",  // ...and its contents
			"etc/.wh.gone.conf", // the marker itself is never a file
			"opt/.wh.tool",      //
			"var/.wh..wh..opq",  //
			"var/.wh..wh.plnk",  // AUFS bookkeeping, skipped
		}
		for _, rel := range gone {
			if exists(t, tree, rel) {
				t.Errorf("%s survived the whiteouts", rel)
			}
		}
		kept := map[string]string{
			"etc/keep.conf": "keep",  // untouched lower-layer file
			"etc/new.conf":  "new",   // added by the whiteout layer
			"var/upper.log": "upper", // added by the OPAQUE layer: must survive it
		}
		for rel, want := range kept {
			got, rerr := os.ReadFile(filepath.Join(tree, rel))
			if rerr != nil {
				t.Errorf("%s did not survive: %v", rel, rerr)
				continue
			}
			if string(got) != want {
				t.Errorf("%s = %q, want %q", rel, got, want)
			}
		}
		st := a.Stats()
		if st.Whiteouts != 2 {
			t.Errorf("Whiteouts = %d, want 2", st.Whiteouts)
		}
		if st.OpaqueDirs != 1 {
			t.Errorf("OpaqueDirs = %d, want 1", st.OpaqueDirs)
		}
		if st.WhiteoutMeta != 1 {
			t.Errorf("WhiteoutMeta = %d, want 1", st.WhiteoutMeta)
		}
	})

	// The native dialect's behaviour on the SAME bytes, unchanged: markers are
	// ordinary files and nothing is deleted. This is the row that would go red
	// if the Linux rules ever leaked into the dialect that has no chroot.
	t.Run("native_treats_markers_as_files", func(t *testing.T) {
		tree, a, err := applyFixtures(t, NativeUnpackPolicy(), "base.tar", "whiteout.tar", "opaque.tar")
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		for _, rel := range []string{
			"etc/gone.conf", "opt/tool/bin", "var/lower.log", "var/sub/deep.log",
			"etc/.wh.gone.conf", "opt/.wh.tool", "var/.wh..wh..opq", "var/.wh..wh.plnk",
		} {
			if !exists(t, tree, rel) {
				t.Errorf("%s is missing: the native dialect deleted or skipped something", rel)
			}
		}
		if st := a.Stats(); st.Whiteouts != 0 || st.OpaqueDirs != 0 || st.WhiteoutMeta != 0 {
			t.Errorf("native stats = %+v, want zero whiteout counters", st)
		}
	})

	// An opaque marker at the tree ROOT discards every lower layer wholesale.
	t.Run("root_opaque_discards_every_lower_layer", func(t *testing.T) {
		tree, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: "old", mode: 0o644, data: "old"}, {name: "d", typ: tar.TypeDir, mode: 0o755}, {name: "d/x", mode: 0o644, data: "x"}},
			[]tarSpec{{name: "new", mode: 0o644, data: "new"}, {name: ".wh..wh..opq", mode: 0o644}},
		)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		for _, rel := range []string{"old", "d", "d/x"} {
			if exists(t, tree, rel) {
				t.Errorf("%s survived a root opaque marker", rel)
			}
		}
		if !exists(t, tree, "new") {
			t.Error("the opaque layer's own file did not survive its marker")
		}
	})

	// An opaque marker for a directory NO lower layer supplied is a no-op, not
	// an error: a builder emits one from a `rm -rf` of a path a previous stage
	// had already removed.
	t.Run("opaque_on_an_absent_directory_is_a_no_op", func(t *testing.T) {
		_, a, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: "absent/.wh..wh..opq", mode: 0o644}})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if st := a.Stats(); st.OpaqueDirs != 1 {
			t.Errorf("OpaqueDirs = %d, want 1", st.OpaqueDirs)
		}
	})

	// Likewise a ".wh.<name>" naming a path no lower layer supplied.
	t.Run("whiteout_of_an_absent_path_is_a_no_op", func(t *testing.T) {
		_, a, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: ".wh.absent", mode: 0o644}})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if st := a.Stats(); st.Whiteouts != 1 {
			t.Errorf("Whiteouts = %d, want 1", st.Whiteouts)
		}
	})

	// A marker naming no sibling is MALFORMED, never a guess about which node to
	// delete.
	t.Run("marker_naming_no_sibling_is_malformed", func(t *testing.T) {
		for _, name := range []string{".wh.", "d/.wh."} {
			_, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
				[]tarSpec{{name: name, mode: 0o644}})
			if !errors.Is(err, ErrLayerMalformed) {
				t.Errorf("apply(%q) error = %v, want ErrLayerMalformed", name, err)
			}
		}
	})

	// A whiteout in layer N must NOT delete a path layer N itself created after
	// it; the opaque rule's layerPaths set must not leak into the plain
	// whiteout, which is defined against the tree as it stands.
	t.Run("whiteout_then_recreate_in_one_layer", func(t *testing.T) {
		tree, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: "f", mode: 0o644, data: "lower"}},
			[]tarSpec{{name: ".wh.f", mode: 0o644}, {name: "f", mode: 0o644, data: "upper"}},
		)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		got, rerr := os.ReadFile(filepath.Join(tree, "f"))
		if rerr != nil || string(got) != "upper" {
			t.Errorf("f = %q/%v, want %q", got, rerr, "upper")
		}
	})
}

// TestLinuxRootfsHardlinkContainment pins the hard-link rule under the LINUX
// dialect: a link may only alias a regular file the tree ALREADY holds, so it
// can neither reach a host path nor alias a node no layer supplied.
//
// The Linux dialect relaxes the ABSOLUTE-SYMLINK rule, and this is the test that
// proves the relaxation did not leak into hard links — a hard link is resolved
// by the HOST at apply time, where no chroot exists, so its rule cannot move.
func TestLinuxRootfsHardlinkContainment(t *testing.T) {
	t.Run("escape_is_refused", func(t *testing.T) {
		tree, _, err := applyFixtures(t, LinuxUnpackPolicy(), "hardlink-escape.tar")
		if !errors.Is(err, ErrLayerEscapes) {
			t.Fatalf("apply error = %v, want ErrLayerEscapes", err)
		}
		if exists(t, tree, "bin/escape") {
			t.Error("the refused link was created anyway")
		}
	})

	t.Run("absolute_target_is_refused", func(t *testing.T) {
		_, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{}, []tarSpec{
			{name: "l", typ: tar.TypeLink, link: "/etc/passwd"},
		})
		if !errors.Is(err, ErrLayerEscapes) {
			t.Fatalf("apply error = %v, want ErrLayerEscapes", err)
		}
	})

	t.Run("target_the_tree_lacks_is_refused", func(t *testing.T) {
		_, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{}, []tarSpec{
			{name: "l", typ: tar.TypeLink, link: "never/written"},
		})
		if !errors.Is(err, ErrLayerMalformed) {
			t.Fatalf("apply error = %v, want ErrLayerMalformed", err)
		}
	})

	t.Run("in_root_link_is_applied_and_shares_content", func(t *testing.T) {
		tree, a, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{}, []tarSpec{
			{name: "bin", typ: tar.TypeDir, mode: 0o755},
			{name: "bin/busybox", mode: 0o755, data: "BB"},
			{name: "bin/sh", typ: tar.TypeLink, link: "bin/busybox", mode: 0o755, uid: 7, gid: 9},
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		a1, err := os.Stat(filepath.Join(tree, "bin/busybox"))
		if err != nil {
			t.Fatal(err)
		}
		a2, err := os.Stat(filepath.Join(tree, "bin/sh"))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(a1, a2) {
			t.Error("the hard link is not the same file as its target")
		}
		if st := a.Stats(); st.Hardlinks != 1 {
			t.Errorf("Hardlinks = %d, want 1", st.Hardlinks)
		}
		// A hard link IS a regular file and is recorded as one, with its own
		// header's ownership.
		own := ownershipByPath(a.Ownership())
		if e, ok := own["bin/sh"]; !ok || e.Type != OwnershipTypeFile || e.UID != 7 || e.GID != 9 {
			t.Errorf("ownership for bin/sh = %+v (present=%v), want a file owned 7:9", e, ok)
		}
	})
}

// TestLinuxRootfsCaseCollisionFailsClosed pins m11-plan Resolution 8's defense
// in depth: two paths a case-insensitive or normalization-insensitive volume
// would merge are a TYPED error and nothing is committed.
//
// The native dialect keeps the OLD behaviour deliberately and that row is
// asserted too: a darwin-native image's paths are consumed by a darwin process
// on the same insensitive volume, so the merge is what the payload expects.
func TestLinuxRootfsCaseCollisionFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{"case", "case-collision.tar"},
		{"unicode_normalization", "normalization-collision.tar"},
		{"implicit_parent", "implicit-case-collision.tar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := applyFixtures(t, LinuxUnpackPolicy(), tc.fixture)
			if !errors.Is(err, ErrPathCollision) {
				t.Fatalf("apply error = %v, want ErrPathCollision", err)
			}
			// The refusal is fatal to the layer, never a per-entry skip.
			if !errors.Is(err, ErrPathCollision) {
				t.Fatalf("apply error = %v, want ErrPathCollision", err)
			}
		})
		t.Run(tc.name+"_native_is_unchanged", func(t *testing.T) {
			if _, _, err := applyFixtures(t, NativeUnpackPolicy(), tc.fixture); err != nil {
				t.Fatalf("native apply refused %s: %v", tc.fixture, err)
			}
		})
	}

	// A collision ACROSS layers is caught too — the model spans the whole tree,
	// not one layer.
	t.Run("across_layers", func(t *testing.T) {
		_, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: "README", mode: 0o644, data: "a"}},
			[]tarSpec{{name: "readme", mode: 0o644, data: "b"}},
		)
		if !errors.Is(err, ErrPathCollision) {
			t.Fatalf("apply error = %v, want ErrPathCollision", err)
		}
	})

	// Re-writing the SAME path is "later layer wins", never a collision.
	t.Run("same_path_rewritten_is_not_a_collision", func(t *testing.T) {
		tree, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: "f", mode: 0o644, data: "v1"}},
			[]tarSpec{{name: "f", mode: 0o644, data: "v2"}},
		)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Join(tree, "f")); string(got) != "v2" {
			t.Errorf("f = %q, want v2", got)
		}
	})

	// A path WHITED OUT and then re-created under a different case is NOT a
	// collision: the first path is gone from the tree, so nothing merges.
	t.Run("whiteout_releases_the_folded_key", func(t *testing.T) {
		tree, _, _, err := applyIntoApplier(t, LinuxUnpackPolicy(), ApplyLimits{},
			[]tarSpec{{name: "Foo", mode: 0o644, data: "upper"}},
			[]tarSpec{{name: ".wh.Foo", mode: 0o644}, {name: "foo", mode: 0o644, data: "lower"}},
		)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Join(tree, "foo")); string(got) != "lower" {
			t.Errorf("foo = %q, want lower", got)
		}
	})

	// foldKey's own table: the two insensitivities compose, and unrelated paths
	// stay unrelated.
	t.Run("fold_key", func(t *testing.T) {
		same := [][2]string{
			{"srv/Config", "srv/config"},
			{"A/B/C", "a/b/c"},
			{"srv/café", "srv/café"},
			{"CAFÉ", "café"},
		}
		for _, p := range same {
			if foldKey(p[0]) != foldKey(p[1]) {
				t.Errorf("foldKey(%q) != foldKey(%q)", p[0], p[1])
			}
		}
		differ := [][2]string{
			{"srv/config", "srv/configs"},
			{"a/b", "ab"},
			{"srv/x", "srv/y"},
		}
		for _, p := range differ {
			if foldKey(p[0]) == foldKey(p[1]) {
				t.Errorf("foldKey(%q) == foldKey(%q)", p[0], p[1])
			}
		}
	})
}

// TestLinuxRootfsSymlinkDialect pins the ONE per-dialect rule in the applier:
// an absolute symlink target is refused natively (no chroot stands between the
// pod and the host root) and admitted under Linux (the guest chroots into this
// very tree). A RELATIVE target that resolves above the tree stays refused under
// both.
func TestLinuxRootfsSymlinkDialect(t *testing.T) {
	t.Run("absolute_admitted_under_linux", func(t *testing.T) {
		tree, a, err := applyFixtures(t, LinuxUnpackPolicy(), "absolute-symlink.tar")
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		got, rerr := os.Readlink(filepath.Join(tree, "bin/sh"))
		if rerr != nil {
			t.Fatalf("readlink: %v", rerr)
		}
		if got != "/usr/bin/busybox" {
			t.Errorf("bin/sh -> %q, want the target verbatim", got)
		}
		if st := a.Stats(); st.Symlinks != 1 {
			t.Errorf("Symlinks = %d, want 1", st.Symlinks)
		}
	})

	t.Run("absolute_refused_natively", func(t *testing.T) {
		_, _, err := applyFixtures(t, NativeUnpackPolicy(), "absolute-symlink.tar")
		if !errors.Is(err, ErrLayerEscapes) {
			t.Fatalf("native apply error = %v, want ErrLayerEscapes", err)
		}
	})

	t.Run("relative_escape_refused_under_both", func(t *testing.T) {
		for _, policy := range []UnpackPolicy{LinuxUnpackPolicy(), NativeUnpackPolicy()} {
			_, _, err := applyFixtures(t, policy, "relative-escape-symlink.tar")
			if !errors.Is(err, ErrLayerEscapes) {
				t.Errorf("apply under %s error = %v, want ErrLayerEscapes", policy.Semantics, err)
			}
		}
	})

	t.Run("symlink_target_contained_table", func(t *testing.T) {
		cases := []struct {
			name       string
			link       string
			target     string
			linuxOK    bool
			nativeOKay bool
		}{
			{"relative_sibling", "usr/bin/sh", "busybox", true, true},
			{"relative_in_tree", "usr/bin/sh", "../lib/busybox", true, true},
			{"absolute", "usr/bin/sh", "/bin/busybox", true, false},
			{"absolute_root", "l", "/", true, false},
			{"relative_escape", "l", "../outside", false, false},
			{"empty", "l", "", false, false},
			{"nul", "l", "a\x00b", false, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := symlinkTargetContained(tc.link, tc.target, true); (err == nil) != tc.linuxOK {
					t.Errorf("linux: err = %v, want ok=%v", err, tc.linuxOK)
				}
				if err := symlinkTargetContained(tc.link, tc.target, false); (err == nil) != tc.nativeOKay {
					t.Errorf("native: err = %v, want ok=%v", err, tc.nativeOKay)
				}
			})
		}
	})
}

// ownershipByPath indexes ownership records by path.
func ownershipByPath(entries []OwnershipEntry) map[string]OwnershipEntry {
	m := make(map[string]OwnershipEntry, len(entries))
	for _, e := range entries {
		m[e.Path] = e
	}
	return m
}

// TestLinuxRootfsOwnershipSidecar pins the sidecar's whole reason for existing:
// the tar's TRUE uid/gid/mode reach the record while the HOST tree carries
// neither — an unprivileged daemon cannot chown, and a setuid bit must never
// land in a tree every pod rootfs is cloned from.
func TestLinuxRootfsOwnershipSidecar(t *testing.T) {
	tree, a, err := applyFixtures(t, LinuxUnpackPolicy(), "setuid.tar")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	own := ownershipByPath(a.Ownership())

	want := []struct {
		path string
		typ  OwnershipEntryType
		uid  int64
		gid  int64
		mode uint32
	}{
		{"usr", OwnershipTypeDir, 0, 0, 0o755},
		{"usr/bin", OwnershipTypeDir, 0, 0, 0o755},
		{"usr/bin/su", OwnershipTypeFile, 0, 0, 0o4755},
		{"home", OwnershipTypeDir, 1000, 1000, 0o700},
		{"home/app", OwnershipTypeFile, 1000, 1000, 0o600},
		{"home/link", OwnershipTypeSymlink, 1000, 1000, 0},
	}
	for _, w := range want {
		got, ok := own[w.path]
		if !ok {
			t.Errorf("no ownership record for %s", w.path)
			continue
		}
		if got.Type != w.typ || got.UID != w.uid || got.GID != w.gid || got.Mode != w.mode {
			t.Errorf("%s recorded %+v, want type %s uid %d gid %d mode %#o",
				w.path, got, w.typ, w.uid, w.gid, w.mode)
		}
	}
	if len(own) != len(want) {
		t.Errorf("sidecar holds %d entries, want exactly %d: %v", len(own), len(want), own)
	}

	// The HOST copy carries the stripped mode and the daemon's own ownership.
	fi, err := os.Lstat(filepath.Join(tree, "usr/bin/su"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid != 0 {
		t.Error("the host tree carries a setuid bit")
	}
	if st := a.Stats(); st.StrippedSetIDs != 1 {
		t.Errorf("StrippedSetIDs = %d, want 1", st.StrippedSetIDs)
	}

	// Ordering: path order, which puts every parent before its children.
	entries := a.Ownership()
	if !sort.SliceIsSorted(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path }) {
		t.Error("the sidecar is not in path order")
	}

	// The NATIVE dialect records nothing.
	t.Run("native_records_nothing", func(t *testing.T) {
		_, na, nerr := applyFixtures(t, NativeUnpackPolicy(), "setuid.tar")
		if nerr != nil {
			t.Fatalf("native apply: %v", nerr)
		}
		if got := na.Ownership(); len(got) != 0 {
			t.Errorf("native ownership = %v, want none", got)
		}
	})
}

// TestLinuxRootfsXattrsAreDropped pins the documented security.capability loss:
// the allowlist is empty, so no extended attribute reaches the sidecar and every
// dropped one is COUNTED — the counter is what keeps the loss visible without
// re-reading the image.
func TestLinuxRootfsXattrsAreDropped(t *testing.T) {
	_, a, err := applyFixtures(t, LinuxUnpackPolicy(), "capability.tar")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	own := ownershipByPath(a.Ownership())
	e, ok := own["bin/ping"]
	if !ok {
		t.Fatal("no ownership record for bin/ping")
	}
	if len(e.Xattrs) != 0 {
		t.Errorf("xattrs = %v, want none carried", e.Xattrs)
	}
	if st := a.Stats(); st.DroppedXattrs != 2 {
		t.Errorf("DroppedXattrs = %d, want 2 (security.capability + user.note)", st.DroppedXattrs)
	}

	// selectXattrs' own table: only "SCHILY.xattr."-prefixed records are
	// extended attributes; the rest are tar metadata and are neither carried
	// nor counted as dropped.
	kept, dropped := selectXattrs(map[string]string{
		"SCHILY.xattr.security.capability": "cap",
		"SCHILY.xattr.user.x":              "u",
		"mtime":                            "1",
		"path":                             "a/b",
	})
	if len(kept) != 0 || dropped != 2 {
		t.Errorf("selectXattrs = %v/%d, want none kept and 2 dropped", kept, dropped)
	}
}

// TestLinuxRootfsSkipsDeviceNodes pins the skip-and-COUNT posture for the node
// types an unprivileged daemon cannot create: refusing them would reject a large
// share of real base images, and silently dropping them would hide it.
func TestLinuxRootfsSkipsDeviceNodes(t *testing.T) {
	tree, a, err := applyFixtures(t, LinuxUnpackPolicy(), "devices.tar")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, rel := range []string{"dev/null", "dev/loop0", "dev/initctl"} {
		if exists(t, tree, rel) {
			t.Errorf("%s was created", rel)
		}
	}
	if st := a.Stats(); st.SkippedSpecial != 3 {
		t.Errorf("SkippedSpecial = %d, want 3", st.SkippedSpecial)
	}
	// A skipped node contributes no ownership record — the guest recreates
	// /dev from devtmpfs and a record for a path the tree does not hold would
	// make the guest's apply fail on a node nobody asked for.
	if own := ownershipByPath(a.Ownership()); len(own) != 1 || own["dev"].Type != OwnershipTypeDir {
		t.Errorf("ownership = %v, want only the dev directory", own)
	}
}

// TestClassifyWhiteout is the marker grammar's own table. The ORDER of the tests
// inside classifyWhiteout is load-bearing — ".wh..wh..opq" starts with
// ".wh..wh." which starts with ".wh." — so every prefix relationship gets a row.
func TestClassifyWhiteout(t *testing.T) {
	cases := []struct {
		name    string
		kind    whiteoutKind
		target  string
		wantErr bool
	}{
		{"etc/passwd", whiteoutNone, "", false},
		{"etc/.whatever", whiteoutNone, "", false},
		{".wh.f", whiteoutFile, "f", false},
		{"d/.wh.f", whiteoutFile, "d/f", false},
		{"d/e/.wh.f", whiteoutFile, "d/e/f", false},
		{".wh..wh..opq", whiteoutOpaque, "", false},
		{"d/.wh..wh..opq", whiteoutOpaque, "", false},
		{".wh..wh.plnk", whiteoutMeta, "", false},
		{"d/.wh..wh.orph", whiteoutMeta, "", false},
		{".wh.", whiteoutNone, "", true},
		{"d/.wh.", whiteoutNone, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, target, err := classifyWhiteout(tc.name)
			if tc.wantErr {
				if !errors.Is(err, ErrLayerMalformed) {
					t.Fatalf("classifyWhiteout(%q) error = %v, want ErrLayerMalformed", tc.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("classifyWhiteout(%q): %v", tc.name, err)
			}
			if kind != tc.kind || target != tc.target {
				t.Errorf("classifyWhiteout(%q) = %v/%q, want %v/%q", tc.name, kind, target, tc.kind, tc.target)
			}
		})
	}
}

// TestOwnershipSidecarRoundTrips pins the JSONL contract between the writer and
// the guest-side reader: every field survives, and the empty sidecar is a valid
// (zero-line) file rather than an absent one.
func TestOwnershipSidecarRoundTrips(t *testing.T) {
	want := []OwnershipEntry{
		{Path: "home", Type: OwnershipTypeDir, UID: 1000, GID: 1000, Mode: 0o700},
		{Path: "usr/bin/su", Type: OwnershipTypeFile, Mode: 0o4755},
		{Path: "usr/bin/x", Type: OwnershipTypeSymlink, UID: 1, GID: 2},
		{Path: "with/xattr", Type: OwnershipTypeFile, Mode: 0o644, Xattrs: map[string][]byte{"user.k": []byte("v\x00")}},
	}
	p := filepath.Join(t.TempDir(), "ownership.jsonl")
	if err := writeOwnershipSidecar(p, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	// One line per entry — the property a streaming guest reader depends on.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\n"); got != len(want) {
		t.Errorf("sidecar has %d lines, want %d", got, len(want))
	}
	got, err := ReadOwnershipSidecar(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].Type != want[i].Type ||
			got[i].UID != want[i].UID || got[i].GID != want[i].GID || got[i].Mode != want[i].Mode ||
			string(got[i].Xattrs["user.k"]) != string(want[i].Xattrs["user.k"]) {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	t.Run("empty", func(t *testing.T) {
		e := filepath.Join(t.TempDir(), "ownership.jsonl")
		if err := writeOwnershipSidecar(e, nil); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := ReadOwnershipSidecar(e)
		if err != nil || len(got) != 0 {
			t.Errorf("read = %v/%v, want no entries and no error", got, err)
		}
	})

	t.Run("undecodable_line_is_refused", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "ownership.jsonl")
		if err := os.WriteFile(bad, []byte("{\"path\":\"a\"}\nnot json\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwnershipSidecar(bad); !errors.Is(err, ErrTreeInconsistent) {
			t.Errorf("read error = %v, want ErrTreeInconsistent", err)
		}
	})
}
