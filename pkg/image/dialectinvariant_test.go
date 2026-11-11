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
	"syscall"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestUnpackPolicyForCoversEverySandboxBackend walks the generated enum map, so
// a backend added to the proto cannot slip past the dialect decision: every
// value must have an explicit row here, VM is the only linux backend, and an
// out-of-range value fails closed.
func TestUnpackPolicyForCoversEverySandboxBackend(t *testing.T) {
	type outcome int
	const (
		native outcome = iota + 1
		linux
		unsupported
	)
	want := map[runtimev1.SandboxBackend]outcome{
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED:     unsupported,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC:   native,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC: native,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL:         native,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_VM:              linux,
		// Today's error is an incidental default: a wasm image stops in the
		// puller before any unpack. Flip this row deliberately when the wasm
		// pull path lands.
		runtimev1.SandboxBackend_SANDBOX_BACKEND_WASM: unsupported,
	}

	var maxValue int32
	linuxCount := 0
	for v, name := range runtimev1.SandboxBackend_name {
		maxValue = max(maxValue, v)
		backend := runtimev1.SandboxBackend(v)
		exp, ok := want[backend]
		if !ok {
			t.Errorf("sandbox backend %s (%d) has no row in the want table: decide that backend's layer dialect before adding it", name, v)
			continue
		}
		got, err := UnpackPolicyFor(backend)
		switch exp {
		case unsupported:
			if !errors.Is(err, ErrUnsupportedLayerSemantics) {
				t.Errorf("UnpackPolicyFor(%s) = %+v, %v; want ErrUnsupportedLayerSemantics", name, got, err)
			}
		case native, linux:
			wantPolicy := NativeUnpackPolicy()
			if exp == linux {
				wantPolicy = LinuxUnpackPolicy()
			}
			if err != nil || got != wantPolicy {
				t.Errorf("UnpackPolicyFor(%s) = %+v, %v; want %+v", name, got, err, wantPolicy)
			}
		}
		if err == nil && got == LinuxUnpackPolicy() {
			linuxCount++
			if backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
				t.Errorf("UnpackPolicyFor(%s) yields the linux policy; only SANDBOX_BACKEND_VM may", name)
			}
		}
	}
	if linuxCount != 1 {
		t.Errorf("%d backends yield the linux policy, want exactly 1 (SANDBOX_BACKEND_VM)", linuxCount)
	}

	outOfRange := runtimev1.SandboxBackend(maxValue + 1)
	if _, err := UnpackPolicyFor(outOfRange); !errors.Is(err, ErrUnsupportedLayerSemantics) {
		t.Errorf("UnpackPolicyFor(%d) error = %v, want ErrUnsupportedLayerSemantics", int32(outOfRange), err)
	}
}

// TestTreeKeyBindsDialect pins that the dialect is an input to the tree key: the
// same manifest unpacked under the native and the linux policy names two
// distinct trees, so one dialect's tree is never served for the other.
func TestTreeKeyBindsDialect(t *testing.T) {
	mfst := &runtimev1.ImageManifest{
		Config: &runtimev1.Descriptor{Digest: "sha256:" + hexOf('a')},
		Layers: []*runtimev1.Descriptor{{Digest: "sha256:" + hexOf('1')}},
	}
	nativeKey, err := TreeKey(mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("TreeKey native: %v", err)
	}
	linuxKey, err := TreeKey(mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("TreeKey linux: %v", err)
	}
	if nativeKey == linuxKey {
		t.Fatalf("TreeKey is %q under both the native and the linux policy; the dialect must be bound into the key", nativeKey)
	}
}

// pathRecordingSigner records the full path of every verify and sign call and
// reports every file unsigned, so AdHocSignTree takes its signing path for each
// Mach-O it reaches.
type pathRecordingSigner struct {
	paths []string
}

func (s *pathRecordingSigner) VerifyArch(_ context.Context, path, _ string) (bool, error) {
	s.paths = append(s.paths, path)
	return false, nil
}

func (s *pathRecordingSigner) Sign(_ context.Context, path string) error {
	s.paths = append(s.paths, path)
	return nil
}

// within reports whether path is root or lies under it, lexically.
func within(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// TestLinuxDialectAbsoluteLinkIsNeverFollowedHostSide is the gate for the
// invariant the linux dialect's absolute-symlink admission rests on: the links
// are admitted because only the guest, chrooted into the tree, resolves them,
// so every host-side reader in this package must treat them as opaque names.
//
// The tree carries "a -> /", "b -> a/etc" (relative, but resolving through a
// to the host's /etc) and absolute links to a canary Mach-O, a canary FIFO and
// their directory outside the tree. Unpack, MaterializeTree, AdHocSignTree and
// the tree prune are driven over it, and the canary must come out byte-for-byte
// and mtime-for-mtime untouched, with no path outside the tree in any output.
// The FIFO makes a read-only follow visible: opening it for reading blocks, so a
// reader that opens through the link hangs and the sign subtest times it out.
//
// What this gates is mainly the SOURCE side: every reader of the tree.
// populated_destination pins that MaterializeTree refuses, rather than
// follows, a link already planted in the destination (the full destination
// gate is TestMaterializeTreeNeverWritesThroughADestinationLink), and
// write_through_across_layers pins that a later layer's entries do not resolve
// through an earlier layer's link at unpack time.
func TestLinuxDialectAbsoluteLinkIsNeverFollowedHostSide(t *testing.T) {
	outside := t.TempDir()
	canary := filepath.Join(outside, "canary")
	thinMachO(t, canary)
	fifo := filepath.Join(outside, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	canaryBytes, err := os.ReadFile(canary)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(canary, old, old); err != nil {
		t.Fatal(err)
	}
	assertCanary := func(t *testing.T, stage string) {
		t.Helper()
		fi, err := os.Lstat(canary)
		if err != nil {
			t.Fatalf("%s: canary gone: %v", stage, err)
		}
		if !fi.ModTime().Equal(old) {
			t.Errorf("%s: canary mtime = %v, want %v: a host reader wrote through a link", stage, fi.ModTime(), old)
		}
		got, err := os.ReadFile(canary)
		if err != nil || !bytes.Equal(got, canaryBytes) {
			t.Errorf("%s: canary content changed (err %v)", stage, err)
		}
		if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&fs.ModeNamedPipe == 0 {
			t.Errorf("%s: canary fifo = %v, %v; want it still a FIFO", stage, fi, err)
		}
		ents, err := os.ReadDir(outside)
		if err != nil || len(ents) != 2 {
			t.Errorf("%s: directory outside the tree holds %d entries (err %v), want only the canary and the fifo", stage, len(ents), err)
		}
	}

	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, linuxImageFrom(t, layerFrom(t, []tarSpec{
		{name: "etc", typ: tar.TypeDir, mode: 0o755},
		{name: "etc/hostname", mode: 0o644, data: "guest"},
		{name: "a", typ: tar.TypeSymlink, link: "/"},
		{name: "b", typ: tar.TypeSymlink, link: "a/etc"},
		{name: "canary", typ: tar.TypeSymlink, link: canary},
		{name: "canaryfifo", typ: tar.TypeSymlink, link: fifo},
		{name: "canarydir", typ: tar.TypeSymlink, link: outside},
	})))

	tree, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("linux Unpack: %v", err)
	}
	if tree.Stats.Symlinks != 5 {
		t.Fatalf("Symlinks = %d, want 5: the fixture did not land as written", tree.Stats.Symlinks)
	}
	cacheRoot := filepath.Dir(c.SnapshotsRoot())
	for _, p := range []string{tree.Rootfs, tree.Ownership} {
		if !within(p, cacheRoot) {
			t.Errorf("tree path %s is outside the cache root %s", p, cacheRoot)
		}
	}
	entries, err := ReadOwnershipSidecar(tree.Ownership)
	if err != nil {
		t.Fatalf("ReadOwnershipSidecar: %v", err)
	}
	for _, e := range entries {
		if filepath.IsAbs(e.Path) || strings.HasPrefix(e.Path, "..") {
			t.Errorf("ownership entry %q is not tree-relative", e.Path)
		}
	}
	assertCanary(t, "unpack")

	t.Run("materialize", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "rootfs")
		for i := range 2 { // the second pass is the idempotent branch
			if _, err := u.MaterializeTree(context.Background(), mfst, LinuxUnpackPolicy(), dst); err != nil {
				t.Fatalf("MaterializeTree pass %d: %v", i, err)
			}
		}
		for name, want := range map[string]string{"a": "/", "b": "a/etc", "canary": canary, "canaryfifo": fifo, "canarydir": outside} {
			fi, err := os.Lstat(filepath.Join(dst, name))
			if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				t.Errorf("materialized %s: mode %v, err %v; want a symlink, not a copy of its target", name, fi, err)
				continue
			}
			if got, _ := os.Readlink(filepath.Join(dst, name)); got != want {
				t.Errorf("materialized %s -> %q, want %q verbatim", name, got, want)
			}
		}
		// Every regular file in the pod rootfs is one the tree holds: nothing
		// was copied in from behind a link.
		var regular []string
		if err := filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				rel, _ := filepath.Rel(dst, p)
				regular = append(regular, rel)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(regular) != 1 || regular[0] != filepath.Join("etc", "hostname") {
			t.Errorf("pod rootfs regular files = %v, want only etc/hostname", regular)
		}
		assertCanary(t, "materialize")
	})

	t.Run("sign", func(t *testing.T) {
		s := &pathRecordingSigner{}
		type result struct {
			stats TreeSignStats
			err   error
		}
		done := make(chan result, 1)
		go func() {
			stats, err := AdHocSignTree(context.Background(), s, runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK, tree.Rootfs)
			done <- result{stats, err}
		}()
		var res result
		select {
		case res = <-done:
		case <-time.After(5 * time.Second):
			// An open for reading of the FIFO blocks until a writer appears.
			// Be that writer, so the blocked reader sees EOF and returns.
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			<-done
			t.Fatalf("AdHocSignTree blocked: a reader opened the canary fifo through the tree's link")
		}
		stats, err := res.stats, res.err
		if err != nil {
			t.Fatalf("AdHocSignTree: %v", err)
		}
		if stats.MachO != 0 || stats.SkippedLinks != 5 {
			t.Errorf("stats = %+v, want 0 Mach-O and the 5 links skipped", stats)
		}
		for _, p := range s.paths {
			if !within(p, tree.Rootfs) {
				t.Errorf("signer reached %s, outside the tree %s", p, tree.Rootfs)
			}
		}
		if len(s.paths) != 0 {
			t.Errorf("signer was called on %v; the tree holds no Mach-O of its own", s.paths)
		}
		assertCanary(t, "sign")
	})

	t.Run("populated_destination", func(t *testing.T) {
		// A destination that already holds "etc -> <victim>" (a link a pod
		// planted in its own rootfs before a restart re-materializes into it):
		// MaterializeTree must refuse with ErrDestinationLink and write
		// nothing through the link.
		victim := t.TempDir()
		dst := filepath.Join(t.TempDir(), "rootfs")
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dst, "etc")); err != nil {
			t.Fatal(err)
		}
		_, err := u.MaterializeTree(context.Background(), mfst, LinuxUnpackPolicy(), dst)
		if !errors.Is(err, ErrDestinationLink) {
			t.Fatalf("MaterializeTree into a destination with a planted etc link: err = %v, want ErrDestinationLink", err)
		}
		if ents, rerr := os.ReadDir(victim); rerr != nil || len(ents) != 0 {
			t.Fatalf("victim holds %d entries (err %v), want none: the write went through the planted link", len(ents), rerr)
		}
		if fi, lerr := os.Lstat(filepath.Join(dst, "etc")); lerr != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("destination etc = %v, %v; want the planted link left in place", fi, lerr)
		}
		assertCanary(t, "populated destination")
	})

	t.Run("write_through_across_layers", func(t *testing.T) {
		// Layer 1 plants the links; each layer-2 variant then names a path
		// THROUGH one of them. The applier resolves entries inside the tree
		// (os.Root), so every variant fails the unpack with os.Root's "path
		// escapes from parent" refusal (wrapped, not ErrLayerEscapes: the
		// applier's lexical check passes and the os.Root walk is what stops it),
		// no tree is returned, and nothing outside the tree may be created,
		// linked or deleted. Each
		// variant is its own image so one refusal cannot mask the next. The
		// hard-link rule on its own is TestLinuxRootfsHardlinkContainment; this
		// is the cross-layer composition with admitted absolute symlinks.
		hostProbe := "k3sm-dialect-invariant-probe"
		layer1 := []tarSpec{
			{name: "etc", typ: tar.TypeDir, mode: 0o755},
			{name: "etc/hostname", mode: 0o644, data: "guest"},
			{name: "a", typ: tar.TypeSymlink, link: "/"},
			{name: "b", typ: tar.TypeSymlink, link: "a/etc"},
			{name: "c", typ: tar.TypeSymlink, link: outside},
		}
		for _, tc := range []struct {
			name   string
			layer2 []tarSpec
		}{
			{"file_through_absolute_root_link", []tarSpec{{name: "a/etc/" + hostProbe, mode: 0o644, data: "x"}}},
			{"file_through_absolute_dir_link", []tarSpec{{name: "c/" + hostProbe, mode: 0o644, data: "x"}}},
			{"dir_through_absolute_dir_link", []tarSpec{{name: "c/" + hostProbe, typ: tar.TypeDir, mode: 0o755}}},
			{"hardlink_target_through_link", []tarSpec{{name: "hl", typ: tar.TypeLink, link: "c/canary"}}},
			{"hardlink_name_through_link", []tarSpec{{name: "c/" + hostProbe, typ: tar.TypeLink, link: "etc/hostname"}}},
			{"whiteout_through_relative_link", []tarSpec{{name: "b/.wh.hosts", mode: 0o644}}},
			{"whiteout_through_absolute_dir_link", []tarSpec{{name: "c/.wh.canary", mode: 0o644}}},
			{"opaque_through_absolute_dir_link", []tarSpec{{name: "c/.wh..wh..opq", mode: 0o644}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c2, u2 := newTestUnpacker(t)
				m := commitImage(t, c2, linuxImageFrom(t, layerFrom(t, layer1), layerFrom(t, tc.layer2)))
				got, err := u2.Unpack(context.Background(), m, LinuxUnpackPolicy())
				if err == nil || got != nil || !strings.Contains(err.Error(), "path escapes from parent") {
					t.Errorf("Unpack = %+v, %v; want nil and os.Root's path-escape refusal", got, err)
				}
				for _, p := range []string{filepath.Join("/etc", hostProbe), filepath.Join(outside, hostProbe)} {
					if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
						t.Errorf("%s exists after the unpack (err %v): a layer wrote outside the tree", p, err)
					}
				}
				if _, err := os.Lstat("/etc/hosts"); err != nil {
					t.Errorf("host /etc/hosts after the unpack: %v", err)
				}
				assertCanary(t, tc.name)
			})
		}
	})

	t.Run("native_open_refuses_the_linux_tree", func(t *testing.T) {
		// The keys already differ (TestTreeKeyBindsDialect), so a native open of
		// this manifest misses the snapshot and builds its own tree, and the
		// native rules refuse the absolute links rather than serve them.
		if _, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy()); !errors.Is(err, ErrLayerEscapes) {
			t.Fatalf("native Unpack error = %v, want ErrLayerEscapes: the linux tree must not be served natively", err)
		}

		// Plant the linux tree, record and all, where the native key files, so
		// the only thing between it and a native pod is the record's policy.
		nativeKey, err := TreeKey(mfst, NativeUnpackPolicy())
		if err != nil {
			t.Fatal(err)
		}
		h, err := parseBlobDigest(nativeKey)
		if err != nil {
			t.Fatal(err)
		}
		planted := c.treeDir(h.Algorithm, h.Hex)
		if err := os.MkdirAll(filepath.Join(planted, TreeRootfsName), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(planted, TreeRootfsName, "a")); err != nil {
			t.Fatal(err)
		}
		rec := treeRecord{
			Version: treeRecordVersion,
			Key:     nativeKey,
			Policy:  LinuxUnpackPolicy(),
			Config:  mfst.GetConfig().GetDigest(),
		}
		for _, l := range mfst.GetLayers() {
			rec.Layers = append(rec.Layers, l.GetDigest())
		}
		if err := writeTreeRecord(filepath.Join(planted, TreeRecordName), rec); err != nil {
			t.Fatal(err)
		}
		got, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
		if !errors.Is(err, ErrTreeInconsistent) || got != nil {
			t.Fatalf("native Unpack over a linux-policy record = %+v, %v; want ErrTreeInconsistent", got, err)
		}
		if _, err := u.MaterializeTree(context.Background(), mfst, NativeUnpackPolicy(), filepath.Join(t.TempDir(), "rootfs")); !errors.Is(err, ErrTreeInconsistent) {
			t.Fatalf("native MaterializeTree over a linux-policy record error = %v, want ErrTreeInconsistent", err)
		}
		if err := os.RemoveAll(planted); err != nil {
			t.Fatal(err)
		}
		assertCanary(t, "native open")
	})

	t.Run("prune", func(t *testing.T) {
		trees, err := c.EnumerateTrees()
		if err != nil {
			t.Fatalf("EnumerateTrees: %v", err)
		}
		nodes, err := c.EnumerateBlobs()
		if err != nil {
			t.Fatalf("EnumerateBlobs: %v", err)
		}
		later := time.Now().Add(time.Hour)
		plan, err := PlanPrune(nodes, trees, nil, nil, time.Minute, later)
		if err != nil {
			t.Fatalf("PlanPrune: %v", err)
		}
		rep, err := c.ExecuteTreePrune(plan, time.Minute, later, nil)
		if err != nil {
			t.Fatalf("ExecuteTreePrune: %v", err)
		}
		if rep.Deleted != 1 {
			t.Fatalf("Deleted = %d, skipped %v; want the one linux tree removed", rep.Deleted, rep.Skipped)
		}
		if _, err := os.Lstat(tree.Rootfs); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("tree rootfs after prune: %v, want gone", err)
		}
		if _, err := os.Stat("/etc"); err != nil {
			t.Errorf("host /etc after prune: %v", err)
		}
		assertCanary(t, "prune")
	})
}
