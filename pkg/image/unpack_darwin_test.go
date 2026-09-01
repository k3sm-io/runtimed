//go:build darwin

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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestUnpackQuarantineDiscipline pins the com.apple.quarantine invariant across
// the two places the unpacker is responsible for it.
//
// The invariant matters because a quarantined file is one Gatekeeper will refuse
// to exec (or will prompt about, which on a headless node is the same thing), so
// an image whose payload carried the attribute would produce a pod that fails at
// spawn with no legible cause. The unpacker asserts it at the TREE — once per
// image — and MaterializeTree re-asserts it on every pod copy.
//
// It is darwin-only because assertNoQuarantine is a no-op elsewhere: there is no
// attribute to set, so the same test off darwin would assert nothing and pass.
func TestUnpackQuarantineDiscipline(t *testing.T) {
	// A real APFSCloner, not ByteCopier: unix.Clonefile carries xattrs across
	// with the extents, which is precisely why the assertion is needed on the
	// destination. A byte copy would silently launder the attribute and the
	// negative case below would be vacuous.
	c, u := newTestUnpacker(t, WithCloner(APFSCloner{}))
	mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{
		{name: "app", mode: 0o755, data: "V1"},
		{name: "usr", typ: tar.TypeDir, mode: 0o755},
		{name: "usr/lib", mode: 0o644, data: "LIB"},
	})))

	tree, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	t.Run("the_unpacked_tree_carries_no_quarantine", func(t *testing.T) {
		for _, rel := range []string{"app", "usr/lib"} {
			p := filepath.Join(tree.Rootfs, rel)
			if _, err := unix.Getxattr(p, QuarantineXattr, nil); err == nil {
				t.Errorf("%s carries %s", rel, QuarantineXattr)
			}
			if err := assertNoQuarantine(p); err != nil {
				t.Errorf("assertNoQuarantine(%s): %v", rel, err)
			}
		}
	})

	t.Run("a_clean_tree_materializes", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "rootfs")
		if _, err := u.MaterializeTree(context.Background(), mfst, NativeUnpackPolicy(), dst); err != nil {
			t.Fatalf("MaterializeTree: %v", err)
		}
		if got := readTree(t, dst, "app"); got != "V1" {
			t.Errorf("materialized app = %q, want V1", got)
		}
	})

	t.Run("a_quarantined_tree_file_refuses_to_materialize", func(t *testing.T) {
		// Plant the attribute on the committed tree after the unpack, which is
		// the only way it can arrive here (the applier creates every file itself
		// and asserts the attribute's absence as it goes).
		if err := unix.Setxattr(filepath.Join(tree.Rootfs, "app"), QuarantineXattr,
			[]byte("0081;00000000;k3sm-test;"), 0); err != nil {
			t.Skipf("cannot set %s on this filesystem: %v", QuarantineXattr, err)
		}
		t.Cleanup(func() {
			_ = unix.Removexattr(filepath.Join(tree.Rootfs, "app"), QuarantineXattr)
		})
		dst := filepath.Join(t.TempDir(), "rootfs")
		_, err := u.MaterializeTree(context.Background(), mfst, NativeUnpackPolicy(), dst)
		if !errors.Is(err, ErrQuarantined) {
			// A byte-copy fallback (a non-APFS temp volume) launders the
			// attribute, so distinguish that from a real miss.
			if _, serr := os.Lstat(filepath.Join(dst, "app")); serr == nil {
				if _, gerr := unix.Getxattr(filepath.Join(dst, "app"), QuarantineXattr, nil); gerr != nil {
					t.Skipf("the clone did not carry the xattr (byte-copy fallback on %s)", dst)
				}
			}
			t.Fatalf("MaterializeTree error = %v, want ErrQuarantined", err)
		}
	})
}
