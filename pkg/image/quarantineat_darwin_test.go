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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAssertNoQuarantineAtNeedsNoReadPermission gates the descriptor-relative
// quarantine check on an entry its unprivileged caller cannot open for
// reading: a 0o200 regular file returns nil whether or not it is quarantined
// (its attribute cannot be read without read permission, and no path is
// re-resolved to try), and a non-regular entry returns ErrDestinationLink.
func TestAssertNoQuarantineAtNeedsNoReadPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the read-permission check this test exercises")
	}
	dirPath := t.TempDir()
	clean := filepath.Join(dirPath, "clean")
	quarantined := filepath.Join(dirPath, "quarantined")
	for _, p := range []string{clean, quarantined} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Setxattr(quarantined, QuarantineXattr, []byte("0081;00000000;test;"), 0); err != nil {
		t.Skipf("cannot set quarantine xattr: %v", err)
	}
	for _, p := range []string{clean, quarantined} {
		if err := os.Chmod(p, 0o200); err != nil {
			t.Fatal(err)
		}
	}
	sub := filepath.Join(dirPath, "sub")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	dir, err := os.Open(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for _, name := range []string{"clean", "quarantined", "sub"} {
		if _, err := openNoFollowAt(dir, name); !errors.Is(err, unix.EACCES) {
			t.Fatalf("O_RDONLY open of unreadable %s: err = %v, want EACCES (the case the fallback covers)", name, err)
		}
	}
	if err := assertNoQuarantineAt(dir, "clean"); err != nil {
		t.Fatalf("assertNoQuarantineAt on an unreadable clean file: %v, want nil", err)
	}
	if err := assertNoQuarantineAt(dir, "quarantined"); err != nil {
		t.Fatalf("assertNoQuarantineAt on an unreadable quarantined file: %v, want nil", err)
	}
	if err := assertNoQuarantineAt(dir, "sub"); !errors.Is(err, ErrDestinationLink) {
		t.Fatalf("assertNoQuarantineAt on an unreadable non-regular entry: err = %v, want ErrDestinationLink", err)
	}

	// Through MaterializeTree: a re-materialize over a destination that
	// already holds a 0o200 file runs the check on it and must not fail.
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "wo"), "w", 0o644)
	mustWrite(t, filepath.Join(dst, "wo"), "w", 0o644)
	if err := os.Chmod(filepath.Join(dst, "wo"), 0o200); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Cloner{"byte": ByteCopier{}, "apfs": APFSCloner{}} {
		if _, err := MaterializeTree(c, src, dst); err != nil {
			t.Fatalf("%s: re-materialize over a 0o200 destination file: %v", name, err)
		}
	}
}
