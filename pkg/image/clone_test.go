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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// TestMaterializeTree checks the recursive materializer: it reproduces the tree
// (dirs, regular files, symlinks), is idempotent on a second run, and reports the
// clone count. Uses ByteCopier so the unit test is portable; real APFS CoW is in
// the integration test.
func TestMaterializeTree(t *testing.T) {
	src := t.TempDir()
	// build: bin/app (regular), lib/data.txt, link -> bin/app
	mustWrite(t, filepath.Join(src, "bin", "app"), "binary", 0o755)
	mustWrite(t, filepath.Join(src, "lib", "data.txt"), "payload", 0o644)
	if err := os.Symlink(filepath.Join(src, "bin", "app"), filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "rootfs")
	cloned, err := MaterializeTree(ByteCopier{}, src, dst)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if cloned != 0 {
		t.Errorf("ByteCopier should report 0 clones, got %d", cloned)
	}

	if got := readFile(t, filepath.Join(dst, "bin", "app")); got != "binary" {
		t.Errorf("bin/app = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "lib", "data.txt")); got != "payload" {
		t.Errorf("lib/data.txt = %q", got)
	}
	if fi, err := os.Lstat(filepath.Join(dst, "link")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link not materialized as symlink: %v %v", fi, err)
	}
	// mode preserved.
	if fi, _ := os.Stat(filepath.Join(dst, "bin", "app")); fi.Mode().Perm() != 0o755 {
		t.Errorf("bin/app mode = %v, want 0755", fi.Mode().Perm())
	}

	// Idempotent: a second run does not error and overwrites nothing.
	if _, err := MaterializeTree(ByteCopier{}, src, dst); err != nil {
		t.Fatalf("second materialize: %v", err)
	}
}

// TestByteCopierExclusive checks Clone refuses to clobber an existing dst.
func TestByteCopierExclusive(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	mustWrite(t, src, "x", 0o644)
	mustWrite(t, dst, "y", 0o644)
	if _, err := (ByteCopier{}).Clone(src, dst); err == nil {
		t.Fatal("Clone should refuse to overwrite an existing dst")
	}
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestCloneOnlyClonesOrRefuses pins the clone-only cloner: the errnos that
// mean "this volume cannot clone" are what IsCloneUnsupported reports and a
// permission error is not, and on darwin a same-volume clone succeeds as a
// clone; off darwin every clone is refused as unsupported, with nothing
// written.
func TestCloneOnlyClonesOrRefuses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{syscall.EXDEV, true},
		{syscall.ENOTSUP, true},
		{syscall.EOPNOTSUPP, true},
		{fmt.Errorf("wrapped: %w", &os.LinkError{Op: "clonefile", Err: syscall.EXDEV}), true},
		{syscall.EACCES, false},
		{syscall.EEXIST, false},
	} {
		if got := IsCloneUnsupported(tc.err); got != tc.want {
			t.Errorf("IsCloneUnsupported(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	mustWrite(t, src, "payload", 0o644)
	cow, err := CloneOnly{}.Clone(src, dst)
	if runtime.GOOS != "darwin" {
		if !IsCloneUnsupported(err) || cow {
			t.Fatalf("CloneOnly off darwin = %v, %v; want an unsupported refusal", cow, err)
		}
		if _, serr := os.Lstat(dst); !errors.Is(serr, os.ErrNotExist) {
			t.Errorf("a refused clone left %s: %v", dst, serr)
		}
		return
	}
	if err != nil || !cow {
		t.Fatalf("CloneOnly on one APFS volume = %v, %v; want a clone", cow, err)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "payload" {
		t.Errorf("clone reads %q, %v", got, err)
	}
}
