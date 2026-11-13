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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// errInjectedRead is the read failure the failing copy reports part-way.
var errInjectedRead = errors.New("injected source read failure")

// failingReader yields the first n bytes of r, then fails.
type failingReader struct {
	r io.Reader
	n int64
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errInjectedRead
	}
	if int64(len(p)) > f.n {
		p = p[:f.n]
	}
	n, err := f.r.Read(p)
	f.n -= int64(n)
	return n, err
}

// TestByteCopyFailureLeavesNoPartialFile checks that when the source read fails
// part-way through the byte-copy fallback, neither byteCopyAt (through
// MaterializeTree) nor byteCopyFile (through ByteCopier.Clone) leaves a
// truncated file at the destination, so a later materialization, which keeps
// any existing regular file, copies the file whole.
func TestByteCopyFailureLeavesNoPartialFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	dst := filepath.Join(tmp, "dst")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	srcFile := filepath.Join(src, "f")
	if err := os.WriteFile(srcFile, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := copyContent
	copyContent = func(w io.Writer, r io.Reader) (int64, error) {
		return io.Copy(w, &failingReader{r: r, n: int64(len(payload) / 2)})
	}
	restored := false
	restore := func() {
		if !restored {
			copyContent = orig
			restored = true
		}
	}
	defer restore()

	if _, err := MaterializeTree(ByteCopier{}, src, dst); !errors.Is(err, errInjectedRead) {
		t.Fatalf("MaterializeTree with a failing read: err = %v, want %v", err, errInjectedRead)
	}
	if _, err := os.Lstat(filepath.Join(dst, "f")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("byteCopyAt left a partial file after a failed read: lstat err = %v", err)
	}

	cloneDst := filepath.Join(tmp, "clone-f")
	if _, err := (ByteCopier{}).Clone(srcFile, cloneDst); !errors.Is(err, errInjectedRead) {
		t.Fatalf("ByteCopier.Clone with a failing read: err = %v, want %v", err, errInjectedRead)
	}
	if _, err := os.Lstat(cloneDst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("byteCopyFile left a partial file after a failed read: lstat err = %v", err)
	}

	restore()
	if _, err := MaterializeTree(ByteCopier{}, src, dst); err != nil {
		t.Fatalf("second MaterializeTree: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "f"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("second materialization: got %d bytes, want the whole %d-byte file", len(got), len(payload))
	}
}

// TestByteCopyFileFailureRemovesOnlyItsOwnFile checks that the cleanup after a
// failed byte copy removes only the file byteCopyFile created: when the
// destination name is swapped for an empty directory before the copy fails,
// the directory survives (a by-path os.Remove would rmdir it) and the returned
// error still carries the copy failure.
func TestByteCopyFileFailureRemovesOnlyItsOwnFile(t *testing.T) {
	tmp := t.TempDir()
	srcFile := filepath.Join(tmp, "src")
	if err := os.WriteFile(srcFile, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(tmp, "dst")

	orig := copyContent
	copyContent = func(io.Writer, io.Reader) (int64, error) {
		if err := os.Remove(dst); err != nil {
			t.Errorf("remove created file: %v", err)
		}
		if err := os.Mkdir(dst, 0o755); err != nil {
			t.Errorf("mkdir in its place: %v", err)
		}
		return 0, errInjectedRead
	}
	defer func() { copyContent = orig }()

	if err := byteCopyFile(srcFile, dst); !errors.Is(err, errInjectedRead) {
		t.Fatalf("byteCopyFile with a failing copy: err = %v, want %v", err, errInjectedRead)
	}
	info, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("the directory swapped in at the destination was removed: lstat err = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("destination mode = %v, want the swapped-in directory", info.Mode())
	}
}

// TestByteCopyFileMissingSourceCreatesNoParent checks a missing source fails
// before the destination's parent directory is created.
func TestByteCopyFileMissingSourceCreatesNoParent(t *testing.T) {
	tmp := t.TempDir()
	newdir := filepath.Join(tmp, "newdir")
	if _, err := (ByteCopier{}).Clone(filepath.Join(tmp, "missing"), filepath.Join(newdir, "f")); err == nil {
		t.Fatal("Clone of a missing source returned nil error")
	}
	if _, err := os.Lstat(newdir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("parent %s exists after failed clone: err = %v", newdir, err)
	}
}

// TestByteCopyFileSourceOpenBeforeParent checks a missing or unreadable source
// fails with its own error identity and leaves no new parent directory, and a
// readable source still copies and creates the parent.
func TestByteCopyFileSourceOpenBeforeParent(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, tmp string) string
		wantErr error
	}{
		{"missing-source", func(t *testing.T, tmp string) string {
			return filepath.Join(tmp, "missing")
		}, os.ErrNotExist},
		{"unreadable-source", func(t *testing.T, tmp string) string {
			if os.Geteuid() == 0 {
				t.Skip("root can read a mode 000 file")
			}
			src := filepath.Join(tmp, "src")
			if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(src, 0); err != nil {
				t.Fatal(err)
			}
			return src
		}, os.ErrPermission},
		{"readable-source", func(t *testing.T, tmp string) string {
			src := filepath.Join(tmp, "src")
			if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			return src
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			src := tc.prepare(t, tmp)
			newdir := filepath.Join(tmp, "newdir")
			dst := filepath.Join(newdir, "f")
			err := byteCopyFile(src, dst)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("byteCopyFile: %v", err)
				}
				got, rerr := os.ReadFile(dst)
				if rerr != nil || string(got) != "data" {
					t.Fatalf("destination = %q, %v; want data", got, rerr)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErr)
			}
			if _, serr := os.Lstat(newdir); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("parent %s exists after failed copy: err = %v", newdir, serr)
			}
		})
	}
}
