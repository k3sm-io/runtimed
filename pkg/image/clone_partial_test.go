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
