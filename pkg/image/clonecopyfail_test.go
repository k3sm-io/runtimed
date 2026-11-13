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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestByteCopyFailureLeavesNoPartialFile gates the byte-copy failure path: a
// copy that fails partway through removes the short file it created, so the
// next materialize copies the whole file instead of keeping the short one as
// already materialized. It swaps copyFn, so it must not run in parallel.
func TestByteCopyFailureLeavesNoPartialFile(t *testing.T) {
	errInjected := errors.New("injected copy failure")
	content := strings.Repeat("payload ", 4096)
	failPartway := func(dst io.Writer, src io.Reader) (int64, error) {
		n, err := io.CopyN(dst, src, 100)
		if err != nil {
			return n, err
		}
		return n, errInjected
	}

	for name, run := range map[string]func(src, dst string) error{
		"materialize_tree": func(src, dst string) error {
			_, err := MaterializeTree(ByteCopier{}, src, dst)
			return err
		},
		"clone_by_path": func(src, dst string) error {
			_, err := ByteCopier{}.Clone(filepath.Join(src, "file"), filepath.Join(dst, "file"))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			mustWrite(t, filepath.Join(src, "file"), content, 0o644)
			target := filepath.Join(dst, "file")

			copyFn = failPartway
			t.Cleanup(func() { copyFn = io.Copy })
			if err := run(src, dst); !errors.Is(err, errInjected) {
				t.Fatalf("err = %v, want the injected copy failure", err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("lstat %s after failed copy: err = %v, want not-exist (a short file was left)", target, err)
			}

			copyFn = io.Copy
			if err := run(src, dst); err != nil {
				t.Fatalf("materialize after the failed one: %v", err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != content {
				t.Fatalf("content after re-materialize: %d bytes, want %d", len(got), len(content))
			}
		})
	}
}
