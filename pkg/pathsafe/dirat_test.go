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

package pathsafe

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpenDirFrom pins what the descriptor walk refuses and creates: a symlink
// component (ELOOP, even though Darwin answers ENOTDIR for it), a file
// component (ENOTDIR), a ".." (outside the root), and a missing component
// (not-exist, or created when asked). Nothing is created through a link.
func TestOpenDirFrom(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	for _, d := range []string{"a/b", "real"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	bfd, err := unix.Open(base, DirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(bfd)
	for _, tc := range []struct {
		rel    string
		create bool
		want   []error
	}{
		{"a/b", false, nil},
		{"link/x", true, []error{ErrSymlinkedPath, unix.ELOOP}},
		{"file/x", true, []error{ErrSymlinkedPath, unix.ENOTDIR}},
		{"a/../..", false, []error{ErrPathOutsideRoot}},
		{"missing/x", false, []error{fs.ErrNotExist}},
		{"real/new/deeper", true, nil},
	} {
		fd, err := OpenDirFrom(bfd, base, tc.rel, tc.create, 0o755)
		if fd >= 0 {
			unix.Close(fd)
		}
		if tc.want == nil && err != nil {
			t.Errorf("OpenDirFrom(%q) = %v, want nil", tc.rel, err)
		}
		for _, w := range tc.want {
			if !errors.Is(err, w) {
				t.Errorf("OpenDirFrom(%q) = %v, want it to wrap %v", tc.rel, err, w)
			}
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("something was created through the link: %v", ents)
	}
	if fi, err := os.Stat(filepath.Join(base, "real/new/deeper")); err != nil || !fi.IsDir() {
		t.Errorf("the missing components were not created: %v", err)
	}
}
