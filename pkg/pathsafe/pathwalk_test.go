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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRefuseSymlinkedPath pins the shared primitive every vm path-creating
// site stands on.
//
// The two halves that matter are in tension, and the table holds both: an
// ABSENT component must pass (every caller is about to create it, and the first
// boot of every pod would fail otherwise), while a PRESENT component that is not
// a plain directory must fail (it is the one thing that can redirect the
// caller's next syscall somewhere it never named).
func TestRefuseSymlinkedPath(t *testing.T) {
	cases := []struct {
		name string
		// setup lays out a tree under a fresh temp dir and returns the root and
		// the path to check.
		setup func(t *testing.T, base string) (root, path string)
		want  error
		// refusedRel, when set, is the component the error must NAME, relative
		// to the base: a walk that reported the deepest link instead of the
		// first one would send an operator to the wrong path.
		refusedRel string
	}{
		{
			name: "a missing leaf is fine: the caller is about to create it",
			setup: func(t *testing.T, base string) (string, string) {
				mkdirAll(t, filepath.Join(base, "run", "vm"))
				return base, filepath.Join(base, "run", "vm", "p1")
			},
		},
		{
			name: "a missing ancestor ends the walk with no verdict on what is below it",
			setup: func(t *testing.T, base string) (string, string) {
				return base, filepath.Join(base, "run", "vm", "p1")
			},
		},
		{
			name:  "the root itself passes when it is a plain directory",
			setup: func(t *testing.T, base string) (string, string) { return base, base },
		},
		{
			name: "a symlinked ancestor is refused",
			setup: func(t *testing.T, base string) (string, string) {
				elsewhere := filepath.Join(base, "elsewhere")
				mkdirAll(t, filepath.Join(elsewhere, "p1"))
				mkdirAll(t, filepath.Join(base, "run"))
				symlink(t, elsewhere, filepath.Join(base, "run", "vm"))
				return base, filepath.Join(base, "run", "vm", "p1")
			},
			want: ErrSymlinkedPath,
		},
		{
			name: "a symlinked leaf is refused",
			setup: func(t *testing.T, base string) (string, string) {
				victim := filepath.Join(base, "victim")
				mkdirAll(t, victim)
				mkdirAll(t, filepath.Join(base, "run", "vm"))
				symlink(t, victim, filepath.Join(base, "run", "vm", "p1"))
				return base, filepath.Join(base, "run", "vm", "p1")
			},
			want: ErrSymlinkedPath,
		},
		{
			name: "a regular file where a directory belongs is refused",
			setup: func(t *testing.T, base string) (string, string) {
				mkdirAll(t, filepath.Join(base, "run"))
				writeFile(t, filepath.Join(base, "run", "vm"), "not a dir")
				return base, filepath.Join(base, "run", "vm", "p1")
			},
			want: ErrSymlinkedPath,
		},
		{
			name: "a symlinked ROOT is refused: the base is checked like any other component",
			setup: func(t *testing.T, base string) (string, string) {
				real := filepath.Join(base, "real")
				mkdirAll(t, filepath.Join(real, "p1"))
				link := filepath.Join(base, "link")
				symlink(t, real, link)
				return link, filepath.Join(link, "p1")
			},
			want: ErrSymlinkedPath,
		},
		{
			name: "an ancestor AND the leaf are both links: the walk stops at the ancestor",
			setup: func(t *testing.T, base string) (string, string) {
				victim := filepath.Join(base, "victim")
				mkdirAll(t, victim)
				elsewhere := filepath.Join(base, "elsewhere")
				mkdirAll(t, elsewhere)
				symlink(t, victim, filepath.Join(elsewhere, "p1"))
				mkdirAll(t, filepath.Join(base, "run"))
				symlink(t, elsewhere, filepath.Join(base, "run", "vm"))
				return base, filepath.Join(base, "run", "vm", "p1")
			},
			want:       ErrSymlinkedPath,
			refusedRel: filepath.Join("run", "vm"),
		},
		{
			name: "a path outside the root is refused before any lstat",
			setup: func(t *testing.T, base string) (string, string) {
				mkdirAll(t, filepath.Join(base, "run"))
				mkdirAll(t, filepath.Join(base, "other"))
				return filepath.Join(base, "run"), filepath.Join(base, "other")
			},
			want: ErrPathOutsideRoot,
		},
		{
			name: "a sibling whose name merely starts the same is outside the root",
			setup: func(t *testing.T, base string) (string, string) {
				mkdirAll(t, filepath.Join(base, "run"))
				mkdirAll(t, filepath.Join(base, "run-evil"))
				return filepath.Join(base, "run"), filepath.Join(base, "run-evil")
			},
			want: ErrPathOutsideRoot,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, path := tc.setup(t, t.TempDir())
			err := RefuseSymlinkedPath(root, path)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("RefuseSymlinkedPath(%s, %s) = %v, want nil", root, path, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("RefuseSymlinkedPath(%s, %s) = %v, want %v", root, path, err, tc.want)
			}
			if tc.refusedRel != "" {
				want := filepath.Join(root, tc.refusedRel)
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %v, want it to name the first bad component %s", err, want)
				}
			}
		})
	}
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
