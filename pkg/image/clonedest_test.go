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
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestMaterializeTreeNeverWritesThroughADestinationLink gates the destination
// side of MaterializeTree: a link already present in the destination (one a pod
// planted in its own rootfs before the next re-materialize) is never followed.
// Where the tree needs a directory or lands a regular file, the walk refuses
// with ErrDestinationLink and the link's target is left untouched; a second
// materialize into the walk's own output still succeeds; and the tree's own
// symlink entries land verbatim. Each case runs with every shipped Cloner.
func TestMaterializeTreeNeverWritesThroughADestinationLink(t *testing.T) {
	cloners := map[string]Cloner{"byte": ByteCopier{}, "apfs": APFSCloner{}}

	// src: a/b/c/file, a/top, link -> ../outside, dirlink -> a
	newSrc := func(t *testing.T) string {
		t.Helper()
		src := t.TempDir()
		mustWrite(t, filepath.Join(src, "a", "b", "c", "file"), "deep", 0o644)
		mustWrite(t, filepath.Join(src, "a", "top"), "top", 0o644)
		if err := os.Symlink("../outside", filepath.Join(src, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("a", filepath.Join(src, "dirlink")); err != nil {
			t.Fatal(err)
		}
		return src
	}
	// assertVictimEmpty fails if anything landed in victim.
	assertVictimEmpty := func(t *testing.T, victim string) {
		t.Helper()
		ents, err := os.ReadDir(victim)
		if err != nil || len(ents) != 0 {
			t.Fatalf("victim holds %d entries (err %v), want none: a write went through the destination link", len(ents), err)
		}
	}

	for cname, c := range cloners {
		t.Run(cname, func(t *testing.T) {
			t.Run("intermediate_directory_link", func(t *testing.T) {
				src, dst, victim := newSrc(t), t.TempDir(), t.TempDir()
				if err := os.MkdirAll(filepath.Join(dst, "a"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, filepath.Join(dst, "a", "b")); err != nil {
					t.Fatal(err)
				}
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				assertVictimEmpty(t, victim)
			})

			t.Run("in_root_directory_link_composes", func(t *testing.T) {
				src, dst := t.TempDir(), t.TempDir()
				mustWrite(t, filepath.Join(src, "lib", "x"), "x", 0o644)
				if err := os.MkdirAll(filepath.Join(dst, "usr", "lib"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("usr/lib", filepath.Join(dst, "lib")); err != nil {
					t.Fatal(err)
				}
				if _, err := MaterializeTree(c, src, dst); err != nil {
					t.Fatalf("materialize through an in-root link: %v", err)
				}
				if got, err := os.ReadFile(filepath.Join(dst, "usr", "lib", "x")); err != nil || string(got) != "x" {
					t.Fatalf("usr/lib/x = %q, %v; want x", got, err)
				}
				if fi, err := os.Lstat(filepath.Join(dst, "lib")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
					t.Fatalf("lib = %v, %v; want the link left in place", fi, err)
				}
			})

			t.Run("relative_link_escaping_root_refused", func(t *testing.T) {
				src, base := t.TempDir(), t.TempDir()
				mustWrite(t, filepath.Join(src, "etc", "passwd"), "root", 0o644)
				dst := filepath.Join(base, "pod", "rootfs")
				victim := filepath.Join(base, "victim")
				for _, d := range []string{dst, victim} {
					if err := os.MkdirAll(d, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink("../../victim", filepath.Join(dst, "etc")); err != nil {
					t.Fatal(err)
				}
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				assertVictimEmpty(t, victim)
			})

			t.Run("leaf_link_where_source_has_file", func(t *testing.T) {
				src, dst, victim := newSrc(t), t.TempDir(), t.TempDir()
				target := filepath.Join(victim, "target")
				if err := os.MkdirAll(filepath.Join(dst, "a"), 0o755); err != nil {
					t.Fatal(err)
				}
				// Both a dangling link (where a follow would create the
				// target) and a link to an existing file are refused.
				if err := os.Symlink(target, filepath.Join(dst, "a", "top")); err != nil {
					t.Fatal(err)
				}
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("dangling leaf link: err = %v, want ErrDestinationLink", err)
				}
				assertVictimEmpty(t, victim)

				mustWrite(t, target, "victim", 0o644)
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("leaf link to a file: err = %v, want ErrDestinationLink", err)
				}
				if got, err := os.ReadFile(target); err != nil || string(got) != "victim" {
					t.Fatalf("victim target = %q, %v; want it unchanged", got, err)
				}
			})

			t.Run("leaf_link_where_source_has_directory", func(t *testing.T) {
				src, dst, victim := newSrc(t), t.TempDir(), t.TempDir()
				if err := os.MkdirAll(filepath.Join(dst, "a", "b"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, filepath.Join(dst, "a", "b", "c")); err != nil {
					t.Fatal(err)
				}
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				assertVictimEmpty(t, victim)

				// A regular file where the tree needs a directory is refused too.
				dst2 := t.TempDir()
				mustWrite(t, filepath.Join(dst2, "a"), "not a dir", 0o644)
				if _, err := MaterializeTree(c, src, dst2); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("file where a directory belongs: err = %v, want ErrDestinationLink", err)
				}
			})

			t.Run("second_materialize_into_own_output", func(t *testing.T) {
				src := newSrc(t)
				dst := filepath.Join(t.TempDir(), "rootfs")
				if _, err := MaterializeTree(c, src, dst); err != nil {
					t.Fatalf("first materialize: %v", err)
				}
				if _, err := MaterializeTree(c, src, dst); err != nil {
					t.Fatalf("second materialize into its own output: %v", err)
				}
				if got, err := os.ReadFile(filepath.Join(dst, "a", "b", "c", "file")); err != nil || string(got) != "deep" {
					t.Fatalf("a/b/c/file = %q, %v; want deep", got, err)
				}
			})

			t.Run("tree_symlinks_land_verbatim", func(t *testing.T) {
				src := newSrc(t)
				dst := filepath.Join(t.TempDir(), "rootfs")
				if _, err := MaterializeTree(c, src, dst); err != nil {
					t.Fatalf("materialize: %v", err)
				}
				for name, want := range map[string]string{"link": "../outside", "dirlink": "a"} {
					p := filepath.Join(dst, name)
					fi, err := os.Lstat(p)
					if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
						t.Fatalf("%s = %v, %v; want a symlink", name, fi, err)
					}
					if got, err := os.Readlink(p); err != nil || got != want {
						t.Fatalf("%s -> %q, %v; want %q", name, got, err, want)
					}
				}
				if _, err := os.Lstat(filepath.Join(filepath.Dir(dst), "outside")); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("link target outside the rootfs exists (err %v); want nothing created there", err)
				}
			})
		})
	}
}
