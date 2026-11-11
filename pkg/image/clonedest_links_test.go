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
	"reflect"
	"testing"
)

// swapCloner wraps a shipped Cloner and, once it has cloned the file named
// trigger, runs after. It forwards cloneAt so the walk still takes its
// descriptor-relative path.
type swapCloner struct {
	inner   Cloner
	trigger string
	after   func()
}

func (s swapCloner) Clone(src, dst string) (bool, error) { return s.inner.Clone(src, dst) }

func (s swapCloner) cloneAt(src string, dir *os.File, name string) (bool, error) {
	cow, err := s.inner.(cloneAter).cloneAt(src, dir, name)
	if err == nil && name == s.trigger {
		s.after()
	}
	return cow, err
}

// TestMaterializeTreeDestinationLinkRules pins how destination directory links
// are resolved: in-root chains compose, loops, absolute targets and a link
// swapped in mid-walk never reach a directory outside the destination.
func TestMaterializeTreeDestinationLinkRules(t *testing.T) {
	cloners := map[string]Cloner{"byte": ByteCopier{}, "apfs": APFSCloner{}}

	// snapshot records every entry under dir (type and content).
	snapshot := func(t *testing.T, dir string) map[string]string {
		t.Helper()
		m := map[string]string{}
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			switch {
			case d.IsDir():
				m[rel] = "dir"
			case d.Type()&fs.ModeSymlink != 0:
				l, _ := os.Readlink(p)
				m[rel] = "link:" + l
			default:
				b, rerr := os.ReadFile(p)
				if rerr != nil {
					return rerr
				}
				m[rel] = "file:" + string(b)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	mkdir := func(t *testing.T, p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, target, p string) {
		t.Helper()
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	missing := func(t *testing.T, p string) {
		t.Helper()
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s exists (err %v); want nothing written there", p, err)
		}
	}

	for cname, c := range cloners {
		// setup builds src, dst and a victim outside dst, returning the victim
		// snapshot check to run at the end of the case.
		setup := func(t *testing.T) (src, dst, victim string, check func()) {
			t.Helper()
			src, dst, victim = t.TempDir(), t.TempDir(), t.TempDir()
			mustWrite(t, filepath.Join(victim, "keep"), "keep", 0o644)
			before := snapshot(t, victim)
			check = func() {
				t.Helper()
				if after := snapshot(t, victim); !reflect.DeepEqual(before, after) {
					t.Fatalf("victim changed: before %v, after %v", before, after)
				}
			}
			return
		}
		t.Run(cname, func(t *testing.T) {
			t.Run("in_root_chain_of_two_links_composes", func(t *testing.T) {
				src, dst, _, check := setup(t)
				mustWrite(t, filepath.Join(src, "a", "x"), "x", 0o644)
				mkdir(t, filepath.Join(dst, "real"))
				link(t, "real", filepath.Join(dst, "b"))
				link(t, "b", filepath.Join(dst, "a"))
				if _, err := MaterializeTree(c, src, dst); err != nil {
					t.Fatalf("materialize through a chain of in-root links: %v", err)
				}
				if got, err := os.ReadFile(filepath.Join(dst, "real", "x")); err != nil || string(got) != "x" {
					t.Fatalf("real/x = %q, %v; want x", got, err)
				}
				check()
			})

			t.Run("link_loop_refused", func(t *testing.T) {
				src, dst, _, check := setup(t)
				mustWrite(t, filepath.Join(src, "a", "x"), "x", 0o644)
				link(t, "b", filepath.Join(dst, "a"))
				link(t, "a", filepath.Join(dst, "b"))
				_, err := MaterializeTree(c, src, dst)
				if err == nil {
					t.Fatal("materialize through a link loop succeeded; want an error")
				}
				t.Logf("link loop error: %v (ErrDestinationLink: %v)", err, errors.Is(err, ErrDestinationLink))
				if !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				if got := snapshot(t, dst); len(got) != 3 {
					t.Fatalf("destination = %v; want only the two links", got)
				}
				check()
			})

			t.Run("absolute_target_refused_even_when_it_names_an_in_root_path", func(t *testing.T) {
				src, dst, _, check := setup(t)
				mustWrite(t, filepath.Join(src, "lib", "x"), "x", 0o644)
				mkdir(t, filepath.Join(dst, "usr", "lib"))
				// An absolute target is never reinterpreted relative to the
				// destination root, even when it spells a path inside it.
				link(t, filepath.Join(dst, "usr", "lib"), filepath.Join(dst, "lib"))
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				missing(t, filepath.Join(dst, "usr", "lib", "x"))
				check()
			})

			t.Run("dangling_in_root_directory_link_refused", func(t *testing.T) {
				src, dst, _, check := setup(t)
				mustWrite(t, filepath.Join(src, "lib", "x"), "x", 0o644)
				link(t, "gone", filepath.Join(dst, "lib"))
				_, err := MaterializeTree(c, src, dst)
				if !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("err = %v, want the not-exist cause kept in the chain", err)
				}
				missing(t, filepath.Join(dst, "gone"))
				check()
			})

			t.Run("absolute_target_to_host_refused", func(t *testing.T) {
				src, dst, victim, check := setup(t)
				mustWrite(t, filepath.Join(src, "etc", "hostname"), "h", 0o644)
				link(t, victim, filepath.Join(dst, "etc"))
				if _, err := MaterializeTree(c, src, dst); !errors.Is(err, ErrDestinationLink) {
					t.Fatalf("err = %v, want ErrDestinationLink", err)
				}
				check()
			})

			t.Run("link_swapped_between_entries", func(t *testing.T) {
				src, dst, victim, check := setup(t)
				mustWrite(t, filepath.Join(src, "d", "one"), "1", 0o644)
				mustWrite(t, filepath.Join(src, "d", "two"), "2", 0o644)
				mkdir(t, filepath.Join(dst, "d"))
				sc := swapCloner{inner: c, trigger: "one", after: func() {
					if err := os.Rename(filepath.Join(dst, "d"), filepath.Join(dst, "d.orig")); err != nil {
						t.Error(err)
						return
					}
					link(t, victim, filepath.Join(dst, "d"))
				}}
				_, err := MaterializeTree(sc, src, dst)
				t.Logf("swap outcome: err = %v", err)
				if fi, lerr := os.Lstat(filepath.Join(dst, "d")); lerr != nil || fi.Mode()&fs.ModeSymlink == 0 {
					t.Fatalf("swap did not happen (%v, %v); test is vacuous", fi, lerr)
				}
				missing(t, filepath.Join(victim, "two"))
				missing(t, filepath.Join(victim, "one"))
				check()
			})
		})
	}
}

// TestMaterializeTreeRefusesATreeDeeperThanTheBound pins the destination
// walk's depth bound: a source tree one directory level past
// maxMaterializeDepth fails with ErrTreeTooDeep and nothing lands at its
// bottom, while a tree exactly at the bound materializes.
func TestMaterializeTreeRefusesATreeDeeperThanTheBound(t *testing.T) {
	build := func(t *testing.T, levels int) (src, bottomRel string) {
		t.Helper()
		src = t.TempDir()
		comps := make([]string, levels)
		for i := range comps {
			comps[i] = "d"
		}
		bottomRel = filepath.Join(append(comps, "f")...)
		if err := os.MkdirAll(filepath.Join(src, filepath.Dir(bottomRel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, bottomRel), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return src, bottomRel
	}

	t.Run("deeper than the bound", func(t *testing.T) {
		src, bottomRel := build(t, maxMaterializeDepth+1)
		dst := filepath.Join(t.TempDir(), "rootfs")
		_, err := MaterializeTree(ByteCopier{}, src, dst)
		if !errors.Is(err, ErrTreeTooDeep) {
			t.Fatalf("MaterializeTree err = %v, want ErrTreeTooDeep", err)
		}
		if _, serr := os.Lstat(filepath.Join(dst, bottomRel)); !errors.Is(serr, fs.ErrNotExist) {
			t.Fatalf("bottom file lstat err = %v, want not exist", serr)
		}
		if _, serr := os.Lstat(filepath.Join(dst, filepath.Dir(bottomRel))); !errors.Is(serr, fs.ErrNotExist) {
			t.Fatalf("directory past the bound lstat err = %v, want not exist", serr)
		}
	})

	t.Run("exactly at the bound", func(t *testing.T) {
		src, bottomRel := build(t, maxMaterializeDepth)
		dst := filepath.Join(t.TempDir(), "rootfs")
		if _, err := MaterializeTree(ByteCopier{}, src, dst); err != nil {
			t.Fatalf("MaterializeTree: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dst, bottomRel)); err != nil {
			t.Fatalf("bottom file: %v", err)
		}
	})
}
