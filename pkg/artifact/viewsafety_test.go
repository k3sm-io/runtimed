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

package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// errCloner stands in for clonefile(2): it writes nothing and fails with err.
type errCloner struct {
	err   error
	calls int
}

func (c *errCloner) Clone(string, string) (bool, error) {
	c.calls++
	return false, c.err
}

// TestArtifactViewCloneRefusesBeforeAnyCopy pins the clone-only cloner: a
// clone that fails because the volume cannot clone (EXDEV, ENOTSUP,
// EOPNOTSUPP) is ErrCrossVolume, with no byte copied and nothing left in
// staging, and the default cloner is the clone-only one.
func TestArtifactViewCloneRefusesBeforeAnyCopy(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EXDEV, syscall.ENOTSUP, syscall.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			e := newEnv(t)
			md := e.pulled(t)
			c := &errCloner{err: &os.LinkError{Op: "clonefile", Err: errno}}
			v := e.views(t, c)
			_, err := v.View(context.Background(), md, nil)
			if !errors.Is(err, ErrCrossVolume) {
				t.Fatalf("View err = %v, want ErrCrossVolume", err)
			}
			if c.calls != 1 {
				t.Errorf("cloner called %d times, want 1: the first refusal must stop the build", c.calls)
			}
			mdir := filepath.Join(v.Root(), strings.TrimPrefix(md, "sha256:"))
			if left := listTree(t, mdir); len(left) != 0 {
				t.Errorf("a refused view left %v in staging", left)
			}
		})
	}
	t.Run("the default cloner never copies", func(t *testing.T) {
		e := newEnv(t)
		v := e.views(t, nil)
		if _, ok := v.cloner.(image.CloneOnly); !ok {
			t.Fatalf("default view cloner is %T, want image.CloneOnly", v.cloner)
		}
	})
}

// TestViewsRefuseOtherDeviceAtStart pins the start-time volume check: a views
// root on another device than the blob store is refused before any view is
// built.
func TestViewsRefuseOtherDeviceAtStart(t *testing.T) {
	e := newEnv(t)
	var asked []string
	dev := func(p string) (uint64, error) {
		asked = append(asked, p)
		if filepath.Base(p) == sandbox.ArtifactViewsSubdir {
			return 2, nil
		}
		return 1, nil
	}
	_, err := NewViews(context.Background(), ViewsConfig{StorePath: e.cache.Root(), Cloner: cowCopier{}, statDev: dev}, e.cache, e.index)
	if !errors.Is(err, ErrCrossVolume) {
		t.Fatalf("NewViews across devices err = %v (stat %v), want ErrCrossVolume", err, asked)
	}
}

// TestViewsDirsOwnedExactMode pins the views directories: created at exactly
// 0711 whatever the umask, and an existing one with another mode is refused
// rather than repaired.
func TestViewsDirsOwnedExactMode(t *testing.T) {
	t.Run("an existing 0700 root is refused", func(t *testing.T) {
		e := newEnv(t)
		root := filepath.Join(e.cache.Root(), sandbox.ArtifactViewsSubdir)
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := NewViews(context.Background(), ViewsConfig{StorePath: e.cache.Root(), Cloner: cowCopier{}}, e.cache, e.index)
		if !errors.Is(err, ErrViewsNotOwned) {
			t.Fatalf("NewViews over a 0700 root err = %v, want ErrViewsNotOwned", err)
		}
		if fi, err := os.Lstat(root); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("the refused root was repaired: %v, %v", fi.Mode(), err)
		}
	})
	t.Run("created under umask 077 is 0711", func(t *testing.T) {
		e := newEnv(t)
		md := e.pulled(t)
		old := syscall.Umask(0o077)
		v, err := NewViews(context.Background(), ViewsConfig{StorePath: e.cache.Root(), Cloner: cowCopier{}}, e.cache, e.index)
		var view string
		if err == nil {
			view, err = v.View(context.Background(), md, nil)
		}
		syscall.Umask(old)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = removeTree(v.Root()) })
		for _, d := range []string{v.Root(), filepath.Dir(view)} {
			fi, err := os.Lstat(d)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != viewParentMode {
				t.Errorf("%s created %v, want %v", d, fi.Mode().Perm(), os.FileMode(viewParentMode))
			}
		}
	})
}

// pullModel publishes layers at testRef, pulls them and returns the result.
func (e *env) pullModel(t *testing.T, layers ...layer) *Result {
	t.Helper()
	e.fetch.publishModel(testRef, layers...)
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	res.Lease.Release()
	return res
}

// TestPruneSweepsViewsOfReplacedManifest pins that a record overwritten for a
// new manifest does not strand the old manifest's views: the next prune
// removes them and keeps the views of the manifest the record now names.
func TestPruneSweepsViewsOfReplacedManifest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	md1 := e.pulled(t)
	v := e.views(t, cowCopier{})
	old, err := v.View(ctx, md1, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := e.pullModel(t, modelLayer("config.json", `{"a":2}`), modelLayer("model.safetensors", "weights v2"))
	cur, err := v.View(ctx, res.ManifestDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.cache.ReclaimUnderPressure(ctx, image.ReclaimConfig{
		Force:        true,
		FreeBytes:    func(string) (uint64, error) { return 0, nil },
		SweepDerived: v.SweepOrphans,
	}); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(old)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("views of the replaced manifest survived the prune: %v", err)
	}
	if got := listTree(t, cur); len(got) != 2 {
		t.Errorf("the current manifest's view holds %v after the prune", got)
	}
}

// TestForgetKeepsRecordRePutConcurrently pins Forget against a re-put of the
// same key for a new manifest landing between its lookup and its removal: the
// newer record survives, and the old manifest's views go.
func TestForgetKeepsRecordRePutConcurrently(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	md1 := e.pulled(t)
	v := e.views(t, cowCopier{})
	old, err := v.View(ctx, md1, nil)
	if err != nil {
		t.Fatal(err)
	}
	var md2 string
	v.beforeRemove = func() {
		v.beforeRemove = nil
		md2 = e.pullModel(t, modelLayer("config.json", `{"a":3}`)).ManifestDigest
	}
	if err := v.Forget(ctx, testRef, artifactv1.ArtifactTypeModel); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if md2 == "" {
		t.Fatal("the re-put seam never ran")
	}
	rec, ok, err := e.puller(t).LookupRecord(ctx, testRef, artifactv1.ArtifactTypeModel)
	if err != nil || !ok || rec.ManifestDigest != md2 {
		t.Fatalf("record after Forget = %v, %v, %v; want the re-put record naming %s", rec, ok, err, md2)
	}
	if _, err := os.Lstat(filepath.Dir(old)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("views of the forgotten manifest survived: %v", err)
	}
	if _, err := v.View(ctx, md2, nil); err != nil {
		t.Errorf("view of the re-put manifest: %v", err)
	}
}

// TestStartupRemovesTamperedViews pins the start-time check of published
// views: a view whose directory is not 0555, holding a file that is not
// 0444, or holding anything but files and directories, is removed so the next
// View rebuilds it; an intact view is kept.
func TestStartupRemovesTamperedViews(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(t *testing.T, view string)
	}{
		{"a directory reopened", func(t *testing.T, view string) {
			if err := os.Chmod(view, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"a file made writable", func(t *testing.T, view string) {
			if err := os.Chmod(filepath.Join(view, "config.json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"a symlink planted", func(t *testing.T, view string) {
			if err := os.Chmod(view, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", filepath.Join(view, "x")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(view, viewDirMode); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			md := e.pulled(t)
			v := e.views(t, cowCopier{})
			bad, err := v.View(ctx, md, []string{"config.json"})
			if err != nil {
				t.Fatal(err)
			}
			good, err := v.View(ctx, md, []string{"model.safetensors"})
			if err != nil {
				t.Fatal(err)
			}
			tc.tamper(t, bad)

			v2 := e.views(t, cowCopier{}) // daemon start
			if _, err := os.Lstat(bad); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the tampered view survived the start: %v", err)
			}
			if got := listTree(t, good); len(got) != 1 {
				t.Errorf("the intact view was touched: %v", got)
			}
			again, err := v2.View(ctx, md, []string{"config.json"})
			if err != nil || again != bad {
				t.Fatalf("rebuild = %s, %v; want %s", again, err, bad)
			}
			if fi, err := os.Lstat(filepath.Join(again, "config.json")); err != nil || fi.Mode().Perm() != viewFileMode {
				t.Errorf("rebuilt file %v, %v; want 0444", fi.Mode(), err)
			}
		})
	}
}
