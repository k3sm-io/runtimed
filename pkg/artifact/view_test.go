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
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// cowCopier byte-copies and reports a clone, so the view logic can be tested
// off APFS. Only TestArtifactViewIsCloneNotLink needs the real cloner.
type cowCopier struct{}

func (cowCopier) Clone(src, dst string) (bool, error) {
	if _, err := (image.ByteCopier{}).Clone(src, dst); err != nil {
		return false, err
	}
	return true, nil
}

// pulled publishes and pulls a three-file model and returns its manifest
// digest.
func (e *env) pulled(t *testing.T) string {
	t.Helper()
	e.fetch.publishModel(testRef,
		modelLayer("config.json", `{"a":1}`),
		modelLayer("model.safetensors", "weights"),
		modelLayer("tok/tokenizer.json", "tokens"),
	)
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	res.Lease.Release()
	return res.ManifestDigest
}

func (e *env) views(t *testing.T, c image.Cloner) *Views {
	t.Helper()
	v, err := NewViews(context.Background(), ViewsConfig{StorePath: e.cache.Root(), Cloner: c}, e.cache, e.index)
	if err != nil {
		t.Fatalf("NewViews: %v", err)
	}
	// View dirs are 0555, which a non-root owner cannot empty; reopen them
	// before TempDir's own cleanup (cleanups run last-registered first).
	t.Cleanup(func() {
		if err := removeTree(v.Root()); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove views: %v", err)
		}
	})
	return v
}

// listTree returns every path under dir, relative, sorted.
func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// TestArtifactViewIsCloneNotLink pins what a view file is: an APFS clone of
// the cache blob, a distinct inode (a hardlink would share mode, owner and
// flags with the blob), mode 0444 in 0555 directories, on the blob's volume.
func TestArtifactViewIsCloneNotLink(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("APFS clonefile is darwin-only")
	}
	e := newEnv(t)
	md := e.pulled(t)
	view, err := e.views(t, nil).View(context.Background(), md, nil)
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if !strings.HasPrefix(view, filepath.Join(e.cache.Root(), sandbox.ArtifactViewsSubdir)+"/") {
		t.Errorf("view %s is not under the views root", view)
	}
	for path, data := range map[string]string{
		"config.json": `{"a":1}`, "model.safetensors": "weights", "tok/tokenizer.json": "tokens",
	} {
		vf := filepath.Join(view, path)
		blob, err := e.cache.BlobPath(digestOfBytes([]byte(data)))
		if err != nil {
			t.Fatal(err)
		}
		var vs, bs syscall.Stat_t
		if err := syscall.Lstat(vf, &vs); err != nil {
			t.Fatalf("stat view file %s: %v", path, err)
		}
		if err := syscall.Lstat(blob, &bs); err != nil {
			t.Fatal(err)
		}
		if vs.Ino == bs.Ino {
			t.Errorf("%s shares inode %d with its blob: a link, not a clone", path, vs.Ino)
		}
		if bs.Nlink != 1 {
			t.Errorf("blob of %s has %d links; the view must not link it", path, bs.Nlink)
		}
		if vs.Dev != bs.Dev {
			t.Errorf("%s is on device %d, its blob on %d", path, vs.Dev, bs.Dev)
		}
		if vs.Mode&0o7777 != viewFileMode || vs.Mode&syscall.S_IFMT != syscall.S_IFREG {
			t.Errorf("%s mode %o, want a regular file 0444", path, vs.Mode)
		}
		got, err := os.ReadFile(vf)
		if err != nil || string(got) != data {
			t.Errorf("%s reads %q, %v; want %q", path, got, err, data)
		}
	}
	for _, d := range []string{view, filepath.Join(view, "tok")} {
		fi, err := os.Lstat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != viewDirMode {
			t.Errorf("dir %s mode %v, want 0555", d, fi.Mode().Perm())
		}
	}
}

// TestArtifactViewRefusesCrossVolume pins the strict cloner: a clone that
// degraded to a byte copy (cow == false, as a cross-volume clonefile does) is
// ErrCrossVolume, and no view and no staging directory is left behind.
func TestArtifactViewRefusesCrossVolume(t *testing.T) {
	e := newEnv(t)
	md := e.pulled(t)
	v := e.views(t, image.ByteCopier{})
	_, err := v.View(context.Background(), md, nil)
	if !errors.Is(err, ErrCrossVolume) {
		t.Fatalf("View err = %v, want ErrCrossVolume", err)
	}
	mdir := filepath.Join(v.Root(), strings.TrimPrefix(md, "sha256:"))
	if left := listTree(t, mdir); len(left) != 0 {
		t.Errorf("a refused view left %v", left)
	}
}

// TestArtifactViewKeyedByPathSet pins the view key: the manifest and the
// sorted path set. No paths is the whole artifact's set, the order of paths
// does not matter, and a subset is its own view holding only its files.
func TestArtifactViewKeyedByPathSet(t *testing.T) {
	e := newEnv(t)
	md := e.pulled(t)
	v := e.views(t, cowCopier{})
	ctx := context.Background()
	all := []string{"config.json", "model.safetensors", "tok/tokenizer.json"}

	whole, err := v.View(ctx, md, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(v.Root(), strings.TrimPrefix(md, "sha256:"), PathSetKey(all))
	if whole != want {
		t.Errorf("whole view at %s, want %s", whole, want)
	}
	if got, err := v.View(ctx, md, []string{"tok/tokenizer.json", "config.json", "model.safetensors"}); err != nil || got != whole {
		t.Errorf("every path, reordered = %s, %v; want the whole view %s", got, err, whole)
	}
	sub, err := v.View(ctx, md, []string{"config.json"})
	if err != nil {
		t.Fatal(err)
	}
	if sub == whole || filepath.Base(sub) != PathSetKey([]string{"config.json"}) {
		t.Errorf("subset view at %s; want its own key beside %s", sub, whole)
	}
	if got := listTree(t, sub); !slices.Equal(got, []string{"config.json"}) {
		t.Errorf("subset view holds %v, want only config.json", got)
	}
	if got := listTree(t, whole); !slices.Equal(got, []string{"config.json", "model.safetensors", "tok", "tok/tokenizer.json"}) {
		t.Errorf("whole view holds %v", got)
	}
	if PathSetKey([]string{"a", "b"}) == PathSetKey([]string{"ab"}) {
		t.Error("path sets that concatenate alike share a key")
	}

	t.Run("refusals", func(t *testing.T) {
		if _, err := v.View(ctx, md, []string{"absent.json"}); !errors.Is(err, ErrPathNotInArtifact) {
			t.Errorf("absent path err = %v, want ErrPathNotInArtifact", err)
		}
		if _, err := v.View(ctx, "sha256:"+strings.Repeat("0", 64), nil); !errors.Is(err, ErrNotRecorded) {
			t.Errorf("unrecorded manifest err = %v, want ErrNotRecorded", err)
		}
		if _, err := v.View(ctx, "sha256:../../x", nil); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("malformed digest err = %v, want ErrManifestInvalid", err)
		}
		if _, err := v.View(ctx, md, []string{"../config.json"}); err == nil {
			t.Error("a traversing path was accepted")
		}
	})
}

// TestArtifactViewNeedsCommittedLayers pins that a subset pull records only
// its layers, so a view of a file the node never fetched is refused rather
// than built from a missing blob.
func TestArtifactViewNeedsCommittedLayers(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("a.json", "a"), modelLayer("b.json", "b"))
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, []string{"a.json"})
	if err != nil {
		t.Fatal(err)
	}
	res.Lease.Release()
	v := e.views(t, cowCopier{})
	if _, err := v.View(context.Background(), res.ManifestDigest, []string{"a.json"}); err != nil {
		t.Fatalf("view of the pulled subset: %v", err)
	}
	if _, err := v.View(context.Background(), res.ManifestDigest, nil); !errors.Is(err, ErrLayerNotCommitted) {
		t.Fatalf("whole view err = %v, want ErrLayerNotCommitted", err)
	}
}

// TestArtifactViewConcurrentBuild pins that concurrent requests for one view
// build it once: every caller gets the same complete view and no staging is
// left.
func TestArtifactViewConcurrentBuild(t *testing.T) {
	e := newEnv(t)
	md := e.pulled(t)
	v := e.views(t, cowCopier{})
	const n = 8
	paths := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			paths[i], errs[i] = v.View(context.Background(), md, nil)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || paths[i] != paths[0] {
			t.Fatalf("caller %d: %s, %v; want %s", i, paths[i], errs[i], paths[0])
		}
	}
	mdir := filepath.Dir(paths[0])
	entries, err := os.ReadDir(mdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("manifest dir holds %d entries, want the one view", len(entries))
	}

	t.Run("a view another builder published first is adopted", func(t *testing.T) {
		v2 := e.views(t, cowCopier{})
		got, err := v2.View(context.Background(), md, nil)
		if err != nil || got != paths[0] {
			t.Fatalf("second builder = %s, %v; want %s", got, err, paths[0])
		}
	})
}

// staleStaging plants a half-built staging dir, already chmodded read-only as
// a crash after the chmod and before the rename leaves it.
func staleStaging(t *testing.T, mdir string) string {
	t.Helper()
	stage := filepath.Join(mdir, stagePrefix+"0123456789abcdef-42")
	if err := os.MkdirAll(filepath.Join(stage, "tok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "tok", "t.json"), []byte("x"), viewFileMode); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(stage, "tok"), stage} {
		if err := os.Chmod(d, viewDirMode); err != nil {
			t.Fatal(err)
		}
	}
	return stage
}

// TestStaleViewStagingReapedAtStart pins the start-time reap: a half-built
// staging directory is removed, a published view of a recorded manifest is
// kept, and the views of a manifest no record names are removed.
func TestStaleViewStagingReapedAtStart(t *testing.T) {
	e := newEnv(t)
	md := e.pulled(t)
	view, err := e.views(t, cowCopier{}).View(context.Background(), md, nil)
	if err != nil {
		t.Fatal(err)
	}
	mdir := filepath.Dir(view)
	stage := staleStaging(t, mdir)
	orphan := filepath.Join(filepath.Dir(mdir), strings.Repeat("e", 64))
	if err := os.MkdirAll(orphan, 0o711); err != nil {
		t.Fatal(err)
	}
	orphanStage := staleStaging(t, orphan)

	e.views(t, cowCopier{}) // daemon start

	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("half-built staging survived the start: %v", err)
	}
	if _, err := os.Lstat(orphanStage); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging of an unrecorded manifest survived: %v", err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("views of a manifest no record names survived: %v", err)
	}
	if got := listTree(t, view); len(got) != 4 {
		t.Errorf("the published view was touched: %v", got)
	}
}

// TestForgetRemovesRecordAndViews pins the view lifetime: forgetting the last
// record of a manifest removes its views; forgetting one of two records that
// name it keeps them.
func TestForgetRemovesRecordAndViews(t *testing.T) {
	e := newEnv(t)
	md := e.pulled(t)
	other := testHost + "/models/tiny:also"
	e.fetch.mu.Lock()
	e.fetch.manifests[other] = e.fetch.manifests[testRef]
	e.fetch.mu.Unlock()
	res, err := e.puller(t).PullArtifact(context.Background(), other, nil, volume, nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Lease.Release()
	v := e.views(t, cowCopier{})
	ctx := context.Background()
	view, err := v.View(ctx, md, nil)
	if err != nil {
		t.Fatal(err)
	}
	typ := res.ArtifactType
	if err := v.Forget(ctx, testRef, typ); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, err := os.Lstat(view); err != nil {
		t.Fatalf("a view another record still names was removed: %v", err)
	}
	if err := v.Forget(ctx, other, typ); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(view)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("views survived the last record: %v", err)
	}
	if _, err := v.View(ctx, md, nil); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("View after Forget err = %v, want ErrNotRecorded", err)
	}
	if err := v.Forget(ctx, testRef, typ); err != nil {
		t.Errorf("Forget of an absent record: %v", err)
	}
}

// TestViewsRootMustBePrivate pins that the views root is refused when it is
// not a private directory.
func TestViewsRootMustBePrivate(t *testing.T) {
	e := newEnv(t)
	root := filepath.Join(e.cache.Root(), sandbox.ArtifactViewsSubdir)
	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Fatal(err)
	}
	if _, err := NewViews(context.Background(), ViewsConfig{StorePath: e.cache.Root()}, e.cache, e.index); !errors.Is(err, ErrViewsRoot) {
		t.Fatalf("NewViews over a symlinked root err = %v, want ErrViewsRoot", err)
	}
}
