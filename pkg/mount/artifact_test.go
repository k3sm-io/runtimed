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

package mount

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

var (
	testManifestA = strings.Repeat("a", 64)
	testManifestB = strings.Repeat("b", 64)
	testPathsKey  = strings.Repeat("c", 64)
)

// imageVol is an image volume of the cluster registry.
func imageVol(name string, paths ...string) *runtimev1.Volume {
	return &runtimev1.Volume{Name: name, Image: &runtimev1.ImageVolumeSource{
		Reference: "registry.k3sm.local/models/" + name + ":v1",
		Paths:     paths,
	}}
}

// makeView builds a read-only view directory <root>/<manifest>/<key> holding
// one file, as pkg/artifact leaves it, and returns its path.
func makeView(t *testing.T, root, manifest string) string {
	t.Helper()
	view := filepath.Join(root, manifest, testPathsKey)
	if err := os.MkdirAll(filepath.Join(view, "tokenizer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(view, "weights.safetensors"), []byte("w"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(view, "tokenizer", "t.json"), []byte("{}"), 0o444); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(view, "tokenizer"), view} {
		if err := os.Chmod(d, 0o555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(view, 0o755)
		_ = os.Chmod(filepath.Join(view, "tokenizer"), 0o755)
	})
	return view
}

// TestImageVolumeLinksReadOnlyView pins the native placement of an image
// volume: Materialize leaves it alone (no directory, no layout entry),
// LinkImageVolumes makes the mount path a symlink to the view (to the selected
// element for a subPath mount), grants exactly that view, and the attach-time
// re-derivation reads the same grant back from the links.
func TestImageVolumeLinksReadOnlyView(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "artifacts")
	view := makeView(t, root, testManifestA)
	dataVol := filepath.Join(work, "pods", "pod-1", "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	box := boxWith(imageVol("model"), &runtimev1.Volume{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
	box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts,
		&runtimev1.VolumeMount{Name: "model", MountPath: "/tok", SubPath: "tokenizer"})

	layout, err := Materialize(context.Background(), box, dataVol, "", nil)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	for _, m := range layout.Mounts {
		if m.Name == "model" {
			t.Fatalf("Materialize rendered the image volume at %s", m.Path)
		}
	}
	if _, err := os.Lstat(filepath.Join(dataVol, "etc", "model")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Materialize left something at the image mount path: %v", err)
	}

	views := ImageViews{Root: root, ByVolume: map[string]string{"model": view}}
	grants, err := LinkImageVolumes(box, dataVol, views)
	if err != nil {
		t.Fatalf("LinkImageVolumes: %v", err)
	}
	if want := []string{view}; !reflect.DeepEqual(grants, want) {
		t.Errorf("grants = %v, want %v", grants, want)
	}
	for dest, want := range map[string]string{
		filepath.Join(dataVol, "etc", "model"): view,
		filepath.Join(dataVol, "tok"):          filepath.Join(view, "tokenizer"),
	} {
		got, err := os.Readlink(dest)
		if err != nil {
			t.Fatalf("readlink %s: %v", dest, err)
		}
		if got != want {
			t.Errorf("%s -> %s, want %s", dest, got, want)
		}
	}
	// Read through the link; the view's files are read-only.
	if b, err := os.ReadFile(filepath.Join(dataVol, "etc", "model", "weights.safetensors")); err != nil || string(b) != "w" {
		t.Errorf("read through the link = %q, %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(dataVol, "etc", "model", "weights.safetensors")); err != nil || fi.Mode().Perm()&0o222 != 0 {
		t.Errorf("view file through the link is writable or missing: %v %v", fi.Mode(), err)
	}

	// Idempotent: a re-link replaces the stale links.
	if _, err := LinkImageVolumes(box, dataVol, views); err != nil {
		t.Fatalf("re-link: %v", err)
	}
	again, err := LinkedImageViews(box, dataVol, root)
	if err != nil {
		t.Fatalf("LinkedImageViews: %v", err)
	}
	if !reflect.DeepEqual(again, grants) {
		t.Errorf("re-derived grants %v, want %v", again, grants)
	}

	t.Run("refuses a non-view directory", func(t *testing.T) {
		for name, dir := range map[string]string{
			"the views root":  root,
			"a manifest dir":  filepath.Join(root, testManifestA),
			"outside":         filepath.Join(work, "blobs", testManifestA, testPathsKey),
			"a file in it":    filepath.Join(view, "weights.safetensors"),
			"an unclean path": root + "/" + testManifestA + "/../" + testManifestA + "/" + testPathsKey,
		} {
			_, err := LinkImageVolumes(box, dataVol, ImageViews{Root: root, ByVolume: map[string]string{"model": dir}})
			if !errors.Is(err, ErrImageView) {
				t.Errorf("%s: err = %v, want ErrImageView", name, err)
			}
		}
	})
	t.Run("refuses a missing view", func(t *testing.T) {
		if _, err := LinkImageVolumes(box, dataVol, ImageViews{Root: root}); err == nil {
			t.Error("linked an image volume with no view")
		}
	})
	t.Run("refuses a subPath escaping the view", func(t *testing.T) {
		b := boxWith(imageVol("model"))
		b.Containers[0].VolumeMounts[0].SubPath = "../" + testPathsKey
		if _, err := LinkImageVolumes(b, dataVol, views); err == nil {
			t.Error("linked a subPath that escapes the view")
		}
	})
	t.Run("refuses a real directory at the mount path", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(dataVol, "busy"), 0o755); err != nil {
			t.Fatal(err)
		}
		b := boxWith(imageVol("model"))
		b.Containers[0].VolumeMounts[0].MountPath = "/busy"
		if _, err := LinkImageVolumes(b, dataVol, views); err == nil {
			t.Error("replaced a real directory with a view link")
		}
	})
}

// TestImageVolumeRefusesPaths pins that a non-empty paths is refused, on the
// native and the vm route, and before any fetch (ImageVolumes): this runtime
// mounts whole artifacts only and never serves the whole for a subset.
func TestImageVolumeRefusesPaths(t *testing.T) {
	box := boxWith(imageVol("model", "weights.safetensors"))
	if _, err := ImageVolumes(box); !errors.Is(err, ErrImageVolumePaths) {
		t.Errorf("ImageVolumes err = %v, want ErrImageVolumePaths", err)
	}
	work := t.TempDir()
	root := filepath.Join(work, "artifacts")
	view := makeView(t, root, testManifestA)
	views := ImageViews{Root: root, ByVolume: map[string]string{"model": view}}
	if _, err := LinkImageVolumes(box, filepath.Join(work, "pods", "p", "rootfs"), views); !errors.Is(err, ErrImageVolumePaths) {
		t.Errorf("LinkImageVolumes err = %v, want ErrImageVolumePaths", err)
	}
	_, err := ComputeSharePlanWithViews(planBox(imageVol("model", "a")), filepath.Join(work, "pods", "p"), work, planClass(work), views)
	if !errors.Is(err, ErrImageVolumePaths) {
		t.Errorf("ComputeSharePlanWithViews err = %v, want ErrImageVolumePaths", err)
	}
}

// TestImageVolumeGrantsOnlyItsView is the negative: a pod mounting model A is
// granted A's view only, even with model B's view built on the node, and a
// link re-pointed at B (by the pod, in its writable volume) re-derives as B so
// the attach-time profile differs from the create-time one and is refused.
func TestImageVolumeGrantsOnlyItsView(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "artifacts")
	viewA := makeView(t, root, testManifestA)
	viewB := makeView(t, root, testManifestB)
	dataVol := filepath.Join(work, "pods", "pod-1", "rootfs")
	box := boxWith(imageVol("model"))
	grants, err := LinkImageVolumes(box, dataVol, ImageViews{Root: root, ByVolume: map[string]string{"model": viewA}})
	if err != nil {
		t.Fatalf("LinkImageVolumes: %v", err)
	}
	if !reflect.DeepEqual(grants, []string{viewA}) {
		t.Fatalf("grants = %v, want only %s", grants, viewA)
	}
	for _, g := range grants {
		if isUnder(viewB, g) || isUnder(g, filepath.Join(root, testManifestB)) {
			t.Errorf("grant %s reaches model B's view %s", g, viewB)
		}
	}
	link := filepath.Join(dataVol, "etc", "model")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(viewB, link); err != nil {
		t.Fatal(err)
	}
	again, err := LinkedImageViews(box, dataVol, root)
	if err != nil {
		t.Fatalf("LinkedImageViews: %v", err)
	}
	if reflect.DeepEqual(again, grants) {
		t.Errorf("a re-pointed link re-derived the create-time grants %v", again)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(work, "blobs"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := LinkedImageViews(box, dataVol, root); !errors.Is(err, ErrImageView) {
		t.Errorf("a link out of the views root re-derived: %v", err)
	}
}

// TestVMImageVolumeIsReadOnlyShare pins the vm route: an image volume's view
// is one share whose Writable is false, every bind of it is read-only even
// when the volumeMount does not say so, MaterializeShares creates nothing for
// it, and a plan without the view refuses the pod.
func TestVMImageVolumeIsReadOnlyShare(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "artifacts")
	view := makeView(t, root, testManifestA)
	podDir := filepath.Join(work, "pods", "pod-1")
	box := planBox(imageVol("model"), &runtimev1.Volume{Name: "cache", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
	box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts,
		&runtimev1.VolumeMount{Name: "model", MountPath: "/tok", SubPath: "tokenizer"})
	views := ImageViews{Root: root, ByVolume: map[string]string{"model": view}}

	plan, err := ComputeSharePlanWithViews(box, podDir, work, planClass(work), views)
	if err != nil {
		t.Fatalf("ComputeSharePlanWithViews: %v", err)
	}
	var share *Share
	for i := range plan.Shares {
		if plan.Shares[i].Root == view {
			share = &plan.Shares[i]
		}
	}
	if share == nil {
		t.Fatalf("no share exports the view; shares = %+v", plan.Shares)
	}
	if share.Writable || share.Tag != ShareTagImagePrefix+"0" {
		t.Errorf("view share = %+v, want tag %s0 and read-only", *share, ShareTagImagePrefix)
	}
	n := 0
	for _, b := range plan.Binds["main"] {
		if b.VolumeName != "model" {
			continue
		}
		n++
		if b.ShareTag != share.Tag || !b.ReadOnly || b.SourceRel != "" {
			t.Errorf("image bind = %+v, want read-only from %s at the share root", b, share.Tag)
		}
	}
	if n != 2 {
		t.Errorf("%d image binds, want 2", n)
	}

	if err := MaterializeShares(context.Background(), box, podDir, plan, "", nil); err != nil {
		t.Fatalf("MaterializeShares: %v", err)
	}
	entries, err := os.ReadDir(view)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("MaterializeShares wrote into the view: %v", entries)
	}

	if _, err := ComputeSharePlan(box, podDir, work, planClass(work)); err == nil {
		t.Error("planned an image volume with no view")
	}
	if _, err := ComputeSharePlanWithViews(box, podDir, work, planClass(work),
		ImageViews{Root: root, ByVolume: map[string]string{"model": filepath.Join(root, testManifestA)}}); !errors.Is(err, ErrImageView) {
		t.Errorf("planned a manifest dir as a view: %v", err)
	}
	if _, err := ComputeSharePlanWithViews(box, podDir, work, planClass(work),
		ImageViews{Root: filepath.Join(work, "pods"), ByVolume: map[string]string{"model": filepath.Join(work, "pods", testManifestA, testPathsKey)}}); err == nil {
		t.Error("planned a view under the pods root")
	}
}
