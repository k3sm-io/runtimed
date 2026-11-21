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
	"sort"
	"testing"

	"k3sm.io/runtimed/pkg/pathsafe"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRefreshDoesNotFollowASwappedAncestor: a pod owns its rootfs, so between
// Materialize and a timed Refresh it can rename an ancestor of a projected
// mount away and plant a symlink to any directory the daemon can write. The
// refresh must not create, replace or remove anything in that directory.
func TestRefreshDoesNotFollowASwappedAncestor(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	victim := t.TempDir() // stands in for another pod's rootfs or the server state dir
	if err := os.MkdirAll(filepath.Join(victim, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "cfg", "a"), []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, filepath.Join(victim, "cfg"))

	r := newRefreshResolver()
	r.set("app", false, "a", "pod-chosen")
	box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "app")},
		&runtimev1.VolumeMount{Name: "cfg", MountPath: "/data/x/cfg"})
	layout, err := Materialize(ctx, box, root, "", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	// The pod's move: data/x away, data/x -> victim.
	if err := os.Rename(filepath.Join(root, "data/x"), filepath.Join(root, "data/x.away")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "data/x")); err != nil {
		t.Fatal(err)
	}

	r.set("app", false, "a", "pod-chosen-2")
	_, rerr := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
	t.Logf("Refresh err = %v", rerr)

	after := listDir(t, filepath.Join(victim, "cfg"))
	if !equalStrings(before, after) {
		t.Errorf("refresh wrote through the swapped ancestor: victim/cfg went from %v to %v", before, after)
	}
	if fi, err := os.Lstat(filepath.Join(victim, "cfg", "a")); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("victim/cfg/a was replaced (lstat %v, err %v)", fi, err)
	} else if got := readString(t, filepath.Join(victim, "cfg", "a")); got != "victim" {
		t.Errorf("victim/cfg/a = %q, want %q", got, "victim")
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name()+":"+e.Type().String())
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pinFixture is a pod data volume with one configMap mount at /data/x/cfg, and
// a victim directory standing in for another pod's rootfs or the server state
// dir, holding cfg/a. unchanged reports whether the victim is as it was.
type pinFixture struct {
	root, victim string
	r            *refreshResolver
	box          *runtimev1.PodBox
	before       []string
}

func newPinFixture(t *testing.T) *pinFixture {
	t.Helper()
	f := &pinFixture{root: t.TempDir(), victim: t.TempDir(), r: newRefreshResolver()}
	if err := os.MkdirAll(filepath.Join(f.victim, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.victim, "cfg", "a"), []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.before = listDir(t, filepath.Join(f.victim, "cfg"))
	f.r.set("app", false, "a", "pod-chosen")
	f.box = mountBox([]*runtimev1.Volume{cmVolume("cfg", "app")},
		&runtimev1.VolumeMount{Name: "cfg", MountPath: "/data/x/cfg"})
	return f
}

func (f *pinFixture) checkVictim(t *testing.T) {
	t.Helper()
	if after := listDir(t, filepath.Join(f.victim, "cfg")); !equalStrings(f.before, after) {
		t.Errorf("the daemon wrote outside the pod: victim/cfg went from %v to %v", f.before, after)
	}
	if fi, err := os.Lstat(filepath.Join(f.victim, "cfg", "a")); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("victim/cfg/a was replaced (lstat %v, err %v)", fi, err)
	} else if got := readString(t, filepath.Join(f.victim, "cfg", "a")); got != "victim" {
		t.Errorf("victim/cfg/a = %q, want %q", got, "victim")
	}
}

func (f *pinFixture) materialize(t *testing.T) *Layout {
	t.Helper()
	layout, err := Materialize(context.Background(), f.box, f.root, "", f.r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	return layout
}

func (f *pinFixture) refresh(t *testing.T, layout *Layout) (RefreshResult, error) {
	t.Helper()
	f.r.set("app", false, "a", "pod-chosen-2")
	return Refresh(context.Background(), f.root, f.box, f.r, RefreshOptions{State: layout.State})
}

// swapForLink renames rel under the data volume away and plants a symlink to
// target in its place, as a pod process can at any time.
func (f *pinFixture) swapForLink(t *testing.T, rel, target string) {
	t.Helper()
	p := filepath.Join(f.root, rel)
	if err := os.Rename(p, p+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// TestMaterializeDoesNotFollowASwappedAncestor: a symlinked ancestor of the
// mount dir already in place when the pod is created (a process of an earlier
// instance can plant it) is refused, and nothing is written through it.
func TestMaterializeDoesNotFollowASwappedAncestor(t *testing.T) {
	f := newPinFixture(t)
	if err := os.MkdirAll(filepath.Join(f.root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.victim, filepath.Join(f.root, "data", "x")); err != nil {
		t.Fatal(err)
	}
	_, err := Materialize(context.Background(), f.box, f.root, "", f.r)
	if !errors.Is(err, pathsafe.ErrSymlinkedPath) {
		t.Errorf("Materialize through a symlinked ancestor = %v, want pathsafe.ErrSymlinkedPath", err)
	}
	f.checkVictim(t)
}

// TestRefreshRefusesAnUnsafeMountDir: between Materialize and Refresh the pod
// replaces the mount dir itself with a link, or an ancestor with a file. The
// refresh of that volume fails, the live data is not touched, and nothing is
// written outside the pod.
func TestRefreshRefusesAnUnsafeMountDir(t *testing.T) {
	t.Run("the mount dir itself becomes a link", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		f.swapForLink(t, "data/x/cfg", filepath.Join(f.victim, "cfg"))
		res, err := f.refresh(t, layout)
		if !errors.Is(err, pathsafe.ErrSymlinkedPath) || res.Volumes[0].Outcome != RefreshFailed {
			t.Errorf("Refresh = %v (outcome %s), want RefreshFailed with pathsafe.ErrSymlinkedPath", err, res.Volumes[0].Outcome)
		}
		f.checkVictim(t)
	})
	t.Run("an ancestor becomes a file", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		x := filepath.Join(f.root, "data", "x")
		if err := os.Rename(x, x+".away"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(x, []byte("not a dir"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := f.refresh(t, layout)
		if !errors.Is(err, pathsafe.ErrSymlinkedPath) || res.Volumes[0].Outcome != RefreshFailed {
			t.Errorf("Refresh = %v (outcome %s), want RefreshFailed with pathsafe.ErrSymlinkedPath", err, res.Volumes[0].Outcome)
		}
		if got := readString(t, x); got != "not a dir" {
			t.Errorf("the file in the mount path became %q", got)
		}
		f.checkVictim(t)
	})
	t.Run("Materialize refuses a file in the mount path", func(t *testing.T) {
		f := newPinFixture(t)
		if err := os.MkdirAll(filepath.Join(f.root, "data"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.root, "data", "x"), []byte("f"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Materialize(context.Background(), f.box, f.root, "", f.r); !errors.Is(err, pathsafe.ErrSymlinkedPath) {
			t.Errorf("Materialize = %v, want pathsafe.ErrSymlinkedPath", err)
		}
	})
}

// TestRefreshDoesNotFollowPlantedLinks: the names the layout itself uses, set
// by the pod to symlinks that lead out of its tree, are never followed. A
// ..data that names a generation-shaped link is refused before anything is
// written; a key name that is a link to a file outside is replaced as a link,
// and the file it named is left alone.
func TestRefreshDoesNotFollowPlantedLinks(t *testing.T) {
	t.Run("..data names a link to outside", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		dir := filepath.Join(f.root, "data/x/cfg")
		if err := os.Symlink(filepath.Join(f.victim, "cfg"), filepath.Join(dir, "..evil")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, dataLink)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("..evil", filepath.Join(dir, dataLink)); err != nil {
			t.Fatal(err)
		}
		res, err := f.refresh(t, layout)
		if err == nil || res.Volumes[0].Outcome != RefreshFailed {
			t.Errorf("Refresh = %v (outcome %s), want RefreshFailed", err, res.Volumes[0].Outcome)
		}
		f.checkVictim(t)
	})
	t.Run("a key name is a link to an outside file", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		dir := filepath.Join(f.root, "data/x/cfg")
		if err := os.Remove(filepath.Join(dir, "a")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(f.victim, "cfg", "a"), filepath.Join(dir, "a")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.refresh(t, layout); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if got, err := os.Readlink(filepath.Join(dir, "a")); err != nil || got != "..data/a" {
			t.Errorf("key a -> %q (%v), want the link replaced by ..data/a", got, err)
		}
		if got := readString(t, filepath.Join(dir, "a")); got != "pod-chosen-2" {
			t.Errorf("a = %q, want the refreshed value", got)
		}
		f.checkVictim(t)
	})
	t.Run("..data is a link to outside before the pod is created", func(t *testing.T) {
		f := newPinFixture(t)
		dir := filepath.Join(f.root, "data/x/cfg")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(f.victim, "cfg"), filepath.Join(dir, "..evil")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("..evil", filepath.Join(dir, dataLink)); err != nil {
			t.Fatal(err)
		}
		if _, err := Materialize(context.Background(), f.box, f.root, "", f.r); err == nil {
			t.Error("Materialize over a planted ..data succeeded")
		}
		f.checkVictim(t)
	})
}
