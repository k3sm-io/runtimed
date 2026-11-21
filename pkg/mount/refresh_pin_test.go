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
	"strings"
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
// ..data that names a generation-shaped link is not trusted as the live
// generation: the volume is rendered fresh and the flip replaces ..data. The
// planted link is left where it is (only a trusted previous generation is
// removed) and never followed. A key name that is a link to a file
// outside is replaced as a link, and the file it named is left alone.
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
		if err != nil || res.Volumes[0].Outcome != RefreshUpdated {
			t.Errorf("Refresh = %v (outcome %s), want a fresh render made live", err, res.Volumes[0].Outcome)
		}
		if got := liveGen(t, dir); got == "..evil" {
			t.Error("..data still names the planted link")
		}
		if fi, err := os.Lstat(filepath.Join(dir, "..evil")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the planted link was not left as a link (lstat %v, err %v)", fi, err)
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
		if _, err := Materialize(context.Background(), f.box, f.root, "", f.r); err != nil {
			t.Errorf("Materialize over a planted ..data: %v, want a fresh render", err)
		}
		if got := liveGen(t, dir); got == "..evil" {
			t.Error("..data still names the planted link")
		}
		f.checkVictim(t)
	})
}

// TestWriteFileRefusesAPlantedHardLink: a pod watching a new generation dir can
// plant a name in it while the render waits on the resolver, a hard link to a
// file it may not write among them. writeFile refuses a name this render did
// not create (and never truncates it), and verifyGeneration refuses a file
// with more than one link, so the target is never written and the generation
// never goes live.
func TestWriteFileRefusesAPlantedHardLink(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "other-tenant")
	if err := os.WriteFile(target, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Run("writeFile", func(t *testing.T) {
		dir := t.TempDir()
		flips := countFlips(t, nil)
		_, _, err := writeGeneration(openTestDir(t, dir), nil, func(gen, _ *dirTarget) error {
			if err := os.Link(target, gen.join("k")); err != nil {
				t.Fatal(err)
			}
			return writeFile(gen, "k", []byte("pod-chosen"), 0o644)
		})
		if err == nil || !strings.Contains(err.Error(), "did not create") {
			t.Errorf("err = %v, want writeFile to refuse the planted name", err)
		}
		if *flips != 0 {
			t.Error("the generation went live")
		}
	})
	t.Run("verifyGeneration", func(t *testing.T) {
		dir := t.TempDir()
		_, _, err := writeGeneration(openTestDir(t, dir), nil, func(gen, _ *dirTarget) error {
			if err := writeFile(gen, "a", []byte("x"), 0o644); err != nil {
				return err
			}
			return os.Link(target, gen.join("k"))
		})
		if err == nil || !strings.Contains(err.Error(), "hard links") {
			t.Errorf("err = %v, want verifyGeneration to refuse the linked file", err)
		}
	})
	t.Run("a second write of a name this render created", func(t *testing.T) {
		dir := t.TempDir()
		_, _, err := writeGeneration(openTestDir(t, dir), nil, func(gen, _ *dirTarget) error {
			if err := writeFile(gen, "k", []byte("first, longer"), 0o644); err != nil {
				return err
			}
			return writeFile(gen, "k", []byte("second"), 0o600)
		})
		if err != nil {
			t.Fatalf("writeGeneration: %v", err)
		}
		if got := readString(t, filepath.Join(dir, "k")); got != "second" {
			t.Errorf("k = %q, want the second write, truncated", got)
		}
	})
	if got := readString(t, target); got != "theirs" {
		t.Errorf("the linked file became %q", got)
	}
}

// tokenPinBox is a pod with one projected ServiceAccount token at /sa.
func tokenPinBox() *runtimev1.PodBox {
	return mountBox([]*runtimev1.Volume{{Name: "tok", Projected: &runtimev1.ProjectedVolumeSource{
		Sources: []*runtimev1.VolumeProjection{
			{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: 3600}},
		},
	}}}, &runtimev1.VolumeMount{Name: "tok", MountPath: "/sa"})
}

// TestRefreshTrustsOnlyTheGenerationItMadeLive: a pod points ..data at a
// directory of its own whose token is a hard link to a file it can name but
// not read. The token is fresh, so the refresh would re-read it from the live
// generation; it must not: the live generation is not the one the last render
// made live, so it is not trusted, a token is minted, and the linked file's
// bytes never reach the generation the pod reads.
func TestRefreshTrustsOnlyTheGenerationItMadeLive(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "unreadable-by-the-pod")
	if err := os.WriteFile(secret, []byte("NOT-FOR-THE-POD"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRefreshResolver()
	box := tokenPinBox()
	layout, err := Materialize(ctx, box, root, "", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	dir := filepath.Join(root, "sa")
	planted := filepath.Join(dir, "..2020_01_01_00_00_00.1")
	if err := os.Mkdir(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(planted, "token")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(planted), filepath.Join(dir, "..data_pod")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_pod"), filepath.Join(dir, dataLink)); err != nil {
		t.Fatal(err)
	}

	res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if r.count("token") != 2 {
		t.Errorf("token mints = %d, want a fresh mint for an untrusted live generation", r.count("token"))
	}
	if got := readString(t, filepath.Join(dir, "token")); got != "TOKEN-2" {
		t.Errorf("token = %q, want the fresh TOKEN-2", got)
	}
	if res.Volumes[0].Outcome != RefreshUpdated {
		t.Errorf("outcome = %s, want Updated", res.Volumes[0].Outcome)
	}
	if got := readString(t, secret); got != "NOT-FOR-THE-POD" {
		t.Errorf("the linked file changed: %q", got)
	}

	// And the generation it made live is trusted next time: a fresh token is
	// re-read, not minted.
	if _, err := Refresh(ctx, root, box, r, RefreshOptions{State: res.State}); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}
	if r.count("token") != 2 {
		t.Errorf("token mints = %d after a refresh of a trusted generation, want still 2", r.count("token"))
	}
}

// TestRefreshBoundsWhatItReadsFromThePod: the live generation is the pod's to
// write in a writable mount. A tree nested past maxTreeDepth there makes the
// comparison fail for that volume rather than walk it.
func TestRefreshBoundsWhatItReadsFromThePod(t *testing.T) {
	f := newPinFixture(t)
	layout := f.materialize(t)
	dir := filepath.Join(f.root, "data/x/cfg")
	deep := filepath.Join(dir, liveGen(t, dir))
	for i := 0; i < maxTreeDepth+2; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := f.refresh(t, layout)
	if !errors.Is(err, errTreeTooLarge) || res.Volumes[0].Outcome != RefreshFailed {
		t.Errorf("Refresh = %v (outcome %s), want RefreshFailed with errTreeTooLarge", err, res.Volumes[0].Outcome)
	}
}

// TestRefreshReplacesADataDirectory: a ..data the pod made a directory would
// freeze the mount (a symlink cannot be renamed over a directory). It is
// removed and the volume rendered fresh.
func TestRefreshReplacesADataDirectory(t *testing.T) {
	f := newPinFixture(t)
	layout := f.materialize(t)
	dir := filepath.Join(f.root, "data/x/cfg")
	if err := os.Remove(filepath.Join(dir, dataLink)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, dataLink, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := f.refresh(t, layout)
	if err != nil || res.Volumes[0].Outcome != RefreshUpdated {
		t.Fatalf("Refresh = %v (outcome %s), want Updated", err, res.Volumes[0].Outcome)
	}
	if got := readString(t, filepath.Join(dir, "a")); got != "pod-chosen-2" {
		t.Errorf("a = %q, want the refreshed value", got)
	}
}
