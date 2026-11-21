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
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fdSpare is the descriptors a refresh may hold beyond those open before it:
// walkAt holds one per level up to maxTreeDepth, RemoveTreeAt a few.
const fdSpare = maxTreeDepth + 32

// openFDs counts the descriptors this process has open.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents) - 1 // the one ReadDir itself held
}

// withFDLimit runs fn with the soft RLIMIT_NOFILE at the descriptors open now
// plus spare, so fn fails with EMFILE if it ever holds more than spare more,
// and fails the test if fn leaves any open.
func withFDLimit(t *testing.T, spare int, fn func()) {
	t.Helper()
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	before := openFDs(t)
	lim := old
	lim.Cur = uint64(before + spare)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	fn()
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	after := openFDs(t)
	t.Logf("open descriptors: %d before, %d after, limit %d", before, after, lim.Cur)
	if after != before {
		t.Errorf("open descriptors went from %d to %d", before, after)
	}
}

// plantChain makes name under dir and depth-1 directories "d" nested below
// it, through descriptors (the chain is longer than PATH_MAX), as a pod can.
func plantChain(t *testing.T, dir, name string, depth int) {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < depth; i++ {
		n := "d"
		if i == 0 {
			n = name
		}
		if err := unix.Mkdirat(fd, n, 0o755); err != nil {
			t.Fatal(err)
		}
		next, err := unix.Openat(fd, n, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		fd = next
	}
	unix.Close(fd)
}

// trashNames lists the ..trash_ entries of dir.
func trashNames(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, n := range listDir(t, dir) {
		if strings.HasPrefix(n, "..trash_") {
			out = append(out, n)
		}
	}
	return out
}

// TestRefreshRemovesPlantedTreesWithinBounds: every tree a refresh removes
// from a mount dir can be the pod's (a ..data it made a directory, a
// generation it pointed ..data at, entries it planted in a generation while it
// rendered). None of them may cost the daemon descriptors in proportion to
// their depth, nor unbounded work: a refresh holds a constant number beyond
// walkAt's maxTreeDepth, and a tree over removeBounds fails that volume's
// refresh, the rest left on disk.
func TestRefreshRemovesPlantedTreesWithinBounds(t *testing.T) {
	const deep = 300
	t.Run("a deep ..data directory", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		dir := filepath.Join(f.root, "data/x/cfg")
		if err := os.Remove(filepath.Join(dir, dataLink)); err != nil {
			t.Fatal(err)
		}
		plantChain(t, dir, dataLink, deep)
		var res RefreshResult
		var err error
		withFDLimit(t, fdSpare, func() { res, err = f.refresh(t, layout) })
		if !errors.Is(err, errTreeTooLarge) || res.Volumes[0].Outcome != RefreshFailed {
			t.Fatalf("Refresh = %v (outcome %s), want RefreshFailed with errTreeTooLarge", err, res.Volumes[0].Outcome)
		}
		if n := trashNames(t, dir); len(n) != 1 {
			t.Errorf("trash = %v, want the planted ..data renamed aside once", n)
		}
		// Aside, it no longer stands in the way: the next refresh renders.
		res, err = f.refresh(t, layout)
		if err != nil || res.Volumes[0].Outcome != RefreshUpdated {
			t.Fatalf("second Refresh = %v (outcome %s), want Updated", err, res.Volumes[0].Outcome)
		}
		if got := readString(t, filepath.Join(dir, "a")); got != "pod-chosen-2" {
			t.Errorf("a = %q, want the refreshed value", got)
		}
	})
	t.Run("a wide ..data directory", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		dir := filepath.Join(f.root, "data/x/cfg")
		if err := os.Remove(filepath.Join(dir, dataLink)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, dataLink), 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < maxTreeEntries+2000; i++ {
			if err := os.WriteFile(filepath.Join(dir, dataLink, strconv.Itoa(i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		var res RefreshResult
		var err error
		withFDLimit(t, fdSpare, func() { res, err = f.refresh(t, layout) })
		if !errors.Is(err, errTreeTooLarge) || res.Volumes[0].Outcome != RefreshFailed {
			t.Fatalf("Refresh = %v (outcome %s), want RefreshFailed with errTreeTooLarge", err, res.Volumes[0].Outcome)
		}
		res, err = f.refresh(t, layout)
		if err != nil || res.Volumes[0].Outcome != RefreshUpdated {
			t.Fatalf("second Refresh = %v (outcome %s), want Updated", err, res.Volumes[0].Outcome)
		}
	})
	t.Run("a deep generation ..data names", func(t *testing.T) {
		f := newPinFixture(t)
		layout := f.materialize(t)
		dir := filepath.Join(f.root, "data/x/cfg")
		const planted = "..2020_01_01_00_00_00.1"
		plantChain(t, dir, planted, deep)
		if err := os.Symlink(planted, filepath.Join(dir, "..data_pod")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(dir, "..data_pod"), filepath.Join(dir, dataLink)); err != nil {
			t.Fatal(err)
		}
		var res RefreshResult
		var err error
		withFDLimit(t, fdSpare, func() { res, err = f.refresh(t, layout) })
		if err != nil || res.Volumes[0].Outcome != RefreshUpdated {
			t.Fatalf("Refresh = %v (outcome %s), want a fresh render made live", err, res.Volumes[0].Outcome)
		}
		if _, err := os.Lstat(filepath.Join(dir, planted, "d")); err != nil {
			t.Errorf("the untrusted generation was touched: %v", err)
		}
		if got := readString(t, filepath.Join(dir, "a")); got != "pod-chosen-2" {
			t.Errorf("a = %q, want the refreshed value", got)
		}
	})
	t.Run("a generation the pod deepened while it rendered", func(t *testing.T) {
		dir := t.TempDir()
		target := openTestDir(t, dir)
		var err error
		withFDLimit(t, fdSpare, func() {
			_, _, err = writeGeneration(target, nil, func(gen, _ *dirTarget) error {
				if err := writeFile(gen, "a", []byte("x"), 0o644); err != nil {
					return err
				}
				plantChain(t, gen.path, "sub", deep)
				return nil
			})
		})
		if !errors.Is(err, errTreeTooLarge) {
			t.Errorf("writeGeneration = %v, want errTreeTooLarge", err)
		}
		if _, lerr := os.Lstat(filepath.Join(dir, dataLink)); lerr == nil {
			t.Error("the deepened generation went live")
		}
	})
}

// TestRefreshRendersAReplacedMountDirFresh: a tool in the pod moves a parent
// of the mount aside and makes a new directory in its place, carrying the old
// live generation over with the pod's own bytes in it. That is not the
// directory the last render left, so nothing in it is trusted: the volume is
// rendered fresh (a token is minted, none read from the pod) and the new
// directory is recorded, so the mount keeps rotating instead of failing every
// refresh until the pod restarts.
func TestRefreshRendersAReplacedMountDirFresh(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	r := newRefreshResolver()
	box := tokenPinBox()
	layout, err := Materialize(ctx, box, root, "", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	dir := filepath.Join(root, "sa")
	gen := liveGen(t, dir)
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir+".away", gen), filepath.Join(dir, gen)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, gen, "token"), []byte("POD-TOKEN"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(gen, filepath.Join(dir, dataLink)); err != nil {
		t.Fatal(err)
	}

	res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
	if err != nil || res.Volumes[0].Outcome != RefreshUpdated {
		t.Fatalf("Refresh = %v (outcome %s), want a fresh render made live", err, res.Volumes[0].Outcome)
	}
	if r.count("token") != 2 {
		t.Errorf("token mints = %d, want a fresh mint in a replaced mount dir", r.count("token"))
	}
	if got := readString(t, filepath.Join(dir, "token")); got != "TOKEN-2" {
		t.Errorf("token = %q, want the fresh TOKEN-2", got)
	}
	if _, err := Refresh(ctx, root, box, r, RefreshOptions{State: res.State}); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}
	if r.count("token") != 2 {
		t.Errorf("token mints = %d after a refresh of the recorded dir, want still 2", r.count("token"))
	}
}

// TestRenderBoundsAVolumesBytes: the bytes a refresh may read back from one
// generation (maxVolumeBytes) bound what a render may write to it, so a volume
// too large to refresh fails its create rather than every later refresh. A
// name written twice counts once.
func TestRenderBoundsAVolumesBytes(t *testing.T) {
	r := newRefreshResolver()
	r.set("big", false, "a", strings.Repeat("x", 5<<20), "b", strings.Repeat("y", 5<<20))
	box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "big")}, &runtimev1.VolumeMount{Name: "cfg", MountPath: "/cfg"})
	if _, err := Materialize(context.Background(), box, t.TempDir(), "", r); !errors.Is(err, errTreeTooLarge) {
		t.Errorf("Materialize of a 10 MiB volume = %v, want errTreeTooLarge", err)
	}
	_, _, err := writeGeneration(openTestDir(t, t.TempDir()), nil, func(gen, _ *dirTarget) error {
		big := []byte(strings.Repeat("z", 6<<20))
		if err := writeFile(gen, "k", big, 0o644); err != nil {
			return err
		}
		return writeFile(gen, "k", big, 0o644)
	})
	if err != nil {
		t.Errorf("a 6 MiB name written twice = %v, want it counted once", err)
	}
}
