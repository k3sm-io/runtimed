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

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
)

// TestArtifactHoldStoreEntries pins how the hold store treats each kind of
// entry: a name that is not <pod-id>.json can never be a hold, so the reader
// ignores it and the start-up sweep removes it; the hold of a pod that is
// neither live nor re-attached is removed by the sweep even when it cannot be
// read; a live pod's hold stays, readable or not; a crashed commit's temp is
// left to the reader to skip.
func TestArtifactHoldStoreEntries(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	dir := filepath.Join(rt.cache.IndexRoot(), image.ArtifactHoldIndexSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	registerLivePod(rt, "live")
	rt.mu.Lock()
	rt.podReapStarted = true
	rt.mu.Unlock()
	for _, tc := range []struct {
		name    string
		symlink bool
		body    string
		reader  string // "ignored", "fails" or "reads"
		swept   bool
	}{
		{name: "A.json", body: "{", reader: "ignored", swept: true},
		{name: "-x.json", body: "{", reader: "ignored", swept: true},
		{name: "notes", body: "{", reader: "ignored", swept: true},
		{name: "dead.json", body: "{", reader: "fails", swept: true},
		{name: "ghost.json", symlink: true, reader: "fails", swept: true},
		{name: "gone.json", body: `{"references":["r"]}`, reader: "reads", swept: true},
		{name: "live.json", body: "{", reader: "fails", swept: false},
		{name: ".index-live.json", body: "{", reader: "ignored", swept: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name)
			if tc.symlink {
				if err := os.Symlink("/etc/hosts", p); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(p)
			_, err := rt.index.ArtifactHolds(context.Background())
			switch tc.reader {
			case "ignored", "reads":
				if err != nil {
					t.Errorf("ArtifactHolds = %v, want the entry %s", err, tc.reader)
				}
			case "fails":
				var he *image.HoldReadError
				if !errors.As(err, &he) || he.Path != p {
					t.Errorf("ArtifactHolds = %v, want a HoldReadError naming %s", err, p)
				}
			}
			rt.sweepArtifactHolds()
			_, err = os.Lstat(p)
			if gone := errors.Is(err, os.ErrNotExist); gone != tc.swept {
				t.Errorf("after the start-up sweep the entry is gone=%v, want %v", gone, tc.swept)
			}
		})
	}
}

// TestDeletePodOfUnheldPodEndsItsHold pins that a DeletePod of a pod this
// daemon does not hold (not re-attached after a restart) still ends its
// artifact hold and runs the release.
func TestDeletePodOfUnheldPodEndsItsHold(t *testing.T) {
	f := newLifetimeFixture(t)
	view := f.create("pod-a")
	f.rt.mu.Lock()
	delete(f.rt.pods, "pod-a")
	f.rt.mu.Unlock()
	f.delete("pod-a")
	f.prune()
	if f.kept(view) {
		t.Fatal("a delete of a pod the daemon does not hold left its artifact held")
	}
}

// TestFailedCreateRemovesOnlyItsOwnHold pins the failed-create rule: the
// failure removes the hold when it is the only create of the id in flight,
// and leaves it when another create of the same id is in flight, whose hold
// it is too.
func TestFailedCreateRemovesOnlyItsOwnHold(t *testing.T) {
	for _, tc := range []struct {
		name         string
		otherCreates int
		wantHold     bool
	}{
		{name: "sole create", otherCreates: 0, wantHold: false},
		{name: "another create in flight", otherCreates: 1, wantHold: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{ArtifactPuller: &scriptedArtifactPuller{err: errors.New("registry down")}})
			id := "pod-c"
			rt.mu.Lock()
			rt.creating[id] += tc.otherCreates
			rt.mu.Unlock()
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: imageVolumeBox(rt, id, artifactTestHost+"/models/tiny:v1")})
			if err != nil || resp.GetError() == nil {
				t.Fatalf("CreatePod = %v, %v; want a refused create", resp, err)
			}
			holds, err := rt.index.ArtifactHolds(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			pid, _ := image.ParsePodID(id)
			if _, ok := holds[pid]; ok != tc.wantHold {
				t.Errorf("hold present = %v, want %v", ok, tc.wantHold)
			}
		})
	}
}

// TestSecondCreateMergesIntoTheHold pins that a second create of the same pod
// id adds to the hold rather than replacing it: the manifest the first create
// mounted stays held.
func TestSecondCreateMergesIntoTheHold(t *testing.T) {
	f := newLifetimeFixture(t)
	f.create("pod-a")
	box := imageVolumeBox(f.rt, "pod-a", f.ref)
	vols, err := mount.ImageVolumes(box)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rt.holdArtifacts(context.Background(), box, vols); err != nil {
		t.Fatal(err)
	}
	held, err := f.rt.index.HeldManifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !held[f.mdig] {
		t.Fatalf("a second create of pod-a dropped the manifest the first one mounts; held = %v", held)
	}
}
