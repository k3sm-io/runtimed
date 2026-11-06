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
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// lifetimeFixture is a runtime with the real puller and views over its own
// store, serving one model artifact.
type lifetimeFixture struct {
	t      *testing.T
	rt     *Runtime
	client runtimev1.ImagesClient
	fetch  *fakeArtifactFetcher
	ref    string
	mdig   string
	blobs  []string
}

func newLifetimeFixture(t *testing.T) *lifetimeFixture {
	t.Helper()
	if goruntime.GOOS != "darwin" {
		t.Skip("the daemon's views clone with APFS clonefile, darwin-only")
	}
	cfg, w := []byte(`{}`), []byte("weights")
	f := modelArtifact(map[string][]byte{"config.json": cfg, "w.safetensors": w}, []string{"config.json", "w.safetensors"})
	client, rt := artifactRPCClient(t, f)
	t.Cleanup(func() { restoreWritable(t, filepath.Join(rt.cache.Root(), sandbox.ArtifactViewsSubdir)) })
	return &lifetimeFixture{
		t: t, rt: rt, client: client, fetch: f,
		ref:   artifactTestHost + "/models/tiny:v1",
		mdig:  sha(f.manifest),
		blobs: []string{sha(cfg), sha(w)},
	}
}

func (f *lifetimeFixture) create(podID string) string {
	f.t.Helper()
	mustCreatePod(f.t, f.rt, imageVolumeBox(f.rt, podID, f.ref))
	view, err := os.Readlink(filepath.Join(f.rt.cfg.Root, "pods", podID, "rootfs", "models"))
	if err != nil {
		f.t.Fatalf("pod %s has no image mount: %v", podID, err)
	}
	return view
}

func (f *lifetimeFixture) delete(podID string) {
	f.t.Helper()
	if _, err := f.rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID}); err != nil {
		f.t.Fatalf("DeletePod %s: %v", podID, err)
	}
}

// prune runs a forced reclaim with every blob past its grace, as PruneImages
// does an hour from now.
func (f *lifetimeFixture) prune() {
	f.t.Helper()
	if err := f.reclaim(true); err != nil {
		f.t.Fatalf("prune: %v", err)
	}
}

// reclaim runs one reclaim pass an hour from now: forced, as PruneImages
// runs it, or under disk pressure (free space reads zero), as the daemon's
// own pass does.
func (f *lifetimeFixture) reclaim(force bool) error {
	_, err := f.rt.cache.ReclaimUnderPressure(context.Background(), image.ReclaimConfig{
		Force:        force,
		FreeBytes:    func(string) (uint64, error) { return 0, nil },
		Now:          func() time.Time { return time.Now().Add(time.Hour) },
		UntrackedPod: f.rt.podUntracked,
		SweepDerived: f.rt.viewSweeper(),
	})
	return err
}

// kept reports whether the artifact's record, view and blobs are all present
// (true) or all gone (false); a mix fails the test.
func (f *lifetimeFixture) kept(view string) bool {
	f.t.Helper()
	_, recorded, err := f.rt.index.ArtifactRecord(context.Background(), artifact.Key(f.ref, artifactv1.ArtifactTypeModel))
	if err != nil {
		f.t.Fatal(err)
	}
	_, verr := os.Lstat(view)
	state := map[string]bool{"record": recorded, "view": verr == nil}
	for _, d := range f.blobs {
		state["blob "+d] = f.rt.cache.Has(d)
	}
	all, none := true, true
	for _, v := range state {
		all = all && v
		none = none && !v
	}
	if !all && !none {
		f.t.Fatalf("artifact half released: %v", state)
	}
	return all
}

// TestImageVolumeLifetime pins that a pod's artifact is held from fetch to pod
// deletion and no longer: two pods share one artifact, deleting one keeps it,
// and deleting the other lets the prune reclaim the view and the blobs.
func TestImageVolumeLifetime(t *testing.T) {
	f := newLifetimeFixture(t)
	view := f.create("pod-a")
	if f.create("pod-b") != view {
		t.Fatal("two pods mounting one artifact got different views")
	}
	f.delete("pod-a")
	f.prune()
	if !f.kept(view) {
		t.Fatal("the artifact was released while pod-b still mounts it")
	}
	if b, err := os.ReadFile(filepath.Join(view, "w.safetensors")); err != nil || string(b) != "weights" {
		t.Fatalf("pod-b's view reads %q, %v", b, err)
	}
	f.delete("pod-b")
	f.prune()
	if f.kept(view) {
		t.Fatal("the artifact survived the deletion of every pod that mounted it")
	}
}

// TestImageVolumeLifetimeKeepsOperatorPin pins that only pods' holds are
// released: an artifact the operator pulled with the PullArtifact RPC keeps
// its record, before or after the pods that mount it.
func TestImageVolumeLifetimeKeepsOperatorPin(t *testing.T) {
	for _, order := range []string{"pull-first", "pull-after-create"} {
		t.Run(order, func(t *testing.T) {
			f := newLifetimeFixture(t)
			pull := func() {
				if _, err := f.client.PullArtifact(context.Background(), &runtimev1.PullArtifactRequest{
					Reference: f.ref, ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME,
				}); err != nil {
					t.Fatalf("PullArtifact: %v", err)
				}
			}
			if order == "pull-first" {
				pull()
			}
			view := f.create("pod-a")
			if order != "pull-first" {
				pull()
			}
			f.delete("pod-a")
			f.prune()
			if !f.kept(view) {
				t.Fatal("an operator-pinned artifact was released with its last pod")
			}
		})
	}
}

// TestImageVolumeLifetimeFailsClosed pins that a hold set the daemon cannot
// read in full releases and removes nothing: a live pod's unreadable hold
// keeps another pod's artifact past its last pod, refuses the prune, survives
// the start-up sweep and is reported by GetRuntimeInfo, naming its file.
// Once it reads again, the next release takes the artifact.
func TestImageVolumeLifetimeFailsClosed(t *testing.T) {
	f := newLifetimeFixture(t)
	view := f.create("pod-a")
	registerLivePod(f.rt, "pod-z")
	broken := filepath.Join(f.rt.cache.IndexRoot(), image.ArtifactHoldIndexSubdir, "pod-z.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.delete("pod-a")
	if err := f.reclaim(true); err == nil {
		t.Fatal("a prune ran although the holds could not all be read")
	}
	if !f.kept(view) {
		t.Fatal("the artifact was released although the holds could not all be read")
	}
	f.rt.sweepArtifactHolds()
	if _, err := os.Lstat(broken); err != nil {
		t.Fatalf("the start-up sweep removed a live pod's hold: %v", err)
	}
	info, err := f.rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	c := findCondition(info, ConditionArtifactHoldsReadable)
	if c == nil || c.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_FALSE || !strings.Contains(c.GetMessage(), broken) {
		t.Fatalf("GetRuntimeInfo condition = %v, want %s FALSE naming %s", c, ConditionArtifactHoldsReadable, broken)
	}

	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}
	f.rt.releaseArtifactHolds(context.Background(), "", 0)
	f.prune()
	if f.kept(view) {
		t.Fatal("the artifact survived a release with every hold readable")
	}
	info, err = f.rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if c := findCondition(info, ConditionArtifactHoldsReadable); c != nil {
		t.Errorf("GetRuntimeInfo still reports %v with every hold readable", c)
	}
}

// TestImageVolumeLifetimeStartupRelease pins the start-up rule: a pod the node
// did not re-attach is untracked once the reap has run, so its stale hold ends
// and what only it held is released; a pod the node re-attached keeps its own.
func TestImageVolumeLifetimeStartupRelease(t *testing.T) {
	f := newLifetimeFixture(t)
	view := f.create("pod-a")
	// What a restart leaves when nothing re-attaches pod-a: its hold on disk,
	// no sandbox and no reap record, first before the startup reap has run (the
	// served test runtime has run it already, so it is undone here), then after.
	f.rt.mu.Lock()
	delete(f.rt.pods, "pod-a")
	f.rt.podReapStarted = false
	f.rt.mu.Unlock()
	f.rt.removePodReapRecords("pod-a")

	f.rt.releaseArtifactHolds(context.Background(), "", 0)
	if !f.kept(view) {
		t.Fatal("a hold was ended before the startup reap could prove its pod gone")
	}
	f.rt.mu.Lock()
	f.rt.podReapStarted = true
	f.rt.mu.Unlock()
	f.rt.releaseArtifactHolds(context.Background(), "", 0)
	f.prune()
	if f.kept(view) {
		t.Fatal("a pod that was not re-attached still holds its artifact")
	}
}

// TestImageVolumeLifetimeSurvivesAMovedTag pins that a pod keeps the manifest
// it mounted when its tag moves: pod A mounts tag -> M1, then the tag moves to
// M2 (a second pod's create or an operator pull replaces the record), and
// neither a prune nor a pressure reclaim takes M1's view or blobs while A
// lives. Once A is deleted, the prune takes them.
func TestImageVolumeLifetimeSurvivesAMovedTag(t *testing.T) {
	for _, mover := range []string{"second pod", "operator pull"} {
		t.Run(mover, func(t *testing.T) {
			f := newLifetimeFixture(t)
			viewM1 := f.create("pod-a")
			m1Weights := f.blobs[1]

			m2 := modelArtifact(map[string][]byte{"config.json": []byte(`{}`), "w.safetensors": []byte("weights v2")}, []string{"config.json", "w.safetensors"})
			f.fetch.manifest = m2.manifest
			for d, b := range m2.blobs {
				f.fetch.blobs[d] = b
			}
			if mover == "second pod" {
				if f.create("pod-b") == viewM1 {
					t.Fatal("the moved tag still resolved to M1")
				}
			} else if _, err := f.client.PullArtifact(context.Background(), &runtimev1.PullArtifactRequest{
				Reference: f.ref, ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME,
			}); err != nil {
				t.Fatalf("PullArtifact: %v", err)
			}
			rec, ok, err := f.rt.index.ArtifactRecord(context.Background(), artifact.Key(f.ref, artifactv1.ArtifactTypeModel))
			if err != nil || !ok || !strings.Contains(string(rec), sha(m2.manifest)) {
				t.Fatalf("the record does not name M2 after the move (%v, %v)", ok, err)
			}

			for _, force := range []bool{true, false} {
				if err := f.reclaim(force); err != nil {
					t.Fatalf("reclaim (force %v): %v", force, err)
				}
				if b, err := os.ReadFile(filepath.Join(viewM1, "w.safetensors")); err != nil || string(b) != "weights" {
					t.Fatalf("after a reclaim (force %v) pod-a's M1 view reads %q, %v", force, b, err)
				}
				if !f.rt.cache.Has(m1Weights) {
					t.Fatalf("a reclaim (force %v) took M1's weights while pod-a mounts them", force)
				}
			}

			f.delete("pod-a")
			f.prune()
			if _, err := os.Lstat(viewM1); err == nil {
				t.Error("M1's view survived the deletion of the only pod that mounted it")
			}
			if f.rt.cache.Has(m1Weights) {
				t.Error("M1's weights survived the deletion of the only pod that mounted them")
			}
		})
	}
}
