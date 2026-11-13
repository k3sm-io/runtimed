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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// contentSorting returns a content string, distinct per prefix, whose sha256
// digest falls in the lower half of the digest space when low is set and in
// the upper half otherwise. A test uses it to put image blobs BEFORE artifact
// blobs in path order, so an eviction that only walked paths would take the
// images first.
func contentSorting(prefix string, low bool) string {
	for i := 0; ; i++ {
		s := fmt.Sprintf("%s %d", prefix, i)
		sum := sha256.Sum256([]byte(s))
		if (sum[0] < 0x80) == low {
			return s
		}
	}
}

// TestReclaimEvictsUnreferencedArtifactsFirst pins the eviction order under
// pressure: the blobs of an artifact whose record was released go before the
// blobs of an unreferenced image, whatever their path order, and the order
// makes nothing eligible that was not. A pinned artifact (its record still
// exists), a held one (a pod's hold names it after its record went) and a
// young one survive both the pressure pass and a forced drain.
func TestReclaimEvictsUnreferencedArtifactsFirst(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	imgCfg := f.blob(contentSorting("image config", true), time.Hour)
	imgLayer := f.blob(contentSorting("image layer", true), time.Hour)
	recordImage(t, x, "registry.example/app:v1", imgCfg, imgLayer)

	artCfg := f.blob(contentSorting("released config", false), time.Hour)
	artLayer := f.blob(contentSorting("released weights", false), time.Hour)
	putTypedArtifact(t, x, "registry.example/models/a:v1@"+testModelType, testModelType, artCfg, artLayer)
	releaseArtifact(t, x, "registry.example/models/a:v1@"+testModelType)

	pinCfg := f.blob("pinned config", time.Hour)
	pinLayer := f.blob("pinned weights", time.Hour)
	putTypedArtifact(t, x, "registry.example/models/pin:v1@"+testModelType, testModelType, pinCfg, pinLayer)

	heldCfg := f.blob("held config", time.Hour)
	heldLayer := f.blob("held weights", time.Hour)
	putTypedArtifact(t, x, "registry.example/models/held:v1@"+testModelType, testModelType, heldCfg, heldLayer)
	pod, err := ParsePodID("pod-held")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("held manifest"))
	if err := x.AddArtifactHoldManifest(ctx, pod, HeldManifest{
		Digest: fmt.Sprintf("sha256:%x", sum), Config: heldCfg, Layers: []string{heldLayer},
	}); err != nil {
		t.Fatal(err)
	}
	releaseArtifact(t, x, "registry.example/models/held:v1@"+testModelType)

	youngCfg := f.blob("young config", time.Second)
	youngLayer := f.blob("young weights", time.Second)
	putTypedArtifact(t, x, "registry.example/models/young:v1@"+testModelType, testModelType, youngCfg, youngLayer)
	releaseArtifact(t, x, "registry.example/models/young:v1@"+testModelType)

	survivors := []string{pinCfg, pinLayer, heldCfg, heldLayer, youngCfg, youngLayer}

	// Sample one is the trigger; the two unlinks after it run under pressure,
	// and the sample before the third meets the target.
	free := &fakeFree{free: []uint64{0, 0, 0, 30 << 30}}
	rep, err := f.cache.ReclaimUnderPressure(ctx, ReclaimConfig{
		HighFreeBytes: 5 << 30, TargetFreeBytes: 10 << 30, Grace: time.Minute, FreeBytes: free.sample,
	})
	if err != nil {
		t.Fatalf("ReclaimUnderPressure: %v", err)
	}
	removed := slices.Sorted(slices.Values(rep.Removed))
	want := slices.Sorted(slices.Values([]string{artCfg, artLayer}))
	if !slices.Equal(removed, want) {
		t.Fatalf("pressure pass removed %v; want the released artifact's blobs %v", removed, want)
	}
	for _, d := range append([]string{imgCfg, imgLayer}, survivors...) {
		if !f.exists(d) {
			t.Errorf("blob %s was evicted before the released artifact's blobs ran out", d)
		}
	}

	// A forced drain then takes the image, and still nothing that was never
	// eligible.
	rep, err = f.cache.ReclaimUnderPressure(ctx, ReclaimConfig{
		Force: true, Grace: time.Minute, FreeBytes: (&fakeFree{free: []uint64{0}}).sample,
	})
	if err != nil {
		t.Fatalf("forced ReclaimUnderPressure: %v", err)
	}
	for _, d := range []string{imgCfg, imgLayer} {
		if f.exists(d) {
			t.Errorf("unreferenced image blob %s survived a forced drain", d)
		}
	}
	for _, d := range survivors {
		if !f.exists(d) {
			t.Errorf("ineligible blob %s was evicted (pinned, held or young)", d)
		}
	}
}

// TestReclaimEvictsLeastRecentlyReleasedArtifactFirst pins the order among
// released artifacts (the older release goes first, whatever the path order)
// and that a forced drain sweeps the released record copies whose blobs are
// gone while keeping the copy of a blob still on disk.
func TestReclaimEvictsLeastRecentlyReleasedArtifactFirst(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	newer := f.blob(contentSorting("newer release", true), time.Hour)
	older := f.blob(contentSorting("older release", false), time.Hour)
	young := f.blob("young release", time.Second)
	for key, d := range map[string]string{"newer": newer, "older": older, "young": young} {
		putTypedArtifact(t, x, "registry.example/models/"+key+":v1@"+testModelType, testModelType, d)
		releaseArtifact(t, x, "registry.example/models/"+key+":v1@"+testModelType)
	}
	copies, err := x.releasedArtifacts()
	if err != nil || len(copies) != 3 {
		t.Fatalf("releasedArtifacts = %d copies, %v; want 3", len(copies), err)
	}
	for _, rc := range copies {
		at := f.clock.Add(-time.Minute)
		if rc.root.ConfigDigest == older {
			at = f.clock.Add(-time.Hour)
		}
		if err := os.Chtimes(filepath.Join(x.dir, ArtifactReleasedIndexSubdir, rc.name), at, at); err != nil {
			t.Fatal(err)
		}
	}

	free := &fakeFree{free: []uint64{0, 0, 30 << 30}}
	rep, err := f.cache.ReclaimUnderPressure(ctx, ReclaimConfig{Grace: time.Minute, FreeBytes: free.sample})
	if err != nil {
		t.Fatalf("ReclaimUnderPressure: %v", err)
	}
	if !slices.Equal(rep.Removed, []string{older}) {
		t.Fatalf("pressure pass removed %v; want only the older release %s", rep.Removed, older)
	}
	if got := rep.ReclaimedByClass[testModelType]; got != rep.ReclaimedBytes || got <= 0 {
		t.Errorf("ReclaimedByClass = %v; want the removed bytes under %s", rep.ReclaimedByClass, testModelType)
	}

	if _, err := f.cache.ReclaimUnderPressure(ctx, ReclaimConfig{
		Force: true, Grace: time.Minute, FreeBytes: (&fakeFree{free: []uint64{0}}).sample,
	}); err != nil {
		t.Fatalf("forced ReclaimUnderPressure: %v", err)
	}
	if f.exists(newer) || !f.exists(young) {
		t.Fatalf("after the drain newer exists=%v young exists=%v; want false, true", f.exists(newer), f.exists(young))
	}
	copies, err = x.releasedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 || copies[0].root.ConfigDigest != young {
		t.Fatalf("released copies after the drain = %+v; want only the young one", copies)
	}
}

// TestPinnedNowHonoursALeaseTakenAfterPlanning pins the re-read of the leases
// before each executor run: a planned blob that an ingest leased since the
// plan is left in place and reported kept as leased.
func TestPinnedNowHonoursALeaseTakenAfterPlanning(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("planned a", time.Hour)
	b := f.blob("planned b", time.Hour)
	dels := []PruneDecision{
		{Node: BlobNode{Path: "sha256/" + a[len("sha256:"):], Digest: a, Kind: BlobKindContent}, Reason: ReasonDeleteUnreferenced},
		{Node: BlobNode{Path: "sha256/" + b[len("sha256:"):], Digest: b, Kind: BlobKindContent}, Reason: ReasonDeleteUnreferenced},
	}
	lease := f.cache.AcquireLease([]string{b}, time.Hour)
	defer lease.Release()
	pinned := func() (map[string]PruneReason, error) { return f.cache.pinnedNow(nil) }
	rep, err := f.cache.executePrune(&PrunePlan{Delete: dels}, 0, f.clock, nil, pinned, nil)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if len(rep.Removed) != 1 || rep.Removed[0] != a {
		t.Fatalf("executePrune removed %v; want only %s", rep.Removed, a)
	}
	if len(rep.pinned) != 1 || rep.pinned[0].Digest != b || rep.pinned[0].Reason != ReasonKeptLeased {
		t.Fatalf("rep.pinned = %+v; want %s kept as leased", rep.pinned, b)
	}
	if !f.exists(b) {
		t.Fatal("the leased blob was unlinked")
	}
}

// planOf returns a delete plan naming each digest's blob.
func planOf(digests ...string) *PrunePlan {
	p := &PrunePlan{}
	for _, d := range digests {
		p.Delete = append(p.Delete, PruneDecision{
			Node:   BlobNode{Path: "sha256/" + d[len("sha256:"):], Digest: d, Kind: BlobKindContent},
			Reason: ReasonDeleteUnreferenced,
		})
	}
	return p
}

// TestExecutePruneUnlinksNothingWhenThePinReadFails pins the fail-closed rule
// of the per-batch pin read: an error from pinned aborts the run before any
// unlink, because a short pin set would condemn what it failed to name.
func TestExecutePruneUnlinksNothingWhenThePinReadFails(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("planned a", time.Hour)
	b := f.blob("planned b", time.Hour)
	boom := errors.New("pin read failed")
	pinned := func() (map[string]PruneReason, error) { return nil, boom }
	if _, err := f.cache.executePrune(planOf(a, b), 0, f.clock, nil, pinned, nil); !errors.Is(err, boom) {
		t.Fatalf("executePrune error = %v; want %v", err, boom)
	}
	if !f.exists(a) || !f.exists(b) {
		t.Fatalf("a failed pin read still unlinked: a exists=%v b exists=%v", f.exists(a), f.exists(b))
	}
}

// TestPinnedNowFailsClosedOnAnIncompleteRootSet pins that the batch's root
// re-read inherits the roots' fatality: a node under the pods tree that is
// not a pod dir makes pinnedNow fail, and the batch unlinks nothing.
func TestPinnedNowFailsClosedOnAnIncompleteRootSet(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("planned a", time.Hour)
	f.pod("pod-a")
	if err := os.WriteFile(filepath.Join(f.cache.PodsRoot(), "stray"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pinned := func() (map[string]PruneReason, error) { return f.cache.pinnedNow(nil) }
	if _, err := f.cache.executePrune(planOf(a), 0, f.clock, nil, pinned, nil); !errors.Is(err, ErrRootsIncomplete) {
		t.Fatalf("executePrune error = %v; want ErrRootsIncomplete", err)
	}
	if !f.exists(a) {
		t.Fatal("an incomplete root set still unlinked a planned blob")
	}
}

// TestExecutePruneKeepsABlobLeasedMidBatch pins the per-unlink lease re-check:
// a lease taken after the batch's pin read, before that blob's unlink, keeps
// the blob, while the blob unlinked before it is gone. stop runs before each
// entry's checks, which is what places the lease inside the batch.
func TestExecutePruneKeepsABlobLeasedMidBatch(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("planned a", time.Hour)
	b := f.blob("planned b", time.Hour)
	var lease *Lease
	defer func() { lease.Release() }()
	calls := 0
	stop := func() bool {
		calls++
		if calls == 2 { // after a's unlink, before b's
			lease = f.cache.AcquireLease([]string{b}, time.Hour)
		}
		return false
	}
	pinned := func() (map[string]PruneReason, error) { return f.cache.pinnedNow(nil) }
	rep, err := f.cache.executePrune(planOf(a, b), 0, f.clock, stop, pinned, nil)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if f.exists(a) {
		t.Fatal("the blob before the lease survived, so the run proved nothing")
	}
	if !f.exists(b) {
		t.Fatal("a blob leased mid-batch was unlinked")
	}
	if len(rep.pinned) != 1 || rep.pinned[0].Digest != b || rep.pinned[0].Reason != ReasonKeptLeased {
		t.Fatalf("rep.pinned = %+v; want %s kept as leased", rep.pinned, b)
	}
}

// TestLeaseHasMatchesLeasedDigests checks that the per-blob lease check agrees
// with the full lease set for live, released and expired leases, and that it
// allocates nothing.
func TestLeaseHasMatchesLeasedDigests(t *testing.T) {
	f := newGCFixture(t)
	f.cache.AcquireLease([]string{"sha256:live-a", "sha256:shared"}, time.Hour)
	released := f.cache.AcquireLease([]string{"sha256:released", "sha256:shared"}, time.Hour)
	f.cache.AcquireLease([]string{"sha256:expired"}, time.Minute)
	f.cache.AcquireLease([]string{"sha256:live-b"}, 2*time.Hour)
	released.Release()
	f.clock = f.clock.Add(30 * time.Minute)

	digests := []string{"sha256:live-a", "sha256:live-b", "sha256:shared", "sha256:released", "sha256:expired", "sha256:never"}
	want := map[string]bool{"sha256:live-a": true, "sha256:live-b": true, "sha256:shared": true}
	for _, d := range digests {
		got := f.cache.leaseHas(d)
		if set := f.cache.leasedDigests()[d]; got != set {
			t.Errorf("leaseHas(%q) = %v, leasedDigests has %v", d, got, set)
		}
		if got != want[d] {
			t.Errorf("leaseHas(%q) = %v, want %v", d, got, want[d])
		}
	}

	allocs := testing.AllocsPerRun(100, func() {
		for _, d := range digests {
			_ = f.cache.leaseHas(d)
		}
	})
	if allocs != 0 {
		t.Errorf("leaseHas allocated %v times per run, want 0", allocs)
	}
}
