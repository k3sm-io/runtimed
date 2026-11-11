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
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestEvictRacesRootAndLease drives the eviction executor seams against a
// writer goroutine that runs between the guard's roots read and the per-blob
// check, ordered by channel barriers in afterPlan: the guard's read names
// nothing, so only the per-blob check under leaseMu can keep the blob.
//
//   - a root written under a lease that is released before the per-blob check
//     keeps the blob on disk, typed rooted (operator root) or in-use (pod
//     record);
//   - a lease taken after the plan and still held keeps it, typed leased;
//   - with no writer, the blob is unlinked;
//   - through Cache.Evict itself, a root written and its lease released after
//     the plan, at the guard of the executor call that holds the blob, keeps
//     it, typed rooted in the result.
func TestEvictRacesRootAndLease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// race runs on its own goroutine after the guard's roots read; the
		// returned func, when non-nil, runs after the executor returns.
		race func(t *testing.T, f *gcFixture, pid PodID, digest string) (cleanup func())
		// want is the refusal; nil means the blob is unlinked.
		want *SkipRefusal
	}{
		{
			name: "operator root written and lease released before the per-blob check",
			race: func(t *testing.T, f *gcFixture, _ PodID, digest string) func() {
				l := f.cache.AcquireLease([]string{digest}, 0)
				err := f.cache.RecordOperatorImage("app:v1", Platform{OS: "linux", Architecture: "arm64"}, ImageRoot{Reference: "app:v1", Config: digest})
				l.Release()
				if err != nil {
					t.Errorf("RecordOperatorImage: %v", err)
				}
				return nil
			},
			want: &SkipRefusal{Kind: RefusedByUnlink, Reason: EvictKeptRooted},
		},
		{
			name: "pod root written and lease released before the per-blob check",
			race: func(t *testing.T, f *gcFixture, pid PodID, digest string) func() {
				l := f.cache.AcquireLease([]string{digest}, 0)
				err := f.cache.RecordPodImage(pid, ImageRoot{Reference: "app:v1", Config: digest})
				l.Release()
				if err != nil {
					t.Errorf("RecordPodImage: %v", err)
				}
				return nil
			},
			want: &SkipRefusal{Kind: RefusedByUnlink, Reason: EvictKeptInUse},
		},
		{
			name: "lease taken after the plan and still held",
			race: func(_ *testing.T, f *gcFixture, _ PodID, digest string) func() {
				return f.cache.AcquireLease([]string{digest}, 0).Release
			},
			want: &SkipRefusal{Kind: RefusedByUnlink, Reason: EvictKeptLeased},
		},
		{
			name: "no race unlinks the blob",
			race: func(*testing.T, *gcFixture, PodID, string) func() { return nil },
		},
	}
	t.Run("through Cache.Evict: operator root written and lease released after the plan", func(t *testing.T) {
		t.Parallel()
		testEvictRacesThroughEvict(t)
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			pid := f.pod("pod-a")
			digest := f.blob("evict-race", time.Hour)
			nodes, err := f.cache.EnumerateBlobs()
			if err != nil {
				t.Fatalf("EnumerateBlobs: %v", err)
			}
			roots, err := f.cache.classifiedRoots(nil)
			if err != nil {
				t.Fatalf("classifiedRoots: %v", err)
			}
			plan, err := PlanPrune(nodes, nil, roots.flatten(), nil, time.Minute, f.clock)
			if err != nil {
				t.Fatalf("PlanPrune: %v", err)
			}
			if len(plan.Delete) != 1 || plan.Delete[0].Node.Digest != digest {
				t.Fatalf("plan.Delete = %v; want exactly %s", plan.Delete, digest)
			}

			planned := make(chan struct{})
			raced := make(chan func())
			go func() {
				<-planned
				raced <- tc.race(t, f, pid, digest)
			}()
			var cleanup func()
			var once sync.Once
			calls := 0
			cfg := &ReclaimConfig{afterPlan: func() {
				calls++
				once.Do(func() {
					close(planned)
					cleanup = <-raced
				})
			}}
			rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, f.cache.evictHooks(cfg))
			if cleanup != nil {
				cleanup()
			}
			if err != nil {
				t.Fatalf("executePrune: %v", err)
			}
			if calls != 1 {
				t.Errorf("afterPlan ran %d times; want 1", calls)
			}

			if tc.want == nil {
				if !reflect.DeepEqual(rep.Removed, []string{digest}) || len(rep.Skipped) != 0 {
					t.Fatalf("Removed = %v, Skipped = %v; want %s removed and nothing skipped", rep.Removed, rep.Skipped, digest)
				}
				if f.exists(digest) {
					t.Errorf("%s still on disk after an unraced eviction", digest)
				}
				return
			}
			if !f.exists(digest) {
				t.Fatalf("%s unlinked; want it kept as %s", digest, tc.want.Reason)
			}
			if len(rep.Removed) != 0 || len(rep.Skipped) != 1 {
				t.Fatalf("Removed = %v, Skipped = %v; want nothing removed and one skip", rep.Removed, rep.Skipped)
			}
			want := *tc.want
			want.Digest = digest
			if got := rep.Skipped[0].Refusal; got == nil || *got != want {
				t.Errorf("Refusal = %+v; want %+v", got, want)
			}
		})
	}
}

// TestUnlinkUnlessLeasedRootsUnreadable pins the fail-closed per-blob read: a
// root set that cannot be read keeps the blob and is a typed unlink failure.
func TestUnlinkUnlessLeasedRootsUnreadable(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	digest := f.blob("evict-unreadable", time.Hour)
	nodes, err := f.cache.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	plan, err := PlanPrune(nodes, nil, nil, nil, time.Minute, f.clock)
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	hooks := f.cache.evictHooks(&ReclaimConfig{})
	hooks.guard = nil // the pass-level read is not under test here
	// A pod dir with no record is an incomplete root set.
	pid, err := ParsePodID("pod-b")
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	if err := os.MkdirAll(f.cache.PodDir(pid), 0o755); err != nil {
		t.Fatalf("mkdir pod dir: %v", err)
	}
	rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, hooks)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if !f.exists(digest) {
		t.Fatalf("%s unlinked with the roots unreadable", digest)
	}
	want := SkipRefusal{Digest: digest, Kind: RefusedRemoveFailed, Reason: EvictKeptUnlinkFailed}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Refusal == nil || *rep.Skipped[0].Refusal != want {
		t.Fatalf("Skipped = %+v; want one refusal %+v", rep.Skipped, want)
	}
}

// testEvictRacesThroughEvict is the Cache.Evict case of
// TestEvictRacesRootAndLease, run as its subtest so the gate name covers it.
func testEvictRacesThroughEvict(t *testing.T) {
	f := newGCFixture(t)
	digest := f.blob("evict-race-pass", time.Hour)
	sf := &sharedFixture{t: t, cache: f.cache, idx: &FileIndex{dir: f.cache.IndexRoot()}}
	manifest := sf.entry("app:v1", "race", false, digest)

	// The guard runs once per executor call: released artifacts, trees, then
	// the remaining blobs, which hold the target. The writer runs at the
	// third call, after that guard's own roots read, so only the per-blob
	// re-read under leaseMu can see the root.
	const blobCall = 3
	planned := make(chan struct{})
	raced := make(chan struct{})
	go func() {
		<-planned
		l := f.cache.AcquireLease([]string{digest}, 0)
		err := f.cache.RecordOperatorImage("app:v1", Platform{OS: "linux", Architecture: "arm64"}, ImageRoot{Reference: "app:v1", Config: digest})
		l.Release()
		if err != nil {
			t.Errorf("RecordOperatorImage: %v", err)
		}
		close(raced)
	}()
	var once sync.Once
	calls := 0
	cfg := ReclaimConfig{
		FreeBytes: func(string) (uint64, error) { return 1, nil },
		afterPlan: func() {
			calls++
			if calls == blobCall {
				once.Do(func() {
					close(planned)
					<-raced
				})
			}
		},
	}
	res, err := f.cache.Evict(context.Background(), manifest, []string{digest}, cfg)
	if err != nil {
		t.Fatalf("Evict: %v", err)
	}
	if calls != blobCall {
		t.Errorf("guard ran %d times; want %d, once per executor call", calls, blobCall)
	}
	if !f.exists(digest) {
		t.Fatalf("%s unlinked; want it kept as rooted", digest)
	}
	want := &EvictResult{Kept: []EvictKept{{Digest: digest, Reason: EvictKeptRooted}}}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Evict = %+v; want %+v", res, want)
	}
}

// TestUnlinkUnlessLeasedHoldsLeaseMu pins that the per-blob roots re-read and
// the unlink run under leaseMu: the remove closure finds the lock held, so
// hoisting the unlink out of the lock goes red.
func TestUnlinkUnlessLeasedHoldsLeaseMu(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	digest := f.blob("evict-locked", time.Hour)
	called := false
	removed, why, err := f.cache.unlinkUnlessLeased(digest, func() error {
		called = true
		if f.cache.leaseMu.TryLock() {
			f.cache.leaseMu.Unlock()
			t.Error("leaseMu not held across the unlink")
		}
		return nil
	}, nil)
	if err != nil || !removed || why != "" || !called {
		t.Fatalf("unlinkUnlessLeased = %v, %q, %v (remove called %v); want removed", removed, why, err, called)
	}
}

// TestEvictSharedPerBlob pins the narrow-mode per-blob shared-set read: an
// index entry naming the target's layer, written under a lease that is
// released after the blob executor's guard read and before its per-blob
// check, keeps the layer, typed shared. Only the read under leaseMu can see
// the entry, so removing it goes red.
func TestEvictSharedPerBlob(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	cfgDigest := f.blob("evict-shared-cfg", time.Hour)
	layer := f.blob("evict-shared-layer", time.Hour)
	sf := &sharedFixture{t: t, cache: f.cache, idx: &FileIndex{dir: f.cache.IndexRoot()}}
	manifest := sf.entry("app:v1", "target", false, cfgDigest, layer)

	// Guard calls: released artifacts, trees, then the remaining blobs.
	const blobCall = 3
	planned := make(chan struct{})
	raced := make(chan struct{})
	go func() {
		<-planned
		l := f.cache.AcquireLease([]string{layer}, 0)
		other := f.blob("evict-shared-other-cfg", time.Hour)
		sf.entry("other:v1", "other", false, other, layer)
		l.Release()
		close(raced)
	}()
	var once sync.Once
	calls := 0
	cfg := ReclaimConfig{
		FreeBytes: func(string) (uint64, error) { return 1, nil },
		afterPlan: func() {
			calls++
			if calls == blobCall {
				once.Do(func() {
					close(planned)
					<-raced
				})
			}
		},
	}
	res, err := f.cache.Evict(context.Background(), manifest, []string{cfgDigest, layer}, cfg)
	if err != nil {
		t.Fatalf("Evict: %v", err)
	}
	if !f.exists(layer) {
		t.Fatalf("%s unlinked; want it kept as shared", layer)
	}
	want := &EvictResult{
		Removed:        []string{cfgDigest},
		Kept:           []EvictKept{{Digest: layer, Reason: EvictKeptShared}},
		ReclaimedBytes: res.ReclaimedBytes,
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Evict = %+v; want %+v", res, want)
	}
}

// TestUnlinkUnlessHeldSharedUnreadable pins the fail-closed per-blob shared
// read: an error keeps the blob and is returned.
func TestUnlinkUnlessHeldSharedUnreadable(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	digest := f.blob("evict-shared-unreadable", time.Hour)
	called := false
	removed, _, err := f.cache.unlinkUnlessHeld(digest, func() error {
		called = true
		return nil
	}, nil, func(string) (bool, error) { return false, errors.New("boom") })
	if err == nil || removed || called {
		t.Fatalf("unlinkUnlessHeld = %v, %v (remove called %v); want kept with an error", removed, err, called)
	}
}

// TestEvictTreePerTreeCheck pins the narrow-mode per-tree check: a root
// written for the tree's backing blob, under a lease released after the tree
// executor's guard read and before the tree's removal, keeps the tree. Only
// the per-tree re-read under leaseMu can see it.
func TestEvictTreePerTreeCheck(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	cfgDigest := f.blob("evict-tree-cfg", time.Hour)
	layer := f.blob("evict-tree-layer", time.Hour)
	sf := &sharedFixture{t: t, cache: f.cache, idx: &FileIndex{dir: f.cache.IndexRoot()}}
	manifest := sf.entry("app:v1", "tree", false, cfgDigest, layer)
	tree := f.nativeTree(cfgDigest, []string{layer}, 10, time.Hour).dir

	const treeCall = 2
	planned := make(chan struct{})
	raced := make(chan struct{})
	go func() {
		<-planned
		l := f.cache.AcquireLease([]string{cfgDigest}, 0)
		err := f.cache.RecordOperatorImage("app:v1", Platform{OS: "linux", Architecture: "arm64"}, ImageRoot{Reference: "app:v1", Config: cfgDigest})
		l.Release()
		if err != nil {
			t.Errorf("RecordOperatorImage: %v", err)
		}
		close(raced)
	}()
	var once sync.Once
	calls := 0
	cfg := ReclaimConfig{
		FreeBytes: func(string) (uint64, error) { return 1, nil },
		afterPlan: func() {
			calls++
			if calls == treeCall {
				once.Do(func() {
					close(planned)
					<-raced
				})
			}
		},
	}
	if _, err := f.cache.Evict(context.Background(), manifest, []string{cfgDigest, layer}, cfg); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	if _, err := os.Lstat(tree); err != nil {
		t.Fatalf("tree %s removed (%v); want it kept by the per-tree check", tree, err)
	}
}
