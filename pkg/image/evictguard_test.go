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
	"strings"
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

// TestUnlinkUnlessHeldSharedUnderLeaseMu pins that the per-blob shared-set
// read runs under leaseMu: the sharedNow stub finds the lock held, so moving
// the read out of the lock goes red.
func TestUnlinkUnlessHeldSharedUnderLeaseMu(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	digest := f.blob("evict-shared-locked", time.Hour)
	asked := false
	removed, why, err := f.cache.unlinkUnlessHeld(digest, func() error { return nil }, nil, func(d string) (bool, error) {
		asked = true
		if d != digest {
			t.Errorf("sharedNow asked about %s; want %s", d, digest)
		}
		if f.cache.leaseMu.TryLock() {
			f.cache.leaseMu.Unlock()
			t.Error("leaseMu not held across the shared-set read")
		}
		return false, nil
	})
	if err != nil || !removed || why != "" || !asked {
		t.Fatalf("unlinkUnlessHeld = %v, %q, %v (sharedNow called %v); want removed", removed, why, err, asked)
	}
}

// TestTreeUnlessHeld pins the per-tree check's branches: a live lease on a
// backing blob keeps the tree typed leased and names that blob; an unreadable
// root set keeps it and returns an error; otherwise remove runs under leaseMu.
func TestTreeUnlessHeld(t *testing.T) {
	t.Parallel()
	t.Run("leased", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		cfgDigest := f.blob("tree-held-cfg", time.Hour)
		layer := f.blob("tree-held-layer", time.Hour)
		l := f.cache.AcquireLease([]string{layer}, 0)
		defer l.Release()
		called := false
		removed, dg, why, err := f.cache.treeUnlessHeld([]string{"", cfgDigest, layer}, func() error {
			called = true
			return nil
		}, nil)
		if err != nil || removed || called || dg != layer || why != evictLeased {
			t.Fatalf("treeUnlessHeld = %v, %s, %q, %v (remove called %v); want kept leased by %s", removed, dg, why, err, called, layer)
		}
	})
	t.Run("roots unreadable", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		cfgDigest := f.blob("tree-unreadable-cfg", time.Hour)
		// A pod dir with no record is an incomplete root set.
		pid, err := ParsePodID("pod-b")
		if err != nil {
			t.Fatalf("ParsePodID: %v", err)
		}
		if err := os.MkdirAll(f.cache.PodDir(pid), 0o755); err != nil {
			t.Fatalf("mkdir pod dir: %v", err)
		}
		called := false
		removed, _, why, err := f.cache.treeUnlessHeld([]string{cfgDigest}, func() error {
			called = true
			return nil
		}, nil)
		if err == nil || removed || called || why != "" {
			t.Fatalf("treeUnlessHeld = %v, %q, %v (remove called %v); want kept with an error", removed, why, err, called)
		}
	})
	t.Run("remove under leaseMu", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		cfgDigest := f.blob("tree-locked-cfg", time.Hour)
		called := false
		removed, dg, why, err := f.cache.treeUnlessHeld([]string{cfgDigest}, func() error {
			called = true
			if f.cache.leaseMu.TryLock() {
				f.cache.leaseMu.Unlock()
				t.Error("leaseMu not held across the tree removal")
			}
			return nil
		}, nil)
		if err != nil || !removed || dg != "" || why != "" || !called {
			t.Fatalf("treeUnlessHeld = %v, %s, %q, %v (remove called %v); want removed", removed, dg, why, err, called)
		}
	})
}

// TestEvictOutcomeBranches pins two of evictOutcome's placements: a condemned
// blob refused with a typed reason is kept with that reason, even when an
// untyped refusal for it follows; a condemned blob neither removed nor
// refused that is gone from the store is absent.
func TestEvictOutcomeBranches(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	shared := f.blob("outcome-shared", time.Hour)
	vanished := "sha256:" + strings.Repeat("a", 64)
	if f.cache.Has(vanished) {
		t.Fatalf("%s present; want it missing from the store", vanished)
	}
	ev := &evictPass{
		plan: &EvictPlan{Delete: []PruneDecision{
			{Node: BlobNode{Digest: shared}},
			{Node: BlobNode{Digest: vanished}},
		}},
		skipped: []SkippedBlob{
			{Digest: shared, Refusal: &SkipRefusal{Digest: shared, Kind: RefusedByGuard, Reason: EvictKeptShared}},
			{Digest: shared, Reason: "untyped"},
		},
	}
	res, err := f.cache.evictOutcome(ev)
	if err != nil {
		t.Fatalf("evictOutcome: %v", err)
	}
	want := &EvictResult{
		Kept:   []EvictKept{{Digest: shared, Reason: EvictKeptShared}},
		Absent: []string{vanished},
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("evictOutcome = %+v; want %+v", res, want)
	}
}

// TestEvictTreeTrashDeleteOutsideLeaseMu pins that the per-tree check holds
// leaseMu only while the tree is detached, not while it is deleted: the
// trash delete is blocked until another goroutine has taken leaseMu (through
// AcquireLease), which deadlocks — and fails on the timeout — if the delete
// runs under the lock. While the delete is blocked, the tree is already gone
// by its real name and sits under a trash name outside the key grammar.
func TestEvictTreeTrashDeleteOutsideLeaseMu(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	cfgDigest := f.blob("trash-unlocked-cfg", time.Hour)
	tf := f.nativeTree(cfgDigest, nil, 10, time.Hour)
	plan := f.planFor(time.Minute)
	if len(plan.DeleteTrees) != 1 {
		t.Fatalf("DeleteTrees = %v; want exactly %s", plan.DeleteTrees, tf.key)
	}

	deleted := 0
	hooks := &treePruneHooks{
		unlink: func(backing []string, remove func() error) (bool, string, evictReason, error) {
			return f.cache.treeUnlessHeld(backing, remove, nil)
		},
		removeTrash: func(root *os.Root, name string) error {
			deleted++
			if !strings.HasPrefix(name, treeTrashPrefix) {
				t.Errorf("trash name %q; want prefix %q", name, treeTrashPrefix)
			}
			if _, err := os.Lstat(tf.dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("tree %s reachable by its real name during the delete: %v", tf.dir, err)
			}
			leased := make(chan struct{})
			go func() {
				f.cache.AcquireLease([]string{cfgDigest}, 0).Release()
				close(leased)
			}()
			select {
			case <-leased:
			case <-time.After(5 * time.Second):
				t.Fatal("leaseMu held across the trash delete")
			}
			return root.RemoveAll(name)
		},
	}
	rep, err := f.cache.executeTreePrune(plan, time.Minute, f.clock, nil, hooks)
	if err != nil {
		t.Fatalf("executeTreePrune: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("trash delete ran %d times; want 1", deleted)
	}
	if !reflect.DeepEqual(rep.Removed, []string{tf.key}) || len(rep.Skipped) != 0 || rep.TrashLeft != 0 {
		t.Fatalf("report = %+v; want %s removed, nothing skipped or left", rep, tf.key)
	}
	assertNoTrash(t, f)
}

// TestEvictTreeTrashSwept pins the failed-delete path: a trash delete that
// fails still reports the tree removed (it is unreachable by name), the
// leftover trash is inventoried as an unknown node and never as a tree, and
// the next run's opening sweep deletes it.
func TestEvictTreeTrashSwept(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	cfgDigest := f.blob("trash-swept-cfg", time.Hour)
	tf := f.nativeTree(cfgDigest, nil, 10, time.Hour)
	plan := f.planFor(time.Minute)

	hooks := &treePruneHooks{
		unlink: func(backing []string, remove func() error) (bool, string, evictReason, error) {
			return f.cache.treeUnlessHeld(backing, remove, nil)
		},
		removeTrash: func(*os.Root, string) error { return errors.New("delete failed") },
	}
	rep, err := f.cache.executeTreePrune(plan, time.Minute, f.clock, nil, hooks)
	if err != nil {
		t.Fatalf("executeTreePrune: %v", err)
	}
	if !reflect.DeepEqual(rep.Removed, []string{tf.key}) || rep.Deleted != 1 || len(rep.Skipped) != 0 || rep.TrashLeft != 1 {
		t.Fatalf("report = %+v; want %s removed with one trash entry left", rep, tf.key)
	}
	if rep.TrashErr == nil || !strings.Contains(rep.TrashErr.Error(), "delete failed") {
		t.Errorf("TrashErr = %v; want the failed delete's error", rep.TrashErr)
	}
	if _, err := os.Lstat(tf.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tree %s still reachable by its real name: %v", tf.dir, err)
	}

	trees, err := f.cache.EnumerateTrees()
	if err != nil {
		t.Fatalf("EnumerateTrees: %v", err)
	}
	trash := 0
	for _, n := range trees {
		if n.Kind == TreeKindTree {
			t.Errorf("tree listed after removal: %+v", n)
		}
		if strings.HasPrefix(n.Path, treeTrashPrefix) {
			trash++
			if n.Kind != TreeKindUnknown || n.Key != "" {
				t.Errorf("trash node = %+v; want an unknown node with no key", n)
			}
		}
	}
	if trash != 1 {
		t.Fatalf("inventory = %+v; want exactly one trash node", trees)
	}
	next := f.planFor(time.Minute)
	if len(next.DeleteTrees) != 0 {
		t.Fatalf("DeleteTrees = %+v; want the trash never planned as a tree", next.DeleteTrees)
	}

	rep, err = f.cache.ExecuteTreePrune(next, time.Minute, f.clock, nil)
	if err != nil {
		t.Fatalf("ExecuteTreePrune: %v", err)
	}
	if rep.TrashSwept != 1 || rep.TrashRemaining != 0 || rep.TrashErr != nil {
		t.Errorf("sweep = %d swept, %d remaining, err %v; want 1, 0, nil", rep.TrashSwept, rep.TrashRemaining, rep.TrashErr)
	}
	assertNoTrash(t, f)
}

// assertNoTrash fails if any tree store holds a trash entry.
func assertNoTrash(t *testing.T, f *gcFixture) {
	t.Helper()
	for _, store := range treeStores {
		dir, _, err := f.cache.treeStoreLayout(store)
		if err != nil {
			t.Fatalf("treeStoreLayout: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("ReadDir %s: %v", dir, err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), treeTrashPrefix) {
				t.Errorf("trash entry %s left in %s", e.Name(), dir)
			}
		}
	}
}
