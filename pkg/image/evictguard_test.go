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
	"os"
	"reflect"
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
//   - with no writer, the blob is unlinked.
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
			calls := 0
			cfg := &ReclaimConfig{afterPlan: func() {
				calls++
				close(planned)
				cleanup = <-raced
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
