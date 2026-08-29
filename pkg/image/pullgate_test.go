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
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// freeProbe is a FreeBytesFunc that reports a fixed measurement, or fails the
// way a sick volume fails, and COUNTS its calls.
//
// The count is load-bearing, not diagnostic: a warm serve must not consult it at
// all, which is the mechanical statement of "the admission gate sits below the
// presence decision". A test that only checked the outcome would pass for a gate
// wired above presence that happened to be given a roomy number.
type freeProbe struct {
	free  uint64
	fail  bool
	calls int
}

func (f *freeProbe) sample(string) (uint64, error) {
	f.calls++
	if f.fail {
		return 0, errors.New("statfs: input/output error")
	}
	return f.free, nil
}

// blobFileSet is every file currently in the content-addressed store, by
// store-relative path. Comparing it across a call is how a row proves the pull
// wrote NOTHING — stronger than CacheHit, which reports what the puller believes
// rather than what landed on disk.
func blobFileSet(t *testing.T, c *Cache) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	root := filepath.Join(c.Root(), "blobs")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out[rel] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("walk blob store: %v", err)
	}
	return out
}

func sameFileSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// TestPullRefusesUnderDiskPressure is the B114 gate: past a free-space floor the
// puller REFUSES TO BEGIN a new fetch, fail-closed, while content already on the
// node is still served.
//
// The property it defends is not a node inconvenience. /var/lib/k3sm is shared
// with kine's state.db, so a puller that keeps streaming layers into a nearly
// full volume takes the control plane down with it — and B130b's reclaim cannot
// prevent that, because reclaim frees only what nothing references and a fully
// referenced store has nothing to give back.
//
// Every refusal row is wired to a fetcher that CANNOT SUCCEED (offlineFetch) and
// asserts zero calls on it, so "refused" means no registry traffic happened
// rather than none happened to be needed. Every serve row additionally asserts
// the blob store is byte-for-byte unchanged: OVER-blocking is a bug too, and a
// gate that quietly refused warm IfNotPresent/Never serves would strand pods
// whose images this node already holds, at exactly the moment it cannot fetch
// them again.
//
// NOTE ON THE SPLIT: the backlog names TestSnapshotPrune for B114's other half —
// pruning extracted snapshot TREES — which stays blocked on B100 because the
// snapshot store does not exist yet. This gate covers the disk-pressure
// stop-new-pulls condition only.
func TestPullRefusesUnderDiskPressure(t *testing.T) {
	const ref = "example.com/app:latest"

	// Rows are stated RELATIVE to the shipped constant, so the table exercises
	// the production floor rather than a number invented for the test.
	const (
		atFloor    = DefaultPullRefuseFreeBytes
		belowFloor = DefaultPullRefuseFreeBytes - 1
		roomy      = DefaultPullRefuseFreeBytes * 4
	)

	cases := []struct {
		name string
		pull runtimev1.ImagePullPolicy
		// state is the local-store precondition (see cacheState).
		state cacheState
		// free is the measurement the volume reports; fail makes the sample error.
		free uint64
		fail bool
		// wantSamples is how many times the volume must be measured. Zero means
		// the decision was made before the gate — the warm-serve path.
		wantSamples int
		wantFetches int
		wantErr     error
		// wantErrAlso is a second sentinel the error must also match.
		wantErrAlso  error
		wantCacheHit bool
	}{
		{
			// A roomy volume changes nothing about any policy.
			name:        "roomy_volume_absent_pulls",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:       stateAbsent,
			free:        roomy,
			wantSamples: 1,
			wantFetches: 1,
		},
		{
			// The boundary is `free < floor` refuses, so exactly AT the floor the
			// pull still proceeds. Pinned because an off-by-one here silently
			// moves the whole ladder by one byte in the direction of refusing.
			name:        "exactly_at_the_floor_still_pulls",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:       stateAbsent,
			free:        atFloor,
			wantSamples: 1,
			wantFetches: 1,
		},
		{
			name:        "one_byte_below_the_floor_refuses",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:       stateAbsent,
			free:        belowFloor,
			wantSamples: 1,
			wantFetches: 0,
			wantErr:     ErrPullRefusedDiskPressure,
		},
		{
			// The legacy pull-through path is a fetch like any other.
			name:        "below_floor_unspecified_refused",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED,
			state:       stateAbsent,
			free:        1 << 20,
			wantSamples: 1,
			wantFetches: 0,
			wantErr:     ErrPullRefusedDiskPressure,
		},
		{
			// IfNotPresent that MISSES falls through to a fetch, so it refuses.
			name:        "below_floor_if_not_present_miss_refused",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:       stateAbsent,
			free:        1 << 20,
			wantSamples: 1,
			wantFetches: 0,
			wantErr:     ErrPullRefusedDiskPressure,
		},
		{
			// A recorded reference whose blobs were evicted is a MISS, so it is
			// a fetch and it refuses — presence is about the bytes, not the entry.
			name:        "below_floor_recorded_but_evicted_refused",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:       stateEvicted,
			free:        1 << 20,
			wantSamples: 1,
			wantFetches: 0,
			wantErr:     ErrPullRefusedDiskPressure,
		},
		{
			// THE OVER-BLOCKING ROW. A warm node under pressure still starts pods.
			name:         "below_floor_if_not_present_warm_still_served",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:        stateWarm,
			free:         1 << 20,
			wantSamples:  0,
			wantFetches:  0,
			wantCacheHit: true,
		},
		{
			// Never NEVER fetches, so pressure can have no bearing on it at all.
			name:         "below_floor_never_warm_still_served",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			state:        stateWarm,
			free:         1 << 20,
			wantSamples:  0,
			wantFetches:  0,
			wantCacheHit: true,
		},
		{
			// Never + absent is ErrImageNotPresent, NOT the pressure error: the
			// presence verdict is reached first and is the honest one. Reporting
			// disk pressure would send an operator to free space for a pull that
			// was never going to happen.
			name:        "below_floor_never_absent_reports_not_present",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			state:       stateAbsent,
			free:        1 << 20,
			wantSamples: 0,
			wantFetches: 0,
			wantErr:     ErrImageNotPresent,
		},
		{
			// ALWAYS is refused even on a warm node: honoring it requires the
			// re-resolution being refused, and serving the recorded content
			// instead would silently answer IfNotPresent.
			name:        "below_floor_always_warm_still_refused",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:       stateWarm,
			free:        1 << 20,
			wantSamples: 1,
			wantFetches: 0,
			wantErr:     ErrPullRefusedDiskPressure,
		},
		{
			// FAIL-CLOSED ON IGNORANCE: an unsamplable volume refuses. It matches
			// both sentinels, so a caller can key on the refusal or on its cause.
			name:        "unsamplable_volume_refuses",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:       stateAbsent,
			fail:        true,
			wantSamples: 1,
			wantFetches: 0,
			wantErr:     ErrPullRefusedDiskPressure,
			wantErrAlso: ErrFreeSpaceUnknown,
		},
		{
			// ...and an unsamplable volume still serves what is already here,
			// because that path never asks.
			name:         "unsamplable_volume_warm_still_served",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:        stateWarm,
			fail:         true,
			wantSamples:  0,
			wantFetches:  0,
			wantCacheHit: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}}
			img := pullPolicyImage(t)
			if tc.state != stateAbsent {
				primeLocalImage(t, cache, idx, ref, img, tc.state == stateEvicted)
			}

			// Every row expecting ZERO fetches is wired to a fetcher that cannot
			// succeed, so a gate that leaked would fail loudly rather than
			// quietly; the admitting rows get a working one, which is the
			// positive control that makes the refusals mean "refused" rather
			// than "this table cannot pull at all".
			ff := &fakeFetch{img: img}
			off := &offlineFetch{}
			fetch := ff.fetch
			if tc.wantFetches == 0 {
				fetch = off.fetch
			}
			probe := &freeProbe{free: tc.free, fail: tc.fail}
			p, err := NewPuller(cache, fetch, idx, WithFreeBytes(probe.sample))
			if err != nil {
				t.Fatalf("NewPuller: %v", err)
			}

			before := blobFileSet(t, cache)
			res, perr := p.Pull(context.Background(), ref, nil, nativePolicy(), tc.pull)
			after := blobFileSet(t, cache)

			if probe.calls != tc.wantSamples {
				t.Errorf("free-space samples = %d, want %d", probe.calls, tc.wantSamples)
			}
			if fetches := ff.calls + off.calls; fetches != tc.wantFetches {
				t.Errorf("fetch calls = %d, want %d", fetches, tc.wantFetches)
			}
			if tc.wantFetches == 0 && !sameFileSet(before, after) {
				t.Errorf("blob store changed (%d -> %d files); a pull that made no fetch must write nothing",
					len(before), len(after))
			}
			if tc.wantErr != nil {
				if !errors.Is(perr, tc.wantErr) {
					t.Fatalf("Pull error = %v, want %v", perr, tc.wantErr)
				}
				if tc.wantErrAlso != nil && !errors.Is(perr, tc.wantErrAlso) {
					t.Errorf("Pull error = %v, want it to also match %v", perr, tc.wantErrAlso)
				}
				return
			}
			if perr != nil {
				t.Fatalf("Pull: %v", perr)
			}
			if res.CacheHit != tc.wantCacheHit {
				t.Errorf("CacheHit = %v, want %v", res.CacheHit, tc.wantCacheHit)
			}
			if res.Manifest.GetReference() != ref {
				t.Errorf("manifest reference = %q, want %q", res.Manifest.GetReference(), ref)
			}
		})
	}

	// The refusal message must be diagnosable without reproducing it: an
	// operator reading one line from the daemon log needs both numbers.
	t.Run("refusal_names_the_measurement_and_the_floor", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		off := &offlineFetch{}
		probe := &freeProbe{free: 1234567}
		p, err := NewPuller(cache, off.fetch, NoLocalIndex{}, WithFreeBytes(probe.sample), WithPullFloor(9999999))
		if err != nil {
			t.Fatalf("NewPuller: %v", err)
		}
		_, perr := p.Pull(context.Background(), ref, nil, nativePolicy(),
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if !errors.Is(perr, ErrPullRefusedDiskPressure) {
			t.Fatalf("Pull error = %v, want %v", perr, ErrPullRefusedDiskPressure)
		}
		msg := perr.Error()
		for _, want := range []string{"1234567", "9999999", ref} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal message %q does not name %q", msg, want)
			}
		}
		// WithPullFloor took effect: the default floor would have admitted this.
		if probe.free >= DefaultPullRefuseFreeBytes {
			t.Fatalf("test bug: %d is not below the default floor", probe.free)
		}
	})

	// THE COMPOSITION. The floor's value is chosen by its ordering against the
	// thresholds either side of it, so the ordering — not the number — is what
	// is pinned. Re-ordering it (a floor above the GC trigger) must fail here.
	t.Run("floor_composes_with_the_reclaim_constants", func(t *testing.T) {
		// B27's proposed node DiskPressure floor (docs/BACKLOG.md B27: "ABSOLUTE
		// floor, True below 2 GiB free, clearing at 10 GiB"). It is spelled here
		// as a literal because it is a PROPOSAL — no shipped symbol carries it
		// yet — and this assertion is what will red when B27 lands a value that
		// does not fit under the pull floor.
		const proposedDiskPressureFloorBytes uint64 = 2 << 30

		if DefaultPullRefuseFreeBytes >= DefaultReclaimHighFreeBytes {
			t.Errorf("pull floor %d >= reclaim trigger %d: pods would be denied images before the GC that would have made room had run",
				DefaultPullRefuseFreeBytes, DefaultReclaimHighFreeBytes)
		}
		if DefaultPullRefuseFreeBytes <= proposedDiskPressureFloorBytes {
			t.Errorf("pull floor %d <= the node DiskPressure floor %d: the node would be tainted before new pulls stopped",
				DefaultPullRefuseFreeBytes, proposedDiskPressureFloorBytes)
		}
		if DefaultReclaimTargetFreeBytes < DefaultReclaimHighFreeBytes {
			t.Errorf("reclaim target %d < reclaim trigger %d", DefaultReclaimTargetFreeBytes, DefaultReclaimHighFreeBytes)
		}
	})
}
