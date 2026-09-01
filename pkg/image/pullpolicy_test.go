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
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeIndex is a LocalIndex whose whole state is an in-memory map, so a test can
// put a reference in the "recorded locally" state directly. It keeps this
// table about the puller's policy branching: the on-disk index's own rules
// (platform keying, corruption, ownership) are gated by
// TestRefDigestIndexDecidesPresence, which drives the real FileIndex. It can
// fail, because "the index could not be read" is deliberately not a miss.
type fakeIndex struct {
	entries map[string]*runtimev1.ImageManifest
	err     error
	// lastPolicy records the platform policy the key was resolved under — the
	// index is keyed (reference x platform), so the policy must reach it.
	lastPolicy PlatformPolicy
	// records counts Record calls: a successful pull must keep the index current.
	records int
}

func (f *fakeIndex) Lookup(_ context.Context, ref string, policy PlatformPolicy) (*runtimev1.ImageManifest, bool, error) {
	f.lastPolicy = policy
	if f.err != nil {
		return nil, false, f.err
	}
	m, ok := f.entries[ref]
	return m, ok, nil
}

// Record mirrors Lookup's ref-only keying: the platform half is asserted through
// the real index, not here.
func (f *fakeIndex) Record(_ context.Context, ref string, _ Platform, mfst *runtimev1.ImageManifest) error {
	f.records++
	f.entries[ref] = mfst
	return nil
}

// offlineFetch is a FetchFunc that fails the way a blackholed network fails. Any
// case that reaches it has performed registry traffic, which is exactly what the
// IfNotPresent/Never warm-cache rows must not do — a counter alone would prove
// only that a pull did not happen to be needed.
type offlineFetch struct{ calls int }

func (o *offlineFetch) fetch(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
	o.calls++
	return nil, errors.New("dial tcp: connect: network is unreachable")
}

// pullPolicyImage is the platform-stamped fixture every policy row pulls.
func pullPolicyImage(t *testing.T) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	return withPlatform(t, img, "darwin", "arm64", "")
}

// cacheState is the local-store precondition a policy row runs against.
type cacheState string

const (
	// stateAbsent: the reference is in no index and no blob is cached.
	stateAbsent cacheState = "absent"
	// stateWarm: the reference is recorded and every blob it names is in the CAS.
	stateWarm cacheState = "warm"
	// stateEvicted: the reference is recorded but its blobs are gone (a stale
	// index entry — presence-by-reference must not outlive the bytes).
	stateEvicted cacheState = "recorded-blobs-evicted"
)

// TestPullPolicyHonored is the B120 / M12.1-a1 gate: the policy x cache-state
// matrix the puller must obey, including the UNSPECIFIED=legacy rows (an old
// provider never stamps the field, and absent must never be read as Never) and
// the offline IfNotPresent warm-cache row (proving zero registry traffic rather
// than "no fetch happened to be needed" — the fetcher it is wired to cannot
// succeed).
//
// runtimed never re-derives a policy from the image tag: every row's reference
// is `:latest`, the tag whose corev1 default is Always, yet each row obeys the
// stamped value it is given. A re-derivation would make the IfNotPresent and
// Never rows fetch.
func TestPullPolicyHonored(t *testing.T) {
	const ref = "example.com/app:latest"

	cases := []struct {
		name         string
		pull         runtimev1.ImagePullPolicy
		state        cacheState
		offline      bool
		wantFetches  int
		wantErr      error
		wantCacheHit bool
	}{
		{
			name:        "unspecified_legacy_pulls_when_absent",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED,
			state:       stateAbsent,
			wantFetches: 1,
		},
		{
			// The skew contract in the other direction: an old provider that
			// never sets the field must keep TODAY's pull-through behavior, not
			// silently acquire IfNotPresent (and never Never). CacheHit is true
			// here because no BLOB was rewritten — which is precisely why the
			// fetch count, not CacheHit, is what proves registry traffic.
			name:         "unspecified_legacy_pulls_through_when_warm",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED,
			state:        stateWarm,
			wantFetches:  1,
			wantCacheHit: true,
		},
		{
			name:        "always_pulls_when_absent",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:       stateAbsent,
			wantFetches: 1,
		},
		{
			// Always RE-RESOLVES: a recorded reference does not short-circuit it
			// (the fetch happens; the already-cached blobs are still reused).
			name:         "always_re_resolves_when_warm",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS,
			state:        stateWarm,
			wantFetches:  1,
			wantCacheHit: true,
		},
		{
			name:        "if_not_present_pulls_on_miss",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:       stateAbsent,
			wantFetches: 1,
		},
		{
			name:         "if_not_present_warm_performs_zero_registry_traffic",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:        stateWarm,
			wantFetches:  0,
			wantCacheHit: true,
		},
		{
			// The M12.1-d4 posture: a registry outage must not strand a pod whose
			// image is already on the node.
			name:         "if_not_present_warm_offline_still_starts",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:        stateWarm,
			offline:      true,
			wantFetches:  0,
			wantCacheHit: true,
		},
		{
			// A recorded reference whose bytes are gone is not present.
			name:        "if_not_present_evicted_blobs_pulls_again",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			state:       stateEvicted,
			wantFetches: 1,
		},
		{
			name:        "never_absent_fails_with_no_pull_attempt",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			state:       stateAbsent,
			wantFetches: 0,
			wantErr:     ErrImageNotPresent,
		},
		{
			name:         "never_warm_offline_succeeds",
			pull:         runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			state:        stateWarm,
			offline:      true,
			wantFetches:  0,
			wantCacheHit: true,
		},
		{
			name:        "never_evicted_blobs_fails_with_no_pull_attempt",
			pull:        runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			state:       stateEvicted,
			wantFetches: 0,
			wantErr:     ErrImageNotPresent,
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

			// The subject puller is built after priming so the offline rows are
			// wired to a fetcher that cannot succeed.
			ff := &fakeFetch{img: img}
			off := &offlineFetch{}
			fetch := ff.fetch
			if tc.offline {
				fetch = off.fetch
			}
			p := mustPullerIndex(t, cache, fetch, idx)

			res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), tc.pull)

			fetches := ff.calls + off.calls
			if fetches != tc.wantFetches {
				t.Errorf("fetch calls = %d, want %d", fetches, tc.wantFetches)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Pull error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pull: %v", err)
			}
			if res.CacheHit != tc.wantCacheHit {
				t.Errorf("CacheHit = %v, want %v", res.CacheHit, tc.wantCacheHit)
			}
			if res.Manifest.GetReference() != ref {
				t.Errorf("manifest reference = %q, want %q", res.Manifest.GetReference(), ref)
			}
		})
	}

	// The index is keyed (reference x platform), so the platform policy must
	// reach it — a lookup that ignored it would serve a foreign-platform image
	// to a policy that could not run it.
	t.Run("index_lookup_receives_the_platform_policy", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}}
		ff := &fakeFetch{img: pullPolicyImage(t)}
		p := mustPullerIndex(t, cache, ff.fetch, idx)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT); err != nil {
			t.Fatalf("Pull: %v", err)
		}
		if idx.lastPolicy != nativePolicy() {
			t.Errorf("index saw policy %+v, want %+v", idx.lastPolicy, nativePolicy())
		}
	})

	// An index that cannot be READ is not a miss: reporting "absent" would make
	// Never fail for an image that is present, and would send an IfNotPresent
	// pod to the registry precisely when the operator asked it not to go.
	t.Run("index_read_failure_is_an_error_not_a_miss", func(t *testing.T) {
		for _, pull := range []runtimev1.ImagePullPolicy{
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
		} {
			t.Run(pull.String(), func(t *testing.T) {
				cache, err := NewCache(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				boom := errors.New("index unreadable")
				idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}, err: boom}
				ff := &fakeFetch{img: pullPolicyImage(t)}
				p := mustPullerIndex(t, cache, ff.fetch, idx)

				_, err = p.Pull(context.Background(), ref, nil, nativePolicy(), pull)
				if !errors.Is(err, boom) {
					t.Fatalf("Pull error = %v, want the index error", err)
				}
				if ff.calls != 0 {
					t.Errorf("fetch called %d times on an index failure, want 0", ff.calls)
				}
			})
		}
	})

	// NoLocalIndex is the explicit "this caller keeps no record" binding (the
	// daemon's own binding is the on-disk FileIndex). It reports every reference
	// absent, so IfNotPresent degrades to the pre-M12 pull-through (safe) and
	// Never has nothing to run — the cold-node behavior, which must stay
	// reachable and unchanged.
	t.Run("no_local_index_reports_absent", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ff := &fakeFetch{img: pullPolicyImage(t)}
		p := mustPuller(t, cache, ff.fetch)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER); !errors.Is(err, ErrImageNotPresent) {
			t.Fatalf("Never with no index: error = %v, want ErrImageNotPresent", err)
		}
		if ff.calls != 0 {
			t.Errorf("fetch called %d times under Never, want 0", ff.calls)
		}
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT); err != nil {
			t.Fatalf("IfNotPresent with no index: %v", err)
		}
		if ff.calls != 1 {
			t.Errorf("fetch called %d times under IfNotPresent, want 1 (pull-through)", ff.calls)
		}
	})
}

// primeLocalImage puts ref in the local-store state a row needs: it pulls img
// once (populating the blob CAS) and records the resulting manifest in idx. When
// evict is true the blobs are then removed, leaving a STALE index entry.
func primeLocalImage(t *testing.T, cache *Cache, idx *fakeIndex, ref string, img ggcrv1.Image, evict bool) {
	t.Helper()
	prime := &fakeFetch{img: img}
	p := mustPuller(t, cache, prime.fetch)
	res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if err != nil {
		t.Fatalf("prime pull: %v", err)
	}
	idx.entries[ref] = res.Manifest
	if !evict {
		return
	}
	digests := []string{res.Manifest.GetConfig().GetDigest()}
	for _, l := range res.Manifest.GetLayers() {
		digests = append(digests, l.GetDigest())
	}
	for _, d := range digests {
		path, err := cache.BlobPath(d)
		if err != nil {
			t.Fatalf("blob path %s: %v", d, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("evict blob %s: %v", d, err)
		}
	}
}
