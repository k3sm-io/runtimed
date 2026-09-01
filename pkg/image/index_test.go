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
	"path/filepath"
	"strings"
	"testing"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRefDigestIndexDecidesPresence is the B128 / M12.1-d1 gate: the on-disk
// ref->digest index decides presence-BY-REFERENCE for this node, and does so
// without ever becoming a reachability root.
//
// every assertion the gate makes is a subtest of this function — the item is run
// as `go test -run '^TestRefDigestIndexDecidesPresence$'`, so anything asserted
// in a sibling Test... would not be gate-proving.
//
// Behaviour at main (image.NoLocalIndex was the daemon's binding), for the rows
// below:
//
//	IfNotPresent on a warm reference   → pulled from the registry     (RED)
//	Never on a warm reference          → ErrImageNotPresent           (RED)
//	a corrupt entry                    → not reachable at all         (n/a)
//	an index entry protecting its blobs from the GC → n/a (no entries existed)
func TestRefDigestIndexDecidesPresence(t *testing.T) {
	const ref = "example.com/app:latest"

	// -----------------------------------------------------------------
	// Presence: what the index decides, and what it must not decide.
	// -----------------------------------------------------------------

	// The whole point of the deliverable: a reference this node pulled is served
	// locally, proven against a fetcher that cannot succeed. A counter alone
	// would show only that a pull did not happen to be needed.
	t.Run("warm_reference_serves_locally_with_zero_registry_traffic", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		want := primeIndexedPull(t, cache, idx, ref, nativePolicy())

		for _, pull := range []runtimev1.ImagePullPolicy{
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
		} {
			t.Run(pull.String(), func(t *testing.T) {
				off := &offlineFetch{}
				p := mustPullerIndex(t, cache, off.fetch, idx)
				res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), pull)
				if err != nil {
					t.Fatalf("Pull: %v", err)
				}
				defer res.Lease.Release()
				if off.calls != 0 {
					t.Errorf("registry fetches = %d, want 0", off.calls)
				}
				if !res.CacheHit {
					t.Error("CacheHit = false, want true (nothing was written)")
				}
				assertSameManifest(t, res.Manifest, want)
			})
		}
	})

	// The record is ON DISK, not in the process that wrote it: a restarted
	// daemon must still know what this node has. A fresh FileIndex over the same
	// cache is the closest in-process stand-in for that restart.
	t.Run("record_survives_a_new_index_over_the_same_cache", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		want := primeIndexedPull(t, cache, idx, ref, nativePolicy())

		reopened, err := NewFileIndex(cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		got, ok, err := reopened.Lookup(context.Background(), ref, nativePolicy())
		if err != nil || !ok {
			t.Fatalf("Lookup = (%v, %v, %v), want the recorded manifest", got, ok, err)
		}
		assertSameManifest(t, got, want)
	})

	// A reference nobody pulled is absent — and absence is a miss, not an error,
	// so IfNotPresent still reaches the registry and Never still fails honestly.
	t.Run("unindexed_reference_is_a_miss", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		if got, ok, err := idx.Lookup(context.Background(), "example.com/never-pulled:v1", nativePolicy()); ok || err != nil {
			t.Fatalf("Lookup = (%v, %v, %v), want a clean miss", got, ok, err)
		}

		ff := &fakeFetch{img: indexTestImage(t, "darwin", "arm64")}
		p := mustPullerIndex(t, cache, ff.fetch, idx)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER); !errors.Is(err, ErrImageNotPresent) {
			t.Fatalf("Never on an unindexed ref: error = %v, want ErrImageNotPresent", err)
		}
		if ff.calls != 0 {
			t.Errorf("registry fetches under Never = %d, want 0", ff.calls)
		}
	})

	// Presence-by-reference and the bytes have independent lifetimes: the GC
	// evicts blobs and never touches this index (see the edge-not-root rows
	// below). A recorded reference whose blobs are gone must therefore be a miss
	// — the index still holds the entry, and the consumer's blob check is what
	// turns it into "not present".
	t.Run("recorded_reference_with_evicted_blobs_is_not_present", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		mfst := primeIndexedPull(t, cache, idx, ref, nativePolicy())
		evictBlobs(t, cache, mfst)

		// The index itself still answers: it records references, not bytes.
		if _, ok, err := idx.Lookup(context.Background(), ref, nativePolicy()); err != nil || !ok {
			t.Fatalf("Lookup after eviction = (%v, %v), want the entry to survive", ok, err)
		}
		// The PULLER says not present: Never fails, IfNotPresent re-pulls.
		ff := &fakeFetch{img: indexTestImage(t, "darwin", "arm64")}
		p := mustPullerIndex(t, cache, ff.fetch, idx)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER); !errors.Is(err, ErrImageNotPresent) {
			t.Fatalf("Never with evicted blobs: error = %v, want ErrImageNotPresent", err)
		}
		if ff.calls != 0 {
			t.Errorf("registry fetches under Never = %d, want 0", ff.calls)
		}
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT); err != nil {
			t.Fatalf("IfNotPresent with evicted blobs: %v", err)
		}
		if ff.calls != 1 {
			t.Errorf("registry fetches under IfNotPresent = %d, want 1 (a re-pull)", ff.calls)
		}
	})

	// The index is keyed (reference x platform). A node that pulled linux/arm64
	// for a vm pod holds bytes a native pod cannot execute, so the same reference
	// under a native policy is a miss — not a hit that would start a container
	// whose payload is the wrong machine code.
	t.Run("platform_policy_mismatch_is_a_miss", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		primeIndexedPullImage(t, cache, idx, ref, indexTestImage(t, "linux", "arm64"), vmPolicy())

		if got, ok, err := idx.Lookup(context.Background(), ref, nativePolicy()); ok || err != nil {
			t.Fatalf("native Lookup of a vm-recorded ref = (%v, %v, %v), want a clean miss", got, ok, err)
		}
		if _, ok, err := idx.Lookup(context.Background(), ref, vmPolicy()); err != nil || !ok {
			t.Fatalf("vm Lookup = (%v, %v), want a hit", ok, err)
		}
		ff := &fakeFetch{img: indexTestImage(t, "darwin", "arm64")}
		p := mustPullerIndex(t, cache, ff.fetch, idx)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER); !errors.Is(err, ErrImageNotPresent) {
			t.Fatalf("Never under a mismatched platform: error = %v, want ErrImageNotPresent", err)
		}
	})

	// A policy whose backend has no candidates cannot key a lookup at all. It
	// fails closed rather than looking up under an empty platform, which would
	// collide every image on the node into one key.
	t.Run("zero_platform_policy_fails_closed", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		if _, ok, err := idx.Lookup(context.Background(), ref, PlatformPolicy{}); !errors.Is(err, ErrNoPlatformMatch) || ok {
			t.Fatalf("Lookup with a zero policy = (%v, %v), want ErrNoPlatformMatch", ok, err)
		}
	})

	// -----------------------------------------------------------------
	// A damaged index is an ERROR, never a miss.
	// -----------------------------------------------------------------

	// A miss would fail Never for an image that IS on the node and would send an
	// IfNotPresent pod to the registry at exactly the moment the operator asked
	// it not to go. So every unbelievable entry degrades loudly, and no row of it
	// performs registry traffic.
	t.Run("unbelievable_entry_is_an_error_not_a_miss", func(t *testing.T) {
		native := mustCandidates(t, nativePolicy())[0]
		cases := []struct {
			name    string
			damage  func(t *testing.T, cache *Cache)
			wantErr error
		}{
			{
				name: "truncated_json",
				damage: func(t *testing.T, cache *Cache) {
					writeEntryFile(t, cache, entryName(ref, native), []byte(`{"schema":1,"refere`))
				},
				wantErr: ErrIndexEntryCorrupt,
			},
			{
				name: "unreadable_entry",
				damage: func(t *testing.T, cache *Cache) {
					// A DIRECTORY where an entry belongs: not a regular file, so it
					// is refused by readAnchored rather than read as an empty record
					// (and, as a directory, it cannot be read as a file even by a
					// daemon that can read everything else).
					path := filepath.Join(cache.IndexRoot(), entryName(ref, native))
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				},
				wantErr: ErrIndexEntryCorrupt,
			},
			{
				name: "unknown_schema_version",
				damage: func(t *testing.T, cache *Cache) {
					entry := readEntryFile(t, cache, entryName(ref, native))
					writeEntryFile(t, cache, entryName(ref, native),
						[]byte(strings.Replace(string(entry), `"schema":1`, `"schema":9999`, 1)))
				},
				wantErr: ErrIndexEntryCorrupt,
			},
			{
				name: "entry_planted_under_another_key",
				damage: func(t *testing.T, cache *Cache) {
					// The file name is a hash: it identifies a key, it does not
					// prove one. An entry for a different reference copied to this
					// key's name must be refused, not served — that copy is exactly
					// what a writable index would buy an attacker.
					other := readEntryFile(t, cache, entryName("example.com/other:latest", native))
					writeEntryFile(t, cache, entryName(ref, native), other)
				},
				wantErr: ErrIndexEntryCorrupt,
			},
			{
				name: "index_directory_writable_by_others",
				damage: func(t *testing.T, cache *Cache) {
					// The substitution door: whoever can write the parent can swap
					// the index tree for one they own. Mode and owner are re-checked
					// at every open, so a swapped tree is refused rather than read.
					if err := os.Chmod(cache.IndexRoot(), 0o777); err != nil {
						t.Fatal(err)
					}
				},
				wantErr: ErrIndexNotOwned,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cache, idx := newIndexedCache(t)
				primeIndexedPull(t, cache, idx, ref, nativePolicy())
				// A second, intact reference: every row must damage only its own
				// entry, so a row that passed by taking the whole index down is
				// visible as this reference failing too (except the directory row,
				// where taking the tree down IS the finding).
				primeIndexedPullImage(t, cache, idx, "example.com/other:latest", indexTestImage(t, "darwin", "arm64"), nativePolicy())
				tc.damage(t, cache)

				if _, ok, err := idx.Lookup(context.Background(), ref, nativePolicy()); !errors.Is(err, tc.wantErr) || ok {
					t.Fatalf("Lookup = (%v, %v), want %v", ok, err, tc.wantErr)
				}
				for _, pull := range []runtimev1.ImagePullPolicy{
					runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
					runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
				} {
					ff := &fakeFetch{img: indexTestImage(t, "darwin", "arm64")}
					p := mustPullerIndex(t, cache, ff.fetch, idx)
					_, err := p.Pull(context.Background(), ref, nil, nativePolicy(), pull)
					if !errors.Is(err, tc.wantErr) {
						t.Errorf("%v: Pull error = %v, want %v", pull, err, tc.wantErr)
					}
					if ff.calls != 0 {
						t.Errorf("%v: registry fetches = %d, want 0 (a damaged index must not be read as absent)", pull, ff.calls)
					}
				}
			})
		}
	})

	// The recorded manifest must name the reference it is recorded under: a pod's
	// reachability root is keyed on ImageManifest.Reference, so an entry whose
	// manifest names something else would record a root for a reference the pod
	// never asked for. Refused at WRITE, so it can never be read back.
	t.Run("record_refuses_a_manifest_naming_another_reference", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		err := idx.Record(context.Background(), ref, mustCandidates(t, nativePolicy())[0],
			&runtimev1.ImageManifest{Reference: "example.com/other:latest"})
		if err == nil {
			t.Fatal("Record accepted a manifest naming another reference")
		}
		if _, ok, lerr := idx.Lookup(context.Background(), ref, nativePolicy()); ok || lerr != nil {
			t.Fatalf("Lookup after the refused Record = (%v, %v), want a clean miss", ok, lerr)
		}
	})

	// -----------------------------------------------------------------
	// Entries are edges, never roots.
	// -----------------------------------------------------------------

	// The load-bearing invariant. An index entry records that a reference
	// RESOLVED; it never asserts that anything still needs those bytes. If it
	// could protect them, a node would accumulate every image it ever pulled and
	// the disk-pressure GC (B130b) would have nothing to reclaim — and a mutable
	// tag re-pointed by a registry would get to choose what survives.
	t.Run("an_index_entry_does_not_protect_its_blobs_from_the_gc", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		mfst := primeIndexedPull(t, cache, idx, ref, nativePolicy())

		// A live pod that references nothing (a native host-binary pod), so the
		// pods tree is walked for real. Without it Roots short-circuits on the
		// absent pods dir and never reaches the code an index-as-root regression
		// would live in — the root set would be empty for the wrong reason.
		bystander, err := ParsePodID("pod-references-nothing")
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.EnsurePodReferences(bystander); err != nil {
			t.Fatal(err)
		}

		// The GC's two enumerators. neither can reach the index tree: Roots reads
		// pods/, EnumerateBlobs reads blobs/. No pod references this image, so
		// there is no root — and the index's existence must not change that.
		roots, err := cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(roots) != 0 {
			t.Fatalf("Roots = %+v, want none: an index entry is an edge, never a root", roots)
		}
		nodes, err := cache.EnumerateBlobs()
		if err != nil {
			t.Fatalf("EnumerateBlobs: %v", err)
		}
		if len(nodes) != len(manifestDigests(mfst)) {
			t.Fatalf("inventory = %+v, want exactly the %d image blobs (the index tree is not inventory)",
				nodes, len(manifestDigests(mfst)))
		}

		plan, err := PlanPrune(nodes, nil, roots, nil, 0, time.Now())
		if err != nil {
			t.Fatalf("PlanPrune: %v", err)
		}
		condemned := make(map[string]PruneReason, len(plan.Delete))
		for _, d := range plan.Delete {
			condemned[d.Node.Digest] = d.Reason
		}
		for _, d := range manifestDigests(mfst) {
			if got, ok := condemned[d]; !ok || got != ReasonDeleteUnreferenced {
				t.Errorf("blob %s: plan says %q (present=%v), want %q — the index entry must not protect it",
					d, got, ok, ReasonDeleteUnreferenced)
			}
		}

		// And it really is reclaimed: after the prune the entry survives (the
		// prune is blobs-only) while the reference is no longer present.
		if _, err := cache.ExecutePrune(plan, 0, time.Now(), nil); err != nil {
			t.Fatalf("ExecutePrune: %v", err)
		}
		if _, ok, err := idx.Lookup(context.Background(), ref, nativePolicy()); err != nil || !ok {
			t.Fatalf("Lookup after prune = (%v, %v), want the entry to survive the blob GC", ok, err)
		}
		off := &offlineFetch{}
		p := mustPullerIndex(t, cache, off.fetch, idx)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER); !errors.Is(err, ErrImageNotPresent) {
			t.Fatalf("Never after the GC reclaimed the blobs: error = %v, want ErrImageNotPresent", err)
		}
	})

	// The pod's reachability root is what protects blobs, and it is authored by
	// the daemon in the pods tree — the positive control for the row above, so
	// "condemned" there means "no root named it", not "the planner condemns
	// everything".
	t.Run("a_pod_root_does_protect_the_same_blobs", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		mfst := primeIndexedPull(t, cache, idx, ref, nativePolicy())

		podID, err := ParsePodID("pod-index-gate")
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.EnsurePodReferences(podID); err != nil {
			t.Fatal(err)
		}
		layers := make([]string, 0, len(mfst.GetLayers()))
		for _, l := range mfst.GetLayers() {
			layers = append(layers, l.GetDigest())
		}
		if err := cache.RecordPodImage(podID, ImageRoot{Reference: ref, Config: mfst.GetConfig().GetDigest(), Layers: layers}); err != nil {
			t.Fatal(err)
		}

		roots, err := cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		nodes, err := cache.EnumerateBlobs()
		if err != nil {
			t.Fatalf("EnumerateBlobs: %v", err)
		}
		plan, err := PlanPrune(nodes, nil, roots, nil, 0, time.Now())
		if err != nil {
			t.Fatalf("PlanPrune: %v", err)
		}
		if len(plan.Delete) != 0 {
			t.Errorf("plan condemns %+v, want nothing: a pod root protects these blobs", plan.Delete)
		}
	})

	// The two legs above pin the pure layers (Roots, PlanPrune). This leg pins the
	// COMPOSED production path: a "helpfully" index-aware ReclaimUnderPressure —
	// protection injected at the call site rather than in Roots — would pass both
	// pure legs and still ship the regression. Found by an orchestrator mutation
	// that did exactly that and stayed green against the pure legs.
	t.Run("the_production_reclaim_deletes_index_named_blobs_end_to_end", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		mfst := primeIndexedPull(t, cache, idx, ref, nativePolicy())

		rep, err := cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes:   100,
			TargetFreeBytes: 150,
			Grace:           1, // nanosecond: nothing is saved by age
			Force:           true,
			FreeBytes:       func(string) (uint64, error) { return 10, nil },
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		want := map[string]bool{mfst.GetConfig().GetDigest(): false}
		for _, l := range mfst.GetLayers() {
			want[l.GetDigest()] = false
		}
		for _, d := range rep.Removed {
			if _, ok := want[d]; ok {
				want[d] = true
			}
		}
		for d, removed := range want {
			if !removed {
				t.Errorf("index-named blob %s survived the production reclaim — an index entry must never protect content", d)
			}
		}
		// And composed presence now answers honestly: the record remains (Lookup's
		// contract is "is there a record"), but the Puller's presence check sees the
		// evicted blobs — so Never fails with ErrImageNotPresent and no fetch happens.
		off := &offlineFetch{}
		p := mustPullerIndex(t, cache, off.fetch, idx)
		if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(),
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER); !errors.Is(err, ErrImageNotPresent) {
			t.Errorf("Never after reclaim: err = %v, want ErrImageNotPresent", err)
		}
		if off.calls != 0 {
			t.Errorf("Never performed %d fetches; want zero registry traffic", off.calls)
		}
	})
}

// newIndexedCache returns a fresh cache and the on-disk index over it.
func newIndexedCache(t *testing.T) (*Cache, *FileIndex) {
	t.Helper()
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	idx, err := NewFileIndex(cache)
	if err != nil {
		t.Fatalf("NewFileIndex: %v", err)
	}
	return cache, idx
}

// indexTestImage is a platform-stamped fixture image.
func indexTestImage(t *testing.T, os, arch string) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	return withPlatform(t, img, os, arch, "")
}

// primeIndexedPull pulls a fresh native image through the real index, leaving
// ref in the "this node has it" state by the production path — not by writing an
// entry the test made up.
func primeIndexedPull(t *testing.T, cache *Cache, idx *FileIndex, ref string, policy PlatformPolicy) *runtimev1.ImageManifest {
	t.Helper()
	return primeIndexedPullImage(t, cache, idx, ref, indexTestImage(t, "darwin", "arm64"), policy)
}

// primeIndexedPullImage is primeIndexedPull with a caller-chosen image, for the
// rows that need a specific platform.
func primeIndexedPullImage(t *testing.T, cache *Cache, idx *FileIndex, ref string, img ggcrv1.Image, policy PlatformPolicy) *runtimev1.ImageManifest {
	t.Helper()
	ff := &fakeFetch{img: img}
	p := mustPullerIndex(t, cache, ff.fetch, idx)
	res, err := p.Pull(context.Background(), ref, nil, policy, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if err != nil {
		t.Fatalf("prime pull %q: %v", ref, err)
	}
	// The lease is the in-flight pin; this test's pod-root and GC rows measure
	// the store without it, exactly as a caller that has finished recording does.
	res.Lease.Release()
	return res.Manifest
}

// evictBlobs removes every blob the manifest names, leaving the index entry
// behind — the stale-entry state the GC creates for real.
func evictBlobs(t *testing.T, cache *Cache, mfst *runtimev1.ImageManifest) {
	t.Helper()
	for _, d := range manifestDigests(mfst) {
		path, err := cache.BlobPath(d)
		if err != nil {
			t.Fatalf("blob path %s: %v", d, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("evict blob %s: %v", d, err)
		}
	}
}

// readEntryFile reads one raw index entry.
func readEntryFile(t *testing.T, cache *Cache, name string) []byte {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join(cache.IndexRoot(), name))
	if err != nil {
		t.Fatalf("read index entry %s: %v", name, err)
	}
	return buf
}

// writeEntryFile overwrites one raw index entry with damaged bytes.
func writeEntryFile(t *testing.T, cache *Cache, name string, buf []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cache.IndexRoot(), name), buf, 0o600); err != nil {
		t.Fatalf("write index entry %s: %v", name, err)
	}
}

// assertSameManifest compares the digests a manifest names — the fact the whole
// warm path turns on (the caller materializes exactly these blobs).
func assertSameManifest(t *testing.T, got, want *runtimev1.ImageManifest) {
	t.Helper()
	if got.GetReference() != want.GetReference() {
		t.Errorf("reference = %q, want %q", got.GetReference(), want.GetReference())
	}
	g, w := manifestDigests(got), manifestDigests(want)
	if len(g) != len(w) {
		t.Fatalf("manifest names %d blobs, want %d", len(g), len(w))
	}
	for i := range g {
		if g[i] != w[i] {
			t.Errorf("blob %d = %s, want %s", i, g[i], w[i])
		}
	}
}
