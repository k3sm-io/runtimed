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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var planNow = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

// node is a well-formed content node fixture: a 64-hex sha256 path built from a
// one-character seed, aged by age.
func node(seed byte, size int64, age time.Duration) BlobNode {
	hex := strings.Repeat(string(seed), 64)
	return BlobNode{
		Path:    "sha256/" + hex,
		Digest:  "sha256:" + hex,
		Kind:    BlobKindContent,
		Size:    size,
		ModTime: planNow.Add(-age),
	}
}

// TestPlanPruneReachability pins the planner's ONE rule — a content blob is kept
// iff a daemon-authored root names it or a lease pins it — and every fail-closed
// exit from it. The planner is pure, so each row is exact.
func TestPlanPruneReachability(t *testing.T) {
	t.Parallel()

	rooted := node('a', 10, time.Hour)
	orphan := node('b', 20, time.Hour)
	young := node('c', 30, time.Second)
	leased := node('d', 40, time.Hour)

	tests := []struct {
		name    string
		nodes   []BlobNode
		roots   []ImageRoot
		leased  []string
		want    map[string]PruneReason // path -> reason
		wantErr bool
	}{
		{
			name:  "a rooted blob is kept, an unrooted one is deleted",
			nodes: []BlobNode{rooted, orphan},
			roots: []ImageRoot{{Reference: "app:v1", Config: rooted.Digest}},
			want: map[string]PruneReason{
				rooted.Path: ReasonKeptInUse,
				orphan.Path: ReasonDeleteUnreferenced,
			},
		},
		{
			name:  "a layer digest roots as surely as a config digest",
			nodes: []BlobNode{rooted, orphan},
			roots: []ImageRoot{{Reference: "app:v1", Layers: []string{orphan.Digest}}},
			want: map[string]PruneReason{
				rooted.Path: ReasonDeleteUnreferenced,
				orphan.Path: ReasonKeptInUse,
			},
		},
		{
			name:   "a lease keeps a blob no root names",
			nodes:  []BlobNode{leased},
			leased: []string{leased.Digest},
			want:   map[string]PruneReason{leased.Path: ReasonKeptLeased},
		},
		{
			name:  "a blob younger than grace is kept",
			nodes: []BlobNode{young},
			want:  map[string]PruneReason{young.Path: ReasonKeptYoung},
		},
		{
			name: "an out-of-grammar path is kept, never deleted",
			nodes: []BlobNode{
				{Path: "sha256/NOTHEX", Kind: BlobKindUnknown, ModTime: planNow.Add(-time.Hour)},
				{Path: "sha256", Kind: BlobKindUnknown, ModTime: planNow.Add(-time.Hour)},
			},
			want: map[string]PruneReason{
				"sha256/NOTHEX": ReasonKeptUnknownProvenance,
				"sha256":        ReasonKeptUnknownProvenance,
			},
		},
		{
			name: "a node whose declared digest disagrees with its path is kept",
			nodes: []BlobNode{{
				Path:    "sha256/" + strings.Repeat("a", 64),
				Digest:  "sha256:" + strings.Repeat("b", 64), // lies about itself
				Kind:    BlobKindContent,
				ModTime: planNow.Add(-time.Hour),
			}},
			want: map[string]PruneReason{"sha256/" + strings.Repeat("a", 64): ReasonKeptUnknownProvenance},
		},
		{
			name: "a stale temp file is deleted, a fresh one kept",
			nodes: []BlobNode{
				{Path: "sha256/.blob-1", Kind: BlobKindTemp, ModTime: planNow.Add(-time.Hour)},
				{Path: "sha256/.blob-2", Kind: BlobKindTemp, ModTime: planNow},
			},
			want: map[string]PruneReason{
				"sha256/.blob-1": ReasonDeleteStaleTemp,
				"sha256/.blob-2": ReasonKeptYoung,
			},
		},
		{
			name:  "a root naming an absent digest is harmless",
			nodes: []BlobNode{orphan},
			roots: []ImageRoot{{Reference: "gone:v1", Config: "sha256:" + strings.Repeat("f", 64)}},
			want:  map[string]PruneReason{orphan.Path: ReasonDeleteUnreferenced},
		},
		{
			name:    "a duplicate inventory path is an error, not a guess",
			nodes:   []BlobNode{rooted, rooted},
			wantErr: true,
		},
		{
			name:    "a negative size is an error",
			nodes:   []BlobNode{{Path: "sha256/x", Kind: BlobKindContent, Size: -1, ModTime: planNow}},
			wantErr: true,
		},
		{
			name:    "an undeclared kind is an error",
			nodes:   []BlobNode{{Path: "sha256/x", Kind: BlobKind("made-up"), ModTime: planNow}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := PlanPrune(tc.nodes, tc.roots, tc.leased, time.Minute, planNow)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("PlanPrune succeeded; want an error")
				}
				if plan != nil {
					t.Errorf("PlanPrune returned a plan alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("PlanPrune: %v", err)
			}
			got := make(map[string]PruneReason)
			for _, d := range plan.Delete {
				got[d.Node.Path] = d.Reason
			}
			for _, k := range plan.Keep {
				got[k.Node.Path] = k.Reason
			}
			if len(got) != len(tc.want) {
				t.Fatalf("decided %d nodes; want %d (%v)", len(got), len(tc.want), got)
			}
			for path, want := range tc.want {
				if got[path] != want {
					t.Errorf("%s: reason %q; want %q", path, got[path], want)
				}
			}
		})
	}
}

// TestPlanPruneIsAnExactPartition asserts the property the executor's contract
// rests on: every inventory node is decided exactly once. A node in neither set
// is a node the plan is silent about.
func TestPlanPruneIsAnExactPartition(t *testing.T) {
	t.Parallel()
	nodes := []BlobNode{
		node('a', 1, time.Hour),
		node('b', 2, time.Second),
		{Path: "sha256/.blob-9", Kind: BlobKindTemp, ModTime: planNow.Add(-time.Hour)},
		{Path: "weird", Kind: BlobKindUnknown, ModTime: planNow.Add(-time.Hour)},
	}
	plan, err := PlanPrune(nodes, []ImageRoot{{Reference: "r", Config: nodes[0].Digest}}, nil, time.Minute, planNow)
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	seen := make(map[string]int)
	for _, d := range append(append([]PruneDecision{}, plan.Delete...), plan.Keep...) {
		seen[d.Node.Path]++
	}
	if len(seen) != len(nodes) {
		t.Fatalf("decided %d distinct nodes; want %d", len(seen), len(nodes))
	}
	for p, n := range seen {
		if n != 1 {
			t.Errorf("%s decided %d times; want exactly 1", p, n)
		}
	}
}

// TestEnumerateBlobsReadsNoContent pins that the inventory is derived from names
// and modes alone. A blob whose CONTENT looks like a manifest gets no special
// standing — content-derived reachability is the capability this package does
// not have, and a test that only checked the happy path would not notice it
// coming back.
func TestEnumerateBlobsReadsNoContent(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	manifestish := f.blob(`{"schemaVersion":2,"config":{"digest":"sha256:deadbeef"},"layers":[]}`, time.Hour)
	plain := f.blob("just bytes", time.Hour)

	nodes, err := f.cache.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	byDigest := make(map[string]BlobNode)
	for _, n := range nodes {
		byDigest[n.Digest] = n
	}
	for _, d := range []string{manifestish, plain} {
		n, ok := byDigest[d]
		if !ok {
			t.Fatalf("blob %s missing from the inventory", d)
		}
		if n.Kind != BlobKindContent {
			t.Errorf("blob %s classified %q; every regular blob is plain content", d, n.Kind)
		}
	}
	// Both are equally unreferenced, so both must be planned for deletion: the
	// manifest-shaped one gets no authority from its bytes.
	plan, err := PlanPrune(nodes, nil, nil, time.Minute, planNow)
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	if len(plan.Delete) != 2 {
		t.Fatalf("planned %d deletions; want 2 — manifest-shaped content earned standing it must not have", len(plan.Delete))
	}
}

// TestExecutePruneReVerifiesBeforeUnlink pins that the executor re-checks every
// fact that made a node deletable, in the window between planning and unlinking.
func TestExecutePruneReVerifiesBeforeUnlink(t *testing.T) {
	t.Parallel()

	t.Run("a node swapped for a symlink after planning is skipped", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		victim := f.blob("condemned", time.Hour)
		nodes, err := f.cache.EnumerateBlobs()
		if err != nil {
			t.Fatalf("EnumerateBlobs: %v", err)
		}
		plan, err := PlanPrune(nodes, nil, nil, time.Minute, f.clock)
		if err != nil {
			t.Fatalf("PlanPrune: %v", err)
		}
		// Swap the planned target for a symlink to something precious.
		p, err := f.cache.BlobPath(victim)
		if err != nil {
			t.Fatalf("BlobPath: %v", err)
		}
		target := filepath.Join(t.TempDir(), "precious")
		if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		rep, err := f.cache.ExecutePrune(plan, time.Minute, f.clock, nil)
		if err != nil {
			t.Fatalf("ExecutePrune: %v", err)
		}
		if rep.Deleted != 0 {
			t.Errorf("Deleted = %d; the swapped node must be skipped", rep.Deleted)
		}
		if len(rep.Skipped) != 1 {
			t.Fatalf("Skipped = %v; want exactly one refusal", rep.Skipped)
		}
		if _, err := os.Stat(target); err != nil {
			t.Errorf("the symlink target was removed — the executor followed the link: %v", err)
		}
	})

	t.Run("a node touched after planning is skipped as young", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		victim := f.blob("condemned", time.Hour)
		nodes, err := f.cache.EnumerateBlobs()
		if err != nil {
			t.Fatalf("EnumerateBlobs: %v", err)
		}
		plan, err := PlanPrune(nodes, nil, nil, time.Minute, f.clock)
		if err != nil {
			t.Fatalf("PlanPrune: %v", err)
		}
		p, _ := f.cache.BlobPath(victim)
		if err := os.Chtimes(p, f.clock, f.clock); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
		rep, err := f.cache.ExecutePrune(plan, time.Minute, f.clock, nil)
		if err != nil {
			t.Fatalf("ExecutePrune: %v", err)
		}
		if rep.Deleted != 0 || !f.exists(victim) {
			t.Errorf("a node re-touched between plan and unlink was deleted")
		}
	})

	t.Run("an out-of-grammar delete entry is refused by the executor too", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		// A hand-built plan condemning a traversal path. The planner would never
		// produce one; the executor must refuse it anyway, since it is the layer
		// that turns a path into an unlink.
		plan := &PrunePlan{Delete: []PruneDecision{{
			Node:   BlobNode{Path: "../../etc/passwd", Kind: BlobKindContent, ModTime: f.clock.Add(-time.Hour)},
			Reason: ReasonDeleteUnreferenced,
		}}}
		rep, err := f.cache.ExecutePrune(plan, time.Minute, f.clock, nil)
		if err != nil {
			t.Fatalf("ExecutePrune: %v", err)
		}
		if rep.Deleted != 0 {
			t.Fatalf("Deleted = %d; a traversal path must never be unlinked", rep.Deleted)
		}
		if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Reason, "grammar") {
			t.Errorf("Skipped = %v; want a grammar refusal", rep.Skipped)
		}
	})
}

// TestRootsFailClosed pins the fail-closed enumeration: anything that makes the
// root set less than complete aborts the whole prune, because an incomplete root
// set does not degrade the answer, it inverts it.
func TestRootsFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("no pods tree means no pods, not an error", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		roots, err := f.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(roots) != 0 {
			t.Errorf("Roots = %v; want empty", roots)
		}
	})

	t.Run("a pod dir with no record is incomplete", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		if err := os.MkdirAll(filepath.Join(f.cache.PodsRoot(), "pod-a"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		_, err := f.cache.Roots()
		if !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("err = %v; want ErrRootsIncomplete", err)
		}
	})

	t.Run("a malformed record is incomplete", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		pid := f.pod("pod-a")
		if err := os.WriteFile(filepath.Join(f.cache.PodDir(pid), PodReferencesName), []byte("{ not json"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := f.cache.Roots(); !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("err = %v; want ErrRootsIncomplete", err)
		}
	})

	t.Run("a record naming an unusable digest is incomplete", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		pid := f.pod("pod-a")
		body := `{"images":[{"reference":"app:v1","config":"md5:abcd","layers":[]}]}`
		if err := os.WriteFile(filepath.Join(f.cache.PodDir(pid), PodReferencesName), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		// A root the store cannot map to a path cannot protect anything, so it must
		// not be quietly dropped — dropping it is what turns a protected blob into
		// an unrooted one.
		if _, err := f.cache.Roots(); !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("err = %v; want ErrRootsIncomplete", err)
		}
	})

	t.Run("a non-directory node in the pods tree is incomplete", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		f.pod("pod-a")
		if err := os.WriteFile(filepath.Join(f.cache.PodsRoot(), "stray"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := f.cache.Roots(); !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("err = %v; want ErrRootsIncomplete", err)
		}
	})

	t.Run("re-recording a reference replaces it and keeps the others", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		pid := f.pod("pod-a",
			ImageRoot{Reference: "a:v1", Config: "sha256:" + strings.Repeat("1", 64)},
			ImageRoot{Reference: "b:v1", Config: "sha256:" + strings.Repeat("2", 64)},
		)
		if err := f.cache.RecordPodImage(pid, ImageRoot{Reference: "a:v2", Config: "sha256:" + strings.Repeat("3", 64)}); err != nil {
			t.Fatalf("RecordPodImage: %v", err)
		}
		roots, err := f.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(roots) != 3 {
			t.Fatalf("Roots = %v; want three entries", roots)
		}
		if err := f.cache.RecordPodImage(pid, ImageRoot{Reference: "a:v1", Config: "sha256:" + strings.Repeat("4", 64)}); err != nil {
			t.Fatalf("RecordPodImage: %v", err)
		}
		roots, err = f.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(roots) != 3 {
			t.Fatalf("re-recording a reference grew the record to %d entries; want 3", len(roots))
		}
	})
}
