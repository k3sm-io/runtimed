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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/random"
)

// Planner fixture clock: everything is judged against pruneNow with a 1h grace.
var (
	pruneNow   = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	pruneGrace = time.Hour
	oldT       = pruneNow.Add(-2 * time.Hour)   // past grace: delete-eligible
	youngT     = pruneNow.Add(-1 * time.Minute) // inside grace: kept
)

// cnode builds a well-formed content inventory node.
func cnode(hex string, kind BlobKind, mt time.Time) BlobNode {
	return BlobNode{Path: "sha256/" + hex, Digest: "sha256:" + hex, Kind: kind, Size: 10, ModTime: mt}
}

// planReasons flattens a plan into (deleteSet, keepSet) path→reason maps and
// asserts the exact-partition invariant over the input inventory.
func planReasons(t *testing.T, plan *PrunePlan, inventory []BlobNode) (map[string]PruneReason, map[string]PruneReason) {
	t.Helper()
	del := make(map[string]PruneReason)
	keep := make(map[string]PruneReason)
	for _, d := range plan.Delete {
		del[d.Node.Path] = d.Reason
	}
	for _, d := range plan.Keep {
		keep[d.Node.Path] = d.Reason
	}
	if len(del)+len(keep) != len(inventory) {
		t.Fatalf("partition violation: %d delete + %d keep != %d nodes", len(del), len(keep), len(inventory))
	}
	for _, n := range inventory {
		_, inDel := del[n.Path]
		_, inKeep := keep[n.Path]
		if inDel == inKeep {
			t.Fatalf("partition violation: node %q inDelete=%v inKeep=%v", n.Path, inDel, inKeep)
		}
	}
	return del, keep
}

// TestSnapshotPrune is the B114 gate: the pure prune planner's exact-partition
// semantics, the enumerator's fail-closed classification, and the blobs-only
// executor, end to end through the REAL pull write paths.
func TestSnapshotPrune(t *testing.T) {
	t.Run("planner", testPrunePlanner)
	t.Run("planner input errors", testPrunePlannerErrors)
	t.Run("enumerate and execute round trip", testPruneRoundTrip)
	t.Run("executor re-verify", testPruneExecutorReverify)
	t.Run("hostile plan cannot escape blobs", testPruneHostilePlan)
}

func testPrunePlanner(t *testing.T) {
	cases := []struct {
		name       string
		nodes      []BlobNode
		edges      []ImageEdge
		inUse      []string
		wantDelete map[string]PruneReason
		wantKeep   map[string]PruneReason
	}{
		{
			// Two platforms of one image (A1/A2, in use) and a distinct image B
			// (unreferenced, old) sharing a base layer: B's manifest + config +
			// unique layer go; every shared blob stays.
			name: "shared base layers across images and platforms",
			nodes: []BlobNode{
				cnode("aaaa1111", BlobKindManifest, oldT), // manifest A1 (in use)
				cnode("aaaa2222", BlobKindManifest, oldT), // manifest A2 (in use)
				cnode("bbbb1111", BlobKindManifest, oldT), // manifest B (unreferenced)
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("caaa2222", BlobKindConfig, oldT),
				cnode("cbbb1111", BlobKindConfig, oldT),
				cnode("11ba5eff", BlobKindLayer, oldT), // shared base layer
				cnode("11aa0123", BlobKindLayer, oldT), // unique to A1
				cnode("11bb0123", BlobKindLayer, oldT), // unique to B
			},
			edges: []ImageEdge{
				{Manifest: "sha256:aaaa1111", Platform: "darwin/arm64", Config: "sha256:caaa1111", Layers: []string{"sha256:11ba5eff", "sha256:11aa0123"}},
				{Manifest: "sha256:aaaa2222", Platform: "linux/arm64", Config: "sha256:caaa2222", Layers: []string{"sha256:11ba5eff"}},
				{Manifest: "sha256:bbbb1111", Config: "sha256:cbbb1111", Layers: []string{"sha256:11ba5eff", "sha256:11bb0123"}},
			},
			inUse: []string{"sha256:aaaa1111", "sha256:aaaa2222"},
			wantDelete: map[string]PruneReason{
				"sha256/bbbb1111": ReasonDeleteUnreferenced,
				"sha256/cbbb1111": ReasonDeleteUnreferenced,
				"sha256/11bb0123": ReasonDeleteUnreferenced,
			},
			wantKeep: map[string]PruneReason{
				"sha256/aaaa1111": ReasonKeptInUse,
				"sha256/aaaa2222": ReasonKeptInUse,
				"sha256/caaa1111": ReasonKeptInUse,
				"sha256/caaa2222": ReasonKeptInUse,
				"sha256/11ba5eff": ReasonKeptInUse,
				"sha256/11aa0123": ReasonKeptInUse,
			},
		},
		{
			name: "in-use image keeps its entire chain",
			nodes: []BlobNode{
				cnode("aaaa1111", BlobKindManifest, oldT),
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("11111111", BlobKindLayer, oldT),
				cnode("22222222", BlobKindLayer, oldT),
			},
			edges: []ImageEdge{
				{Manifest: "sha256:aaaa1111", Config: "sha256:caaa1111", Layers: []string{"sha256:11111111", "sha256:22222222"}},
			},
			inUse:      []string{"sha256:aaaa1111"},
			wantDelete: map[string]PruneReason{},
			wantKeep: map[string]PruneReason{
				"sha256/aaaa1111": ReasonKeptInUse,
				"sha256/caaa1111": ReasonKeptInUse,
				"sha256/11111111": ReasonKeptInUse,
				"sha256/22222222": ReasonKeptInUse,
			},
		},
		{
			name: "fully unreferenced old image is deleted whole",
			nodes: []BlobNode{
				cnode("aaaa1111", BlobKindManifest, oldT),
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("11111111", BlobKindLayer, oldT),
			},
			edges: []ImageEdge{
				{Manifest: "sha256:aaaa1111", Config: "sha256:caaa1111", Layers: []string{"sha256:11111111"}},
			},
			wantDelete: map[string]PruneReason{
				"sha256/aaaa1111": ReasonDeleteUnreferenced,
				"sha256/caaa1111": ReasonDeleteUnreferenced,
				"sha256/11111111": ReasonDeleteUnreferenced,
			},
			wantKeep: map[string]PruneReason{},
		},
		{
			name:       "empty cache plans nothing",
			wantDelete: map[string]PruneReason{},
			wantKeep:   map[string]PruneReason{},
		},
		{
			// No persisted manifest names these: fail-closed keep, even when old.
			name: "unknown provenance is kept",
			nodes: []BlobNode{
				cnode("0badc0de", BlobKindUnknown, oldT),
				cnode("deadfeed", BlobKindLayer, oldT), // layer-kinded but named by no edge
			},
			wantDelete: map[string]PruneReason{},
			wantKeep: map[string]PruneReason{
				"sha256/0badc0de": ReasonKeptUnknownProvenance,
				"sha256/deadfeed": ReasonKeptUnknownProvenance,
			},
		},
		{
			// A manifest-kind blob on disk that NO edge record describes — the
			// shape an UNPARSEABLE persisted manifest leaves behind (the
			// enumerator refuses to name its blobs, so the image's chain is
			// unknowable). Old, not in use, and still KEPT: fail-closed. This is
			// the manifest sibling of the config/layer !namedByAny branch above,
			// and the accompanying well-formed unreferenced image proves the row
			// is not vacuous — that chain IS deleted in the same plan.
			name: "manifest with no edge record is kept-unknown, not deleted",
			nodes: []BlobNode{
				cnode("bad0bad0", BlobKindManifest, oldT), // no edge names it
				cnode("aaaa1111", BlobKindManifest, oldT), // well-formed, unreferenced
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("11111111", BlobKindLayer, oldT),
			},
			edges: []ImageEdge{
				{Manifest: "sha256:aaaa1111", Config: "sha256:caaa1111", Layers: []string{"sha256:11111111"}},
			},
			wantDelete: map[string]PruneReason{
				"sha256/aaaa1111": ReasonDeleteUnreferenced,
				"sha256/caaa1111": ReasonDeleteUnreferenced,
				"sha256/11111111": ReasonDeleteUnreferenced,
			},
			wantKeep: map[string]PruneReason{
				"sha256/bad0bad0": ReasonKeptUnknownProvenance,
			},
		},
		{
			// Blob of a pruned image inside the grace window survives this round.
			name: "young unreferenced blob is kept-young",
			nodes: []BlobNode{
				cnode("aaaa1111", BlobKindManifest, oldT),
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("11111111", BlobKindLayer, youngT),
			},
			edges: []ImageEdge{
				{Manifest: "sha256:aaaa1111", Config: "sha256:caaa1111", Layers: []string{"sha256:11111111"}},
			},
			wantDelete: map[string]PruneReason{
				"sha256/aaaa1111": ReasonDeleteUnreferenced,
				"sha256/caaa1111": ReasonDeleteUnreferenced,
			},
			wantKeep: map[string]PruneReason{
				"sha256/11111111": ReasonKeptYoung,
			},
		},
		{
			// A just-pulled image not yet used by any pod: the young manifest is a
			// keep-root, so its (older, shared-with-nothing) chain is referenced.
			name: "young manifest keeps its chain referenced",
			nodes: []BlobNode{
				cnode("aaaa1111", BlobKindManifest, youngT),
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("11111111", BlobKindLayer, oldT),
			},
			edges: []ImageEdge{
				{Manifest: "sha256:aaaa1111", Config: "sha256:caaa1111", Layers: []string{"sha256:11111111"}},
			},
			wantDelete: map[string]PruneReason{},
			wantKeep: map[string]PruneReason{
				"sha256/aaaa1111": ReasonKeptYoung,
				"sha256/caaa1111": ReasonKeptReferenced,
				"sha256/11111111": ReasonKeptReferenced,
			},
		},
		{
			// An edge whose manifest blob is NOT in the inventory: age unknowable,
			// so the blobs it names are kept (fail-closed).
			name: "edge without inventory manifest keeps its blobs",
			nodes: []BlobNode{
				cnode("caaa1111", BlobKindConfig, oldT),
				cnode("11111111", BlobKindLayer, oldT),
			},
			edges: []ImageEdge{
				{Manifest: "sha256:absent00", Config: "sha256:caaa1111", Layers: []string{"sha256:11111111"}},
			},
			wantDelete: map[string]PruneReason{},
			wantKeep: map[string]PruneReason{
				"sha256/caaa1111": ReasonKeptReferenced,
				"sha256/11111111": ReasonKeptReferenced,
			},
		},
		{
			name: "stale temp deleted, young temp kept",
			nodes: []BlobNode{
				{Path: "sha256/.blob-1111", Kind: BlobKindTemp, Size: 5, ModTime: oldT},
				{Path: "sha256/.blob-2222", Kind: BlobKindTemp, Size: 5, ModTime: youngT},
			},
			wantDelete: map[string]PruneReason{
				"sha256/.blob-1111": ReasonDeleteStaleTemp,
			},
			wantKeep: map[string]PruneReason{
				"sha256/.blob-2222": ReasonKeptYoung,
			},
		},
		{
			// Hostile inventory rows: whatever kind they claim, an out-of-grammar
			// path is NEVER in the delete set.
			name: "hostile paths are never delete candidates",
			nodes: []BlobNode{
				{Path: "blobs-evil", Digest: "sha256:deadbeef", Kind: BlobKindLayer, Size: 1, ModTime: oldT},
				{Path: "sha256/../evil", Digest: "sha256:deadbeef", Kind: BlobKindLayer, Size: 1, ModTime: oldT},
				{Path: "/etc/passwd", Kind: BlobKindLayer, Size: 1, ModTime: oldT},
				{Path: "sha256/NOTHEX!", Kind: BlobKindManifest, Size: 1, ModTime: oldT},
				{Path: "sha256/aaaa1111/extra", Kind: BlobKindLayer, Size: 1, ModTime: oldT},
				// Digest that does not match the path it claims.
				{Path: "sha256/aaaa1111", Digest: "sha256:bbbb2222", Kind: BlobKindLayer, Size: 1, ModTime: oldT},
			},
			wantDelete: map[string]PruneReason{},
			wantKeep: map[string]PruneReason{
				"blobs-evil":            ReasonKeptUnknownProvenance,
				"sha256/../evil":        ReasonKeptUnknownProvenance,
				"/etc/passwd":           ReasonKeptUnknownProvenance,
				"sha256/NOTHEX!":        ReasonKeptUnknownProvenance,
				"sha256/aaaa1111/extra": ReasonKeptUnknownProvenance,
				"sha256/aaaa1111":       ReasonKeptUnknownProvenance,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanPrune(tc.nodes, tc.edges, tc.inUse, pruneGrace, pruneNow)
			if err != nil {
				t.Fatalf("PlanPrune: %v", err)
			}
			del, keep := planReasons(t, plan, tc.nodes)
			assertReasonMap(t, "delete", del, tc.wantDelete)
			assertReasonMap(t, "keep", keep, tc.wantKeep)
		})
	}
}

// assertReasonMap compares a COMPLETE decision set (paths and reasons).
func assertReasonMap(t *testing.T, which string, got, want map[string]PruneReason) {
	t.Helper()
	for p, r := range want {
		if gr, ok := got[p]; !ok {
			t.Errorf("%s set: missing %q (want %s)", which, p, r)
		} else if gr != r {
			t.Errorf("%s set: %q reason = %s, want %s", which, p, gr, r)
		}
	}
	for p, r := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("%s set: unexpected %q (%s)", which, p, r)
		}
	}
}

func testPrunePlannerErrors(t *testing.T) {
	good := []BlobNode{cnode("aaaa1111", BlobKindLayer, oldT)}
	cases := []struct {
		name  string
		nodes []BlobNode
		edges []ImageEdge
		inUse []string
		grace time.Duration
		now   time.Time
	}{
		{"zero now", good, nil, nil, pruneGrace, time.Time{}},
		{"negative grace", good, nil, nil, -time.Second, pruneNow},
		{"empty node path", []BlobNode{{Kind: BlobKindLayer}}, nil, nil, pruneGrace, pruneNow},
		{"duplicate node path", []BlobNode{cnode("aaaa1111", BlobKindLayer, oldT), cnode("aaaa1111", BlobKindConfig, oldT)}, nil, nil, pruneGrace, pruneNow},
		{"unknown kind", []BlobNode{{Path: "sha256/aaaa1111", Kind: BlobKind("weird")}}, nil, nil, pruneGrace, pruneNow},
		{"negative size", []BlobNode{{Path: "sha256/aaaa1111", Kind: BlobKindLayer, Size: -1}}, nil, nil, pruneGrace, pruneNow},
		{"empty edge manifest", good, []ImageEdge{{Config: "sha256:caaa1111"}}, nil, pruneGrace, pruneNow},
		{"empty in-use entry", good, nil, []string{""}, pruneGrace, pruneNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PlanPrune(tc.nodes, tc.edges, tc.inUse, tc.grace, tc.now); err == nil {
				t.Fatal("want error, got nil (an invalid record must delete nothing)")
			}
		})
	}
}

// pullFixtureImage pulls a fresh random image through the REAL Pull write path
// and returns its manifest digest.
func pullFixtureImage(t *testing.T, p *Puller, ff *fakeFetch, ref string, layers int64) string {
	t.Helper()
	img, err := random.Image(512, layers)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	ff.img = withPlatform(t, img, "darwin", "arm64", "")
	res, err := p.Pull(context.Background(), ref, nil, nativePolicy())
	if err != nil {
		t.Fatalf("pull %s: %v", ref, err)
	}
	if res.ManifestDigest == "" {
		t.Fatalf("pull %s: empty ManifestDigest", ref)
	}
	return res.ManifestDigest
}

// blobEntry is one on-disk snapshot row for re-scan equality.
type blobEntry struct {
	size  int64
	mtime time.Time
	mode  fs.FileMode
}

// walkBlobEntries snapshots every non-directory entry (plus any planted
// directory at depth 1) under the blobs root, keyed by blobs-relative path.
func walkBlobEntries(t *testing.T, c *Cache) map[string]blobEntry {
	t.Helper()
	out := make(map[string]blobEntry)
	blobs := c.blobsDir()
	err := filepath.WalkDir(blobs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(blobs, path)
		if rerr != nil || rel == "." {
			return rerr
		}
		info, ierr := d.Info() // lstat semantics via WalkDir
		if ierr != nil {
			return ierr
		}
		if d.IsDir() {
			// Algo dirs are structure, not inventory; a deeper planted dir is.
			if !filepath.IsLocal(rel) || filepath.Dir(rel) == "." {
				return nil
			}
		}
		out[rel] = blobEntry{size: info.Size(), mtime: info.ModTime(), mode: info.Mode()}
		return nil
	})
	if err != nil {
		t.Fatalf("walk blobs: %v", err)
	}
	return out
}

// ageAllBlobs rewinds the mtime of every regular file under blobs/ to when.
func ageAllBlobs(t *testing.T, c *Cache, when time.Time) {
	t.Helper()
	blobs := c.blobsDir()
	err := filepath.WalkDir(blobs, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		return os.Chtimes(path, when, when)
	})
	if err != nil {
		t.Fatalf("age blobs: %v", err)
	}
}

// testPruneRoundTrip drives the full pipeline on a real tempdir cache: pull two
// images through the REAL write paths (so layout drift reds this test), plant
// hostile entries by hand, enumerate, plan with one image in use, verify the
// dry-run mutates nothing, execute, and verify EXACTLY the delete set is gone.
func testPruneRoundTrip(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ff := &fakeFetch{}
	p := mustPuller(t, cache, ff.fetch)

	digA := pullFixtureImage(t, p, ff, "example.com/keep:v1", 2)
	digB := pullFixtureImage(t, p, ff, "example.com/prune:v1", 2)

	// The manifest persistence pin: Pull stored the raw manifest as a CAS blob
	// keyed by the manifest digest (the prune edge record).
	if !cache.Has(digA) || !cache.Has(digB) {
		t.Fatalf("persisted manifests missing: Has(%s)=%v Has(%s)=%v", digA, cache.Has(digA), digB, cache.Has(digB))
	}

	// Everything pulled is now old.
	ageAllBlobs(t, cache, oldT)

	// Hand-place ONLY the malformed/hostile entries, rooted via the real path
	// helpers where a digest is involved.
	blobs := filepath.Join(cache.Root(), "blobs")
	orphanPath, err := cache.blobPath("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanPath, []byte("orphan bytes no manifest names"), 0o644); err != nil {
		t.Fatal(err)
	}
	staleTemp := filepath.Join(blobs, "sha256", ".blob-424242")
	if err := os.WriteFile(staleTemp, []byte("half-written"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{orphanPath, staleTemp} {
		if err := os.Chtimes(f, oldT, oldT); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink planted in the tree (hex-looking name), a directory where a
	// file should be, and a stray top-level file: all unknown provenance.
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("must survive"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkRel := "sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.Symlink(victim, filepath.Join(blobs, symlinkRel)); err != nil {
		t.Fatal(err)
	}
	dirRel := "sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := os.Mkdir(filepath.Join(blobs, dirRel), 0o755); err != nil {
		t.Fatal(err)
	}
	strayRel := "stray-file"
	if err := os.WriteFile(filepath.Join(blobs, strayRel), []byte("?"), 0o644); err != nil {
		t.Fatal(err)
	}

	nodes, edges, err := cache.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("want 2 image edges, got %d: %+v", len(edges), edges)
	}
	kinds := make(map[string]BlobKind, len(nodes))
	for _, n := range nodes {
		kinds[n.Path] = n.Kind
	}
	for rel, want := range map[string]BlobKind{
		symlinkRel:            BlobKindUnknown,
		dirRel:                BlobKindUnknown,
		strayRel:              BlobKindUnknown,
		"sha256/.blob-424242": BlobKindTemp,
		relOf(t, cache, digA): BlobKindManifest,
		relOf(t, cache, digB): BlobKindManifest,
	} {
		if kinds[rel] != want {
			t.Errorf("enumerator classified %q as %s, want %s", rel, kinds[rel], want)
		}
	}
	for _, e := range edges {
		if e.Platform != "darwin/arm64" {
			t.Errorf("edge %s platform = %q, want darwin/arm64", e.Manifest, e.Platform)
		}
	}

	before := walkBlobEntries(t, cache)

	plan, err := PlanPrune(nodes, edges, []string{digA}, pruneGrace, pruneNow)
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	del, keep := planReasons(t, plan, nodes)

	// The delete set is EXACTLY image B's chain + the stale temp.
	wantDelete := map[string]PruneReason{"sha256/.blob-424242": ReasonDeleteStaleTemp}
	for _, e := range edges {
		if e.Manifest != digB {
			continue
		}
		wantDelete[relOf(t, cache, e.Manifest)] = ReasonDeleteUnreferenced
		wantDelete[relOf(t, cache, e.Config)] = ReasonDeleteUnreferenced
		for _, l := range e.Layers {
			wantDelete[relOf(t, cache, l)] = ReasonDeleteUnreferenced
		}
	}
	assertReasonMap(t, "delete", del, wantDelete)
	// Spot-check keep reasons (the partition check already proved completeness).
	if keep[relOf(t, cache, digA)] != ReasonKeptInUse {
		t.Errorf("in-use manifest kept as %s, want %s", keep[relOf(t, cache, digA)], ReasonKeptInUse)
	}
	for _, rel := range []string{symlinkRel, dirRel, strayRel, "sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"} {
		if keep[rel] != ReasonKeptUnknownProvenance {
			t.Errorf("%q kept as %s, want %s", rel, keep[rel], ReasonKeptUnknownProvenance)
		}
	}

	// Dry-run (planning) left the tree byte-identical: re-scan equality.
	after := walkBlobEntries(t, cache)
	if len(before) != len(after) {
		t.Fatalf("planning mutated the tree: %d entries before, %d after", len(before), len(after))
	}
	for rel, b := range before {
		if a, ok := after[rel]; !ok || a != b {
			t.Fatalf("planning mutated %q: before %+v after %+v", rel, b, after[rel])
		}
	}

	// Execute removes EXACTLY the delete set and nothing else.
	rep, err := cache.ExecutePrune(plan, pruneGrace, pruneNow)
	if err != nil {
		t.Fatalf("ExecutePrune: %v", err)
	}
	if rep.Deleted != len(wantDelete) {
		t.Errorf("executor deleted %d, want %d (skipped: %+v)", rep.Deleted, len(wantDelete), rep.Skipped)
	}
	if len(rep.Skipped) != 0 {
		t.Errorf("unexpected skips: %+v", rep.Skipped)
	}
	if rep.DeletedBytes <= 0 {
		t.Errorf("DeletedBytes = %d, want > 0", rep.DeletedBytes)
	}
	survivors := walkBlobEntries(t, cache)
	for rel := range wantDelete {
		if _, still := survivors[rel]; still {
			t.Errorf("delete-set entry %q survived execution", rel)
		}
	}
	for rel := range keep {
		if _, ok := survivors[rel]; !ok {
			t.Errorf("keep-set entry %q was removed", rel)
		}
	}
	for rel := range survivors {
		if _, ok := keep[rel]; !ok {
			t.Errorf("survivor %q is not in the keep set", rel)
		}
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "must survive" {
		t.Errorf("symlink victim damaged: %q, %v", got, err)
	}
}

// relOf maps a digest to its blobs-relative path via the real path helper.
func relOf(t *testing.T, c *Cache, digest string) string {
	t.Helper()
	p, err := c.blobPath(digest)
	if err != nil {
		t.Fatalf("blobPath(%s): %v", digest, err)
	}
	rel, err := filepath.Rel(c.blobsDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// testPruneExecutorReverify pins the executor's pre-unlink re-verification:
// a plan entry swapped for a symlink after planning is SKIPPED (never
// followed), a refreshed entry is younger-than-grace SKIPPED, and an
// out-of-grammar plan entry can never reach the filesystem.
func testPruneExecutorReverify(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ff := &fakeFetch{}
	p := mustPuller(t, cache, ff.fetch)
	digest := pullFixtureImage(t, p, ff, "example.com/gone:v1", 2)
	ageAllBlobs(t, cache, oldT)

	nodes, edges, err := cache.EnumerateBlobs()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanPrune(nodes, edges, nil, pruneGrace, pruneNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Delete) != 4 { // manifest + config + 2 layers, all unreferenced+old
		t.Fatalf("want 4 delete entries, got %d", len(plan.Delete))
	}

	blobs := filepath.Join(cache.Root(), "blobs")
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("must survive"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Swap the first planned entry for a symlink; refresh the second's mtime.
	swapped := plan.Delete[0].Node.Path
	refreshed := plan.Delete[1].Node.Path
	if err := os.Remove(filepath.Join(blobs, swapped)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(blobs, swapped)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(blobs, refreshed), pruneNow, pruneNow); err != nil {
		t.Fatal(err)
	}
	// And a hostile plan entry that never came from a planner.
	outside := filepath.Join(cache.Root(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside blobs"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(outside, oldT, oldT); err != nil {
		t.Fatal(err)
	}
	plan.Delete = append(plan.Delete, PruneDecision{
		Node:   BlobNode{Path: "../outside.txt", Kind: BlobKindLayer, ModTime: oldT},
		Reason: ReasonDeleteUnreferenced,
	})

	rep, err := cache.ExecutePrune(plan, pruneGrace, pruneNow)
	if err != nil {
		t.Fatalf("ExecutePrune: %v", err)
	}
	if rep.Deleted != 2 { // 4 planned - swapped - refreshed; hostile skipped
		t.Errorf("deleted %d, want 2 (skipped: %+v)", rep.Deleted, rep.Skipped)
	}
	skippedWhy := make(map[string]string, len(rep.Skipped))
	for _, s := range rep.Skipped {
		skippedWhy[s.Path] = s.Reason
	}
	if why, ok := skippedWhy[swapped]; !ok || why == "" {
		t.Errorf("symlink-swapped %q not skipped: %+v", swapped, rep.Skipped)
	}
	if why := skippedWhy[refreshed]; why != "younger than grace" {
		t.Errorf("refreshed %q skip reason = %q, want younger than grace", refreshed, why)
	}
	if why := skippedWhy["../outside.txt"]; why != "path fails blob grammar" {
		t.Errorf("hostile entry skip reason = %q, want path fails blob grammar", why)
	}
	// Neither the symlink victim nor the outside file was touched, and the
	// symlink itself is still in place (skipped, not followed, not unlinked).
	if got, err := os.ReadFile(victim); err != nil || string(got) != "must survive" {
		t.Errorf("victim damaged: %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(blobs, swapped)); err != nil {
		t.Errorf("swapped symlink removed: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("outside file removed: %v", err)
	}
	_ = digest
}

// testPruneHostilePlan is the containment tripwire: feed ExecutePrune a plan
// that is ENTIRELY hostile — no entry came from PlanPrune — and assert the
// executor is structurally incapable of reaching outside blobs/. Every sibling
// tree the daemon owns (server/ datastore, run/ keys, storage/ PV data,
// pods/ rootfs) is planted with a crown-jewel file first, so an escape is a
// destroyed file, not a subtle reason mismatch.
//
// The last entry is a SYMLINK inside blobs/ whose path is valid blob grammar
// and whose target is the datastore: it must be refused as non-regular, never
// followed, and never itself unlinked.
func testPruneHostilePlan(t *testing.T) {
	root := t.TempDir()
	c, err := NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	jewels := []string{"server/db/state.db", "run/keys/token", "storage/pvc/data", "pods/p1/rootfs/bin/sh"}
	for _, p := range jewels {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linkRel := "sha256/aa" + strings.Repeat("b", 62)
	link := filepath.Join(root, "blobs", linkRel)
	if err := os.Symlink(filepath.Join(root, "server", "db", "state.db"), link); err != nil {
		t.Fatal(err)
	}

	hostile := []string{
		"../server/db/state.db",
		"../../etc/passwd",
		"/etc/passwd",
		".",
		"/",
		"..",
		"sha256/../../server/db/state.db",
		"sha256/./" + strings.Repeat("c", 64),
		"pods/p1/rootfs/bin/sh",
		"../run/keys/token",
		"../storage/pvc/data",
		linkRel, // valid grammar, must be refused as non-regular
	}
	plan := &PrunePlan{}
	for _, h := range hostile {
		plan.Delete = append(plan.Delete, PruneDecision{
			Node:   BlobNode{Path: h, Kind: BlobKindLayer, ModTime: oldT, Size: 1},
			Reason: ReasonDeleteUnreferenced,
		})
	}

	rep, err := c.ExecutePrune(plan, pruneGrace, pruneNow)
	if err != nil {
		t.Fatalf("ExecutePrune errored on a hostile plan; it must skip-and-report, never error: %v", err)
	}
	if rep.Deleted != 0 {
		t.Errorf("containment breach: executor deleted %d entries from a wholly hostile plan (want 0)", rep.Deleted)
	}
	if len(rep.Skipped) != len(hostile) {
		t.Errorf("executor recorded %d skips for %d hostile entries; every refusal must be reported", len(rep.Skipped), len(hostile))
	}
	skippedWhy := make(map[string]string, len(rep.Skipped))
	for _, s := range rep.Skipped {
		skippedWhy[s.Path] = s.Reason
	}
	if why := skippedWhy[linkRel]; !strings.Contains(why, "not a regular file") {
		t.Errorf("in-blobs symlink %q skip reason = %q, want a non-regular-file refusal (it must not be followed)", linkRel, why)
	}
	for _, p := range jewels {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("containment breach: %s was destroyed by a blobs-only executor: %v", p, err)
		}
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the refused symlink was itself unlinked; a skipped entry must be left in place: %v", err)
	}
}
