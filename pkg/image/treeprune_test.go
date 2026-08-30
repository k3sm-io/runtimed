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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// treeDigest builds a well-formed sha256 digest from a one-character seed, the
// same fixture shape prune_test.go's node uses.
func treeDigest(seed string) string { return "sha256:" + strings.Repeat(seed, 64) }

// treeFixture is one committed tree written by hand exactly as Unpacker.commit
// lands it: <store>/<algo>/<hex>/{rootfs/, <record>}, back-dated so the grace
// window is not what a case is testing.
type treeFixture struct {
	store TreeStore
	key   string
	dir   string
	bytes int64
}

// writeTree commits a tree fixture into store. rec is written verbatim, so a
// case can hand it a record that disagrees with the path it lands at.
func (f *gcFixture) writeTree(store TreeStore, key string, rec treeRecord, age time.Duration) treeFixture {
	f.t.Helper()
	h, err := parseBlobDigest(key)
	if err != nil {
		f.t.Fatalf("parse tree key %s: %v", key, err)
	}
	root, recordName, err := f.cache.treeStoreLayout(store)
	if err != nil {
		f.t.Fatalf("treeStoreLayout(%s): %v", store, err)
	}
	dir := filepath.Join(root, h.Algorithm, h.Hex)
	if err := os.MkdirAll(filepath.Join(dir, TreeRootfsName), 0o755); err != nil {
		f.t.Fatalf("mkdir tree %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, TreeRootfsName, "payload"), []byte("unpacked bytes"), 0o644); err != nil {
		f.t.Fatalf("write tree payload: %v", err)
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		f.t.Fatalf("encode tree record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, recordName), buf, 0o644); err != nil {
		f.t.Fatalf("write tree record: %v", err)
	}
	if rec.Ownership != "" {
		if err := os.WriteFile(filepath.Join(dir, rec.Ownership), []byte("{}\n"), 0o644); err != nil {
			f.t.Fatalf("write ownership sidecar: %v", err)
		}
	}
	old := f.clock.Add(-age)
	if err := os.Chtimes(dir, old, old); err != nil {
		f.t.Fatalf("Chtimes tree: %v", err)
	}
	return treeFixture{store: store, key: key, dir: dir, bytes: rec.Stats.Bytes}
}

// nativeTree writes a native (unpacked/) tree built from cfg + layers, keyed
// exactly as TreeKey would key it.
func (f *gcFixture) nativeTree(cfg string, layers []string, size int64, age time.Duration) treeFixture {
	f.t.Helper()
	policy := NativeUnpackPolicy()
	mfst := &runtimev1.ImageManifest{Config: &runtimev1.Descriptor{Digest: cfg}}
	for _, l := range layers {
		mfst.Layers = append(mfst.Layers, &runtimev1.Descriptor{Digest: l})
	}
	key, err := TreeKey(mfst, policy)
	if err != nil {
		f.t.Fatalf("TreeKey: %v", err)
	}
	return f.writeTree(TreeStoreUnpacked, key, treeRecord{
		Version: treeRecordVersion,
		Key:     key,
		Policy:  policy,
		Config:  cfg,
		Layers:  layers,
		Stats:   ApplyStats{Files: 1, Bytes: size},
	}, age)
}

// snapshotTree writes a Linux-dialect (snapshots/) tree keyed by the OCI chain
// id over diffIDs, with the ownership sidecar a real snapshot carries.
func (f *gcFixture) snapshotTree(cfg string, layers, diffIDs []string, size int64, age time.Duration) treeFixture {
	f.t.Helper()
	key, err := ChainID(diffIDs)
	if err != nil {
		f.t.Fatalf("ChainID: %v", err)
	}
	return f.writeTree(TreeStoreSnapshots, key, treeRecord{
		Version:   treeRecordVersion,
		Key:       key,
		Policy:    LinuxUnpackPolicy(),
		Config:    cfg,
		Layers:    layers,
		Stats:     ApplyStats{Files: 1, Bytes: size},
		DiffIDs:   diffIDs,
		Ownership: SnapshotOwnershipName,
	}, age)
}

// planFor runs the whole GC pipeline against the fixture's store — both
// inventories, the fail-closed root read, the planner — the way
// ReclaimUnderPressure does.
func (f *gcFixture) planFor(grace time.Duration) *PrunePlan {
	f.t.Helper()
	nodes, err := f.cache.EnumerateBlobs()
	if err != nil {
		f.t.Fatalf("EnumerateBlobs: %v", err)
	}
	trees, err := f.cache.EnumerateTrees()
	if err != nil {
		f.t.Fatalf("EnumerateTrees: %v", err)
	}
	roots, err := f.cache.Roots()
	if err != nil {
		f.t.Fatalf("Roots: %v", err)
	}
	plan, err := PlanPrune(nodes, trees, roots, nil, grace, f.clock)
	if err != nil {
		f.t.Fatalf("PlanPrune: %v", err)
	}
	return plan
}

// treeVerdict returns the plan's verdict for one tree fixture.
func treeVerdict(t *testing.T, plan *PrunePlan, tf treeFixture) PruneReason {
	t.Helper()
	for _, d := range append(append([]TreeDecision{}, plan.DeleteTrees...), plan.KeepTrees...) {
		if d.Node.Store == tf.store && d.Node.Key == tf.key {
			return d.Reason
		}
	}
	t.Fatalf("tree %s/%s is absent from the plan — the GC cannot see it at all", tf.store, tf.key)
	return ""
}

// TestPruneSeesUnpackedTrees is B191's gate: the unpacked/ and snapshots/ tree
// stores are visible to the disk-pressure accounting and to the prune planner,
// under a root-set rule that protects a tree whose backing image a live pod
// still names.
//
// Before this, both stores were invisible to every enumerator: StoreBytes
// reported zero for a store holding nothing but trees, and PlanPrune had no tree
// to offer, so derived content grew without bound and without accounting.
func TestPruneSeesUnpackedTrees(t *testing.T) {
	t.Parallel()

	cfg, layer := treeDigest("a"), treeDigest("b")

	t.Run("a store holding only a tree accounts for it and offers it", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Hour)

		got, err := f.cache.StoreBytes()
		if err != nil {
			t.Fatalf("StoreBytes: %v", err)
		}
		if got != tf.bytes {
			t.Errorf("StoreBytes = %d; want %d — the tree store is unaccounted", got, tf.bytes)
		}

		plan := f.planFor(time.Minute)
		if r := treeVerdict(t, plan, tf); r != ReasonDeleteUnreferenced {
			t.Errorf("verdict %q; want %q — no pod roots this tree's image", r, ReasonDeleteUnreferenced)
		}
		if n := plan.DeletedBytes(); n != tf.bytes {
			t.Errorf("DeletedBytes = %d; want the tree's %d", n, tf.bytes)
		}
	})

	t.Run("a tree whose image a live pod roots is protected", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Hour)
		f.pod("pod-a", ImageRoot{Reference: "app:v1", Config: cfg, Layers: []string{layer}})

		plan := f.planFor(time.Minute)
		if r := treeVerdict(t, plan, tf); r != ReasonKeptInUse {
			t.Fatalf("verdict %q; want %q — a live pod's image must protect its tree", r, ReasonKeptInUse)
		}
		if len(plan.DeleteTrees) != 0 {
			t.Errorf("DeleteTrees = %v; want none", plan.DeleteTrees)
		}
	})

	t.Run("a layer root protects the tree as surely as the config", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Hour)
		f.pod("pod-a", ImageRoot{Reference: "app:v1", Layers: []string{layer}})

		if r := treeVerdict(t, f.planFor(time.Minute), tf); r != ReasonKeptInUse {
			t.Errorf("verdict %q; want %q", r, ReasonKeptInUse)
		}
	})

	t.Run("a tree younger than grace is kept", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Second)

		if r := treeVerdict(t, f.planFor(time.Minute), tf); r != ReasonKeptYoung {
			t.Errorf("verdict %q; want %q", r, ReasonKeptYoung)
		}
	})

	t.Run("a corrupt tree record is reclaimable", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Hour)
		// No pod roots this image, so the tree would be reclaimable anyway — what
		// this case pins is the VERDICT: an unreadable record is named as such,
		// because a tree no unpack can serve is condemned on its own unusability
		// rather than being quietly lumped in with unreferenced content.
		if err := os.WriteFile(filepath.Join(tf.dir, TreeRecordName), []byte("{not json"), 0o644); err != nil {
			t.Fatalf("corrupt record: %v", err)
		}
		old := f.clock.Add(-time.Hour)
		if err := os.Chtimes(tf.dir, old, old); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}

		trees, err := f.cache.EnumerateTrees()
		if err != nil {
			t.Fatalf("EnumerateTrees: %v", err)
		}
		if len(trees) != 1 || !trees[0].RecordUnusable {
			t.Fatalf("inventory = %+v; want one tree flagged RecordUnusable", trees)
		}
		if r := treeVerdict(t, f.planFor(time.Minute), tf); r != ReasonDeleteUnusableTree {
			t.Errorf("verdict %q; want %q — a tree no unpack can serve holds space for nothing", r, ReasonDeleteUnusableTree)
		}
	})

	t.Run("a record disagreeing with its path is unusable, and protects nothing", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Hour)
		// Rewrite the record to claim another key AND to name a rooted digest: a
		// record that could rename or re-root the node it describes would be a
		// registry-reachable way to make a tree immortal.
		rec := treeRecord{
			Version: treeRecordVersion,
			Key:     treeDigest("c"),
			Policy:  NativeUnpackPolicy(),
			Config:  treeDigest("d"),
			Stats:   ApplyStats{Bytes: 1 << 20},
		}
		buf, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tf.dir, TreeRecordName), buf, 0o644); err != nil {
			t.Fatalf("write record: %v", err)
		}
		old := f.clock.Add(-time.Hour)
		if err := os.Chtimes(tf.dir, old, old); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
		f.pod("pod-a", ImageRoot{Reference: "other:v1", Config: treeDigest("d")})

		if r := treeVerdict(t, f.planFor(time.Minute), tf); r != ReasonDeleteUnusableTree {
			t.Errorf("verdict %q; want %q — a record that disagrees with its path is not believed", r, ReasonDeleteUnusableTree)
		}
	})

	t.Run("a snapshot chain tree is decided on the same terms", func(t *testing.T) {
		t.Parallel()
		diffIDs := []string{treeDigest("e"), treeDigest("f")}

		orphan := newGCFixture(t)
		otf := orphan.snapshotTree(cfg, []string{layer}, diffIDs, 8192, time.Hour)
		if got, err := orphan.cache.StoreBytes(); err != nil || got != otf.bytes {
			t.Errorf("StoreBytes = %d, %v; want %d — snapshots/ is unaccounted", got, err, otf.bytes)
		}
		if r := treeVerdict(t, orphan.planFor(time.Minute), otf); r != ReasonDeleteUnreferenced {
			t.Errorf("orphan snapshot verdict %q; want %q", r, ReasonDeleteUnreferenced)
		}

		rooted := newGCFixture(t)
		rtf := rooted.snapshotTree(cfg, []string{layer}, diffIDs, 8192, time.Hour)
		rooted.pod("pod-a", ImageRoot{Reference: "app:v1", Config: cfg, Layers: []string{layer}})
		if r := treeVerdict(t, rooted.planFor(time.Minute), rtf); r != ReasonKeptInUse {
			t.Errorf("rooted snapshot verdict %q; want %q", r, ReasonKeptInUse)
		}
	})

	t.Run("a leftover staging directory is kept, never removed", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		staging := filepath.Join(f.cache.UnpackedRoot(), ".tree-123456")
		if err := os.MkdirAll(staging, 0o755); err != nil {
			t.Fatalf("mkdir staging: %v", err)
		}
		old := f.clock.Add(-time.Hour)
		if err := os.Chtimes(staging, old, old); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
		plan := f.planFor(time.Minute)
		if len(plan.DeleteTrees) != 0 {
			t.Fatalf("DeleteTrees = %v; an out-of-grammar node must never be condemned", plan.DeleteTrees)
		}
		if len(plan.KeepTrees) != 1 || plan.KeepTrees[0].Reason != ReasonKeptUnknownProvenance {
			t.Errorf("KeepTrees = %+v; want one kept-unknown-provenance node", plan.KeepTrees)
		}
	})

	t.Run("reclaiming a tree leaves the blobs to their own rules", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		// Blobs YOUNGER than grace, tree older: the tree goes, the blobs stay by
		// the blob rule alone. That is the ordering B191 asks for — a tree is
		// rebuildable from its blobs, so it is given up first.
		cfgDigest := f.blob("config bytes", time.Second)
		layerDigest := f.blob("layer bytes", time.Second)
		tf := f.nativeTree(cfgDigest, []string{layerDigest}, 4096, time.Hour)
		f.pod("pod-a")

		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			Force:     true,
			Grace:     time.Minute,
			Now:       func() time.Time { return f.clock },
			FreeBytes: (&fakeFree{free: []uint64{10}}).sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if len(rep.RemovedTrees) != 1 || rep.RemovedTrees[0] != tf.key {
			t.Errorf("RemovedTrees = %v; want the one condemned tree %s", rep.RemovedTrees, tf.key)
		}
		if _, err := os.Lstat(tf.dir); !os.IsNotExist(err) {
			t.Errorf("the condemned tree survived the reclaim: %v", err)
		}
		if len(rep.Removed) != 0 {
			t.Errorf("Removed = %v; the blobs are inside the grace window", rep.Removed)
		}
		if !f.exists(cfgDigest) || !f.exists(layerDigest) {
			t.Errorf("a tree prune removed blobs — the two executors are not disjoint")
		}
		if rep.ReclaimedBytes != tf.bytes {
			t.Errorf("ReclaimedBytes = %d; want the tree's accounted %d", rep.ReclaimedBytes, tf.bytes)
		}
	})

	t.Run("a tree never keeps its own blobs alive", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		cfgDigest := f.blob("config bytes", time.Hour)
		layerDigest := f.blob("layer bytes", time.Hour)
		f.nativeTree(cfgDigest, []string{layerDigest}, 4096, time.Hour)
		f.pod("pod-a")

		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			Force:     true,
			Grace:     time.Minute,
			Now:       func() time.Time { return f.clock },
			FreeBytes: (&fakeFree{free: []uint64{10}}).sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if len(rep.Removed) != 2 {
			t.Errorf("Removed = %v; want both blobs — a tree record is an edge, never a root", rep.Removed)
		}
		if f.exists(cfgDigest) || f.exists(layerDigest) {
			t.Errorf("blobs survived because a derived tree named them")
		}
	})

	t.Run("a tree swapped for a symlink after planning is skipped", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		tf := f.nativeTree(cfg, []string{layer}, 4096, time.Hour)
		plan := f.planFor(time.Minute)
		if len(plan.DeleteTrees) != 1 {
			t.Fatalf("DeleteTrees = %v; want the one tree", plan.DeleteTrees)
		}
		precious := filepath.Join(t.TempDir(), "precious")
		if err := os.MkdirAll(precious, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.RemoveAll(tf.dir); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if err := os.Symlink(precious, tf.dir); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		rep, err := f.cache.ExecuteTreePrune(plan, time.Minute, f.clock, nil)
		if err != nil {
			t.Fatalf("ExecuteTreePrune: %v", err)
		}
		if rep.Deleted != 0 || len(rep.Skipped) != 1 {
			t.Errorf("Deleted = %d, Skipped = %v; the swapped node must be skipped", rep.Deleted, rep.Skipped)
		}
		if _, err := os.Stat(precious); err != nil {
			t.Errorf("the symlink target was removed — the executor followed the link: %v", err)
		}
	})
}

// TestPlanPruneTreeInputsAreValidated pins that a structurally invalid tree
// inventory is an ERROR, on the same terms as an invalid blob inventory: a
// planner that guessed would be deciding removals from data it does not
// understand.
func TestPlanPruneTreeInputsAreValidated(t *testing.T) {
	t.Parallel()
	good := TreeNode{Store: TreeStoreUnpacked, Path: "sha256/" + strings.Repeat("a", 64), Key: treeDigest("a"), Kind: TreeKindTree, ModTime: planNow}

	tests := []struct {
		name  string
		trees []TreeNode
	}{
		{"an empty path", []TreeNode{{Store: TreeStoreUnpacked, Kind: TreeKindTree, ModTime: planNow}}},
		{"a duplicate path", []TreeNode{good, good}},
		{"an unknown store", []TreeNode{{Store: TreeStore("elsewhere"), Path: good.Path, Kind: TreeKindTree, ModTime: planNow}}},
		{"an undeclared kind", []TreeNode{{Store: TreeStoreUnpacked, Path: good.Path, Kind: TreeKind("made-up"), ModTime: planNow}}},
		{"a negative size", []TreeNode{{Store: TreeStoreUnpacked, Path: good.Path, Kind: TreeKindTree, Size: -1, ModTime: planNow}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := PlanPrune(nil, tc.trees, nil, nil, time.Minute, planNow)
			if err == nil {
				t.Fatalf("PlanPrune succeeded; want an error")
			}
			if plan != nil {
				t.Errorf("PlanPrune returned a plan alongside an error")
			}
		})
	}

	t.Run("a well-formed inventory is an exact partition", func(t *testing.T) {
		t.Parallel()
		same := good
		same.Store = TreeStoreSnapshots // same path in the OTHER store is a distinct node
		plan, err := PlanPrune(nil, []TreeNode{good, same}, nil, nil, time.Minute, planNow)
		if err != nil {
			t.Fatalf("PlanPrune: %v", err)
		}
		if got := len(plan.DeleteTrees) + len(plan.KeepTrees); got != 2 {
			t.Errorf("decided %d tree nodes; want 2", got)
		}
	})
}
