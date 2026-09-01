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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// TreeStore names one of the two derived-content stores the unpacker commits
// into: unpacked/ (native trees, keyed by TreeKey) and snapshots/ (Linux
// dialect trees, keyed by the OCI chain id).
//
// It is carried on every tree node because the two stores are separate
// directories with separate record names and, in production, may sit on
// separate APFS volumes (see SnapshotsSubdir). A node that did not say which
// store it came from could not be turned back into a path without re-deriving
// the dialect discriminator a second time, which is exactly what treeLocation
// exists to prevent on the write path.
type TreeStore string

const (
	// TreeStoreUnpacked is the native dialect's store, <root>/unpacked.
	TreeStoreUnpacked TreeStore = "unpacked"
	// TreeStoreSnapshots is the Linux dialect's store, <root>/snapshots.
	TreeStoreSnapshots TreeStore = "snapshots"
)

// TreeKind classifies one filesystem node under a tree store root, from its
// PATH and its Lstat mode alone.
type TreeKind string

const (
	// TreeKindTree is a committed tree directory at "<algo>/<hex>".
	TreeKindTree TreeKind = "tree"
	// TreeKindUnknown is anything else under a tree store: a regular file, a
	// symlink, a leftover ".tree-*" staging directory, a name outside the key
	// grammar. The planner never deletes an unknown node.
	TreeKindUnknown TreeKind = "unknown"
)

// TreeNode is one entry of the tree-store inventory, as caller-supplied data —
// the planner itself never touches the filesystem.
type TreeNode struct {
	// Store is which tree store this node lives under.
	Store TreeStore
	// Path is the node's path relative to that store's root ("<algo>/<hex>").
	Path string
	// Key is the tree's content-addressed identity ("<algo>:<hex>") for a
	// TreeKindTree node, empty otherwise. It is derived from the PATH, never
	// from the record, so a record that lies about its own key cannot rename
	// the node it describes.
	Key string
	// Kind classifies the node (see TreeKind).
	Kind TreeKind
	// Size is the tree's accounted size in bytes — see EnumerateTrees for what
	// that figure is and, precisely, what it is not.
	Size int64
	// ModTime is the tree directory's modification time, compared against the
	// grace window.
	ModTime time.Time
	// Backing are the blob digests the tree's DAEMON-AUTHORED record says it was
	// built from (config + layers). They are PROTECTION INPUTS only: a digest
	// here that a live pod root also names keeps the tree, and nothing here can
	// ever keep a BLOB alive (see planTrees).
	Backing []string
	// RecordUnusable reports that the tree's record is missing, unreadable,
	// undecodable, of an unknown version, or disagrees with the path it sits at.
	// Such a tree can no longer be served — Unpacker.openCommitted refuses it as
	// ErrTreeInconsistent — so it is reclaimable, and it protects nothing.
	RecordUnusable bool
}

// TreeDecision pairs a tree node with the reason it was decided.
type TreeDecision struct {
	Node   TreeNode
	Reason PruneReason
}

// treeStoreLayout maps a store to its root directory and the filename of the
// daemon-authored record inside each committed tree.
//
// It is the READ-side twin of Unpacker.locate: one switch, evaluated once, so a
// snapshot can never be read looking for an unpacked tree's record name. An
// unrecognised store is an error rather than a default, because defaulting here
// would silently point a delete path at the wrong directory.
func (c *Cache) treeStoreLayout(store TreeStore) (dir, recordName string, err error) {
	switch store {
	case TreeStoreUnpacked:
		return c.UnpackedRoot(), TreeRecordName, nil
	case TreeStoreSnapshots:
		return c.SnapshotsRoot(), SnapshotRecordName, nil
	default:
		return "", "", fmt.Errorf("image: unknown tree store %s", quoteBounded(string(store), maxTokenLen))
	}
}

// treeStores is the closed set of stores the inventory walks, in the order it
// walks them.
var treeStores = []TreeStore{TreeStoreUnpacked, TreeStoreSnapshots}

// classifyTreeKey validates a store-root-relative path against the tree key
// grammar — the same "<algo>/<hex>" shape a blob path has, because a tree
// directory is named by a parsed digest through exactly the same allowlist
// (Cache.treeDir, Cache.snapshotDir, both fed by parseBlobDigest).
//
// Reusing classifyBlobRel is deliberate: two spellings of one grammar drift, and
// the grammar is what the executor re-validates against before it removes a
// directory tree.
func classifyTreeKey(rel string) (key string, ok bool) {
	cls, dig := classifyBlobRel(rel)
	if cls != relContent {
		return "", false
	}
	return dig, true
}

// EnumerateTrees inventories both tree stores: one TreeNode per filesystem node
// directly under "<store>/<algo>/", classified by PATH GRAMMAR and Lstat mode,
// plus the tree's own DAEMON-AUTHORED record.
//
// # What it reads, and why that is not the thing prune.go forbids
//
// EnumerateBlobs never opens a blob, because a blob's bytes are registry-supplied
// and must never be able to author the GC's root set. This walk opens exactly one
// file per tree — the record the UNPACKER wrote (writeTreeRecord), the same class
// of document as a pod's images.json — and it uses it for exactly two things:
// the tree's accounted size, and the backing digests that can PROTECT the tree.
// The monotone edge is preserved end to end: a record can only make a tree more
// protected (a digest that matches a live root keeps it) and never less (a record
// that cannot be read at all leaves the tree reclaimable, which is the floor).
// Nothing read here ever enters the blob reachability set, so a tree still cannot
// keep a blob alive — the invariant UnpackedSubdir is sited on.
//
// # The size figure
//
// Size is the record's ApplyStats.Bytes: the decompressed regular-file content
// the apply wrote. It is an ACCOUNTING FIGURE, not a walk of the tree, and the
// difference is deliberate:
//
//   - a walk is O(files), and an unpacked base image is routinely six figures of
//     them, while StoreBytes is on the ImageFsInfo RPC path the kubelet polls;
//   - a walk would not be truer anyway. The bytes are materialized into pod
//     rootfs dirs with APFS clonefile, so the extents are shared and no
//     per-tree sum describes what the volume would get back — the same reason
//     PrunePlan.DeletedBytes is documented as an over-estimate.
//
// It over-counts a file a later layer replaced (the apply wrote both) and
// under-counts directory and symlink metadata. A tree whose record is unusable
// accounts as zero, and is reclaimable on that same fact.
//
// An absent store directory inventories as empty.
func (c *Cache) EnumerateTrees() ([]TreeNode, error) {
	var out []TreeNode
	for _, store := range treeStores {
		nodes, err := c.enumerateTreeStore(store)
		if err != nil {
			return nil, err
		}
		out = append(out, nodes...)
	}
	return out, nil
}

// enumerateTreeStore inventories one store. Every read goes through an os.Root
// anchored at the store root, so no symlink planted under it can redirect the
// walk out of the store — the same containment Cache.Roots applies to pods/.
func (c *Cache) enumerateTreeStore(store TreeStore) ([]TreeNode, error) {
	dir, recordName, err := c.treeStoreLayout(store)
	if err != nil {
		return nil, err
	}
	algoDirs, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enumerate trees %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate trees: open %s: %w", dir, err)
	}
	defer root.Close()

	var out []TreeNode
	for _, algo := range algoDirs {
		// A top-level entry that is not an algorithm directory is inventoried as
		// one unknown node and is not descended into. That is what makes a
		// ".tree-*" staging directory — the residue of an unpack that died
		// mid-apply — visible to the accounting as a single kept node, instead of
		// vanishing (it holds no "<algo>/<hex>" children) or being flattened into
		// a walk of whatever an interrupted apply happened to have written.
		if !algo.IsDir() || !blobAlgoRe.MatchString(algo.Name()) {
			out = append(out, TreeNode{Store: store, Path: algo.Name(), Kind: TreeKindUnknown, ModTime: modTimeOf(root, algo.Name())})
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dir, algo.Name()))
		if err != nil {
			return nil, fmt.Errorf("enumerate trees %s/%s: %w", dir, algo.Name(), err)
		}
		for _, e := range entries {
			rel := filepath.Join(algo.Name(), e.Name())
			fi, err := root.Lstat(rel)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue // raced with a concurrent removal; nothing to decide
				}
				return nil, fmt.Errorf("stat tree %s/%s: %w", dir, rel, err)
			}
			node := TreeNode{Store: store, Path: rel, ModTime: fi.ModTime()}
			key, ok := classifyTreeKey(rel)
			switch {
			case !fi.IsDir():
				// A regular file, a SYMLINK, a device node. Judged on itself
				// (Lstat), never followed, and never deletable.
				node.Kind = TreeKindUnknown
			case !ok:
				// A ".tree-*" staging directory from an unpack that died, or any
				// other out-of-grammar name. Unknown provenance: kept.
				node.Kind = TreeKindUnknown
			default:
				node.Kind, node.Key = TreeKindTree, key
				rec, rerr := readTreeRecord(root, filepath.Join(rel, recordName), key)
				if rerr != nil {
					node.RecordUnusable = true
				} else {
					node.Backing = rec.backing()
					node.Size = rec.Stats.Bytes
				}
			}
			out = append(out, node)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// modTimeOf reports rel's mtime through root, or the zero time if it cannot be
// stated. The zero time only ever makes a node look OLDER, and an unknown node
// is kept regardless of age, so a miss here cannot condemn anything.
func modTimeOf(root *os.Root, rel string) time.Time {
	fi, err := root.Lstat(rel)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// backing returns the blob digests the record says the tree was built from.
func (r treeRecord) backing() []string {
	out := make([]string, 0, len(r.Layers)+1)
	if r.Config != "" {
		out = append(out, r.Config)
	}
	return append(out, r.Layers...)
}

// readTreeRecord reads and validates one tree's record through root.
//
// It applies the same agreement checks Unpacker.openCommitted does — version,
// and the record's key against the path it sits at — minus the policy, which an
// inventory has nothing to compare against. Every backing digest must parse
// through the store's closed allowlist: a record naming a digest this store
// could never have written is not a record this daemon wrote, so it is treated
// as unusable rather than half-believed.
//
// It deliberately reads one file per tree and stops there: the Linux dialect's
// ownership sidecar is not checked, so a snapshot missing it reads as usable
// here while Unpacker.openCommitted refuses to serve it. The two predicates are
// not meant to be identical — such a tree is still protected by its backing
// image's roots and is reclaimed on the ordinary unreferenced rule once they go,
// and widening the inventory to every openCommitted refusal would put a second
// copy of that check in the GC.
func readTreeRecord(root *os.Root, rel, key string) (treeRecord, error) {
	buf, err := readAnchored(root, rel)
	if err != nil {
		return treeRecord{}, fmt.Errorf("read tree record %s: %v", rel, boundErr(err))
	}
	var rec treeRecord
	if err := json.Unmarshal(buf, &rec); err != nil {
		return treeRecord{}, fmt.Errorf("decode tree record %s: %v", rel, boundErr(err))
	}
	if rec.Version != treeRecordVersion {
		return treeRecord{}, fmt.Errorf("tree record %s has version %d, want %d", rel, rec.Version, treeRecordVersion)
	}
	if rec.Key != key {
		return treeRecord{}, fmt.Errorf("tree record %s claims key %s", rel, quoteBounded(rec.Key, maxDigestLen))
	}
	for _, d := range rec.backing() {
		if _, err := parseBlobDigest(d); err != nil {
			return treeRecord{}, fmt.Errorf("tree record %s names unusable digest: %v", rel, err)
		}
	}
	return rec, nil
}

// validTreeKind reports whether k is one of the declared TreeKind constants.
func validTreeKind(k TreeKind) bool {
	switch k {
	case TreeKindTree, TreeKindUnknown:
		return true
	}
	return false
}

// planTrees decides every tree node, using the same reachable and leased sets
// the blob half of the plan is decided from. It is pure: no filesystem, no clock.
//
// # The root-set rule
//
// A tree is derived content — every byte in it is reconstructible from blobs the
// image's manifest names — and deleting one cannot kill a running pod: the pod's
// rootfs was materialized with APFS clonefile and holds its own references to the
// extents, so what a wrongly-deleted tree breaks is a RESTART or a
// re-materialization, never a running process (DESIGN §5a; the same analysis
// ReclaimUnderPressure states for blobs). That asymmetry is what licenses the
// rule below to be simpler than the blob rule, not laxer:
//
//	a tree is reclaimable iff NO live pod root names any blob it was built
//	from, and no in-flight lease pins one either — i.e. iff its backing image
//	is itself reclaim-eligible.
//
// Both halves of B191's condition collapse into that one test on purpose. The
// root set records an (image) per pod, never an (image x policy) — ImageRoot
// deliberately carries no dialect — so the strongest honest reading is that a
// live pod using an image protects every tree built from that image, in either
// dialect. That is more protection than the (image x policy) rule asks for, and
// more is the safe direction; the alternative would need a policy recorded in a
// root, which would make the root set carry content metadata it is designed not
// to have.
//
// A tree whose record is unusable is reclaimable regardless: openCommitted
// already refuses to serve it, so it is occupying the store while being unable
// to satisfy a single unpack, and rebuilding it is the only way it becomes
// useful again.
//
// Everything else fails closed exactly as the blob planner does: an
// out-of-grammar or non-directory node is kept, and a node younger than grace is
// kept.
func planTrees(plan *PrunePlan, trees []TreeNode, reachable, leased map[string]bool, grace time.Duration, now time.Time) {
	young := func(n TreeNode) bool { return now.Sub(n.ModTime) < grace }
	keep := func(n TreeNode, r PruneReason) {
		plan.KeepTrees = append(plan.KeepTrees, TreeDecision{Node: n, Reason: r})
	}
	del := func(n TreeNode, r PruneReason) {
		plan.DeleteTrees = append(plan.DeleteTrees, TreeDecision{Node: n, Reason: r})
	}

	for _, n := range trees {
		key, ok := classifyTreeKey(n.Path)
		if n.Kind != TreeKindTree || !ok || n.Key != key {
			// Unknown provenance, or a node whose declared key disagrees with its
			// own path: an inventory this planner did not produce. Kept.
			keep(n, ReasonKeptUnknownProvenance)
			continue
		}
		var rooted, pinned bool
		for _, d := range n.Backing {
			if reachable[d] {
				rooted = true
				break
			}
			if leased[d] {
				pinned = true
			}
		}
		switch {
		case rooted:
			keep(n, ReasonKeptInUse)
		case pinned:
			keep(n, ReasonKeptLeased)
		case young(n):
			keep(n, ReasonKeptYoung)
		case n.RecordUnusable:
			del(n, ReasonDeleteUnusableTree)
		default:
			del(n, ReasonDeleteUnreferenced)
		}
	}
	sort.Slice(plan.DeleteTrees, func(i, j int) bool { return treeLess(plan.DeleteTrees[i].Node, plan.DeleteTrees[j].Node) })
	sort.Slice(plan.KeepTrees, func(i, j int) bool { return treeLess(plan.KeepTrees[i].Node, plan.KeepTrees[j].Node) })
}

// treeLess orders tree decisions deterministically by (store, path).
func treeLess(a, b TreeNode) bool {
	if a.Store != b.Store {
		return a.Store < b.Store
	}
	return a.Path < b.Path
}

// SkippedTree records one planned tree the executor refused to remove, and why.
type SkippedTree struct {
	// Store and Path locate the tree (Path is store-root-relative).
	Store TreeStore
	Path  string
	// Key is the tree's content-addressed identity.
	Key string
	// Reason is a short human-readable refusal reason.
	Reason string
}

// TreeExecuteReport summarizes one ExecuteTreePrune run.
type TreeExecuteReport struct {
	// Removed are the keys of the trees actually removed.
	Removed []string
	// Deleted is the number of trees removed.
	Deleted int
	// DeletedBytes is the summed accounted size of the removed trees. Like
	// ExecuteReport.DeletedBytes it is what was REMOVED, not what the volume got
	// back — the payload's extents may still be shared with a live pod rootfs.
	DeletedBytes int64
	// Skipped lists planned trees that failed re-verification or whose removal
	// failed. A skip is never an error: it leaves the tree in place for the next
	// planning round.
	Skipped []SkippedTree
	// StoppedEarly reports that stop() ended the run before the plan was
	// exhausted — the disk-pressure target was met.
	StoppedEarly bool
}

// ExecuteTreePrune executes plan's DeleteTrees set against this cache.
//
// It is TREE-STORES-only BY construction: every operation goes through an
// os.Root opened at the store root the node names (fd-anchored, symlinks not
// followed), and only relative paths matching the validated "<algo>/<hex>" key
// grammar are ever removed. It is therefore structurally incapable of reaching
// blobs/, pods/, server/ or storage/ — a tree prune cannot delete a blob, which
// is the same containment ExecutePrune has in the other direction.
//
// Before each removal the entry is RE-verified against the facts that made it
// deletable: the path still matches the grammar, Lstat still reports a DIRECTORY
// (a tree swapped for a symlink after planning is skipped, not followed), and
// the mtime is still older than grace.
//
// # Why the record is unlinked first
//
// The removal is two steps — unlink the record, then remove the directory — and
// the order is load-bearing rather than tidy. A plain recursive remove deletes
// children in filesystem order, so a concurrent Unpack could read a still-valid
// record and then clone a half-DELETED payload into a pod's rootfs: a silently
// truncated image, which is worse than any failure. Unlinking the record first
// makes the tree read as absent to openCommitted (its ErrNotExist path) for the
// whole of the removal, so a racing unpack rebuilds or fails loudly instead. If
// the recursive remove then fails partway, the residue is a directory with no
// record, which the next inventory classifies as RecordUnusable and re-plans.
//
// stop, when non-nil, is consulted before each removal and ends the run when it
// returns true, on the same measured-target terms as ExecutePrune.
func (c *Cache) ExecuteTreePrune(plan *PrunePlan, grace time.Duration, now time.Time, stop func() bool) (*TreeExecuteReport, error) {
	if plan == nil {
		return nil, errors.New("execute tree prune: nil plan")
	}
	if now.IsZero() {
		return nil, errors.New("execute tree prune: zero reference time")
	}
	if grace < 0 {
		return nil, fmt.Errorf("execute tree prune: negative grace %v", grace)
	}
	c.pruneMu.Lock()
	defer c.pruneMu.Unlock()

	rep := &TreeExecuteReport{}
	skip := func(d TreeDecision, reason string) {
		rep.Skipped = append(rep.Skipped, SkippedTree{Store: d.Node.Store, Path: d.Node.Path, Key: d.Node.Key, Reason: reason})
	}
	// One anchored root per store, opened at most once and only if the plan
	// actually condemns something in it.
	roots := make(map[TreeStore]*os.Root)
	records := make(map[TreeStore]string)
	defer func() {
		for _, r := range roots {
			r.Close()
		}
	}()

	for _, d := range plan.DeleteTrees {
		if stop != nil && stop() {
			rep.StoppedEarly = true
			break
		}
		rel := d.Node.Path
		if _, ok := classifyTreeKey(rel); !ok {
			skip(d, "path fails tree key grammar")
			continue
		}
		root, ok := roots[d.Node.Store]
		if !ok {
			dir, recordName, err := c.treeStoreLayout(d.Node.Store)
			if err != nil {
				skip(d, err.Error())
				continue
			}
			root, err = os.OpenRoot(dir)
			if err != nil {
				skip(d, fmt.Sprintf("open tree store: %v", err))
				continue
			}
			roots[d.Node.Store], records[d.Node.Store] = root, recordName
		}
		fi, err := root.Lstat(rel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				skip(d, "already absent")
			} else {
				skip(d, fmt.Sprintf("lstat: %v", err))
			}
			continue
		}
		if !fi.IsDir() {
			skip(d, fmt.Sprintf("not a directory (mode %v)", fi.Mode().Type()))
			continue
		}
		if now.Sub(fi.ModTime()) < grace {
			skip(d, "younger than grace")
			continue
		}
		// Step 1: the record. An absent one is not a failure — a tree planned as
		// RecordUnusable may never have had one.
		if err := root.Remove(filepath.Join(rel, records[d.Node.Store])); err != nil && !errors.Is(err, fs.ErrNotExist) {
			skip(d, fmt.Sprintf("remove record: %v", err))
			continue
		}
		// Step 2: the payload.
		if err := root.RemoveAll(rel); err != nil {
			skip(d, fmt.Sprintf("remove tree: %v", err))
			continue
		}
		rep.Deleted++
		rep.DeletedBytes += d.Node.Size
		if d.Node.Key != "" {
			rep.Removed = append(rep.Removed, d.Node.Key)
		}
	}
	return rep, nil
}
