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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// BlobKind classifies one filesystem node under the blobs root for planning.
//
// The kinds are derived from the node's PATH and its Lstat mode only. Nothing in
// this package opens a blob to decide what it is: an earlier design sniffed
// every small blob for manifest-shaped JSON and accepted whatever it found as an
// authority on reachability, which handed a registry the ability to author the
// GC's root set. Classification by content is not a bug that was fixed here; it
// is a capability that does not exist here.
type BlobKind string

const (
	// BlobKindContent is a well-formed content blob at "<algo>/<hex>".
	BlobKindContent BlobKind = "content"
	// BlobKindTemp is an in-flight CommitBlob temp file (".blob-*").
	BlobKindTemp BlobKind = "temp"
	// BlobKindUnknown is anything else under the blobs tree: a directory, a
	// symlink, a device node, a name outside the blob grammar. The planner never
	// deletes an unknown node.
	BlobKindUnknown BlobKind = "unknown"
)

// BlobNode is one entry of the store inventory, as caller-supplied data — the
// planner itself never touches the filesystem.
type BlobNode struct {
	// Path is the node's path relative to the blobs root ("<algo>/<hex>" or
	// "<algo>/.blob-<n>"). A path outside that grammar is unknown-provenance to
	// the planner and is refused again by the executor.
	Path string
	// Digest is "<algo>:<hex>" for content nodes, empty otherwise.
	Digest string
	// Kind classifies the node (see BlobKind).
	Kind BlobKind
	// Size is the node's logical size in bytes.
	Size int64
	// ModTime is the node's modification time, compared against the grace window.
	ModTime time.Time
}

// PruneReason is the planner's verdict for one node. Every inventory node gets
// exactly one, and delete reasons and keep reasons are disjoint.
type PruneReason string

const (
	// ReasonKeptInUse marks a blob a recorded pod root reaches.
	ReasonKeptInUse PruneReason = "kept-in-use"
	// ReasonKeptLeased marks a blob an in-flight ingest holds a lease over.
	ReasonKeptLeased PruneReason = "kept-leased"
	// ReasonKeptUnknownProvenance marks a node the planner cannot account for —
	// an out-of-grammar path, a non-regular node, an unknown kind. Fail-closed.
	ReasonKeptUnknownProvenance PruneReason = "kept-unknown-provenance"
	// ReasonKeptYoung marks a delete-eligible node younger than the grace window.
	ReasonKeptYoung PruneReason = "kept-young"
	// ReasonDeleteUnreferenced marks a content blob no root reaches and no lease
	// pins, older than grace.
	ReasonDeleteUnreferenced PruneReason = "delete-unreferenced"
	// ReasonDeleteStaleTemp marks an abandoned CommitBlob temp file older than
	// grace.
	ReasonDeleteStaleTemp PruneReason = "delete-stale-temp"
	// ReasonDeleteUnusableTree marks an unpacked tree whose daemon-authored
	// record is missing, unreadable or self-contradictory. Such a tree can no
	// longer be served (Unpacker.openCommitted refuses it), so it holds space
	// while satisfying nothing; rebuilding it is the only way back. It is a
	// TREE-only verdict: no blob is ever deleted for being unreadable.
	ReasonDeleteUnusableTree PruneReason = "delete-unusable-tree"
)

// PruneDecision pairs an inventory node with the reason it was decided.
type PruneDecision struct {
	Node   BlobNode
	Reason PruneReason
}

// PrunePlan is an exact PARTITION of the inventory: every input node appears in
// exactly one of Delete or Keep, with a reason, in deterministic path order.
//
// The partition is asserted, not assumed. A node that fell out of both sets
// would be a node the plan says nothing about, and the executor's contract
// ("delete exactly what the plan condemns") would then be silently narrower than
// the planner's contract ("account for everything").
//
// The same partition is asserted over the TREE inventory: DeleteTrees and
// KeepTrees are the same exact partition of the caller-supplied TreeNodes, kept
// in their own fields because the two halves are executed by different, mutually
// unreachable executors (ExecutePrune touches only blobs/, ExecuteTreePrune only
// the tree stores) and a single mixed list would have to be re-split by kind at
// every use.
type PrunePlan struct {
	Delete []PruneDecision
	Keep   []PruneDecision
	// DeleteTrees and KeepTrees are the tree-store half of the plan (treeprune.go).
	DeleteTrees []TreeDecision
	KeepTrees   []TreeDecision
}

// DeletedBytes is the summed logical size of everything the plan condemns —
// blobs and trees.
//
// It is what a DRY RUN reports as reclaimable, and it is deliberately an
// over-estimate rather than a prediction: under APFS clonefile a blob or a tree
// whose extents are still shared with a materialized pod rootfs frees nothing
// when it is removed. Real reclaim is therefore measured with statfs after the
// fact (see ReclaimUnderPressure), never computed from this number.
func (p *PrunePlan) DeletedBytes() int64 {
	var n int64
	for _, d := range p.Delete {
		n += d.Node.Size
	}
	for _, d := range p.DeleteTrees {
		n += d.Node.Size
	}
	return n
}

// Blob-path grammar — the exact shape CommitBlob produces on disk. The executor
// re-validates against it before every unlink; the planner routes anything
// outside it to kept-unknown-provenance.
var (
	blobAlgoRe = regexp.MustCompile(`^[a-z0-9]+$`)
	blobHexRe  = regexp.MustCompile(`^[a-f0-9]{8,}$`)
	blobTempRe = regexp.MustCompile(`^\.blob-[0-9]+$`)
)

// relClass is the grammar verdict for a blobs-root-relative path.
type relClass int

const (
	relInvalid relClass = iota
	relContent
	relTemp
)

// classifyBlobRel validates rel against the blob-path grammar: exactly two clean
// components, "<algo>/<hex>" (relContent, digest returned) or "<algo>/.blob-<n>"
// (relTemp). Anything else — absolute paths, dotdot, extra components,
// undecodable names — is relInvalid.
func classifyBlobRel(rel string) (relClass, string) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel {
		return relInvalid, ""
	}
	algo, name, ok := strings.Cut(rel, "/")
	if !ok || strings.Contains(name, "/") || !blobAlgoRe.MatchString(algo) {
		return relInvalid, ""
	}
	switch {
	case blobTempRe.MatchString(name):
		return relTemp, ""
	case blobHexRe.MatchString(name):
		return relContent, algo + ":" + name
	default:
		return relInvalid, ""
	}
}

// validKind reports whether k is one of the declared BlobKind constants.
func validKind(k BlobKind) bool {
	switch k {
	case BlobKindContent, BlobKindTemp, BlobKindUnknown:
		return true
	}
	return false
}

// PlanPrune computes a prune plan over caller-supplied data. It performs NO
// filesystem access and reads no clock: now is injected.
//
// nodes is the blob inventory (Cache.EnumerateBlobs, or a fixture); trees is the
// tree-store inventory (Cache.EnumerateTrees, or a fixture, or nil to plan blobs
// alone); roots is the COMPLETE daemon-authored root set (Cache.Roots — an
// incomplete one must never reach here); leased is the digest set in-flight
// ingests hold; grace is the minimum age a node must have before it is
// delete-eligible.
//
// Reachability is the whole rule and it is one line: a content blob is kept iff
// some root names it or some lease pins it. There is no promotion rule, no
// transitive walk through fetched content, and no way for a blob to make another
// blob reachable — the only thing that can make a blob survive is a record the
// DAEMON wrote. Everything else is fail-closed:
//
//   - a node outside the blob grammar, or of an unknown kind, is kept;
//   - a node younger than grace is kept;
//   - a structurally invalid input (empty/duplicate path, unknown kind, negative
//     size, zero now, negative grace) is an ERROR and nothing is planned.
//
// Trees are decided from the same root and lease sets by planTrees (treeprune.go),
// which states their own — deliberately different — root-set rule. The one rule
// that spans both halves is the one this function enforces by construction: a
// tree's record contributes nothing to blob reachability, so derived content can
// never keep a blob alive.
func PlanPrune(nodes []BlobNode, trees []TreeNode, roots []ImageRoot, leased []string, grace time.Duration, now time.Time) (*PrunePlan, error) {
	if now.IsZero() {
		return nil, errors.New("plan prune: zero reference time")
	}
	if grace < 0 {
		return nil, fmt.Errorf("plan prune: negative grace %v", grace)
	}
	seen := make(map[string]bool, len(nodes))
	for i, n := range nodes {
		if n.Path == "" {
			return nil, fmt.Errorf("plan prune: node %d has an empty path", i)
		}
		if seen[n.Path] {
			return nil, fmt.Errorf("plan prune: duplicate inventory path %q", n.Path)
		}
		seen[n.Path] = true
		if !validKind(n.Kind) {
			return nil, fmt.Errorf("plan prune: node %q has unknown kind %q", n.Path, n.Kind)
		}
		if n.Size < 0 {
			return nil, fmt.Errorf("plan prune: node %q has negative size %d", n.Path, n.Size)
		}
	}
	seenTrees := make(map[string]bool, len(trees))
	for i, n := range trees {
		if n.Path == "" {
			return nil, fmt.Errorf("plan prune: tree %d has an empty path", i)
		}
		id := string(n.Store) + "/" + n.Path
		if seenTrees[id] {
			return nil, fmt.Errorf("plan prune: duplicate tree inventory path %q", id)
		}
		seenTrees[id] = true
		if n.Store != TreeStoreUnpacked && n.Store != TreeStoreSnapshots {
			return nil, fmt.Errorf("plan prune: tree %q has unknown store %q", n.Path, n.Store)
		}
		if !validTreeKind(n.Kind) {
			return nil, fmt.Errorf("plan prune: tree %q has unknown kind %q", n.Path, n.Kind)
		}
		if n.Size < 0 {
			return nil, fmt.Errorf("plan prune: tree %q has negative size %d", n.Path, n.Size)
		}
	}

	reachable := make(map[string]bool)
	for _, r := range roots {
		for _, d := range r.Digests() {
			reachable[d] = true
		}
	}
	leasedSet := make(map[string]bool, len(leased))
	for _, d := range leased {
		leasedSet[d] = true
	}

	young := func(n BlobNode) bool { return now.Sub(n.ModTime) < grace }
	// accountable is the only shape the planner will reason about: a content node
	// whose declared digest agrees with its own path. A node whose two halves
	// disagree is not a blob whose provenance is merely unclear — it is an
	// inventory the planner did not produce, so it is kept.
	accountable := func(n BlobNode) bool {
		cls, dig := classifyBlobRel(n.Path)
		return cls == relContent && n.Kind == BlobKindContent && n.Digest == dig && n.Digest != ""
	}

	plan := &PrunePlan{}
	keep := func(n BlobNode, r PruneReason) { plan.Keep = append(plan.Keep, PruneDecision{Node: n, Reason: r}) }
	del := func(n BlobNode, r PruneReason) { plan.Delete = append(plan.Delete, PruneDecision{Node: n, Reason: r}) }

	for _, n := range nodes {
		cls, _ := classifyBlobRel(n.Path)
		switch {
		case n.Kind == BlobKindTemp && cls == relTemp:
			if young(n) {
				keep(n, ReasonKeptYoung)
			} else {
				del(n, ReasonDeleteStaleTemp)
			}
		case !accountable(n):
			keep(n, ReasonKeptUnknownProvenance)
		case reachable[n.Digest]:
			keep(n, ReasonKeptInUse)
		case leasedSet[n.Digest]:
			keep(n, ReasonKeptLeased)
		case young(n):
			keep(n, ReasonKeptYoung)
		default:
			del(n, ReasonDeleteUnreferenced)
		}
	}

	planTrees(plan, trees, reachable, leasedSet, grace, now)

	sort.Slice(plan.Delete, func(i, j int) bool { return plan.Delete[i].Node.Path < plan.Delete[j].Node.Path })
	sort.Slice(plan.Keep, func(i, j int) bool { return plan.Keep[i].Node.Path < plan.Keep[j].Node.Path })

	// Exact-partition invariant. The loop above makes a violation structurally
	// impossible; assert anyway so a future edit cannot silently break it.
	if got := len(plan.Delete) + len(plan.Keep); got != len(nodes) {
		return nil, fmt.Errorf("plan prune: internal partition violation: %d decisions for %d nodes", got, len(nodes))
	}
	part := make(map[string]bool, len(nodes))
	for _, d := range plan.Delete {
		part[d.Node.Path] = true
	}
	for _, d := range plan.Keep {
		if part[d.Node.Path] {
			return nil, fmt.Errorf("plan prune: internal partition violation: %q in both sets", d.Node.Path)
		}
		part[d.Node.Path] = true
	}
	for p := range seen {
		if !part[p] {
			return nil, fmt.Errorf("plan prune: internal partition violation: %q undecided", p)
		}
	}
	if got := len(plan.DeleteTrees) + len(plan.KeepTrees); got != len(trees) {
		return nil, fmt.Errorf("plan prune: internal partition violation: %d tree decisions for %d trees", got, len(trees))
	}
	treePart := make(map[string]bool, len(trees))
	for _, d := range plan.DeleteTrees {
		treePart[string(d.Node.Store)+"/"+d.Node.Path] = true
	}
	for _, d := range plan.KeepTrees {
		id := string(d.Node.Store) + "/" + d.Node.Path
		if treePart[id] {
			return nil, fmt.Errorf("plan prune: internal partition violation: %q in both tree sets", id)
		}
		treePart[id] = true
	}
	for id := range seenTrees {
		if !treePart[id] {
			return nil, fmt.Errorf("plan prune: internal partition violation: %q undecided", id)
		}
	}
	return plan, nil
}

// EnumerateBlobs inventories the blobs tree: one BlobNode per filesystem node,
// classified by PATH GRAMMAR and Lstat mode alone.
//
// It never opens a blob. The inventory is a list of names and modes; what a blob
// contains is not evidence about whether it may be deleted, because its content
// is supplied by a registry and reachability roots may only be daemon-authored
// (see ImageRoot). An absent blobs dir inventories as empty.
func (c *Cache) EnumerateBlobs() ([]BlobNode, error) {
	blobs := c.blobsDir()
	algoDirs, err := os.ReadDir(blobs)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enumerate blobs %s: %w", blobs, err)
	}
	var out []BlobNode
	for _, algo := range algoDirs {
		if !algo.IsDir() {
			out = append(out, BlobNode{Path: algo.Name(), Kind: BlobKindUnknown})
			continue
		}
		entries, err := os.ReadDir(filepath.Join(blobs, algo.Name()))
		if err != nil {
			return nil, fmt.Errorf("enumerate blobs %s/%s: %w", blobs, algo.Name(), err)
		}
		for _, e := range entries {
			rel := filepath.Join(algo.Name(), e.Name())
			fi, err := os.Lstat(filepath.Join(blobs, rel))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue // raced with a concurrent unlink; nothing to decide
				}
				return nil, fmt.Errorf("stat blob %s: %w", rel, err)
			}
			node := BlobNode{Path: rel, Size: fi.Size(), ModTime: fi.ModTime()}
			cls, dig := classifyBlobRel(rel)
			switch {
			case !fi.Mode().IsRegular():
				// A directory, a SYMLINK, a device node. Judged on itself (Lstat),
				// never followed, and never deletable.
				node.Kind = BlobKindUnknown
			case cls == relContent:
				node.Kind, node.Digest = BlobKindContent, dig
			case cls == relTemp:
				node.Kind = BlobKindTemp
			default:
				node.Kind = BlobKindUnknown
			}
			out = append(out, node)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// SkippedBlob records one plan entry the executor refused to unlink, and why.
type SkippedBlob struct {
	// Path is the entry's blobs-root-relative path.
	Path string
	// Digest is the entry's content digest, empty for a temp file.
	Digest string
	// Reason is a short human-readable refusal reason.
	Reason string
}

// ExecuteReport summarizes one ExecutePrune run.
type ExecuteReport struct {
	// Removed are the digests actually unlinked (temp files contribute none).
	Removed []string
	// Deleted is the number of nodes unlinked, temp files included.
	Deleted int
	// DeletedBytes is the summed logical size of the unlinked nodes. It is what
	// was unlinked, not what the volume got back — see PrunePlan.DeletedBytes.
	DeletedBytes int64
	// Skipped lists plan entries that failed re-verification or whose unlink
	// failed. A skip is never an error: it leaves the node in place for the next
	// planning round.
	Skipped []SkippedBlob
	// StoppedEarly reports that stop() ended the run before the plan was
	// exhausted — the disk-pressure target was met.
	StoppedEarly bool
}

// ExecutePrune executes plan's Delete set against this cache.
//
// It is BLOBS-only BY construction: every operation goes through an os.Root
// opened at the blobs dir (fd-anchored, symlinks not followed), and only
// relative paths matching the validated blob grammar are ever removed. It is
// therefore structurally incapable of reaching server/, run/, storage/ or pods/,
// and it never recurses or RemoveAlls — an emptied algo dir is left behind,
// which is harmless.
//
// Before each unlink the entry is RE-verified against the same facts that made
// it deletable: the path still matches the grammar, Lstat still reports a
// regular file (a node swapped for a symlink after planning is skipped, not
// followed), and the mtime is still older than grace. A verification miss skips
// that node rather than failing the run into a partial, ambiguous state.
//
// stop, when non-nil, is consulted before each unlink and ends the run when it
// returns true. That is how disk-pressure reclaim stops on a measured target
// rather than on a precomputed byte budget: under APFS clonefile an unlink whose
// extents are still shared frees nothing, so the only honest stopping rule is to
// re-measure.
func (c *Cache) ExecutePrune(plan *PrunePlan, grace time.Duration, now time.Time, stop func() bool) (*ExecuteReport, error) {
	if plan == nil {
		return nil, errors.New("execute prune: nil plan")
	}
	if now.IsZero() {
		return nil, errors.New("execute prune: zero reference time")
	}
	if grace < 0 {
		return nil, fmt.Errorf("execute prune: negative grace %v", grace)
	}
	c.pruneMu.Lock()
	defer c.pruneMu.Unlock()

	root, err := os.OpenRoot(c.blobsDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &ExecuteReport{}, nil
		}
		return nil, fmt.Errorf("execute prune: open blobs root: %w", err)
	}
	defer root.Close()

	rep := &ExecuteReport{}
	skip := func(d PruneDecision, reason string) {
		rep.Skipped = append(rep.Skipped, SkippedBlob{Path: d.Node.Path, Digest: d.Node.Digest, Reason: reason})
	}
	for _, d := range plan.Delete {
		if stop != nil && stop() {
			rep.StoppedEarly = true
			break
		}
		rel := d.Node.Path
		if cls, _ := classifyBlobRel(rel); cls == relInvalid {
			skip(d, "path fails blob grammar")
			continue
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
		if !fi.Mode().IsRegular() {
			skip(d, fmt.Sprintf("not a regular file (mode %v)", fi.Mode().Type()))
			continue
		}
		if now.Sub(fi.ModTime()) < grace {
			skip(d, "younger than grace")
			continue
		}
		if err := root.Remove(rel); err != nil {
			skip(d, fmt.Sprintf("remove: %v", err))
			continue
		}
		rep.Deleted++
		rep.DeletedBytes += fi.Size()
		if d.Node.Digest != "" {
			rep.Removed = append(rep.Removed, d.Node.Digest)
		}
	}
	return rep, nil
}
