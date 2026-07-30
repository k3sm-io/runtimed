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

// BlobKind classifies a cache node for prune planning.
type BlobKind string

// The blob kinds the enumerator produces and the planner understands. Anything
// the enumerator cannot positively classify is BlobKindUnknown, which the
// planner keeps unconditionally (fail-closed).
const (
	// BlobKindConfig is an image config blob (named as config by a persisted manifest).
	BlobKindConfig BlobKind = "config"
	// BlobKindLayer is a layer blob (named as a layer by a persisted manifest).
	BlobKindLayer BlobKind = "layer"
	// BlobKindManifest is a persisted image manifest (the prune edge record).
	BlobKindManifest BlobKind = "manifest"
	// BlobKindTemp is an in-flight writeBlob temp file (".blob-*").
	BlobKindTemp BlobKind = "temp"
	// BlobKindUnknown is anything else: a symlink or directory planted in the
	// blobs tree, an undecodable name, a blob no persisted manifest names. The
	// planner NEVER deletes an unknown node.
	BlobKindUnknown BlobKind = "unknown"
)

// BlobNode is one entry of the cache inventory: a single filesystem node under
// the blobs root, as caller-supplied data (the planner never touches disk).
type BlobNode struct {
	// Path is the node's path RELATIVE to the blobs root ("<algo>/<hex>" or
	// "<algo>/.blob-<n>"). A path outside that grammar marks the node
	// unknown-provenance for the planner and is skipped by the executor.
	Path string
	// Digest is "<algo>:<hex>" for content nodes; empty for temp/unknown nodes.
	Digest string
	// Kind classifies the node (see BlobKind).
	Kind BlobKind
	// Size is the node's logical size in bytes.
	Size int64
	// ModTime is the node's modification time, compared against the grace window.
	ModTime time.Time
}

// ImageEdge is the reachability record for one image: the persisted manifest's
// digest and the config + layer digests it names. The edges come from persisted
// manifests (Cache.EnumerateBlobs) or are supplied directly by tests.
type ImageEdge struct {
	// Manifest is the image manifest's digest ("<algo>:<hex>").
	Manifest string
	// Platform is informational ("os/arch[/variant]", best-effort, may be empty);
	// it never influences planning.
	Platform string
	// Config is the digest of the config blob the manifest names.
	Config string
	// Layers are the digests of the layer blobs the manifest names.
	Layers []string
}

// PruneReason explains one planner decision. Delete reasons and keep reasons
// are disjoint; every inventory node gets exactly one.
type PruneReason string

// The planner's per-node decision reasons.
const (
	// ReasonKeptInUse marks a node reachable from an in-use image (or an in-use
	// digest itself).
	ReasonKeptInUse PruneReason = "kept-in-use"
	// ReasonKeptReferenced marks a blob named by a kept (but not in-use) image's
	// edges — e.g. a shared base layer, or the chain of a young manifest.
	ReasonKeptReferenced PruneReason = "kept-referenced"
	// ReasonKeptUnknownProvenance marks a node no persisted manifest names, an
	// undecodable path, or anything else the planner cannot account for.
	// Fail-closed: unknown is always kept.
	ReasonKeptUnknownProvenance PruneReason = "kept-unknown-provenance"
	// ReasonKeptYoung marks a delete-eligible node younger than the grace window.
	ReasonKeptYoung PruneReason = "kept-young"
	// ReasonDeleteUnreferenced marks a content blob named by no kept image and
	// older than grace.
	ReasonDeleteUnreferenced PruneReason = "delete-unreferenced"
	// ReasonDeleteStaleTemp marks a writeBlob temp file older than grace.
	ReasonDeleteStaleTemp PruneReason = "delete-stale-temp"
)

// PruneDecision pairs an inventory node with the planner's reason for it.
type PruneDecision struct {
	Node   BlobNode
	Reason PruneReason
}

// PrunePlan is an EXACT PARTITION of the inventory: every input node appears in
// exactly one of Delete or Keep, with a reason. Delete order and Keep order are
// deterministic (sorted by path).
type PrunePlan struct {
	Delete []PruneDecision
	Keep   []PruneDecision
}

// Blob-path grammar, the strict shape writeBlob produces on disk. The executor
// re-validates against this before every unlink; the planner routes anything
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

// classifyBlobRel validates rel against the blob-path grammar: exactly two
// clean components, "<algo>/<hex>" (⇒ relContent, digest returned) or
// "<algo>/.blob-<n>" (⇒ relTemp). Anything else — absolute paths, dotdot,
// separator siblings, extra components, undecodable names — is relInvalid.
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
	case BlobKindConfig, BlobKindLayer, BlobKindManifest, BlobKindTemp, BlobKindUnknown:
		return true
	}
	return false
}

// PlanPrune computes a prune plan over caller-supplied data — it performs NO
// filesystem access. nodes is the cache inventory (Cache.EnumerateBlobs, or a
// test fixture), edges the per-image reachability records, inUse the manifest
// digests of images currently used by live pods (empty is legal). grace is the
// minimum age a node must have to be delete-eligible, judged against now
// (injected — the planner never calls time.Now).
//
// The result is an exact partition of nodes (asserted internally). Semantics
// are FAIL-CLOSED throughout:
//
//   - a node whose provenance is unknown (no persisted manifest names it, or an
//     out-of-grammar path/kind) is KEPT (kept-unknown-provenance), never deleted;
//   - a node younger than grace is KEPT (kept-young);
//   - an edge referencing a digest absent from the inventory is fine (already
//     absent); an edge whose MANIFEST digest has no inventory node keeps its
//     named blobs (the manifest's age cannot be assessed);
//   - a structurally invalid input record (empty path, duplicate path, unknown
//     kind, negative size, empty edge manifest, zero now, negative grace) is an
//     ERROR and nothing is planned for deletion.
//
// A manifest blob is delete-eligible only when the whole image it describes is
// unreferenced (not in use, older than grace); its config and unique layers go
// with it, but any blob named by a kept image's edges survives (shared base
// layers). Temp files (".blob-*") are invisible to reachability by construction
// and are delete-eligible once older than grace.
func PlanPrune(nodes []BlobNode, edges []ImageEdge, inUse []string, grace time.Duration, now time.Time) (*PrunePlan, error) {
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
	for i, e := range edges {
		if e.Manifest == "" {
			return nil, fmt.Errorf("plan prune: edge %d has an empty manifest digest", i)
		}
	}
	inUseSet := make(map[string]bool, len(inUse))
	for i, d := range inUse {
		if d == "" {
			return nil, fmt.Errorf("plan prune: in-use entry %d is empty", i)
		}
		inUseSet[d] = true
	}

	young := func(n BlobNode) bool { return now.Sub(n.ModTime) < grace }

	// accountable reports whether the node is a well-formed content node whose
	// declared digest matches its path — the only shape the planner will ever
	// reason about. Everything else is kept-unknown-provenance.
	accountable := func(n BlobNode) bool {
		cls, dig := classifyBlobRel(n.Path)
		return cls == relContent && n.Digest == dig && n.Digest != ""
	}

	// Index accountable content nodes by digest.
	nodeByDigest := make(map[string]*BlobNode, len(nodes))
	for i := range nodes {
		if accountable(nodes[i]) {
			nodeByDigest[nodes[i].Digest] = &nodes[i]
		}
	}

	// Decide which images (edges) are keep-roots, and collect the digests their
	// edges name. Fail-closed: an image is a keep-root unless its manifest node
	// is a well-formed, on-disk, out-of-use manifest older than grace.
	referencedInUse := make(map[string]bool)
	referencedKept := make(map[string]bool)
	namedByAny := make(map[string]bool)
	for _, e := range edges {
		named := append([]string{e.Config}, e.Layers...)
		for _, d := range named {
			namedByAny[d] = true
		}
		var into map[string]bool
		switch mn := nodeByDigest[e.Manifest]; {
		case inUseSet[e.Manifest]:
			into = referencedInUse
		case mn == nil, mn.Kind != BlobKindManifest, young(*mn):
			// Absent manifest node (age unknowable), mis-kinded node, or a young
			// manifest: the image is kept, so its chain is kept too.
			into = referencedKept
		default:
			// A well-formed manifest node, not in use, older than grace: the
			// whole image is unreferenced; its named blobs get no keep vote from
			// this edge.
			continue
		}
		for _, d := range named {
			into[d] = true
		}
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
		case !accountable(n) || n.Kind == BlobKindUnknown:
			keep(n, ReasonKeptUnknownProvenance)
		case inUseSet[n.Digest], referencedInUse[n.Digest]:
			keep(n, ReasonKeptInUse)
		case referencedKept[n.Digest]:
			keep(n, ReasonKeptReferenced)
		case n.Kind == BlobKindManifest:
			if !manifestHasEdge(edges, n.Digest) {
				// A manifest node with no edge record (an unparseable manifest fed
				// directly): its named blobs are unknowable — keep it.
				keep(n, ReasonKeptUnknownProvenance)
			} else if young(n) {
				keep(n, ReasonKeptYoung)
			} else {
				del(n, ReasonDeleteUnreferenced)
			}
		default: // config / layer
			if !namedByAny[n.Digest] {
				keep(n, ReasonKeptUnknownProvenance)
			} else if young(n) {
				keep(n, ReasonKeptYoung)
			} else {
				del(n, ReasonDeleteUnreferenced)
			}
		}
	}

	sort.Slice(plan.Delete, func(i, j int) bool { return plan.Delete[i].Node.Path < plan.Delete[j].Node.Path })
	sort.Slice(plan.Keep, func(i, j int) bool { return plan.Keep[i].Node.Path < plan.Keep[j].Node.Path })

	// Exact-partition invariant: Delete ∪ Keep = inventory, disjoint. The loop
	// above makes a violation structurally impossible; assert anyway so a future
	// edit cannot silently break the contract.
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
	return plan, nil
}

// manifestHasEdge reports whether any edge record describes manifest digest d.
func manifestHasEdge(edges []ImageEdge, d string) bool {
	for _, e := range edges {
		if e.Manifest == d {
			return true
		}
	}
	return false
}

// SkippedBlob records one plan entry the executor refused to unlink, and why.
type SkippedBlob struct {
	// Path is the entry's blobs-root-relative path.
	Path string
	// Reason is a short human-readable refusal reason.
	Reason string
}

// ExecuteReport summarizes one ExecutePrune run.
type ExecuteReport struct {
	// Deleted is the number of blobs unlinked.
	Deleted int
	// DeletedBytes is the sum of the unlinked blobs' logical sizes.
	DeletedBytes int64
	// Skipped lists plan entries that failed re-verification (never an error:
	// a skip leaves the node in place for the next planning round).
	Skipped []SkippedBlob
}

// ExecutePrune executes a plan's Delete set against this cache. It is
// BLOBS-ONLY by construction: every operation is anchored on an os.Root opened
// at the blobs dir (fd-anchored — no traversal can escape it, symlinks are not
// followed), and only relative paths of the validated blob grammar are ever
// removed. It is therefore structurally incapable of touching server/, run/,
// storage/ or pods/ trees, and it never recurses or RemoveAlls (empty algo dirs
// may be left behind — harmless).
//
// Before each unlink the entry is RE-VERIFIED: the path must still match the
// blob grammar, Lstat must report a regular file (a node swapped for a symlink
// after planning is skipped, not followed), and the mtime must still be older
// than grace against now. Any verification miss SKIPS that node (recorded in
// the report) rather than erroring the run into a partial ambiguous state.
//
// Dry-run is the planner output alone — nothing touches disk until this is
// explicitly called. In-process callers are serialized against Pull via the
// cache's prune lock (writeBlob holds the read side per blob write).
func (c *Cache) ExecutePrune(plan *PrunePlan, grace time.Duration, now time.Time) (*ExecuteReport, error) {
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
		return nil, fmt.Errorf("execute prune: open blobs root: %w", err)
	}
	defer root.Close()

	rep := &ExecuteReport{}
	skip := func(rel, reason string) { rep.Skipped = append(rep.Skipped, SkippedBlob{Path: rel, Reason: reason}) }
	for _, d := range plan.Delete {
		rel := d.Node.Path
		if cls, _ := classifyBlobRel(rel); cls == relInvalid {
			skip(rel, "path fails blob grammar")
			continue
		}
		fi, err := root.Lstat(rel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				skip(rel, "already absent")
			} else {
				skip(rel, fmt.Sprintf("lstat: %v", err))
			}
			continue
		}
		if !fi.Mode().IsRegular() {
			skip(rel, fmt.Sprintf("not a regular file (mode %v)", fi.Mode().Type()))
			continue
		}
		if now.Sub(fi.ModTime()) < grace {
			skip(rel, "younger than grace")
			continue
		}
		if err := root.Remove(rel); err != nil {
			skip(rel, fmt.Sprintf("remove: %v", err))
			continue
		}
		rep.Deleted++
		rep.DeletedBytes += fi.Size()
	}
	return rep, nil
}
