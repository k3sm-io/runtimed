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
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// UnpackedSubdir is the cache-root-relative directory the per-image unpacked
// trees live in: <root>/unpacked, a SIBLING of blobs/, pods/, index/ and
// ingest/.
//
// Being a sibling is deliberate, exactly as it is for IndexSubdir and
// IngestSubdir: the image GC's two enumerators read blobs/
// (Cache.EnumerateBlobs) and pods/ (Cache.Roots), so an unpacked tree can
// neither be mistaken for a content blob of unknown provenance nor become a
// reachability root. A tree is DERIVED content — every byte in it is
// reconstructible from blobs the manifest names — so it must never be able to
// keep a blob alive.
//
// The honest consequence, stated where a reader will meet it: those same two
// enumerators are the ONLY things that walk the store, so a tree under here is
// today invisible to both the prune planner and the disk-pressure accounting
// (Cache.StoreBytes). Trees are not reclaimed. The bound on their growth is that
// the key is content-addressed — a re-pull of the same (image x policy) is a hit
// that writes nothing — so the store holds one tree per distinct image ever run
// on the node, not one per pod. Extending the GC to a second sweepable tree is a
// separate deliverable with its own root-set question ("which trees may a live
// pod's clone still depend on?"), and improvising it here would put a delete
// path in the store that no reachability rule covers.
const UnpackedSubdir = "unpacked"

// TreeRootfsName is the subdirectory of a committed tree that holds the applied
// image content, and TreeRecordName is the daemon-authored record beside it.
//
// The payload is one level down rather than being the tree directory itself so
// that the record can never collide with an image path: an image containing a
// file literally called "tree.json" writes it inside rootfs/, where it is just a
// file. It is also the shape M11.2-d1's ChainID-keyed snapshot store uses
// (snapshots/<algo>/<chainid>/rootfs + meta.json), so the two do not have to
// disagree about where a tree's payload lives.
const (
	TreeRootfsName = "rootfs"
	TreeRecordName = "tree.json"
)

// SnapshotsSubdir is the cache-root-relative directory the LINUX dialect's
// ChainID-keyed snapshots live in: <root>/snapshots, a sibling of unpacked/,
// blobs/, pods/, index/ and ingest/ (m11-plan §M11.2-d1).
//
// It is a SEPARATE store from unpacked/, not a second dialect filed in the same
// one, for two reasons that are both about the key rather than about tidiness:
//
//   - the keys are different KINDS. An unpacked tree is keyed by TreeKey, a
//     digest over the manifest's config + layers + policy; a snapshot is keyed
//     by the OCI CHAIN ID, a digest over the layer diffIDs alone. Two keys of
//     different provenance in one namespace can only be told apart by reading a
//     record inside the directory they name, which is exactly the thing a
//     content-addressed layout exists to avoid.
//   - the chain id is the ONLY key that lets two different images sharing a
//     layer prefix share stored bytes, and it is the key the guest's rootfs
//     shares are named by — so the snapshot store is what moves to the
//     dedicated case-sensitive APFS volume (m11-plan Resolution 8), while
//     unpacked/ stays with the rest of the cache.
//
// Snapshots inherit unpacked/'s honest limitation verbatim: neither GC
// enumerator walks this directory, so a snapshot is invisible to the prune
// planner and to Cache.StoreBytes and is never reclaimed. The same bound
// applies — the key is content-addressed, so the store holds one snapshot per
// distinct layer chain ever run on the node, not one per pod.
const SnapshotsSubdir = "snapshots"

// SnapshotRecordName is the daemon-authored record beside a committed snapshot,
// and SnapshotOwnershipName is its ownership sidecar. Both sit BESIDE
// TreeRootfsName rather than inside it, so an image containing a file called
// "meta.json" writes it inside rootfs/ where it is just a file.
const (
	SnapshotRecordName    = "meta.json"
	SnapshotOwnershipName = "ownership.jsonl"
)

// treeRecordVersion is the on-disk schema version of TreeRecordName. It exists
// so a future reader can refuse a record it does not understand instead of
// silently reading absent fields as zero.
const treeRecordVersion = 1

// ErrDiffIDMismatch reports that a layer's DECOMPRESSED bytes contradict the
// diffID the image config claims for them.
//
// It is distinct from ErrDigestMismatch, which is about the COMPRESSED blob
// against its manifest descriptor, and the two are not interchangeable: the
// compressed check proves the store holds the bytes the manifest named, while
// this one proves those bytes decompress to the content the image's own config
// commits to. An image can pass the first and fail the second only if its
// manifest and its config disagree — which is exactly the condition an operator
// must be able to name, because it means the two halves of the image were signed
// over different content.
var ErrDiffIDMismatch = errors.New("image: layer content does not match the config's diffID")

// ErrUnsupportedLayerMediaType reports a layer this unpacker cannot decompress.
//
// The compression is chosen from the DECLARED media type against a closed
// allowlist, never sniffed from the bytes: sniffing lets the content decide how
// it is interpreted, which is the same class of mistake as classifying a blob by
// reading it (see BlobKind). gzip, zstd and uncompressed tar are admitted; xz,
// the nondistributable variants, and anything unrecognised land here.
var ErrUnsupportedLayerMediaType = errors.New("image: unsupported layer media type")

// ErrUnsupportedLayerSemantics reports a layer-application DIALECT this build
// does not implement — an unset or unrecognised LayerSemantics, or a sandbox
// backend with no dialect mapped to it (UnpackPolicyFor).
//
// It is distinct from ErrUnsupportedLayerMediaType, which is about COMPRESSION,
// and the two were briefly conflated. They are not the same verdict about the
// same thing: a media type is a property of a layer BLOB and a dialect is a
// property of the CALLER's request, so an operator seeing one knows to look at
// the image and seeing the other knows to look at the pod.
var ErrUnsupportedLayerSemantics = errors.New("image: unsupported layer semantics")

// ErrTreeInconsistent reports that a COMMITTED tree on disk is not usable: its
// record is absent, undecodable, or claims a key other than the one the tree is
// filed under. It is fail-closed — the tree is refused, never repaired in place,
// because a tree whose record disagrees with its path cannot be reasoned about
// and repairing it would mean writing content under a key it was not derived for.
var ErrTreeInconsistent = errors.New("image: unpacked tree is inconsistent with its record")

// UnpackPolicy is the set of decisions that change the BYTES an unpack produces.
// It is half of an unpacked tree's key, so a change of policy yields a different
// tree rather than silently reusing one built under different rules.
//
// It is a struct rather than a bare LayerSemantics because it is a KEY INPUT:
// every future knob that changes the output (M11.2-d1's xattr allowlist, an
// ownership-sidecar toggle) must join the key, and a struct makes adding one a
// compile-visible change to canonical() rather than an invisible one.
type UnpackPolicy struct {
	// Semantics selects the layer-application dialect. It has no usable zero
	// value on purpose: an unset dialect is refused by Validate rather than
	// defaulted, because defaulting it would make the key say "native" for a
	// caller that never chose native.
	Semantics LayerSemantics `json:"semantics"`
}

// NativeUnpackPolicy is the policy for the darwin-native host-process spine.
func NativeUnpackPolicy() UnpackPolicy { return UnpackPolicy{Semantics: SemanticsNative} }

// UnpackPolicyFor maps a RESOLVED sandbox backend to the layer-application
// dialect its rootfs must be built under. It is the ONE producer of that
// discriminator, mirroring image.Candidates' backend switch so the two cannot
// disagree about which spine a backend belongs to.
//
// It FAILS CLOSED on the zero value and on any unknown backend, for the reason
// PlatformPolicy gives for the same shape: sandbox.SelectBackend never returns
// UNSPECIFIED on its success path, so a caller holding one never chose a
// backend — and defaulting an unchosen backend to the native dialect would
// apply Mach-O rules to a Linux image and commit the result under a key that
// claims otherwise.
func UnpackPolicyFor(backend runtimev1.SandboxBackend) (UnpackPolicy, error) {
	switch backend {
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL:
		return NativeUnpackPolicy(), nil
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_VM:
		return LinuxUnpackPolicy(), nil
	default:
		return UnpackPolicy{}, fmt.Errorf("sandbox backend %v has no layer dialect: %w",
			backend, ErrUnsupportedLayerSemantics)
	}
}

// Validate reports whether the policy names a dialect this build implements.
// It fails closed: an empty or unrecognised LayerSemantics is an error, never a
// fall-through to the native dialect.
func (p UnpackPolicy) Validate() error {
	switch p.Semantics {
	case SemanticsNative, SemanticsLinux:
		return nil
	case "":
		return errors.New("unpack policy: layer semantics is required")
	default:
		return fmt.Errorf("unpack policy: %w: layer semantics %s",
			ErrUnsupportedLayerSemantics, quoteBounded(string(p.Semantics), maxTokenLen))
	}
}

// canonical renders the policy for the tree key. It is a fixed, ordered,
// self-describing rendering — "semantics=<dialect>" — so a policy gaining a
// field changes the key of every tree built after it, which is the correct
// behavior: the old trees were built under different rules.
func (p UnpackPolicy) canonical() string {
	return "semantics=" + string(p.Semantics)
}

// Tree is one committed unpacked image tree.
type Tree struct {
	// Key is the tree's content-addressed identity, "<algo>:<hex>" — see TreeKey.
	Key string
	// Rootfs is the absolute path to the tree's applied payload. It is the
	// SOURCE of a pod-rootfs materialization and is never handed to a pod.
	Rootfs string
	// Policy is the dialect this tree was built under.
	Policy UnpackPolicy
	// Stats is what the apply produced (see ApplyStats). For a cache hit it is
	// read back from the tree's record, so it describes the build that actually
	// happened rather than the one this call would have done.
	Stats ApplyStats
	// CacheHit reports that the tree was already committed and no layer was
	// applied by this call.
	CacheHit bool
	// Ownership is the absolute path to the tree's ownership sidecar, or EMPTY
	// for a dialect that records none (see OwnershipEntry). It is the file the
	// guest reads to restore the uid/gid/mode the unprivileged host could not
	// write; nothing on the native spine consumes it, and nothing on either
	// spine hands it to a pod.
	Ownership string
}

// MaterializeResult is the outcome of cloning a Tree into a pod rootfs.
type MaterializeResult struct {
	// Tree is the source tree (already committed).
	Tree *Tree
	// Cloned is how many files were materialized as real APFS clones rather than
	// byte copies — the same figure MaterializeTree returns. A zero here on
	// darwin means the tree and the pod rootfs are NOT on one APFS volume, which
	// is a performance fact worth logging, not an error.
	Cloned int
}

// treeRecord is the daemon-authored record written beside a committed tree.
//
// It records what the tree WAS BUILT FROM, never what it is for: no pod id, no
// reference, no timestamp. A reference would be a lie the moment a second
// reference resolved to the same content (the key is content-addressed, so the
// second unpack is a hit that rewrites nothing), and a pod id would make a
// derived, shared artifact look owned.
type treeRecord struct {
	Version int          `json:"version"`
	Key     string       `json:"key"`
	Policy  UnpackPolicy `json:"policy"`
	Config  string       `json:"config"`
	Layers  []string     `json:"layers"`
	Stats   ApplyStats   `json:"stats"`
	// DiffIDs and Ownership are the LINUX dialect's additions: the decompressed
	// layer digests the Key (a chain id) is derived from, and the filename of
	// the ownership sidecar committed beside the payload.
	//
	// Both are omitempty, which is not a formatting preference: a native tree's
	// record must stay BYTE-IDENTICAL to the one it carried before this dialect
	// existed, so that every tree already on disk keeps decoding under an
	// unchanged treeRecordVersion. Adding a field that a native unpack writes
	// as a zero value would have forced a version bump and orphaned every
	// committed tree on the node.
	DiffIDs   []string `json:"diff_ids,omitempty"`
	Ownership string   `json:"ownership,omitempty"`
}

// Unpacker builds and serves per-image unpacked trees out of a Cache.
//
// It is safe for concurrent use: two unpacks of one key race only on the final
// directory rename, and the loser adopts the winner's tree (see commit).
type Unpacker struct {
	cache  *Cache
	cloner Cloner
	limits ApplyLimits
}

// UnpackerOption adjusts an Unpacker at construction.
type UnpackerOption func(*Unpacker)

// WithCloner sets the Cloner used to materialize a tree into a pod rootfs. The
// default is APFSCloner (a real copy-on-write clone on darwin, a byte copy
// elsewhere); tests inject ByteCopier.
func WithCloner(c Cloner) UnpackerOption {
	return func(u *Unpacker) { u.cloner = c }
}

// WithApplyLimits sets the unpack resource guards (see ApplyLimits). The zero
// value of any field keeps that field's default.
func WithApplyLimits(l ApplyLimits) UnpackerOption {
	return func(u *Unpacker) { u.limits = l }
}

// NewUnpacker returns an Unpacker over cache.
//
// The cache is REQUIRED and is the same store the pull path committed the blobs
// to: an unpacker reading a different store could not verify a single byte it
// applies, because the digests it checks against come from the manifest that
// store's pull resolved.
func NewUnpacker(cache *Cache, opts ...UnpackerOption) (*Unpacker, error) {
	if cache == nil {
		return nil, errors.New("image unpacker: cache is required")
	}
	u := &Unpacker{cache: cache, cloner: APFSCloner{}}
	for _, o := range opts {
		o(u)
	}
	lim, err := u.limits.withDefaults()
	if err != nil {
		return nil, fmt.Errorf("image unpacker: %w", err)
	}
	u.limits = lim
	return u, nil
}

// UnpackedRoot returns the directory every unpacked tree lives under
// (<root>/unpacked). Like Cache.PodsRoot it exists so a caller that must BOUND
// an operation to the tree store asks for the root instead of re-spelling the
// component.
func (c *Cache) UnpackedRoot() string { return filepath.Join(c.root, UnpackedSubdir) }

// SnapshotsRoot returns the directory every LINUX-dialect snapshot lives under
// (<root>/snapshots). Like UnpackedRoot it exists so a caller that must BOUND an
// operation to the snapshot store asks for the root instead of re-spelling the
// component — and, in production, so the caller that must place that store on
// the dedicated case-sensitive volume has one path to place.
func (c *Cache) SnapshotsRoot() string { return filepath.Join(c.root, SnapshotsSubdir) }

// snapshotDir maps a PARSED chain id to its directory, on the same terms as
// treeDir: the layout is unreachable without the digest allowlist having run.
func (c *Cache) snapshotDir(algo, hexBody string) string {
	return filepath.Join(c.SnapshotsRoot(), algo, hexBody)
}

// treeDir maps a PARSED tree key to its directory. It takes a parsed hash for
// the same reason Cache.pathFor does: the layout is unreachable without the
// digest allowlist having run.
func (c *Cache) treeDir(algo, hexBody string) string {
	return filepath.Join(c.UnpackedRoot(), algo, hexBody)
}

// TreeKey is the content-addressed identity of the tree mfst unpacks to under
// policy: sha256 over a canonical key document naming the image's CONFIG digest,
// its layer digests in apply order, and the policy.
//
// # Why not "the manifest digest"
//
// Because a manifest digest alone is the wrong key twice over. It does not cover
// the POLICY, so two dialects of one image would collide on a single tree; and
// runtimev1.ImageManifest deliberately carries no field for the manifest's own
// digest (it carries the config and layer descriptors, which is what the store
// actually holds — see ImageRoot for the same reasoning about roots). The
// document below is strictly stronger than a manifest digest for this purpose:
// it is derived from exactly the inputs the unpack reads, so two manifests that
// produce byte-identical trees key to the same tree, and any change to a layer,
// to the layer ORDER, or to the dialect changes the key.
//
// Every digest is validated through parseBlobDigest before it enters the
// document, so no registry-supplied string can inject a line separator into it —
// the algorithm halves come from a closed allowlist and the bodies are
// fixed-length lowercase hex.
func TreeKey(mfst *runtimev1.ImageManifest, policy UnpackPolicy) (string, error) {
	if mfst == nil {
		return "", errors.New("tree key: manifest is required")
	}
	if err := policy.Validate(); err != nil {
		return "", err
	}
	cfg := mfst.GetConfig().GetDigest()
	if _, err := parseBlobDigest(cfg); err != nil {
		return "", fmt.Errorf("tree key: config digest: %w", err)
	}
	var doc strings.Builder
	doc.WriteString("k3sm.image.tree/v1\n")
	doc.WriteString("policy " + policy.canonical() + "\n")
	doc.WriteString("config " + cfg + "\n")
	for i, l := range mfst.GetLayers() {
		d := l.GetDigest()
		if _, err := parseBlobDigest(d); err != nil {
			return "", fmt.Errorf("tree key: layer %d digest: %w", i, err)
		}
		doc.WriteString("layer " + d + "\n")
	}
	sum := sha256.Sum256([]byte(doc.String()))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Unpack returns the committed unpacked tree for mfst under policy, building it
// from the cached layer blobs if it is not already present.
//
// # The verification it performs
//
// Unpack is where the CAS's write-time-only verification ceiling
// (Cache.CommitBlob) is finally closed for the bytes a pod actually runs,
// because this is the one path that reads every blob of an image end to end
// anyway. Per layer, and for free on the same single read:
//
//   - the COMPRESSED bytes are re-hashed against the manifest descriptor's
//     digest (ErrDigestMismatch) — so a blob that was corrupted, truncated, or
//     substituted on disk AFTER it was committed is caught here rather than
//     executed;
//   - the DECOMPRESSED bytes are re-hashed against the image config's diffID for
//     that layer (ErrDiffIDMismatch) — so the manifest and the config are proven
//     to describe the same content.
//
// The config blob itself is re-hashed against its own descriptor before it is
// parsed. None of this authenticates the IMAGE — a hostile source supplies the
// manifest and the config together and can make them agree; that is a signature
// problem (SignaturePolicy), not a CAS problem, and it is stated the same way on
// Cache.CommitBlob.
//
// # Two stores, one mechanism
//
// The DIALECT decides which store the tree is filed in and under what key (see
// treeLocation): the native dialect goes to unpacked/ keyed by TreeKey, the
// Linux dialect to snapshots/ keyed by the OCI chain id, with an ownership
// sidecar committed beside it. Everything else — the staging directory, the
// per-layer verification, the single-rename commit, the losing-race adoption —
// is one implementation shared by both, because a second extractor is how two
// dialects come to disagree about what "committed" means.
//
// # Atomicity
//
// The tree is applied into a staging directory and committed by a single
// os.Rename, so a crash, a cancellation, or any layer failure leaves NO
// partially-applied tree at the key. The staging directory is created inside the
// destination store, so the rename never crosses a filesystem — which matters
// because the snapshot store is on its own APFS volume. A concurrent unpack of
// the same key is resolved by that rename: whoever loses adopts the winner's
// tree.
func (u *Unpacker) Unpack(ctx context.Context, mfst *runtimev1.ImageManifest, policy UnpackPolicy) (*Tree, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	loc, err := u.locate(mfst, policy)
	if err != nil {
		return nil, err
	}
	if t, ok, err := u.openCommitted(loc, policy); err != nil {
		return nil, err
	} else if ok {
		return t, nil
	}

	if !loc.configRead {
		if loc.diffIDs, err = u.configDiffIDs(mfst); err != nil {
			return nil, err
		}
		loc.configRead = true
	}
	layers := mfst.GetLayers()
	if len(loc.diffIDs) != len(layers) {
		return nil, fmt.Errorf("image config lists %d diffIDs but the manifest lists %d layers: %w",
			len(loc.diffIDs), len(layers), ErrManifestInconsistent)
	}

	stats, ownership, staging, err := u.applyStaged(ctx, layers, loc.diffIDs, policy)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging) // no-op after a successful rename

	rec := treeRecord{
		Version: treeRecordVersion,
		Key:     loc.key,
		Policy:  policy,
		Config:  mfst.GetConfig().GetDigest(),
		Stats:   stats,
	}
	for _, l := range layers {
		rec.Layers = append(rec.Layers, l.GetDigest())
	}
	if loc.ownershipName != "" {
		rec.DiffIDs = loc.diffIDs
		rec.Ownership = loc.ownershipName
		if err := writeOwnershipSidecar(filepath.Join(staging, loc.ownershipName), ownership); err != nil {
			return nil, err
		}
	}
	if err := writeTreeRecord(filepath.Join(staging, loc.recordName), rec); err != nil {
		return nil, err
	}
	return u.commit(staging, loc, policy, stats)
}

// treeLocation is where ONE dialect files ONE image: the store directory, the
// key that directory is named by, and the names of the two documents committed
// beside the payload.
//
// It exists so the dialect discriminator is evaluated EXACTLY ONCE per unpack,
// in locate, rather than at each of the five places that need to know which
// store it is talking to. Every field is derived together from one switch, so a
// snapshot can never be written with an unpacked tree's record name, or filed
// under a key the other store's reader would try to parse.
type treeLocation struct {
	// dir is the absolute directory the committed tree lives at.
	dir string
	// key is the content-addressed identity dir is named by: TreeKey under the
	// native dialect, the OCI chain id under Linux.
	key string
	// recordName is the daemon-authored record's filename inside dir.
	recordName string
	// ownershipName is the ownership sidecar's filename inside dir, EMPTY for a
	// dialect that records no ownership. Emptiness is the discriminator the
	// commit path reads — there is deliberately no second boolean that could
	// disagree with it.
	ownershipName string
	// diffIDs are the image config's layer diffIDs, and configRead reports
	// whether they were read at all.
	//
	// They are carried here ONLY for the Linux dialect, which cannot compute its
	// key without them, so a second read would be pure waste. The native
	// dialect deliberately leaves them unread: its key comes from the manifest
	// alone, and reading the config here would cost a native CACHE HIT a blob
	// read it has never needed — a hit currently succeeds with the whole blob
	// store deleted, which is the strongest available proof that it re-applies
	// nothing, and that property is worth keeping.
	diffIDs    []string
	configRead bool
}

// locate resolves where mfst unpacks to under policy, reading and verifying the
// image config on the way (it holds the diffIDs both dialects need).
//
// The Linux dialect pays for the config blob's read and re-hash even on a cache
// HIT, and that is inherent rather than sloppy: a chain id is a function of the
// diffIDs, so there is no cheaper way to learn which snapshot a manifest maps to.
// The blob is a few KiB and is bounded by maxArchiveMetadataBytes.
func (u *Unpacker) locate(mfst *runtimev1.ImageManifest, policy UnpackPolicy) (treeLocation, error) {
	if err := policy.Validate(); err != nil {
		return treeLocation{}, err
	}
	var loc treeLocation
	var err error
	switch policy.Semantics {
	case SemanticsNative:
		loc.key, err = TreeKey(mfst, policy)
		loc.recordName = TreeRecordName
	case SemanticsLinux:
		loc.diffIDs, err = u.configDiffIDs(mfst)
		if err != nil {
			return treeLocation{}, err
		}
		loc.configRead = true
		loc.key, err = ChainID(loc.diffIDs)
		loc.recordName = SnapshotRecordName
		loc.ownershipName = SnapshotOwnershipName
	default:
		// Unreachable — Validate ran above. Kept because the store selection
		// must be unreachable without a dialect having been recognised.
		return treeLocation{}, fmt.Errorf("unpack policy: %w: layer semantics %s",
			ErrUnsupportedLayerSemantics, quoteBounded(string(policy.Semantics), maxTokenLen))
	}
	if err != nil {
		return treeLocation{}, err
	}
	h, err := parseBlobDigest(loc.key)
	if err != nil {
		// Reachable for the Linux dialect only, and only via a SINGLE-layer
		// image, whose chain id IS its diffID — a config claiming an
		// unsupported digest algorithm for that one layer lands here rather
		// than becoming a directory name. TreeKey and the multi-layer chain
		// both render a sha256 hex sum this package computed.
		return treeLocation{}, fmt.Errorf("tree key %s: %w", quoteBounded(loc.key, maxDigestLen), err)
	}
	if policy.Semantics == SemanticsLinux {
		loc.dir = u.cache.snapshotDir(h.Algorithm, h.Hex)
	} else {
		loc.dir = u.cache.treeDir(h.Algorithm, h.Hex)
	}
	return loc, nil
}

// MaterializeTree unpacks mfst under policy (or serves the committed tree) and
// clones it into dstRootfs, which is created if absent.
//
// This is the seam pkg/runtime.createPod consumes: it is the ONE call that turns
// "the blobs are in the store" into "the pod's rootfs holds runnable files", so
// the two halves cannot be wired up out of order or one of them forgotten. The
// copy goes through the package's MaterializeTree walk, so it is idempotent, it
// preserves symlinks as symlinks, and it re-asserts the com.apple.quarantine
// invariant on every file it lands.
func (u *Unpacker) MaterializeTree(ctx context.Context, mfst *runtimev1.ImageManifest, policy UnpackPolicy, dstRootfs string) (*MaterializeResult, error) {
	if dstRootfs == "" {
		return nil, errors.New("materialize tree: destination rootfs is required")
	}
	t, err := u.Unpack(ctx, mfst, policy)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dstRootfs, 0o755); err != nil {
		return nil, fmt.Errorf("create rootfs %s: %w", dstRootfs, err)
	}
	cloned, err := MaterializeTree(u.cloner, t.Rootfs, dstRootfs)
	if err != nil {
		return nil, fmt.Errorf("materialize tree %s into %s: %w", quoteBounded(t.Key, maxDigestLen), dstRootfs, err)
	}
	return &MaterializeResult{Tree: t, Cloned: cloned}, nil
}

// openCommitted returns the tree already committed at dir, if there is a
// consistent one.
//
// A directory with no record, an undecodable record, a record of an unknown
// version, or a record whose key or policy disagrees with the path is
// ErrTreeInconsistent — refused, not rebuilt over. Rebuilding over it would mean
// writing into a directory whose provenance is unknown while another process may
// still be cloning out of it.
func (u *Unpacker) openCommitted(loc treeLocation, policy UnpackPolicy) (*Tree, bool, error) {
	dir, key := loc.dir, loc.key
	buf, err := os.ReadFile(filepath.Join(dir, loc.recordName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: read record for %s: %v", ErrTreeInconsistent, quoteBounded(key, maxDigestLen), boundErr(err))
	}
	var rec treeRecord
	if err := json.Unmarshal(buf, &rec); err != nil {
		return nil, false, fmt.Errorf("%w: decode record for %s: %v", ErrTreeInconsistent, quoteBounded(key, maxDigestLen), boundErr(err))
	}
	switch {
	case rec.Version != treeRecordVersion:
		return nil, false, fmt.Errorf("%w: record for %s has version %d, want %d",
			ErrTreeInconsistent, quoteBounded(key, maxDigestLen), rec.Version, treeRecordVersion)
	case rec.Key != key:
		return nil, false, fmt.Errorf("%w: tree at %s records key %s",
			ErrTreeInconsistent, quoteBounded(key, maxDigestLen), quoteBounded(rec.Key, maxDigestLen))
	case rec.Policy != policy:
		return nil, false, fmt.Errorf("%w: tree %s records policy %q, want %q",
			ErrTreeInconsistent, quoteBounded(key, maxDigestLen), rec.Policy.canonical(), policy.canonical())
	}
	rootfs := filepath.Join(dir, TreeRootfsName)
	fi, err := os.Lstat(rootfs)
	if err != nil || !fi.IsDir() {
		return nil, false, fmt.Errorf("%w: tree %s has no %s directory",
			ErrTreeInconsistent, quoteBounded(key, maxDigestLen), TreeRootfsName)
	}
	t := &Tree{Key: key, Rootfs: rootfs, Policy: policy, Stats: rec.Stats, CacheHit: true}
	if loc.ownershipName != "" {
		// The sidecar is committed inside the same rename as the payload, so a
		// dialect that records one and a committed tree that lacks one is a
		// tree from a DIFFERENT build of this daemon — refused, not
		// regenerated, on the same terms as every other record disagreement:
		// the ownership the guest would apply is not derivable from the tree,
		// only from the layers it came from.
		own := filepath.Join(dir, loc.ownershipName)
		if fi, serr := os.Lstat(own); serr != nil || !fi.Mode().IsRegular() {
			return nil, false, fmt.Errorf("%w: tree %s has no %s sidecar",
				ErrTreeInconsistent, quoteBounded(key, maxDigestLen), loc.ownershipName)
		}
		t.Ownership = own
	}
	return t, true, nil
}

// applyStaged builds the tree in a disposable staging directory and returns it
// UNCOMMITTED. The caller renames it into place (commit) or removes it.
func (u *Unpacker) applyStaged(ctx context.Context, layers []*runtimev1.Descriptor, diffIDs []string, policy UnpackPolicy) (_ ApplyStats, _ []OwnershipEntry, _ string, retErr error) {
	// The staging directory is created under the SAME store the tree commits
	// into, because the commit is an os.Rename and rename(2) cannot cross a
	// filesystem — and the Linux dialect's store is, by design, a different
	// APFS volume from the rest of the cache (m11-plan Resolution 8). Staging
	// under a fixed root would make every snapshot commit fail with EXDEV on a
	// correctly provisioned node.
	parent := u.cache.UnpackedRoot()
	if policy.Semantics == SemanticsLinux {
		parent = u.cache.SnapshotsRoot()
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return ApplyStats{}, nil, "", fmt.Errorf("create tree root %s: %w", parent, err)
	}
	staging, err := os.MkdirTemp(parent, ".tree-")
	if err != nil {
		return ApplyStats{}, nil, "", fmt.Errorf("stage unpacked tree: %w", err)
	}
	defer func() {
		if retErr != nil {
			os.RemoveAll(staging)
		}
	}()
	rootfs := filepath.Join(staging, TreeRootfsName)
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		return ApplyStats{}, nil, "", fmt.Errorf("stage tree rootfs: %w", err)
	}
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return ApplyStats{}, nil, "", fmt.Errorf("anchor tree rootfs %s: %w", rootfs, err)
	}
	defer root.Close()

	applier, err := NewLayerApplier(root, policy, u.limits)
	if err != nil {
		return ApplyStats{}, nil, "", err
	}
	for i, desc := range layers {
		if err := u.applyLayer(ctx, applier, desc, diffIDs[i]); err != nil {
			return ApplyStats{}, nil, "", fmt.Errorf("apply layer %d of %d (%s): %w",
				i+1, len(layers), quoteBounded(desc.GetDigest(), maxDigestLen), err)
		}
	}
	return applier.Stats(), applier.Ownership(), staging, nil
}

// applyLayer streams one layer blob out of the store, verifying BOTH its
// compressed digest and its decompressed diffID on the single read, and applies
// it through applier.
//
// The two hashers are wired around the decompressor rather than after it so the
// bytes are hashed exactly once each; the verdicts are checked AFTER the apply
// because a hash is only known at EOF. That ordering is safe because the apply
// happens into a disposable staging tree that is discarded on any error — the
// contract applyStaged is built to provide.
func (u *Unpacker) applyLayer(ctx context.Context, applier *LayerApplier, desc *runtimev1.Descriptor, diffID string) error {
	wantBlob, err := parseBlobDigest(desc.GetDigest())
	if err != nil {
		return err
	}
	wantDiff, err := parseBlobDigest(diffID)
	if err != nil {
		return fmt.Errorf("config diffID: %w", err)
	}
	f, err := u.cache.openBlob(desc.GetDigest())
	if err != nil {
		return err
	}
	defer f.Close()

	blobHash := blobHashers[wantBlob.Algorithm]()
	diffHash := blobHashers[wantDiff.Algorithm]()
	compressed := io.TeeReader(f, blobHash)
	plain, err := decompressLayer(desc.GetMediaType(), compressed)
	if err != nil {
		return err
	}
	defer plain.Close()

	if err := applier.Apply(ctx, io.TeeReader(plain, diffHash)); err != nil {
		return err
	}
	// Drain whatever the tar reader left (its trailing padding, and any bytes
	// after the archive's end-of-archive marker) so BOTH hashers see the whole
	// stream. Without this the digests are computed over a PREFIX and the checks
	// below would pass for a blob with arbitrary appended content.
	if _, err := io.Copy(io.Discard, plain); err != nil {
		return fmt.Errorf("%w: drain layer: %v", ErrLayerMalformed, boundErr(err))
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return fmt.Errorf("%w: drain layer blob: %v", ErrLayerMalformed, boundErr(err))
	}
	if got := hex.EncodeToString(blobHash.Sum(nil)); got != wantBlob.Hex {
		return fmt.Errorf("blob hashed to %s:%s: %w", wantBlob.Algorithm, got, ErrDigestMismatch)
	}
	if got := hex.EncodeToString(diffHash.Sum(nil)); got != wantDiff.Hex {
		return fmt.Errorf("layer content hashed to %s:%s, config claims %s: %w",
			wantDiff.Algorithm, got, quoteBounded(diffID, maxDigestLen), ErrDiffIDMismatch)
	}
	return nil
}

// configDiffIDs reads the image config blob out of the store, re-hashes it
// against its own descriptor, and returns its rootfs.diff_ids.
func (u *Unpacker) configDiffIDs(mfst *runtimev1.ImageManifest) ([]string, error) {
	doc, err := u.imageConfigDoc(mfst)
	if err != nil {
		return nil, err
	}
	return doc.RootFS.DiffIDs, nil
}

// ImageRunConfig reads the image config blob out of the store, re-hashes it
// against its own descriptor, and returns the PROCESS half of it — the fields
// MergeRunSpec merges with a pod's container spec.
//
// It is a separate entry point from configDiffIDs rather than one call
// returning both because the two have different lifetimes: the diffIDs decide
// which tree to build and are consumed inside Unpack, while the run config is
// consumed by the caller AFTER the tree exists, to decide what to execute in it.
func (u *Unpacker) ImageRunConfig(mfst *runtimev1.ImageManifest) (ImageRunConfig, error) {
	doc, err := u.imageConfigDoc(mfst)
	if err != nil {
		return ImageRunConfig{}, err
	}
	return ImageRunConfig{
		Entrypoint: doc.Config.Entrypoint,
		Cmd:        doc.Config.Cmd,
		Env:        doc.Config.Env,
		WorkingDir: doc.Config.WorkingDir,
		User:       doc.Config.User,
	}, nil
}

// imageConfigDoc is the decoded subset of an OCI image config this package
// reads. Every field is registry-supplied and is treated as bounded DATA.
type imageConfigDoc struct {
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
		User       string   `json:"User"`
	} `json:"config"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// imageConfigDoc reads and verifies the image config blob.
//
// The config is read WHOLE (bounded by maxArchiveMetadataBytes, the same cap
// load.go applies to any one archive metadata document) because it is a small
// JSON object; layer CONTENT is never read whole anywhere in this package.
func (u *Unpacker) imageConfigDoc(mfst *runtimev1.ImageManifest) (imageConfigDoc, error) {
	digest := mfst.GetConfig().GetDigest()
	want, err := parseBlobDigest(digest)
	if err != nil {
		return imageConfigDoc{}, fmt.Errorf("image config: %w", err)
	}
	f, err := u.cache.openBlob(digest)
	if err != nil {
		return imageConfigDoc{}, err
	}
	defer f.Close()
	h := blobHashers[want.Algorithm]()
	buf, err := io.ReadAll(io.LimitReader(io.TeeReader(f, h), maxArchiveMetadataBytes+1))
	if err != nil {
		return imageConfigDoc{}, fmt.Errorf("read image config %s: %w", quoteBounded(digest, maxDigestLen), boundErr(err))
	}
	if len(buf) > maxArchiveMetadataBytes {
		return imageConfigDoc{}, fmt.Errorf("image config %s exceeds %d bytes: %w",
			quoteBounded(digest, maxDigestLen), maxArchiveMetadataBytes, ErrManifestInconsistent)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want.Hex {
		return imageConfigDoc{}, fmt.Errorf("image config %s hashed to %s:%s: %w",
			quoteBounded(digest, maxDigestLen), want.Algorithm, got, ErrDigestMismatch)
	}
	var cfg imageConfigDoc
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return imageConfigDoc{}, fmt.Errorf("decode image config %s: %v: %w",
			quoteBounded(digest, maxDigestLen), boundErr(err), ErrManifestInconsistent)
	}
	return cfg, nil
}

// commit renames the staging tree into place at dir.
//
// A LOSING RACE is not an error. rename(2) of a directory onto a non-empty
// directory fails, so the second of two concurrent unpacks of one key finds the
// winner's tree already there — and since the key is content-addressed, that
// tree is byte-equivalent to the one being discarded. Adopting it is correct and
// is the only outcome that keeps two pods starting the same image concurrently
// from failing one of them.
func (u *Unpacker) commit(staging string, loc treeLocation, policy UnpackPolicy, stats ApplyStats) (*Tree, error) {
	if err := os.MkdirAll(filepath.Dir(loc.dir), 0o755); err != nil {
		return nil, fmt.Errorf("create tree dir %s: %w", filepath.Dir(loc.dir), err)
	}
	if err := os.Rename(staging, loc.dir); err != nil {
		if t, ok, cerr := u.openCommitted(loc, policy); cerr == nil && ok {
			return t, nil
		}
		return nil, fmt.Errorf("commit unpacked tree %s: %w", quoteBounded(loc.key, maxDigestLen), err)
	}
	t := &Tree{Key: loc.key, Rootfs: filepath.Join(loc.dir, TreeRootfsName), Policy: policy, Stats: stats}
	if loc.ownershipName != "" {
		t.Ownership = filepath.Join(loc.dir, loc.ownershipName)
	}
	return t, nil
}

// writeOwnershipSidecar writes the ownership records as NEWLINE-DELIMITED JSON,
// one entry per line, in the order sortOwnership produced.
//
// JSONL rather than one JSON array because the file is O(entries) and an
// unpacked base image is routinely six figures of them: a guest reading a single
// array must hold the whole document to decode any of it, while a line-delimited
// file is applied streaming, in constant memory, and a truncated one is
// detectably truncated at a record boundary instead of being undecodable
// wholesale.
//
// It is written INSIDE the staging directory before the commit rename, for
// exactly the reason writeTreeRecord is: there is no window in which a committed
// tree exists without the sidecar its record claims.
func writeOwnershipSidecar(path string, entries []OwnershipEntry) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create ownership sidecar: %w", err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return fmt.Errorf("encode ownership entry: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return fmt.Errorf("write ownership sidecar: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync ownership sidecar: %w", err)
	}
	return f.Close()
}

// ReadOwnershipSidecar decodes a committed tree's ownership sidecar.
//
// It is the READER half of the contract writeOwnershipSidecar writes, kept here
// beside the writer so the two cannot drift, and it is what the guest-side
// apply consumes. It bounds each line: the sidecar is daemon-authored, but its
// CONTENT is derived from registry-supplied tar headers, so a path is bounded
// data exactly as it is everywhere else in this package.
func ReadOwnershipSidecar(path string) ([]OwnershipEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ownership sidecar: %w", err)
	}
	defer f.Close()
	var out []OwnershipEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxOwnershipLineBytes)
	for sc.Scan() {
		var e OwnershipEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%w: decode ownership entry %d: %v",
				ErrTreeInconsistent, len(out), boundErr(err))
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: read ownership sidecar: %v", ErrTreeInconsistent, boundErr(err))
	}
	return out, nil
}

// maxOwnershipLineBytes bounds ONE sidecar line. A path is capped at
// maxLayerEntryNameLen by the applier and the numeric fields are fixed width, so
// 64 KiB is orders of magnitude of headroom — it exists to stop a corrupted or
// substituted sidecar from making the reader allocate without limit, not to
// constrain any entry this package writes.
const maxOwnershipLineBytes = 64 << 10

// writeTreeRecord writes the tree's record. It is written INSIDE the staging
// directory before the commit rename, so the record and the payload become
// visible in the same atomic step — there is deliberately no window in which a
// committed tree exists without its record, because openCommitted reads the
// record's absence as "no tree here".
func writeTreeRecord(path string, rec treeRecord) error {
	buf, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode tree record: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create tree record: %w", err)
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return fmt.Errorf("write tree record: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync tree record: %w", err)
	}
	return f.Close()
}

// Layer media types this unpacker can decompress. The set is CLOSED and is
// matched against the DECLARED media type — see ErrUnsupportedLayerMediaType for
// why the bytes never get to decide.
const (
	mediaTypeOCILayerGzip    = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaTypeOCILayerZstd    = "application/vnd.oci.image.layer.v1.tar+zstd"
	mediaTypeOCILayerTar     = "application/vnd.oci.image.layer.v1.tar"
	mediaTypeDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// maxZstdWindow bounds one zstd decoder's window memory. A zstd frame DECLARES
// its window size and a decoder honours it, so an unbounded decoder lets a
// registry-supplied header reserve arbitrary host memory before a single byte of
// output is produced — a resource guard the gzip path does not need because
// gzip's window is fixed at 32 KiB by the format.
//
// 128 MiB admits every window a real builder emits (zstd's own maximum for the
// levels docker/buildkit use is 8 MiB; the format's ceiling is far higher) while
// keeping the reservation an order of magnitude below the memory a node running
// pods can spare. It complements, and does not replace, ApplyLimits.MaxBytes:
// that bounds the OUTPUT, this bounds the decoder's own state.
const maxZstdWindow = 128 << 20

// decompressLayer wraps r in the decompressor mediaType declares.
//
// The returned ReadCloser's Close releases only the decompressor; the underlying
// reader is the caller's.
//
// WHERE A MALFORMED STREAM SURFACES differs by format and neither is a defect:
// gzip reads its header eagerly, so garbage is refused HERE; zstd does not, so
// garbage is refused at the first Read. Both end up as ErrLayerMalformed at the
// caller, because LayerApplier.Apply wraps any read failure that way — the
// verdict a caller acts on is therefore the same either way.
func decompressLayer(mediaType string, r io.Reader) (io.ReadCloser, error) {
	switch mediaType {
	case mediaTypeOCILayerGzip, mediaTypeDockerLayerGzip:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("%w: gzip: %v", ErrLayerMalformed, boundErr(err))
		}
		return zr, nil
	case mediaTypeOCILayerZstd:
		// Single-goroutine, window-bounded: the caller already streams one layer
		// at a time and the concurrency would only add goroutines whose lifetime
		// this function cannot state. Close on the returned ReadCloser releases
		// the decoder (zstd.Decoder.Close returns nothing to report).
		zr, err := zstd.NewReader(r,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxWindow(maxZstdWindow))
		if err != nil {
			return nil, fmt.Errorf("%w: zstd: %v", ErrLayerMalformed, boundErr(err))
		}
		return zr.IOReadCloser(), nil
	case mediaTypeOCILayerTar:
		return io.NopCloser(r), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLayerMediaType, quoteBounded(mediaType, maxMediaTypeLen))
	}
}

// openBlob opens the blob for digest for READING, refusing anything that is not
// the regular file this store committed.
//
// It is the sanctioned reader for the CAS, and its containment is two-part:
// Lstat first (so a SYMLINK at the blob path is judged on ITSELF and refused,
// exactly as Cache.Has does), then os.SameFile against the opened file's own
// stat (so a link swapped in between the two is caught rather than followed).
// The residual TOCTOU is additionally closed for the unpack path by the fact
// that every byte read through here is re-hashed against a manifest descriptor:
// a substituted file cannot also produce the claimed digest.
func (c *Cache) openBlob(digest string) (*os.File, error) {
	p, err := c.BlobPath(digest)
	if err != nil {
		return nil, err
	}
	li, err := os.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("open blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("open blob %s: %s is not a regular file (mode %v)",
			quoteBounded(digest, maxDigestLen), p, li.Mode().Type())
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if !os.SameFile(li, fi) {
		f.Close()
		return nil, fmt.Errorf("open blob %s: %s changed identity between stat and open",
			quoteBounded(digest, maxDigestLen), p)
	}
	return f, nil
}
