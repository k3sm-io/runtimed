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
// reading it (see BlobKind). zstd layers land here today; admitting them is a
// one-constant, one-case change plus a direct dependency, and is deliberately
// not taken on speculation.
var ErrUnsupportedLayerMediaType = errors.New("image: unsupported layer media type")

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

// Validate reports whether the policy names a dialect this build implements.
// It fails closed: an empty or unrecognised LayerSemantics is an error, never a
// fall-through to the native dialect.
func (p UnpackPolicy) Validate() error {
	switch p.Semantics {
	case SemanticsNative:
		return nil
	case "":
		return errors.New("unpack policy: layer semantics is required")
	default:
		return fmt.Errorf("unpack policy: %w: layer semantics %s",
			ErrUnsupportedLayerMediaType, quoteBounded(string(p.Semantics), maxTokenLen))
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
// # Atomicity
//
// The tree is applied into a staging directory and committed by a single
// os.Rename, so a crash, a cancellation, or any layer failure leaves NO
// partially-applied tree at the key. A concurrent unpack of the same key is
// resolved by that rename: whoever loses adopts the winner's tree.
func (u *Unpacker) Unpack(ctx context.Context, mfst *runtimev1.ImageManifest, policy UnpackPolicy) (*Tree, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := TreeKey(mfst, policy)
	if err != nil {
		return nil, err
	}
	h, err := parseBlobDigest(key)
	if err != nil {
		// Unreachable: TreeKey renders a sha256 hex sum. Kept because the path
		// derivation must be unreachable without the allowlist having run.
		return nil, fmt.Errorf("tree key %s: %w", quoteBounded(key, maxDigestLen), err)
	}
	dir := u.cache.treeDir(h.Algorithm, h.Hex)
	if t, ok, err := u.openCommitted(dir, key, policy); err != nil {
		return nil, err
	} else if ok {
		return t, nil
	}

	diffIDs, err := u.configDiffIDs(mfst)
	if err != nil {
		return nil, err
	}
	layers := mfst.GetLayers()
	if len(diffIDs) != len(layers) {
		return nil, fmt.Errorf("image config lists %d diffIDs but the manifest lists %d layers: %w",
			len(diffIDs), len(layers), ErrManifestInconsistent)
	}

	stats, staging, err := u.applyStaged(ctx, layers, diffIDs, policy)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging) // no-op after a successful rename

	rec := treeRecord{
		Version: treeRecordVersion,
		Key:     key,
		Policy:  policy,
		Config:  mfst.GetConfig().GetDigest(),
		Stats:   stats,
	}
	for _, l := range layers {
		rec.Layers = append(rec.Layers, l.GetDigest())
	}
	if err := writeTreeRecord(filepath.Join(staging, TreeRecordName), rec); err != nil {
		return nil, err
	}
	return u.commit(staging, dir, key, policy, stats)
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
func (u *Unpacker) openCommitted(dir, key string, policy UnpackPolicy) (*Tree, bool, error) {
	buf, err := os.ReadFile(filepath.Join(dir, TreeRecordName))
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
	return &Tree{Key: key, Rootfs: rootfs, Policy: policy, Stats: rec.Stats, CacheHit: true}, true, nil
}

// applyStaged builds the tree in a disposable staging directory and returns it
// UNCOMMITTED. The caller renames it into place (commit) or removes it.
func (u *Unpacker) applyStaged(ctx context.Context, layers []*runtimev1.Descriptor, diffIDs []string, policy UnpackPolicy) (_ ApplyStats, _ string, retErr error) {
	parent := u.cache.UnpackedRoot()
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return ApplyStats{}, "", fmt.Errorf("create unpacked root %s: %w", parent, err)
	}
	staging, err := os.MkdirTemp(parent, ".tree-")
	if err != nil {
		return ApplyStats{}, "", fmt.Errorf("stage unpacked tree: %w", err)
	}
	defer func() {
		if retErr != nil {
			os.RemoveAll(staging)
		}
	}()
	rootfs := filepath.Join(staging, TreeRootfsName)
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		return ApplyStats{}, "", fmt.Errorf("stage tree rootfs: %w", err)
	}
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return ApplyStats{}, "", fmt.Errorf("anchor tree rootfs %s: %w", rootfs, err)
	}
	defer root.Close()

	applier, err := NewLayerApplier(root, policy, u.limits)
	if err != nil {
		return ApplyStats{}, "", err
	}
	for i, desc := range layers {
		if err := u.applyLayer(ctx, applier, desc, diffIDs[i]); err != nil {
			return ApplyStats{}, "", fmt.Errorf("apply layer %d of %d (%s): %w",
				i+1, len(layers), quoteBounded(desc.GetDigest(), maxDigestLen), err)
		}
	}
	return applier.Stats(), staging, nil
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
//
// The config is read WHOLE (bounded by maxArchiveMetadataBytes, the same cap
// load.go applies to any one archive metadata document) because it is a small
// JSON object; layer CONTENT is never read whole anywhere in this package.
func (u *Unpacker) configDiffIDs(mfst *runtimev1.ImageManifest) ([]string, error) {
	digest := mfst.GetConfig().GetDigest()
	want, err := parseBlobDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	f, err := u.cache.openBlob(digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := blobHashers[want.Algorithm]()
	buf, err := io.ReadAll(io.LimitReader(io.TeeReader(f, h), maxArchiveMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read image config %s: %w", quoteBounded(digest, maxDigestLen), boundErr(err))
	}
	if len(buf) > maxArchiveMetadataBytes {
		return nil, fmt.Errorf("image config %s exceeds %d bytes: %w",
			quoteBounded(digest, maxDigestLen), maxArchiveMetadataBytes, ErrManifestInconsistent)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want.Hex {
		return nil, fmt.Errorf("image config %s hashed to %s:%s: %w",
			quoteBounded(digest, maxDigestLen), want.Algorithm, got, ErrDigestMismatch)
	}
	var cfg struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("decode image config %s: %v: %w",
			quoteBounded(digest, maxDigestLen), boundErr(err), ErrManifestInconsistent)
	}
	return cfg.RootFS.DiffIDs, nil
}

// commit renames the staging tree into place at dir.
//
// A LOSING RACE is not an error. rename(2) of a directory onto a non-empty
// directory fails, so the second of two concurrent unpacks of one key finds the
// winner's tree already there — and since the key is content-addressed, that
// tree is byte-equivalent to the one being discarded. Adopting it is correct and
// is the only outcome that keeps two pods starting the same image concurrently
// from failing one of them.
func (u *Unpacker) commit(staging, dir, key string, policy UnpackPolicy, stats ApplyStats) (*Tree, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, fmt.Errorf("create tree dir %s: %w", filepath.Dir(dir), err)
	}
	if err := os.Rename(staging, dir); err != nil {
		if t, ok, cerr := u.openCommitted(dir, key, policy); cerr == nil && ok {
			return t, nil
		}
		return nil, fmt.Errorf("commit unpacked tree %s: %w", quoteBounded(key, maxDigestLen), err)
	}
	return &Tree{Key: key, Rootfs: filepath.Join(dir, TreeRootfsName), Policy: policy, Stats: stats}, nil
}

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
	mediaTypeOCILayerTar     = "application/vnd.oci.image.layer.v1.tar"
	mediaTypeDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// decompressLayer wraps r in the decompressor mediaType declares.
//
// The returned ReadCloser's Close releases only the decompressor; the underlying
// reader is the caller's.
func decompressLayer(mediaType string, r io.Reader) (io.ReadCloser, error) {
	switch mediaType {
	case mediaTypeOCILayerGzip, mediaTypeDockerLayerGzip:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("%w: gzip: %v", ErrLayerMalformed, boundErr(err))
		}
		return zr, nil
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
