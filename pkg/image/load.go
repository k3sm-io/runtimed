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
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// IngestSubdir is the cache-root-relative directory a streamed archive is
// staged in while it is being read: <root>/ingest, a SIBLING of blobs/, pods/
// and index/.
//
// Being a sibling is deliberate, exactly as it is for IndexSubdir: the GC's
// enumerators read blobs/ (Cache.EnumerateBlobs), pods/ (Cache.Roots) and the
// tree stores (Cache.EnumerateTrees), so a staged archive can neither be
// mistaken for a blob of unknown provenance nor become a reachability root. The staged file itself is unlinked the instant it
// is created (see stageArchive), so the directory is normally empty and a
// crashed ingest leaves nothing behind at all.
const IngestSubdir = "ingest"

// maxArchiveMetadataBytes caps any one archive document this package reads whole
// into memory — index.json, an image manifest, an image config.
//
// The archive is operator-supplied but not therefore trusted: without a cap, a
// 40 GiB file named index.json is an OOM of the root-adjacent daemon before a
// single digest has been checked. Blob CONTENT is never read whole: it streams
// through a hasher and then through CommitBlob.
const maxArchiveMetadataBytes = 4 << 20

// ErrArchiveMalformed reports that an ingested archive does not parse as the
// format it claims to be: not a tar, a missing or undecodable manifest/index, a
// blob entry the manifest names but the archive does not contain, or an entry
// that is not a regular file.
//
// It is distinct from ErrDigestMismatch (the bytes contradict a digest) and from
// ErrArchiveUnsupported (a well-formed archive of a shape this version declines)
// because the three imply different operator remedies: re-export the archive,
// re-hash/re-transfer it, or use a different export mode.
var ErrArchiveMalformed = errors.New("image: archive is malformed")

// ErrArchiveUnsupported reports a well-formed archive whose SHAPE this version
// does not ingest — a nested (multi-platform) index, a manifest media type that
// is neither a docker schema-2 nor an OCI image manifest, or a stream in which
// no known archive format could be detected.
//
// It is deliberately not an "unimplemented" status at the RPC boundary: the RPC
// is implemented, and it is the caller's archive that is out of scope.
var ErrArchiveUnsupported = errors.New("image: archive shape is not supported")

// ErrArchiveMultipleImages reports an archive carrying more than one image — a
// docker-save tar with several manifest entries, one entry with several
// RepoTags, or an OCI layout whose index names several manifests.
//
// v1 refuses rather than choosing one, because a load records exactly one
// reference: picking a manifest (or a tag) would silently drop the others, and
// an operator would discover the loss only when a pod could not find the image.
// The remedy is one load per image.
var ErrArchiveMultipleImages = errors.New("image: archive contains more than one image")

// ErrArchiveForeignLayer reports a descriptor carrying URLs — a foreign
// (externally-hosted) layer.
//
// The URLs field is authored by whoever wrote the archive, and honoring it would
// make an "offline" load reach the network for content the operator believes
// they handed over on disk. Refusing keeps the ingest path exactly as offline as
// it looks.
var ErrArchiveForeignLayer = errors.New("image: archive descriptor names an external URL")

// ErrArchiveClaimMismatch reports that the client's ADVISORY digest or size
// claim about the whole archive does not describe the bytes the server received.
//
// It is a transport check and says nothing about authenticity — see Loader.Load.
var ErrArchiveClaimMismatch = errors.New("image: archive does not match the client's declared digest or size")

// ErrLoadReferenceInvalid reports that the reference an ingest asked to record
// is empty or is not a parseable image reference.
//
// The reference becomes an index key that a pod later resolves by exact match,
// so an unparseable one records an entry nothing can ever hit.
var ErrLoadReferenceInvalid = errors.New("image: load reference is invalid")

// LoadRequest is one ingest: the reference to record the archive's image under,
// the archive's format, and the client's advisory claims about the byte stream.
type LoadRequest struct {
	// Reference is the pull reference to record the loaded image under.
	Reference string
	// Format is the archive format. UNSPECIFIED asks for detection from the bytes.
	Format runtimev1.LoadImageFormat
	// Digest is the client's ADVISORY claim about the whole archive's digest
	// ("<algo>:<hex>"); empty means the client made no claim.
	Digest string
	// Size is the client's ADVISORY claim about the archive's byte length; zero
	// or negative means the client made no claim.
	Size int64
}

// LoadResult reports a completed ingest.
type LoadResult struct {
	// Manifest is the ingested image manifest in the shared apis form, as
	// recorded in the index.
	Manifest *runtimev1.ImageManifest
	// Descriptor is the manifest's own content descriptor — media type, digest
	// (what a user reads as the image id) and size.
	Descriptor *runtimev1.Descriptor
	// Platform is the platform the image's own config declares; it is the second
	// half of the index key the reference does not carry.
	Platform Platform
	// ReceivedBytes is the archive length the SERVER counted off the stream,
	// never the client's advisory claim.
	ReceivedBytes int64
}

// Loader ingests image archives — a `docker save` tar or a tarred OCI image
// layout — into a Cache, recording the reference in a LocalIndex.
//
// # The ordering contract (the property this type exists to guarantee)
//
// Content that arrives from outside the registry path is admitted in THREE
// ordered phases, and the order is the whole security property:
//
//  1. VERIFY — every blob the archive's own manifest names is re-hashed and
//     compared against the digest that manifest claims for it. Nothing is
//     written to the store, no lease is taken, and no reference is recorded.
//  2. LEASE + COMMIT — only once every blob has verified, a lease is taken over
//     the whole digest set (pinning it against a concurrent reclaim, exactly as
//     Puller.Pull does) and each blob is committed through Cache.CommitBlob,
//     which independently re-verifies it at write time.
//  3. RECORD — the reference is recorded last, after every blob it names is
//     committed, and the lease is released only after that.
//
// A mismatch anywhere in phase 1 fails the whole load: nothing is committed, not
// even the blobs that verified, no lease was ever taken, and no reference is
// recorded. That all-or-nothing property is why phase 1 is a separate pass
// rather than a per-blob check folded into phase 2 — a per-blob loop would leave
// the blobs before the bad one committed, and an ingest that half-lands is one a
// later reader cannot distinguish from a completed one.
//
// The two passes read the same staged file, which is unlinked at creation and
// held open by fd alone (see stageArchive), so the bytes verified in phase 1 are
// provably the bytes committed in phase 2: no path exists for anything to
// substitute them in between.
//
// # What this does not claim
//
// A loaded image is PROVENANCE-free by design (the M12 images plan, §M12.2):
// this path evaluates no signature policy, and the archive's manifest is
// supplied by the same party as its bytes. On the docker-save leg in particular
// the per-blob check is self-CONSISTENCY, not authenticity —
// go-containerregistry synthesizes that format's descriptors from the very bytes
// being checked (see Cache.CommitBlob's "what this defends against, honestly").
// The OCI-layout leg is the stronger one: its claims come from a manifest whose
// own digest the archive's index pins, so a corrupted or substituted blob is
// caught. Neither leg authenticates the IMAGE; that is a signature problem.
type Loader struct {
	cache *Cache
	index LocalIndex
}

// NewLoader returns a Loader writing into cache and recording references in
// index.
//
// Both arguments are required, for the same reason NewPuller's are: an ingest
// that silently recorded nothing would produce an image no pod can resolve by
// reference, and the caller that keeps no record says so by passing
// NoLocalIndex{}.
func NewLoader(cache *Cache, index LocalIndex) (*Loader, error) {
	if cache == nil {
		return nil, errors.New("image loader: cache is required")
	}
	if index == nil {
		return nil, errors.New("image loader: index is required (pass image.NoLocalIndex{} when the node keeps none)")
	}
	return &Loader{cache: cache, index: index}, nil
}

// Load ingests the archive streamed from src and records it under
// req.Reference, returning the ingested manifest.
//
// The phases and their ordering guarantee are documented on Loader. src is read
// exactly once, to a staged file; everything after that reads the staged copy.
func (l *Loader) Load(ctx context.Context, req LoadRequest, src io.Reader) (*LoadResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, errors.New("load image: archive stream is required")
	}
	ref, err := loadReference(req.Reference)
	if err != nil {
		return nil, err
	}

	staged, err := l.stageArchive(ctx, req, src)
	if err != nil {
		return nil, fmt.Errorf("load image %q: %w", ref, err)
	}
	defer staged.Close()

	img, err := parseArchive(staged.open, req.Format)
	if err != nil {
		return nil, fmt.Errorf("load image %q: %w", ref, err)
	}

	// phase 1 — verify every blob before the store is touched at all. See the
	// Loader doc comment: this pass is what makes a mismatch reject the whole
	// load instead of leaving the blobs that happened to come first behind.
	if err := verifyArchiveBlobs(ctx, img); err != nil {
		return nil, fmt.Errorf("load image %q: %w", ref, err)
	}

	// phase 2 — lease the whole digest set before the first commit, exactly as
	// Puller.Pull does and for the same reason: a blob this ingest depends on can
	// already be present, already be old, and be named by nothing, which makes it
	// deletable by a concurrent reclaim during the very ingest that needs it.
	// CommitBlob re-verifies each blob independently at write time.
	lease := l.cache.AcquireLease(img.digests(), 0)
	// Released after the reference is recorded (or immediately on a failure that
	// records nothing) — never before, or the window between "the blob is on
	// disk" and "something names it" reopens.
	defer lease.Release()
	for _, b := range img.blobs() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := l.cache.CommitBlob(b.desc.Digest.String(), b.desc.Size, func(w io.Writer) error {
			rc, oerr := b.open()
			if oerr != nil {
				return oerr
			}
			defer rc.Close()
			_, cerr := io.Copy(w, rc)
			return cerr
		}); err != nil {
			return nil, fmt.Errorf("load image %q: %w", ref, err)
		}
	}

	out := &runtimev1.ImageManifest{
		Reference:   ref,
		MediaType:   string(img.manifest.MediaType),
		Config:      descriptorFromGGCR(img.manifest.Config),
		Annotations: img.manifest.Annotations,
	}
	for _, layer := range img.manifest.Layers {
		out.Layers = append(out.Layers, descriptorFromGGCR(layer))
	}

	// phase 3 — record the reference last. Every blob it names is committed and
	// digest-verified by now, and the manifest recorded is the one this ingest
	// parsed and verified. The entry is an EDGE, not a reachability root (see
	// FileIndex): a loaded image whose blobs no pod references is reclaimable
	// like any other unreferenced content.
	if err := l.index.Record(ctx, ref, img.platform, out); err != nil {
		return nil, fmt.Errorf("load image %q: record image index: %w", ref, err)
	}

	return &LoadResult{
		Manifest: out,
		Descriptor: &runtimev1.Descriptor{
			MediaType: string(img.manifest.MediaType),
			Digest:    img.manifestDigest.String(),
			Size:      img.manifestSize,
		},
		Platform:      img.platform,
		ReceivedBytes: staged.size,
	}, nil
}

// loadReference validates the reference an ingest will record.
func loadReference(ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("%w: a reference is required", ErrLoadReferenceInvalid)
	}
	// Parsed for VALIDITY only; the string is recorded verbatim, as the pull path
	// records the reference it was given. Normalizing here would record a
	// different key from the one the operator (and later, a pod spec) names.
	if _, err := name.ParseReference(ref); err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrLoadReferenceInvalid, quoteBounded(ref, maxDigestLen), boundErr(err))
	}
	return ref, nil
}

// ingestRoot is the directory a streamed archive is staged in (IngestSubdir).
func (c *Cache) ingestRoot() string { return filepath.Join(c.root, IngestSubdir) }

// stagedArchive is a streamed archive spooled to a local file, readable any
// number of times and reachable by NO path.
type stagedArchive struct {
	f    *os.File
	size int64
}

// open returns a fresh independent reader over the whole staged archive. It
// satisfies go-containerregistry's tarball.Opener.
//
// Each call gets its own io.SectionReader over the same fd, which reads with
// pread(2) and so carries no shared offset — two readers (the verify pass and
// the commit pass, or ggcr's own repeated opens) cannot disturb each other.
func (s *stagedArchive) open() (io.ReadCloser, error) {
	return io.NopCloser(io.NewSectionReader(s.f, 0, s.size)), nil
}

// Close releases the staged file. Its name was already unlinked, so this is what
// frees the space.
func (s *stagedArchive) Close() error { return s.f.Close() }

// stageArchive spools src to a staged file under <root>/ingest and checks the
// client's advisory claims about it.
//
// The file is unlinked immediately after creation and held open by fd alone.
// Three things follow: no other process can open, replace or symlink-swap the
// bytes between the verify pass and the commit pass; a crashed daemon leaks no
// artifact for a later ingest or a GC to reason about; and the space is returned
// by the kernel on Close.
//
// Spooling is unavoidable rather than a shortcut: both archive formats put their
// manifest at an arbitrary position in the tar, and every per-blob digest claim
// comes from that manifest — so a strictly single-pass ingest would have to
// commit blobs before it knew what they were claimed to be, which is precisely
// the ordering this package refuses.
func (l *Loader) stageArchive(ctx context.Context, req LoadRequest, src io.Reader) (*stagedArchive, error) {
	dir := l.cache.ingestRoot()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ingest dir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".archive-*")
	if err != nil {
		return nil, fmt.Errorf("stage archive: %w", err)
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, fmt.Errorf("unlink staged archive: %w", err)
	}
	staged := &stagedArchive{f: f}

	var hasher hash.Hash
	var claimed ggcrv1.Hash
	var w io.Writer = f
	if req.Digest != "" {
		parsed, perr := parseBlobDigest(req.Digest)
		if perr != nil {
			staged.Close()
			return nil, perr
		}
		claimed = parsed
		hasher = blobHashers[claimed.Algorithm]()
		// io.MultiWriter deliberately does not implement io.ReaderFrom, which is
		// what keeps the hasher on the path — see Cache.CommitBlob.
		w = io.MultiWriter(f, hasher)
	}
	// A declared size caps the spool at one byte past the claim: the archive is
	// written to the store volume before anything about it is known, so a client
	// that declares 4 MiB and then streams forever must be stopped at the
	// declaration rather than at the disk. An UNDECLARED size is not capped here
	// — bounding an ingest that makes no claim is a store-admission decision (see
	// Puller.admitFetch's recorded residual), not something to invent a number for.
	if req.Size > 0 {
		src = io.LimitReader(src, req.Size+1)
	}
	n, err := io.Copy(w, src)
	if err != nil {
		staged.Close()
		// The stream is client-supplied, so its error is bounded, never adopted.
		return nil, fmt.Errorf("receive archive: %w", boundErr(err))
	}
	if err := ctx.Err(); err != nil {
		staged.Close()
		return nil, err
	}
	staged.size = n

	// The client's digest and size are ADVISORY: they describe the archive, and
	// the client is the same party that supplies the bytes, so agreement proves
	// only that the transfer did not corrupt anything. The SECURITY mechanism is
	// the per-blob check in phase 1, whose claims come from the archive's own
	// manifest — a level above the bytes — and are verified before any commit.
	if req.Size > 0 && req.Size != n {
		staged.Close()
		return nil, fmt.Errorf("%w: client declared %d bytes, received %d", ErrArchiveClaimMismatch, req.Size, n)
	}
	if hasher != nil {
		got := claimed.Algorithm + ":" + hex.EncodeToString(hasher.Sum(nil))
		if got != claimed.String() {
			staged.Close()
			return nil, fmt.Errorf("%w: client declared %s, received bytes hash to %s",
				ErrArchiveClaimMismatch, quoteBounded(req.Digest, maxDigestLen), got)
		}
	}
	return staged, nil
}

// archiveBlob is one blob an archive contributes: the descriptor that CLAIMS its
// digest and size, plus a re-openable reader over the archive's copy of the
// bytes.
//
// The descriptor comes from the archive's own MANIFEST, never from the object
// that hands over the bytes — the same rule Puller.Pull follows, and the reason
// the claim can be checked at all.
type archiveBlob struct {
	desc ggcrv1.Descriptor
	open func() (io.ReadCloser, error)
}

// archiveImage is the one image an archive contributes, resolved to the same
// shape both formats reduce to.
type archiveImage struct {
	manifest       *ggcrv1.Manifest
	manifestDigest ggcrv1.Hash
	manifestSize   int64
	config         archiveBlob
	layers         []archiveBlob
	// platform is what the image's own config declares. It is the second half of
	// the (reference x platform) index key.
	platform Platform
}

// blobs returns the config blob followed by the layer blobs, in manifest order.
func (a *archiveImage) blobs() []archiveBlob {
	out := make([]archiveBlob, 0, len(a.layers)+1)
	out = append(out, a.config)
	return append(out, a.layers...)
}

// digests returns every blob digest this image names — the lease set.
func (a *archiveImage) digests() []string {
	out := make([]string, 0, len(a.layers)+1)
	for _, b := range a.blobs() {
		out = append(out, b.desc.Digest.String())
	}
	return out
}

// parseArchive resolves the staged archive to its one image, in the format the
// caller declared or, for UNSPECIFIED, the one detected from the bytes.
func parseArchive(open tarball.Opener, format runtimev1.LoadImageFormat) (*archiveImage, error) {
	switch format {
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE:
		return parseDockerSave(open)
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT:
		return parseOCILayout(open)
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_UNSPECIFIED:
		return parseDetected(open)
	default:
		return nil, fmt.Errorf("%w: unknown archive format %d", ErrArchiveUnsupported, int32(format))
	}
}

// parseDetected picks the format from the archive's own entries.
//
// A modern `docker save` writes both an OCI layout and a manifest.json for
// backwards compatibility, so manifest.json wins: it is the format
// go-containerregistry's tarball reader is written against, and the OCI files it
// sits beside describe the same image.
func parseDetected(open tarball.Opener) (*archiveImage, error) {
	names, err := entryNames(open, "manifest.json", "index.json")
	if err != nil {
		return nil, err
	}
	switch {
	case names["manifest.json"]:
		return parseDockerSave(open)
	case names["index.json"]:
		return parseOCILayout(open)
	default:
		return nil, fmt.Errorf("%w: the stream contains neither manifest.json (docker save) nor index.json (OCI layout)",
			ErrArchiveUnsupported)
	}
}

// parseDockerSave resolves a `docker save` tar.
//
// The per-image work is delegated to go-containerregistry's tarball reader,
// which is the format's reference implementation in this dependency set and
// synthesizes a schema-2 manifest for the archive. What is not delegated is the
// admission policy: the multi-image and multi-tag refusals below are k3sm's, and
// ggcr enforces only the first of them.
func parseDockerSave(open tarball.Opener) (*archiveImage, error) {
	mf, err := tarball.LoadManifest(open)
	if err != nil {
		return nil, fmt.Errorf("%w: read manifest.json: %v", ErrArchiveMalformed, boundErr(err))
	}
	switch {
	case len(mf) == 0:
		return nil, fmt.Errorf("%w: manifest.json names no image", ErrArchiveMalformed)
	case len(mf) > 1:
		return nil, fmt.Errorf("%w: manifest.json names %d images; load one image per archive",
			ErrArchiveMultipleImages, len(mf))
	case len(mf[0].RepoTags) > 1:
		// A load records exactly one reference. Accepting a multi-tag archive
		// would drop every tag but the one the caller named, silently.
		return nil, fmt.Errorf("%w: the archive's image carries %d tags and a load records one reference; re-export one tag per archive",
			ErrArchiveMultipleImages, len(mf[0].RepoTags))
	}

	img, err := tarball.Image(open, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArchiveMalformed, boundErr(err))
	}
	mfst, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrArchiveMalformed, boundErr(err))
	}
	rawMfst, err := img.RawManifest()
	if err != nil {
		return nil, fmt.Errorf("%w: raw manifest: %v", ErrArchiveMalformed, boundErr(err))
	}
	mfstDigest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("%w: manifest digest: %v", ErrArchiveMalformed, boundErr(err))
	}
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("%w: config: %v", ErrArchiveMalformed, boundErr(err))
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("%w: layers: %v", ErrArchiveMalformed, boundErr(err))
	}
	// The loop below pairs layers[i] with mfst.Layers[i]; a divergence is refused
	// here rather than indexed past, exactly as Puller.Pull refuses it.
	if len(layers) != len(mfst.Layers) {
		return nil, fmt.Errorf("archive image has %d layers but its manifest lists %d: %w",
			len(layers), len(mfst.Layers), ErrManifestInconsistent)
	}

	out := &archiveImage{
		manifest:       mfst,
		manifestDigest: mfstDigest,
		manifestSize:   int64(len(rawMfst)),
		config: archiveBlob{
			desc: mfst.Config,
			open: bytesOpener(rawCfg),
		},
	}
	for i, layer := range layers {
		out.layers = append(out.layers, archiveBlob{
			desc: mfst.Layers[i],
			open: layer.Compressed,
		})
	}
	if err := finishArchiveImage(out, rawCfg); err != nil {
		return nil, err
	}
	return out, nil
}

// parseOCILayout resolves a tarred OCI image layout.
//
// This is the leg on which the per-blob digest check is MEANINGFUL rather than
// self-consistent: index.json pins the manifest's digest, the manifest is
// verified against it here, and every blob claim then descends from a document
// whose own digest was checked. Nothing in the archive is read as a filesystem
// path — each blob's tar entry name is COMPUTED from a parsed digest and matched
// against the entries, so a hostile entry name has nothing to escape into.
func parseOCILayout(open tarball.Opener) (*archiveImage, error) {
	raw, err := readTarEntry(open, "index.json")
	if err != nil {
		return nil, err
	}
	var idx ggcrv1.IndexManifest
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("%w: decode index.json: %v", ErrArchiveMalformed, boundErr(err))
	}
	switch {
	case len(idx.Manifests) == 0:
		return nil, fmt.Errorf("%w: index.json names no manifest", ErrArchiveMalformed)
	case len(idx.Manifests) > 1:
		return nil, fmt.Errorf("%w: index.json names %d manifests; load one image per archive",
			ErrArchiveMultipleImages, len(idx.Manifests))
	}
	desc := idx.Manifests[0]
	switch {
	case desc.MediaType.IsIndex():
		// A multi-platform archive. Choosing a platform here would be a
		// SELECTION decision (platform.go's business, driven by a pod's policy),
		// and a load has no pod to decide for — so it is refused rather than
		// guessed.
		return nil, fmt.Errorf("%w: index.json names a nested index (a multi-platform archive); export one platform per archive",
			ErrArchiveUnsupported)
	case !desc.MediaType.IsImage():
		return nil, fmt.Errorf("%w: index.json names media type %s",
			ErrArchiveUnsupported, quoteBounded(string(desc.MediaType), maxMediaTypeLen))
	}

	rawMfst, err := readBlobEntry(open, desc)
	if err != nil {
		return nil, err
	}
	// the ROOT OF the DIGEST CHAIN. Every per-blob claim below is read out of
	// these bytes, so they are checked against the digest index.json pins for
	// them before they are believed. Without this, an archive could rewrite its
	// own manifest and the per-blob checks would agree with the rewrite.
	if err := verifyBytes(rawMfst, desc.Digest, "image manifest"); err != nil {
		return nil, err
	}
	var mfst ggcrv1.Manifest
	if err := json.Unmarshal(rawMfst, &mfst); err != nil {
		return nil, fmt.Errorf("%w: decode image manifest: %v", ErrArchiveMalformed, boundErr(err))
	}

	out := &archiveImage{
		manifest:       &mfst,
		manifestDigest: desc.Digest,
		manifestSize:   int64(len(rawMfst)),
		config: archiveBlob{
			desc: mfst.Config,
			open: blobOpener(open, mfst.Config),
		},
	}
	for _, layer := range mfst.Layers {
		out.layers = append(out.layers, archiveBlob{desc: layer, open: blobOpener(open, layer)})
	}
	// The config is read (bounded) so the image's declared platform is available
	// for the index key. Its bytes are claim-checked like every other blob in
	// phase 1, which runs before anything is recorded, so the platform that
	// reaches the index can only ever have come from a verified config.
	rawCfg, err := readBlobEntry(open, mfst.Config)
	if err != nil {
		return nil, err
	}
	if err := finishArchiveImage(out, rawCfg); err != nil {
		return nil, err
	}
	return out, nil
}

// finishArchiveImage applies the checks and derivations both formats share: the
// foreign-layer refusal, and the platform the image's own config declares.
func finishArchiveImage(a *archiveImage, rawCfg []byte) error {
	for _, b := range a.blobs() {
		if len(b.desc.URLs) > 0 {
			return fmt.Errorf("%w: %s names %d URL(s)",
				ErrArchiveForeignLayer, quoteBounded(b.desc.Digest.String(), maxDigestLen), len(b.desc.URLs))
		}
	}
	var cfg ggcrv1.ConfigFile
	if err := json.Unmarshal(rawCfg, &cfg); err != nil {
		return fmt.Errorf("%w: decode image config: %v", ErrArchiveMalformed, boundErr(err))
	}
	p := Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant, OSVersion: cfg.OSVersion}.Normalize()
	if p.OS == "" || p.Architecture == "" {
		// No platform policy is applied to a load — a loaded image may legitimately
		// be a linux image destined for a vm pod. But the index is keyed
		// (reference x platform), so an image that declares neither cannot be
		// recorded under a key anything could look up.
		return fmt.Errorf("%w: the image config declares no platform (os=%s architecture=%s)",
			ErrArchiveMalformed, quoteBounded(cfg.OS, maxTokenLen), quoteBounded(cfg.Architecture, maxTokenLen))
	}
	a.platform = p
	return nil
}

// verifyArchiveBlobs is phase 1: re-hash every blob the manifest names and
// compare it against the digest that manifest claims. It writes nothing.
func verifyArchiveBlobs(ctx context.Context, a *archiveImage) error {
	for _, b := range a.blobs() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyArchiveBlob(b); err != nil {
			return err
		}
	}
	return nil
}

// verifyArchiveBlob streams one blob through the hasher its own digest names and
// refuses anything that does not match the claim exactly.
func verifyArchiveBlob(b archiveBlob) error {
	digest := b.desc.Digest.String()
	want, err := parseBlobDigest(digest)
	if err != nil {
		return err
	}
	if b.desc.Size < 0 {
		return fmt.Errorf("%w: blob %s declares size %d",
			ErrArchiveMalformed, quoteBounded(digest, maxDigestLen), b.desc.Size)
	}
	rc, err := b.open()
	if err != nil {
		return err
	}
	defer rc.Close()
	h := blobHashers[want.Algorithm]()
	// Bounded at the declared size + 1 byte: enough to DETECT an overrun without
	// hashing an unbounded stream from an operator-supplied archive.
	n, err := io.Copy(h, io.LimitReader(rc, b.desc.Size+1))
	if err != nil {
		return fmt.Errorf("read blob %s: %w", quoteBounded(digest, maxDigestLen), boundErr(err))
	}
	if n > b.desc.Size {
		return fmt.Errorf("blob %s: %w", quoteBounded(digest, maxDigestLen), ErrBlobTooLarge)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want.Hex || n != b.desc.Size {
		return fmt.Errorf("blob %s is %d bytes hashing to %s:%s: %w",
			quoteBounded(digest, maxDigestLen), n, want.Algorithm, got, ErrDigestMismatch)
	}
	return nil
}

// verifyBytes checks an in-memory archive document against the digest a
// higher-level document claims for it. what names the document in the error.
func verifyBytes(raw []byte, want ggcrv1.Hash, what string) error {
	digest := want.String()
	parsed, err := parseBlobDigest(digest)
	if err != nil {
		return err
	}
	h := blobHashers[parsed.Algorithm]()
	// hash.Hash.Write never returns an error (documented); the value is ignored
	// deliberately rather than by omission.
	_, _ = h.Write(raw)
	got := hex.EncodeToString(h.Sum(nil))
	if got != parsed.Hex {
		return fmt.Errorf("%s %s hashed to %s:%s: %w",
			what, quoteBounded(digest, maxDigestLen), parsed.Algorithm, got, ErrDigestMismatch)
	}
	return nil
}

// bytesOpener serves an already-read document as a fresh reader per call.
func bytesOpener(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

// blobOpener opens the archive entry holding desc's content.
//
// The entry NAME is computed from the parsed digest (blobEntryName), never taken
// from the archive: an entry's own name is never used to locate anything, so no
// name in a hostile archive can select a file, escape a directory, or alias
// another blob.
func blobOpener(open tarball.Opener, desc ggcrv1.Descriptor) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		entry, err := blobEntryName(desc.Digest)
		if err != nil {
			return nil, err
		}
		return openTarEntry(open, entry)
	}
}

// readBlobEntry reads desc's content whole, bounded by maxArchiveMetadataBytes.
// It is for archive DOCUMENTS (a manifest, a config) only; blob content streams.
func readBlobEntry(open tarball.Opener, desc ggcrv1.Descriptor) ([]byte, error) {
	entry, err := blobEntryName(desc.Digest)
	if err != nil {
		return nil, err
	}
	return readTarEntry(open, entry)
}

// blobEntryName is the OCI-layout path for a blob: blobs/<algo>/<hex>, built
// from the parsed halves of the digest (parseBlobDigest's closed allowlist), so
// neither half can contain a separator or any other path metacharacter.
func blobEntryName(h ggcrv1.Hash) (string, error) {
	parsed, err := parseBlobDigest(h.String())
	if err != nil {
		return "", err
	}
	return path.Join("blobs", parsed.Algorithm, parsed.Hex), nil
}

// entryNames reports which of the wanted top-level names the archive contains,
// in one pass.
func entryNames(open tarball.Opener, wanted ...string) (map[string]bool, error) {
	want := make(map[string]bool, len(wanted))
	for _, w := range wanted {
		want[w] = true
	}
	found := make(map[string]bool, len(wanted))
	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read archive: %v", ErrArchiveMalformed, boundErr(err))
		}
		if n := tarEntryName(hdr); want[n] {
			found[n] = true
		}
	}
	return found, nil
}

// openTarEntry returns a reader over the archive entry named want.
//
// Only a regular file entry can hold content. A symlink or hard-link entry at a
// blob's name is refused rather than followed: following one is how an archive
// aliases a blob it does not contain onto bytes it did not supply, and the
// aliased entry would then be hashed under the wrong claim.
func openTarEntry(open tarball.Opener, want string) (io.ReadCloser, error) {
	rc, err := open()
	if err != nil {
		return nil, err
	}
	closeIt := true
	defer func() {
		if closeIt {
			rc.Close()
		}
	}()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: %s is not in the archive", ErrArchiveMalformed, quoteBounded(want, maxDigestLen))
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read archive: %v", ErrArchiveMalformed, boundErr(err))
		}
		if tarEntryName(hdr) != want {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: %s is not a regular file (tar type %q)",
				ErrArchiveMalformed, quoteBounded(want, maxDigestLen), string(hdr.Typeflag))
		}
		closeIt = false
		return &tarEntry{Reader: tr, closer: rc}, nil
	}
}

// readTarEntry reads a whole entry, bounded by maxArchiveMetadataBytes.
func readTarEntry(open tarball.Opener, want string) ([]byte, error) {
	rc, err := openTarEntry(open, want)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf, err := io.ReadAll(io.LimitReader(rc, maxArchiveMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrArchiveMalformed, quoteBounded(want, maxDigestLen), boundErr(err))
	}
	if len(buf) > maxArchiveMetadataBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes",
			ErrArchiveMalformed, quoteBounded(want, maxDigestLen), maxArchiveMetadataBytes)
	}
	return buf, nil
}

// tarEntryName normalizes a tar header name to the archive-relative form this
// package matches against ("./index.json" and "index.json" are one entry).
//
// It is a MATCHING key only. No value derived from it ever becomes a filesystem
// path, so normalization here cannot be a traversal vector.
func tarEntryName(hdr *tar.Header) string {
	return path.Clean(strings.TrimPrefix(hdr.Name, "./"))
}

// tarEntry is a reader over one tar entry that closes the underlying archive
// reader with it.
type tarEntry struct {
	io.Reader
	closer io.Closer
}

// Close releases the archive reader this entry was read through.
func (t *tarEntry) Close() error { return t.closer.Close() }
