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

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// Limits. MaxManifestBytes matches the cap the cluster registry applies to a
// manifest put; MaxLayers is the order of the registry's manifest walk bound.
const (
	MaxManifestBytes = 4 << 20
	MaxLayers        = 4096
	// MaxLayerBytes caps one declared blob size: 256 GiB, above the largest
	// single weight file a ModelPack splitter emits (tens of GiB), so no real
	// layer reaches it, while keeping every size far from int64 and uint64 wrap.
	MaxLayerBytes int64 = 256 << 30
	// MaxArtifactBytes caps the declared total of one artifact: 1 TiB, above
	// the largest open-weight model in bf16 (about 800 GB) and far below any
	// sum that can wrap; 4096 layers at the per-layer cap could otherwise
	// declare a petabyte.
	MaxArtifactBytes int64 = 1 << 40
	// DefaultMaxConcurrentLayers is how many layers transfer at once.
	DefaultMaxConcurrentLayers = 2
	// DefaultStallTimeout is how long a blob transfer may go without one byte
	// arriving, from the request (the response headers included) to the end of
	// the body, before it fails. It is an idle bound, never a deadline: a
	// transfer that keeps moving runs as long as it needs (a 40 GB model over a
	// slow link takes many minutes). A manifest, at most MaxManifestBytes, must
	// arrive whole within it.
	DefaultStallTimeout = 60 * time.Second
)

// Media types the manifest-level checks name.
const (
	mediaTypeOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex        = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerConfig    = "application/vnd.docker.container.image.v1+json"
	annotationTitle          = "org.opencontainers.image.title"
	annotationFilepathModern = artifactv1.AnnotationFilepath
)

// Refusals. Each is a sentinel so the gRPC layer and the provider classify with
// errors.Is, never by message text.
var (
	ErrNotClusterRegistry = errors.New("artifact: reference does not name the cluster registry")
	ErrInvalidReference   = errors.New("artifact: reference does not parse")
	ErrManifestTooLarge   = errors.New("artifact: manifest exceeds its size cap")
	ErrManifestInvalid    = errors.New("artifact: manifest is malformed")
	ErrManifestDigest     = errors.New("artifact: manifest does not match the digest the reference names")
	ErrIndexRefused       = errors.New("artifact: an index is refused; name one manifest")
	ErrImageNotArtifact   = errors.New("artifact: an OCI image is not an artifact")
	ErrTypeRefused        = errors.New("artifact: artifact type is not in the allow-set")
	ErrTarLayer           = errors.New("artifact: tar layers are refused")
	ErrLayerTypeRefused   = errors.New("artifact: layer media type is not in the allow-set")
	ErrTooManyLayers      = errors.New("artifact: too many layers")
	ErrNoLayers           = errors.New("artifact: manifest has no layers")
	ErrLayerPath          = errors.New("artifact: layer file path is missing or invalid")
	ErrPathNotInArtifact  = errors.New("artifact: requested path is not in the artifact")
	ErrInsufficientSpace  = errors.New("artifact: refusing the pull, the store volume would fall below its free-space floor")
	ErrBlobTransfer       = errors.New("artifact: blob transfer failed")
	ErrBlobStalled        = errors.New("artifact: blob transfer stalled, no byte arrived within the stall timeout")
	ErrManifestStalled    = errors.New("artifact: manifest fetch did not complete within the stall timeout")
	ErrSizeCap            = errors.New("artifact: declared size exceeds its cap")
	ErrSizeOverflow       = errors.New("artifact: space arithmetic overflows")
	ErrPartialDir         = errors.New("artifact: partial dir is not the private cache child")
)

// BlobCommitter is the cache seam: *image.Cache satisfies it. CommitBlob is the
// one home of the re-hash invariant; Has is the cache-hit test.
type BlobCommitter interface {
	Has(digest string) bool
	CommitBlob(digest string, size int64, fill func(io.Writer) error) (bool, error)
}

// Leaser pins digests against reclaim while a pull is in flight; *image.Cache
// satisfies it.
type Leaser interface {
	AcquireLease(digests []string, ttl time.Duration) *image.Lease
}

// Reclaimer runs one disk-pressure reclaim pass; *image.Cache satisfies it.
type Reclaimer interface {
	ReclaimUnderPressure(ctx context.Context, cfg image.ReclaimConfig) (*image.ReclaimReport, error)
}

// Recorder stores artifact records in the index's artifact namespace;
// *image.FileIndex satisfies it.
type Recorder interface {
	PutArtifactRecord(ctx context.Context, key string, record []byte) error
	ArtifactRecord(ctx context.Context, key string) ([]byte, bool, error)
}

// Fetcher is the transport seam. Production is RegistryFetcher; tests fake it.
type Fetcher interface {
	// Manifest returns the manifest bytes ref names and the media type the
	// registry served them as. It must return at most MaxManifestBytes+1 bytes.
	Manifest(ctx context.Context, ref string, cred *image.RegistryCredential) (raw []byte, mediaType string, err error)
	// Blob opens the blob digest in ref's repository from offset. It returns the
	// offset the body actually starts at: offset for a honoured Range, 0 when
	// the server sent the whole blob.
	Blob(ctx context.Context, ref string, cred *image.RegistryCredential, digest string, offset int64) (body io.ReadCloser, start int64, err error)
}

// Config configures a Puller.
type Config struct {
	// RegistryHost is the cluster registry authority (host:port). A reference
	// naming any other host is refused before any request. Required.
	RegistryHost string
	// PartialDir holds resumable partial blobs. It must be exactly
	// <StorePath>/<sandbox.ArtifactPartialSubdir>: the one child of the cache
	// root the work-dir deny-set names, so it is on the cache volume and no pod
	// can read or write it. Required.
	PartialDir string
	// StorePath is the cache root: the parent of PartialDir and the path whose
	// volume free space is measured. Required, absolute.
	StorePath string
	// FreeBytes samples free space. Nil means image.StatfsFreeBytes.
	FreeBytes image.FreeBytesFunc
	// FloorBytes is the free space a pull must leave. Zero means
	// image.DefaultReclaimHighFreeBytes, the reclaim floor.
	FloorBytes uint64
	// MaxConcurrentLayers bounds layer transfers. Zero means 2.
	MaxConcurrentLayers int
	// StallTimeout fails a blob transfer that receives no byte for this long
	// (ErrBlobStalled, which is also ErrBlobTransfer, so a retry resumes it).
	// Zero means DefaultStallTimeout.
	StallTimeout time.Duration
	// Log receives progress. Nil discards.
	Log *slog.Logger

	// afterFunc arms the stall timer; nil means time.AfterFunc. A test seam.
	afterFunc func(d time.Duration, f func()) idleTimer
}

// idleTimer is the part of *time.Timer the stall watchdog uses.
type idleTimer interface {
	Reset(d time.Duration) bool
	Stop() bool
}

// Deps are the seams a Puller consumes.
type Deps struct {
	Blobs     BlobCommitter
	Leases    Leaser
	Reclaimer Reclaimer
	Index     Recorder
	Fetcher   Fetcher
}

// Puller fetches artifacts. It is safe for concurrent use.
type Puller struct {
	cfg  Config
	deps Deps
	log  *slog.Logger
	sem  chan struct{}

	// resv is the in-process space reservation shared by concurrent pulls.
	resv reservations

	// inflightMu guards inflight: the digests some pull is transferring now,
	// each with a channel closed when that transfer ends, so two pulls never
	// write one partial file at once.
	inflightMu sync.Mutex
	inflight   map[string]chan struct{}

	// recordStripes serialize the read-modify-write of one record key (see
	// record), so concurrent subset pulls of one manifest never lose a layer.
	recordStripes [32]sync.Mutex
}

// New returns a Puller.
func New(cfg Config, deps Deps) (*Puller, error) {
	if cfg.RegistryHost == "" {
		return nil, errors.New("artifact puller: cluster registry host is required")
	}
	if err := checkPartialPlacement(cfg.PartialDir, cfg.StorePath); err != nil {
		return nil, err
	}
	if deps.Blobs == nil || deps.Leases == nil || deps.Reclaimer == nil || deps.Index == nil || deps.Fetcher == nil {
		return nil, errors.New("artifact puller: every dependency is required")
	}
	if cfg.FreeBytes == nil {
		cfg.FreeBytes = image.StatfsFreeBytes
	}
	if cfg.FloorBytes == 0 {
		cfg.FloorBytes = image.DefaultReclaimHighFreeBytes
	}
	if cfg.MaxConcurrentLayers <= 0 {
		cfg.MaxConcurrentLayers = DefaultMaxConcurrentLayers
	}
	if cfg.StallTimeout <= 0 {
		cfg.StallTimeout = DefaultStallTimeout
	}
	if cfg.afterFunc == nil {
		cfg.afterFunc = func(d time.Duration, f func()) idleTimer { return time.AfterFunc(d, f) }
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Puller{
		cfg:      cfg,
		deps:     deps,
		log:      log,
		sem:      make(chan struct{}, cfg.MaxConcurrentLayers),
		inflight: make(map[string]chan struct{}),
	}, nil
}

// checkPartialPlacement refuses a partial dir that is not exactly the
// ArtifactPartialSubdir child of the absolute store path. Anywhere else is
// outside the work-dir deny-set (a pod could read weights mid-transfer or make
// every resume fail its digest) or off the cache volume.
func checkPartialPlacement(partial, store string) error {
	if partial == "" || store == "" {
		return fmt.Errorf("%w: partial dir and store path are required", ErrPartialDir)
	}
	if !filepath.IsAbs(store) {
		return fmt.Errorf("%w: store path %q is not absolute", ErrPartialDir, store)
	}
	want := filepath.Join(filepath.Clean(store), sandbox.ArtifactPartialSubdir)
	if filepath.Clean(partial) != want {
		return fmt.Errorf("%w: %q, want %q", ErrPartialDir, partial, want)
	}
	return nil
}

// Result is what a pull resolved and committed.
type Result struct {
	// ManifestDigest is the resolved manifest digest; callers mount by it.
	ManifestDigest string
	// ArtifactType is the resolved artifact type.
	ArtifactType string
	// ConfigDigest is the manifest's config blob.
	ConfigDigest string
	// LayerDigests are the layers committed for the request, in manifest order.
	LayerDigests []string
	// Paths are the file paths of LayerDigests, index for index.
	Paths []string
	// Fetched reports whether any byte was transferred.
	Fetched bool
	// Lease pins the committed blobs until the caller releases it.
	Lease *image.Lease
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	ArtifactType  string       `json:"artifactType,omitempty"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests,omitempty"`
}

var sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// blob is one blob a pull must hold: the config or a selected layer.
type blob struct {
	digest string
	size   int64
}

// PullArtifact fetches the artifact ref names into the node cache under the
// allow-set policy selects, restricted to paths when non-empty, and records it
// once every requested blob is committed. It is idempotent: blobs already
// cached are not fetched again.
//
// It is the operator's pull: the record it writes is pinned (Record.PodOnly
// false) and stays a root until it is removed (Views.Forget).
func (p *Puller) PullArtifact(ctx context.Context, ref string, cred *image.RegistryCredential, policy runtimev1.ArtifactPolicy, paths []string) (*Result, error) {
	return p.pull(ctx, ref, cred, policy, paths, false)
}

// PullForPod is PullArtifact for a pod's image volume. The record it writes is
// PodOnly unless the operator already pinned the key, so it is released when
// no pod holds the reference any more (Views.ReleasePodOnly). It never unpins
// an operator's record.
func (p *Puller) PullForPod(ctx context.Context, ref string, cred *image.RegistryCredential, policy runtimev1.ArtifactPolicy, paths []string) (*Result, error) {
	return p.pull(ctx, ref, cred, policy, paths, true)
}

func (p *Puller) pull(ctx context.Context, ref string, cred *image.RegistryCredential, policy runtimev1.ArtifactPolicy, paths []string, podOnly bool) (*Result, error) {
	allow, err := artifactv1.AllowSetFor(policy)
	if err != nil {
		return nil, err
	}
	if len(paths) > 0 {
		if err := artifactv1.ValidatePathSet(paths); err != nil {
			return nil, fmt.Errorf("requested paths: %w", err)
		}
	}
	if err := p.CheckHost(ref); err != nil {
		return nil, err
	}

	raw, served, err := p.fetchManifest(ctx, ref, cred)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest of %d bytes, at most %d: %w", len(raw), MaxManifestBytes, ErrManifestTooLarge)
	}
	sum := sha256.Sum256(raw)
	mdigest := "sha256:" + hex.EncodeToString(sum[:])
	if want, ok := digestOf(ref); ok && want != mdigest {
		return nil, fmt.Errorf("manifest hashed to %s, reference names %s: %w", mdigest, want, ErrManifestDigest)
	}
	m, err := parseManifest(raw, served)
	if err != nil {
		return nil, err
	}
	typ, layers, layerPaths, err := checkManifest(m, allow)
	if err != nil {
		return nil, err
	}

	// Select the requested subset, in manifest order.
	selected := make([]int, 0, len(layers))
	if len(paths) == 0 {
		for i := range layers {
			selected = append(selected, i)
		}
	} else {
		at := make(map[string]int, len(layerPaths))
		for i, lp := range layerPaths {
			at[lp] = i
		}
		for _, want := range paths {
			if _, ok := at[want]; !ok {
				return nil, fmt.Errorf("%q: %w", want, ErrPathNotInArtifact)
			}
		}
		for i, lp := range layerPaths {
			if slices.Contains(paths, lp) {
				selected = append(selected, i)
			}
		}
	}

	need := []blob{{digest: m.Config.Digest, size: m.Config.Size}}
	res := &Result{ManifestDigest: mdigest, ArtifactType: typ, ConfigDigest: m.Config.Digest}
	for _, i := range selected {
		need = append(need, blob{digest: layers[i].Digest, size: layers[i].Size})
		res.LayerDigests = append(res.LayerDigests, layers[i].Digest)
		res.Paths = append(res.Paths, layerPaths[i])
	}
	need = dedupe(need)

	digests := make([]string, 0, len(need))
	for _, b := range need {
		digests = append(digests, b.digest)
	}
	// The lease is taken over the whole set BEFORE the presence check, for the
	// reason image.Lease gives: a cache hit writes nothing, so it is exactly the
	// blob old enough for a reclaim pass to take.
	lease := p.deps.Leases.AcquireLease(digests, 0)
	ok := false
	defer func() {
		if !ok {
			lease.Release()
		}
	}()

	var missing []blob
	for _, b := range need {
		if !p.deps.Blobs.Has(b.digest) {
			missing = append(missing, b)
		}
	}
	if len(missing) > 0 {
		r, err := p.reserve(ctx, missing)
		if err != nil {
			return nil, err
		}
		err = p.fetchAll(ctx, ref, cred, missing, r)
		r.release()
		if err != nil {
			return nil, err
		}
		res.Fetched = true
	}
	if err := p.record(ctx, ref, typ, mdigest, raw, m.Config.Digest, res.LayerDigests, podOnly); err != nil {
		return nil, err
	}
	p.log.Info("artifact pulled", "reference", ref, "digest", mdigest, "type", typ,
		"layers", len(res.LayerDigests), "fetched", res.Fetched)
	res.Lease = lease
	ok = true
	return res, nil
}

// fetchManifest fetches ref's manifest under the stall timeout as a whole: a
// manifest is at most MaxManifestBytes, so a registry that has not answered
// with all of it by then is stalled (ErrManifestStalled, also ErrBlobTransfer,
// so a retry is invited). The blob transfers carry their own idle bound.
func (p *Puller) fetchManifest(ctx context.Context, ref string, cred *image.RegistryCredential) ([]byte, string, error) {
	mctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stall := p.cfg.StallTimeout
	timer := p.cfg.afterFunc(stall, func() { cancel(ErrManifestStalled) })
	defer timer.Stop()
	raw, served, err := p.deps.Fetcher.Manifest(mctx, ref, cred)
	if err == nil {
		return raw, served, nil
	}
	if ctx.Err() == nil && errors.Is(context.Cause(mctx), ErrManifestStalled) {
		return nil, "", fmt.Errorf("fetch manifest %s: not complete within %v: %w: %w", image.QuoteBounded(ref, 512), stall, ErrBlobTransfer, ErrManifestStalled)
	}
	return nil, "", fmt.Errorf("fetch manifest %s: %w", image.QuoteBounded(ref, 512), bound(err))
}

// CheckHost refuses a reference whose registry is not the cluster registry.
// It parses locally and makes no request, so a caller can run it before it
// resolves any credential for the reference.
func (p *Puller) CheckHost(ref string) error {
	r, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return fmt.Errorf("%s: %w: %w", image.QuoteBounded(ref, 512), ErrInvalidReference, bound(err))
	}
	got := r.Context().RegistryStr()
	if !strings.EqualFold(got, p.cfg.RegistryHost) {
		return fmt.Errorf("%s names %s, not %s: %w", image.QuoteBounded(ref, 512),
			image.QuoteBounded(got, 256), p.cfg.RegistryHost, ErrNotClusterRegistry)
	}
	return nil
}

// digestOf returns the digest a by-digest reference names.
func digestOf(ref string) (string, bool) {
	i := strings.LastIndex(ref, "@")
	if i < 0 {
		return "", false
	}
	return ref[i+1:], true
}

// parseManifest decodes raw and refuses anything but a single OCI manifest.
func parseManifest(raw []byte, served string) (*manifest, error) {
	served, _, _ = strings.Cut(served, ";")
	served = strings.TrimSpace(served)
	switch served {
	case mediaTypeOCIIndex, mediaTypeDockerList:
		return nil, fmt.Errorf("served as %s: %w", served, ErrIndexRefused)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if m.MediaType == mediaTypeOCIIndex || m.MediaType == mediaTypeDockerList || len(m.Manifests) > 0 {
		return nil, ErrIndexRefused
	}
	if m.SchemaVersion != 2 {
		return nil, fmt.Errorf("%w: schemaVersion %d", ErrManifestInvalid, m.SchemaVersion)
	}
	if m.MediaType == mediaTypeDockerManifest || served == mediaTypeDockerManifest {
		return nil, fmt.Errorf("a docker image manifest: %w", ErrImageNotArtifact)
	}
	if m.MediaType != "" && m.MediaType != mediaTypeOCIManifest {
		return nil, fmt.Errorf("%w: mediaType %s", ErrManifestInvalid, image.QuoteBounded(m.MediaType, 256))
	}
	if served != "" && served != mediaTypeOCIManifest {
		return nil, fmt.Errorf("%w: served as %s", ErrManifestInvalid, image.QuoteBounded(served, 256))
	}
	return &m, nil
}

// checkManifest applies the type, layer and path rules. It returns the
// artifact type, the layers and each layer's file path.
func checkManifest(m *manifest, allow artifactv1.AllowSet) (string, []descriptor, []string, error) {
	if m.Config.MediaType == artifactv1.MediaTypeOCIImageConfig || m.Config.MediaType == mediaTypeDockerConfig {
		return "", nil, nil, fmt.Errorf("config %s: %w", m.Config.MediaType, ErrImageNotArtifact)
	}
	typ := artifactv1.ArtifactType(m.ArtifactType, m.Config.MediaType)
	if typ == artifactv1.MediaTypeOCIImageConfig {
		return "", nil, nil, ErrImageNotArtifact
	}
	if !allow.AllowsType(typ) {
		return "", nil, nil, fmt.Errorf("%s under %s: %w", image.QuoteBounded(typ, 256), allow.Name(), ErrTypeRefused)
	}
	if err := checkDescriptor("config", m.Config); err != nil {
		return "", nil, nil, err
	}
	if len(m.Layers) > MaxLayers {
		return "", nil, nil, fmt.Errorf("%d layers, at most %d: %w", len(m.Layers), MaxLayers, ErrTooManyLayers)
	}
	if len(m.Layers) == 0 {
		return "", nil, nil, ErrNoLayers
	}
	// Every declared size is capped (checkDescriptor) before it is summed, so
	// this total of at most MaxLayers+1 capped terms cannot wrap.
	total := m.Config.Size
	paths := make([]string, len(m.Layers))
	for i, l := range m.Layers {
		if tarLayer(l.MediaType) {
			return "", nil, nil, fmt.Errorf("layer %d %s: %w", i, image.QuoteBounded(l.MediaType, 256), ErrTarLayer)
		}
		if !allow.AllowsLayer(typ, l.MediaType) {
			return "", nil, nil, fmt.Errorf("layer %d %s for %s: %w", i, image.QuoteBounded(l.MediaType, 256), typ, ErrLayerTypeRefused)
		}
		if err := checkDescriptor(fmt.Sprintf("layer %d", i), l); err != nil {
			return "", nil, nil, err
		}
		total += l.Size
		if total > MaxArtifactBytes {
			return "", nil, nil, fmt.Errorf("declared total over %d bytes: %w", MaxArtifactBytes, ErrSizeCap)
		}
		p, err := layerFilePath(i, l)
		if err != nil {
			return "", nil, nil, err
		}
		paths[i] = p
	}
	if err := artifactv1.ValidatePathSet(paths); err != nil {
		return "", nil, nil, fmt.Errorf("%w: %w", ErrLayerPath, err)
	}
	return typ, m.Layers, paths, nil
}

// layerFilePath returns layer i's validated file path: the ModelPack filepath
// annotation, else the OCI title.
func layerFilePath(i int, l descriptor) (string, error) {
	p := l.Annotations[annotationFilepathModern]
	if p == "" {
		p = l.Annotations[annotationTitle]
	}
	if p == "" {
		return "", fmt.Errorf("layer %d has no file path: %w", i, ErrLayerPath)
	}
	if err := artifactv1.ValidatePath(p); err != nil {
		return "", fmt.Errorf("layer %d: %w: %w", i, ErrLayerPath, err)
	}
	return p, nil
}

func checkDescriptor(what string, d descriptor) error {
	if !sha256Digest.MatchString(d.Digest) {
		return fmt.Errorf("%s digest %s: %w", what, image.QuoteBounded(d.Digest, 128), ErrManifestInvalid)
	}
	if d.Size < 0 {
		return fmt.Errorf("%s size %d: %w", what, d.Size, ErrManifestInvalid)
	}
	if d.Size > MaxLayerBytes {
		return fmt.Errorf("%s declares %d bytes, at most %d: %w", what, d.Size, MaxLayerBytes, ErrSizeCap)
	}
	return nil
}

// maxForeignErrBytes bounds foreign (registry, transport) error text carried
// in an error this package returns; it reaches the gRPC status and the log.
const maxForeignErrBytes = 512

// boundedError renders a foreign error bounded and ASCII-quoted, keeping the
// cause visible to errors.Is (the image package's boundErr convention).
type boundedError struct{ err error }

func (e *boundedError) Error() string { return image.QuoteBounded(e.err.Error(), maxForeignErrBytes) }
func (e *boundedError) Unwrap() error { return e.err }

func bound(err error) error {
	if err == nil {
		return nil
	}
	return &boundedError{err: err}
}

// tarLayer reports an archive layer type, which needs an extractor (a
// decompressor of untrusted input) and is refused in v1.
func tarLayer(mt string) bool {
	return strings.HasSuffix(mt, ".tar") || strings.Contains(mt, ".tar+") ||
		strings.HasSuffix(mt, "+gzip") || strings.HasSuffix(mt, "+zstd")
}

func dedupe(bs []blob) []blob {
	seen := make(map[string]bool, len(bs))
	out := bs[:0]
	for _, b := range bs {
		if seen[b.digest] {
			continue
		}
		seen[b.digest] = true
		out = append(out, b)
	}
	return out
}

// Key returns the artifact-namespace index key for ref and its artifact type.
func Key(ref, artifactType string) string { return ref + "@" + artifactType }

// recordSchema is the on-disk version of an artifact record.
const recordSchema = 1

// Record is the on-disk artifact record.
type Record struct {
	Schema         int      `json:"schema"`
	Key            string   `json:"key"`
	Reference      string   `json:"reference"`
	ArtifactType   string   `json:"artifactType"`
	ManifestDigest string   `json:"manifestDigest"`
	ManifestRaw    []byte   `json:"manifestRaw"`
	ConfigDigest   string   `json:"configDigest"`
	LayerDigests   []string `json:"layerDigests"`
	// PodOnly marks a record only pods' image volumes asked for. It is
	// released when no pod holds its reference (Views.ReleasePodOnly). A
	// record without it, every record an operator pull wrote or touched and
	// every record older than the field, is pinned.
	PodOnly bool `json:"podOnly,omitempty"`
}

// record writes the artifact record. A previous record of the same manifest
// keeps its committed layers (a later subset pull widens, never narrows, what
// the record names); a record of another manifest is replaced. A pinned key
// stays pinned: podOnly holds only if the previous record, of any manifest,
// was PodOnly too, and an unreadable previous record pins.
func (p *Puller) record(ctx context.Context, ref, typ, mdigest string, raw []byte, config string, layers []string, podOnly bool) error {
	key := Key(ref, typ)
	h := fnv.New32a()
	_, _ = h.Write([]byte(key)) // hash.Hash.Write never returns an error
	mu := &p.recordStripes[h.Sum32()%uint32(len(p.recordStripes))]
	mu.Lock()
	defer mu.Unlock()
	have := append([]string(nil), layers...)
	old, ok, err := p.LookupRecord(ctx, ref, typ)
	if err == nil && ok && old.ManifestDigest == mdigest {
		have = append(have, old.LayerDigests...)
	}
	if err != nil || (ok && !old.PodOnly) {
		podOnly = false
	}
	sort.Strings(have)
	have = slices.Compact(have)
	buf, err := json.Marshal(Record{
		Schema: recordSchema, Key: key, Reference: ref, ArtifactType: typ,
		ManifestDigest: mdigest, ManifestRaw: raw, ConfigDigest: config, LayerDigests: have,
		PodOnly: podOnly,
	})
	if err != nil {
		return fmt.Errorf("encode artifact record: %w", err)
	}
	if err := p.deps.Index.PutArtifactRecord(ctx, key, buf); err != nil {
		return fmt.Errorf("record artifact %s: %w", image.QuoteBounded(ref, 512), err)
	}
	return nil
}

// LookupRecord returns the record for ref and artifactType. A record whose
// own key disagrees with the key it was found under is an error.
func (p *Puller) LookupRecord(ctx context.Context, ref, artifactType string) (*Record, bool, error) {
	key := Key(ref, artifactType)
	buf, ok, err := p.deps.Index.ArtifactRecord(ctx, key)
	if err != nil || !ok {
		return nil, false, err
	}
	var r Record
	if err := json.Unmarshal(buf, &r); err != nil {
		return nil, false, fmt.Errorf("%w: artifact record: %v", image.ErrIndexEntryCorrupt, err)
	}
	if r.Schema != recordSchema || r.Key != key {
		return nil, false, fmt.Errorf("%w: artifact record for %q found under %q", image.ErrIndexEntryCorrupt, r.Key, key)
	}
	return &r, true, nil
}
