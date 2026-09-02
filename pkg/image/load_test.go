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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// recordingIndex is a LocalIndex that records what an ingest recorded and, via
// onRecord, lets a test observe the STORE state at the instant the reference is
// written — the one moment the load's phase ordering is externally visible.
type recordingIndex struct {
	refs     map[string]*runtimev1.ImageManifest
	entries  map[string]IndexEntry
	platform Platform
	records  int
	err      error
	onRecord func()
}

func newRecordingIndex() *recordingIndex {
	return &recordingIndex{
		refs:    make(map[string]*runtimev1.ImageManifest),
		entries: make(map[string]IndexEntry),
	}
}

func (r *recordingIndex) Lookup(context.Context, string, PlatformPolicy) (IndexEntry, bool, error) {
	return IndexEntry{}, false, nil
}

func (r *recordingIndex) Record(_ context.Context, e IndexEntry) error {
	if r.onRecord != nil {
		r.onRecord()
	}
	if r.err != nil {
		return r.err
	}
	r.records++
	r.platform = e.Platform
	r.refs[e.Reference] = e.Manifest
	r.entries[e.Reference] = e
	return nil
}

// ociSpec describes an OCI-layout fixture. The archive is HAND-built rather than
// produced by a library so a test can state a claim the bytes do not satisfy:
// the whole point of the OCI leg is that a blob's digest is claimed by a
// manifest one level above the bytes, and no round-tripping writer will ever
// emit that disagreement.
type ociSpec struct {
	// config is the image config JSON (its digest is claimed by the manifest).
	config []byte
	// layers are the layer blobs whose digests the manifest claims.
	layers [][]byte
	// poison replaces the bytes stored at layer i's claimed blob path, leaving
	// the manifest's claim about that layer untouched.
	poison map[int][]byte
	// manifests, when > 1, makes index.json name that many manifests (the
	// multi-image refusal).
	manifests int
	// foreignLayer marks layer 0's descriptor with a URL (the foreign-layer
	// refusal).
	foreignLayer bool
}

// nativeConfig is a minimal image config declaring the node's own platform.
func nativeConfig(t *testing.T) []byte {
	t.Helper()
	buf, err := json.Marshal(ggcrv1.ConfigFile{
		OS:           "darwin",
		Architecture: "arm64",
		RootFS:       ggcrv1.RootFS{Type: "layers"},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return buf
}

// ggcrHash is the parsed sha256 of some bytes.
func ggcrHash(t *testing.T, b []byte) ggcrv1.Hash {
	t.Helper()
	sum := sha256.Sum256(b)
	h, err := ggcrv1.NewHash("sha256:" + hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("parse hash: %v", err)
	}
	return h
}

// buildOCIArchive renders spec as a tarred OCI image layout and returns the tar
// bytes plus the manifest's digest.
func buildOCIArchive(t *testing.T, spec ociSpec) (archive []byte, manifestDigest string) {
	t.Helper()
	mfst := ggcrv1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: ggcrv1.Descriptor{
			MediaType: types.OCIConfigJSON,
			Digest:    ggcrHash(t, spec.config),
			Size:      int64(len(spec.config)),
		},
	}
	for i, l := range spec.layers {
		d := ggcrv1.Descriptor{
			MediaType: types.OCILayer,
			Digest:    ggcrHash(t, l),
			Size:      int64(len(l)),
		}
		if i == 0 && spec.foreignLayer {
			d.URLs = []string{"https://example.invalid/layer"}
		}
		mfst.Layers = append(mfst.Layers, d)
	}
	rawMfst, err := json.Marshal(mfst)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	idx := ggcrv1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex}
	n := spec.manifests
	if n == 0 {
		n = 1
	}
	for range n {
		idx.Manifests = append(idx.Manifests, ggcrv1.Descriptor{
			MediaType: types.OCIManifestSchema1,
			Digest:    ggcrHash(t, rawMfst),
			Size:      int64(len(rawMfst)),
		})
	}
	rawIdx, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, body []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	blobName := func(h ggcrv1.Hash) string { return "blobs/" + h.Algorithm + "/" + h.Hex }

	write("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	write("index.json", rawIdx)
	write(blobName(ggcrHash(t, rawMfst)), rawMfst)
	write(blobName(mfst.Config.Digest), spec.config)
	for i, l := range spec.layers {
		stored := l
		if p, ok := spec.poison[i]; ok {
			stored = p
		}
		// The NAME stays the claimed digest's path; only the bytes differ.
		write(blobName(mfst.Layers[i].Digest), stored)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes(), ggcrHash(t, rawMfst).String()
}

// dockerSaveArchive renders img as a `docker save` tar under the given tags.
func dockerSaveArchive(t *testing.T, img ggcrv1.Image, tags ...string) []byte {
	t.Helper()
	refs := make(map[name.Reference]ggcrv1.Image, len(tags))
	for _, tg := range tags {
		ref, err := name.NewTag(tg)
		if err != nil {
			t.Fatalf("parse tag %q: %v", tg, err)
		}
		refs[ref] = img
	}
	var buf bytes.Buffer
	if err := tarball.MultiRefWrite(refs, &buf); err != nil {
		t.Fatalf("tarball.MultiRefWrite: %v", err)
	}
	return buf.Bytes()
}

// mustLoader builds a Loader or fails the test.
func mustLoader(t *testing.T, c *Cache, idx LocalIndex) *Loader {
	t.Helper()
	l, err := NewLoader(c, idx)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return l
}

// contentBlobs is every content-addressed blob currently in the store.
func contentBlobs(t *testing.T, c *Cache) []BlobNode {
	t.Helper()
	nodes, err := c.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	return nodes
}

// TestLoadImageRehashBeforeLeaseCommit is B169's named gate: an ingest must
// re-hash every blob against the digest its archive's manifest CLAIMS, and it
// must do so before any lease is taken and any blob is committed — not as a
// post-hoc rollback.
//
// The fixture is an OCI LAYOUT, deliberately. On the docker-save leg the claimed
// digest is synthesized from the very bytes being checked, so the comparison is
// a tautology that cannot fail (Cache.CommitBlob, "what this defends against,
// honestly"). Only a layout can state a claim its bytes contradict, which is the
// disagreement this gate is about.
//
// # Which assertion kills which wrong implementation
//
//   - "the poisoned blob is absent" alone would not be enough: an implementation
//     that commits first and unlinks on mismatch ends in the same state.
//   - "the GOOD blobs are absent too" is the discriminator. A verify-after-commit
//     implementation — and equally a verify-per-blob-then-commit loop — has
//     already committed the config and the first, valid, layer by the time it
//     reaches the bad one, so the store is non-empty afterwards and this gate
//     goes red.
//   - "no lease" and "no reference recorded" pin the other half of the ordering:
//     the lease is taken only once every blob has verified, and the reference is
//     written only after every blob is committed.
func TestLoadImageRehashBeforeLeaseCommit(t *testing.T) {
	cfg := nativeConfig(t)
	good := []byte("layer-zero-bytes")
	claimed := []byte("layer-one-bytes-as-claimed")
	substituted := []byte("layer-one-bytes-SUBSTITUTE")
	// same length as the claim on purpose: a longer substitution would trip the
	// declared-size resource guard (ErrBlobTooLarge) first, and the verdict under
	// test here is the DIGEST comparison, not the size cap.
	if len(substituted) != len(claimed) {
		t.Fatalf("fixture bug: substituted bytes are %d long, claim is %d", len(substituted), len(claimed))
	}
	archive, _ := buildOCIArchive(t, ociSpec{
		config: cfg,
		layers: [][]byte{good, claimed},
		// Layer 1's stored bytes are not what its descriptor claims.
		poison: map[int][]byte{1: substituted},
	})

	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	idx := newRecordingIndex()
	l := mustLoader(t, cache, idx)

	res, err := l.Load(context.Background(), LoadRequest{
		Reference: "example.com/app:v1",
		Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
	}, bytes.NewReader(archive))
	if err == nil {
		t.Fatalf("a digest-mismatched archive was ADMITTED: %+v", res)
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("load error = %v; want it to wrap ErrDigestMismatch", err)
	}

	// (1) The poisoned blob is in the store under neither its claimed digest nor
	// the digest its bytes actually hash to.
	claimedDigest := ggcrHash(t, claimed).String()
	substitutedDigest := ggcrHash(t, substituted).String()
	if cache.Has(claimedDigest) {
		t.Errorf("the poisoned blob was admitted under its CLAIMED digest %s", claimedDigest)
	}
	if cache.Has(substitutedDigest) {
		t.Errorf("the poisoned blob was admitted under the digest its bytes hash to (%s)", substitutedDigest)
	}

	// (2) the DISCRIMINATOR: nothing at all was committed. The config and the
	// valid layer precede the bad one in manifest order, so any implementation
	// that verifies per blob AS it commits (or after) leaves them behind.
	if nodes := contentBlobs(t, cache); len(nodes) != 0 {
		t.Errorf("a rejected load left %d node(s) in the blob store: %+v; a mismatch must commit NOTHING", len(nodes), nodes)
	}
	if cache.Has(ggcrHash(t, cfg).String()) {
		t.Error("the config blob was committed before the mismatch was detected")
	}
	if cache.Has(ggcrHash(t, good).String()) {
		t.Error("the first (valid) layer was committed before the mismatch was detected")
	}

	// (3) No lease survives, and none was ever needed: the lease is taken only
	// after every blob has verified.
	if leased := cache.leasedDigests(); len(leased) != 0 {
		t.Errorf("a rejected load left %d leased digest(s): %v", len(leased), leased)
	}

	// (4) No reference was recorded — the root/ref is written last, after every
	// blob is committed.
	if idx.records != 0 {
		t.Errorf("a rejected load recorded %d reference(s): %v", idx.records, idx.refs)
	}
}

// TestLoadImageOrdersLeaseBlobsThenReference is the positive half of the
// ordering contract: on a successful load the reference is recorded only after
// every blob is committed, and the lease is still held at that instant.
//
// It observes the one moment the ordering is externally visible — the Record
// call — through the index seam, which is how the package's other tests reach
// the puller's internal sequencing.
func TestLoadImageOrdersLeaseBlobsThenReference(t *testing.T) {
	cfg := nativeConfig(t)
	layers := [][]byte{[]byte("layer-a"), []byte("layer-b")}
	archive, mfstDigest := buildOCIArchive(t, ociSpec{config: cfg, layers: layers})

	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ggcrHash(t, cfg).String()}
	for _, l := range layers {
		want = append(want, ggcrHash(t, l).String())
	}

	idx := newRecordingIndex()
	var blobsAtRecord, leasedAtRecord int
	idx.onRecord = func() {
		for _, d := range want {
			if cache.Has(d) {
				blobsAtRecord++
			}
		}
		leasedAtRecord = len(cache.leasedDigests())
	}
	l := mustLoader(t, cache, idx)

	res, err := l.Load(context.Background(), LoadRequest{
		Reference: "example.com/app:v1",
		Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
	}, bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if blobsAtRecord != len(want) {
		t.Errorf("%d of %d blobs were committed when the reference was recorded; the ref must be written LAST",
			blobsAtRecord, len(want))
	}
	if leasedAtRecord == 0 {
		t.Error("the lease was already released when the reference was recorded; it must cover the whole window")
	}
	if leased := cache.leasedDigests(); len(leased) != 0 {
		t.Errorf("the lease outlived the completed load: %v", leased)
	}
	if res.Descriptor.GetDigest() != mfstDigest {
		t.Errorf("reported image digest %q, want the manifest digest %q", res.Descriptor.GetDigest(), mfstDigest)
	}
}

// TestLoadImageIngestsArchives drives the two archive formats and the refusals,
// asserting the store state each outcome must leave behind.
func TestLoadImageIngestsArchives(t *testing.T) {
	t.Run("OCI layout ingests every blob digest-addressed and records the reference", func(t *testing.T) {
		cfg := nativeConfig(t)
		layers := [][]byte{[]byte("oci-layer-a"), []byte("oci-layer-b")}
		archive, mfstDigest := buildOCIArchive(t, ociSpec{config: cfg, layers: layers})

		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		idx := newRecordingIndex()
		l := mustLoader(t, cache, idx)

		res, err := l.Load(context.Background(), LoadRequest{
			Reference: "example.com/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
			Size:      int64(len(archive)),
			Digest:    digestOf(archive),
		}, bytes.NewReader(archive))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if got := res.Manifest.GetConfig().GetDigest(); got != ggcrHash(t, cfg).String() {
			t.Errorf("recorded config digest %q, want %q", got, ggcrHash(t, cfg).String())
		}
		if len(res.Manifest.GetLayers()) != len(layers) {
			t.Fatalf("recorded %d layers, want %d", len(res.Manifest.GetLayers()), len(layers))
		}
		for i, l := range layers {
			want := ggcrHash(t, l).String()
			if got := res.Manifest.GetLayers()[i].GetDigest(); got != want {
				t.Errorf("layer %d recorded as %q, want %q", i, got, want)
			}
			if !cache.Has(want) {
				t.Errorf("layer %d (%s) is not in the content-addressed store", i, want)
			}
		}
		if !cache.Has(res.Manifest.GetConfig().GetDigest()) {
			t.Error("the config blob is not in the content-addressed store")
		}
		if res.Descriptor.GetDigest() != mfstDigest {
			t.Errorf("image digest %q, want %q", res.Descriptor.GetDigest(), mfstDigest)
		}
		if res.ReceivedBytes != int64(len(archive)) {
			t.Errorf("received %d bytes, want %d", res.ReceivedBytes, len(archive))
		}
		if idx.records != 1 || idx.refs["example.com/app:v1"] == nil {
			t.Fatalf("the reference was not recorded (records=%d, refs=%v)", idx.records, idx.refs)
		}
		if want := (Platform{OS: "darwin", Architecture: "arm64"}).Normalize(); idx.platform != want {
			t.Errorf("recorded platform %v, want %v (the image config's own)", idx.platform, want)
		}
	})

	t.Run("docker save ingests every blob digest-addressed", func(t *testing.T) {
		img := withPlatform(t, mustRandomImage(t), "darwin", "arm64", "")
		archive := dockerSaveArchive(t, img, "example.com/app:v1")

		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		idx := newRecordingIndex()
		l := mustLoader(t, cache, idx)

		res, err := l.Load(context.Background(), LoadRequest{
			Reference: "example.com/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
		}, bytes.NewReader(archive))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		mfst, err := img.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Manifest.GetConfig().GetDigest(); got != mfst.Config.Digest.String() {
			t.Errorf("config digest %q, want %q", got, mfst.Config.Digest.String())
		}
		if !cache.Has(res.Manifest.GetConfig().GetDigest()) {
			t.Error("the config blob is not in the store")
		}
		if len(res.Manifest.GetLayers()) != len(mfst.Layers) {
			t.Fatalf("recorded %d layers, want %d", len(res.Manifest.GetLayers()), len(mfst.Layers))
		}
		for i, d := range res.Manifest.GetLayers() {
			if d.GetDigest() != mfst.Layers[i].Digest.String() {
				t.Errorf("layer %d digest %q, want %q", i, d.GetDigest(), mfst.Layers[i].Digest.String())
			}
			if !cache.Has(d.GetDigest()) {
				t.Errorf("layer %d (%s) is not in the store", i, d.GetDigest())
			}
		}
		if idx.records != 1 {
			t.Errorf("recorded %d references, want 1", idx.records)
		}
	})

	t.Run("the format is detected when the client declares none", func(t *testing.T) {
		cases := map[string][]byte{
			"docker save": dockerSaveArchive(t, withPlatform(t, mustRandomImage(t), "darwin", "arm64", ""), "example.com/app:v1"),
		}
		oci, _ := buildOCIArchive(t, ociSpec{config: nativeConfig(t), layers: [][]byte{[]byte("l")}})
		cases["OCI layout"] = oci
		for name, archive := range cases {
			t.Run(name, func(t *testing.T) {
				cache, err := NewCache(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				l := mustLoader(t, cache, newRecordingIndex())
				if _, err := l.Load(context.Background(), LoadRequest{Reference: "example.com/app:v1"}, bytes.NewReader(archive)); err != nil {
					t.Fatalf("load with an undeclared format: %v", err)
				}
			})
		}
	})

	t.Run("a multi-tag docker-save archive is refused with nothing committed", func(t *testing.T) {
		img := withPlatform(t, mustRandomImage(t), "darwin", "arm64", "")
		archive := dockerSaveArchive(t, img, "example.com/app:v1", "example.com/app:latest")

		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		idx := newRecordingIndex()
		l := mustLoader(t, cache, idx)

		_, err = l.Load(context.Background(), LoadRequest{
			Reference: "example.com/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
		}, bytes.NewReader(archive))
		if !errors.Is(err, ErrArchiveMultipleImages) {
			t.Fatalf("multi-tag load error = %v; want ErrArchiveMultipleImages (v1 refuses rather than dropping a tag)", err)
		}
		if nodes := contentBlobs(t, cache); len(nodes) != 0 {
			t.Errorf("a refused load committed %d node(s)", len(nodes))
		}
		if idx.records != 0 {
			t.Error("a refused load recorded a reference")
		}
	})

	t.Run("a multi-manifest OCI index is refused", func(t *testing.T) {
		archive, _ := buildOCIArchive(t, ociSpec{
			config: nativeConfig(t), layers: [][]byte{[]byte("l")}, manifests: 2,
		})
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		l := mustLoader(t, cache, newRecordingIndex())
		_, err = l.Load(context.Background(), LoadRequest{
			Reference: "example.com/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, bytes.NewReader(archive))
		if !errors.Is(err, ErrArchiveMultipleImages) {
			t.Fatalf("multi-manifest load error = %v; want ErrArchiveMultipleImages", err)
		}
	})

	t.Run("a foreign (URL-bearing) descriptor is refused", func(t *testing.T) {
		archive, _ := buildOCIArchive(t, ociSpec{
			config: nativeConfig(t), layers: [][]byte{[]byte("l")}, foreignLayer: true,
		})
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		l := mustLoader(t, cache, newRecordingIndex())
		_, err = l.Load(context.Background(), LoadRequest{
			Reference: "example.com/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, bytes.NewReader(archive))
		if !errors.Is(err, ErrArchiveForeignLayer) {
			t.Fatalf("foreign-layer load error = %v; want ErrArchiveForeignLayer (an offline load must not fetch)", err)
		}
	})

	t.Run("a stream in no known format is refused", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		l := mustLoader(t, cache, newRecordingIndex())
		var empty bytes.Buffer
		tw := tar.NewWriter(&empty)
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = l.Load(context.Background(), LoadRequest{Reference: "example.com/app:v1"}, bytes.NewReader(empty.Bytes()))
		if !errors.Is(err, ErrArchiveUnsupported) {
			t.Fatalf("empty-archive load error = %v; want ErrArchiveUnsupported", err)
		}
	})

	t.Run("the advisory digest and size are verified when the client supplies them", func(t *testing.T) {
		archive, _ := buildOCIArchive(t, ociSpec{config: nativeConfig(t), layers: [][]byte{[]byte("l")}})
		for name, req := range map[string]LoadRequest{
			"a wrong digest": {Reference: "example.com/app:v1", Digest: digestOf([]byte("not the archive"))},
			"a wrong size":   {Reference: "example.com/app:v1", Size: int64(len(archive)) + 1},
		} {
			t.Run(name, func(t *testing.T) {
				cache, err := NewCache(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				l := mustLoader(t, cache, newRecordingIndex())
				if _, err := l.Load(context.Background(), req, bytes.NewReader(archive)); !errors.Is(err, ErrArchiveClaimMismatch) {
					t.Fatalf("load error = %v; want ErrArchiveClaimMismatch", err)
				}
			})
		}
	})

	t.Run("an unparseable reference is refused before the stream is read", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		l := mustLoader(t, cache, newRecordingIndex())
		for _, ref := range []string{"", "NOT A REFERENCE"} {
			if _, err := l.Load(context.Background(), LoadRequest{Reference: ref}, bytes.NewReader(nil)); !errors.Is(err, ErrLoadReferenceInvalid) {
				t.Errorf("load(%q) error = %v; want ErrLoadReferenceInvalid", ref, err)
			}
		}
	})

	t.Run("a symlinked blob entry is refused rather than followed", func(t *testing.T) {
		// The alias attack: an entry at a blob's claimed path that POINTS at other
		// bytes. Refusing a non-regular entry kills it structurally, so the ingest
		// never has to reason about where a link resolves.
		cfg := nativeConfig(t)
		layer := []byte("aliased-layer")
		archive, _ := buildOCIArchive(t, ociSpec{config: cfg, layers: [][]byte{layer}})
		aliased := relinkBlobEntry(t, archive, ggcrHash(t, layer), "oci-layout")

		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		l := mustLoader(t, cache, newRecordingIndex())
		_, err = l.Load(context.Background(), LoadRequest{
			Reference: "example.com/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, bytes.NewReader(aliased))
		if !errors.Is(err, ErrArchiveMalformed) {
			t.Fatalf("symlinked-blob load error = %v; want ErrArchiveMalformed", err)
		}
		if nodes := contentBlobs(t, cache); len(nodes) != 0 {
			t.Errorf("a refused load committed %d node(s)", len(nodes))
		}
	})
}

// relinkBlobEntry rewrites archive so the entry holding h's content becomes a
// SYMLINK to target instead of a regular file.
func relinkBlobEntry(t *testing.T, archive []byte, h ggcrv1.Hash, target string) []byte {
	t.Helper()
	want := fmt.Sprintf("blobs/%s/%s", h.Algorithm, h.Hex)
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if hdr.Name == want {
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeSymlink, Name: hdr.Name, Linkname: target, Mode: 0o777,
			}); err != nil {
				t.Fatalf("write symlink header: %v", err)
			}
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read fixture entry: %v", err)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return out.Bytes()
}

// mustRandomImage is a small random image fixture.
func mustRandomImage(t *testing.T) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	return img
}
