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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrManifestNotRetained reports that an index entry carries no manifest bytes,
// so the image cannot be named by digest or exported.
//
// It is the honest verdict for an entry written before this store retained
// manifests (see IndexEntry.Descriptor). The remedy is the operator's and it is
// cheap: re-pull or re-load the reference, which records the manifest. Inventing
// one by re-encoding the recorded descriptors would produce an archive whose
// image id is not the id the registry served, which is worse than a refusal
// because nothing downstream could detect it.
var ErrManifestNotRetained = errors.New("image: this entry predates manifest retention; re-pull or re-load the reference")

// ErrExportIncomplete reports that a blob the exported manifest names is not in
// the store, so the archive would be truncated.
//
// An index entry is an EDGE and can outlive its blobs (see FileIndex), so this
// is an ordinary reachable state after a prune, not a corruption. It is checked
// BEFORE the first byte is written, so a caller never receives a partial archive
// for a cause the daemon could have known up front.
var ErrExportIncomplete = errors.New("image: the store no longer holds every blob this image names")

// ociLayoutVersion is the layout marker every OCI image layout carries.
const ociLayoutVersion = "1.0.0"

// refNameAnnotation is the OCI annotation an image layout uses to record the
// reference a manifest was known by. It is what `docker load` and this package's
// own ingest read to name a single-image archive.
const refNameAnnotation = "org.opencontainers.image.ref.name"

// exportModTime is the timestamp every entry in an exported archive carries.
//
// A fixed epoch, not time.Now: two exports of one image must be byte-identical,
// because the whole claim an export makes is that it round-trips — a load of a
// save of a load records the same digests. A wall-clock mtime would make the
// archive's bytes differ on every call while the image did not change, and no
// caller could then tell a re-export from a re-build.
var exportModTime = time.Unix(0, 0).UTC()

// ExportOCILayout writes e to w as a tarred OCI image layout — the `docker save`
// analog and the exact inverse of Loader.Load.
//
// It is byte-DETERMINISTIC: the entry order is fixed (marker, index, manifest,
// config, layers), every header carries the same fixed epoch and mode, and the
// manifest is written from the bytes the index retained rather than re-encoded.
// So an export of a loaded image is loadable, and the digests survive the round
// trip unchanged. That is the property this whole path exists to have; a
// re-encoded manifest would hash differently and silently rename the image.
//
// It takes NO lease, records NO root and unlinks nothing — an export cannot make
// content reachable or unreachable. The consequence is stated rather than
// papered over: a concurrent prune may delete a blob mid-export, which surfaces
// as a read error on that blob, and the client discards the truncated archive.
// Leasing instead would let any caller pin the store for the length of a
// transfer it controls.
//
// The daemon is not the writer of the operator's file: w is the caller's
// stream, never a path this package opens.
func (c *Cache) ExportOCILayout(ctx context.Context, w io.Writer, e IndexEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.Descriptor == nil || len(e.ManifestRaw) == 0 {
		return fmt.Errorf("%w: %s", ErrManifestNotRetained, quoteBounded(e.Reference, maxDigestLen))
	}
	blobs, err := exportBlobs(e)
	if err != nil {
		return err
	}
	// Pre-flight every blob BEFORE the first byte goes out. A caller that has
	// already received chunks has to discard an archive it cannot use, so a
	// condition the daemon can know up front is reported up front.
	for _, b := range blobs {
		if !c.Has(b.digest) {
			return fmt.Errorf("%w: %s is missing %s", ErrExportIncomplete,
				quoteBounded(e.Reference, maxDigestLen), quoteBounded(b.digest, maxDigestLen))
		}
	}

	index, err := exportIndexJSON(e)
	if err != nil {
		return err
	}

	tw := tar.NewWriter(w)
	if err := writeTarFile(tw, "oci-layout", []byte(fmt.Sprintf("{%q:%q}", "imageLayoutVersion", ociLayoutVersion))); err != nil {
		return err
	}
	if err := writeTarFile(tw, "index.json", index); err != nil {
		return err
	}
	manifestName, err := blobEntryNameFor(e.Descriptor.GetDigest())
	if err != nil {
		return err
	}
	// The manifest goes in VERBATIM, from the bytes the index retained. This one
	// line is what makes the round trip digest-stable (see IndexEntry.ManifestRaw).
	if err := writeTarFile(tw, manifestName, e.ManifestRaw); err != nil {
		return err
	}
	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.writeBlobEntry(tw, b); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close export archive: %w", err)
	}
	return nil
}

// exportBlob is one CAS blob an export must carry.
type exportBlob struct {
	digest string
	size   int64
}

// exportBlobs is the config followed by the layers, in manifest order, with
// duplicates dropped.
//
// A tar may not carry two entries at one name, and an image legitimately can
// name one blob twice (the same empty layer applied twice is the common case),
// so the de-duplication is a correctness requirement rather than an
// optimisation: without it the archive is malformed.
func exportBlobs(e IndexEntry) ([]exportBlob, error) {
	seen := map[string]bool{e.Descriptor.GetDigest(): true}
	var out []exportBlob
	add := func(d *runtimev1.Descriptor, what string) error {
		digest := d.GetDigest()
		if digest == "" {
			return fmt.Errorf("%w: %s names a %s with no digest",
				ErrManifestInconsistent, quoteBounded(e.Reference, maxDigestLen), what)
		}
		if _, err := parseBlobDigest(digest); err != nil {
			return err
		}
		if seen[digest] {
			return nil
		}
		seen[digest] = true
		out = append(out, exportBlob{digest: digest, size: d.GetSize()})
		return nil
	}
	if err := add(e.Manifest.GetConfig(), "config"); err != nil {
		return nil, err
	}
	for _, l := range e.Manifest.GetLayers() {
		if err := add(l, "layer"); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// exportIndexJSON is the archive's index.json: one manifest descriptor,
// annotated with the reference the entry was recorded under.
//
// The platform is taken from the entry's KEY, which is the platform this node
// proved the image runnable on, rather than from the manifest — a manifest
// carries a platform only when it resolved through a multi-platform index.
func exportIndexJSON(e IndexEntry) ([]byte, error) {
	desc := ggcrv1.Descriptor{
		MediaType:   types.MediaType(e.Descriptor.GetMediaType()),
		Size:        e.Descriptor.GetSize(),
		Annotations: map[string]string{refNameAnnotation: e.Reference},
	}
	h, err := parseBlobDigest(e.Descriptor.GetDigest())
	if err != nil {
		return nil, err
	}
	desc.Digest = h
	if p := e.Platform.Normalize(); p.OS != "" && p.Architecture != "" {
		desc.Platform = &ggcrv1.Platform{
			OS:           p.OS,
			Architecture: p.Architecture,
			Variant:      p.Variant,
			OSVersion:    p.OSVersion,
		}
	}
	buf, err := json.Marshal(ggcrv1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []ggcrv1.Descriptor{desc},
	})
	if err != nil {
		return nil, fmt.Errorf("encode export index.json: %w", err)
	}
	return buf, nil
}

// blobEntryNameFor is blobEntryName over a digest string.
func blobEntryNameFor(digest string) (string, error) {
	h, err := parseBlobDigest(digest)
	if err != nil {
		return "", err
	}
	return blobEntryName(h)
}

// writeTarFile writes one whole in-memory entry with the archive's fixed header
// shape.
func writeTarFile(tw *tar.Writer, name string, body []byte) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(body)),
		ModTime:  exportModTime,
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write export entry %s: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("write export entry %s: %w", name, err)
	}
	return nil
}

// writeBlobEntry streams one CAS blob into the archive.
//
// The header's size comes from the blob's own stat, not from the manifest
// descriptor: tar requires the declared length and the written length to agree
// exactly, and a descriptor that disagrees with the file on disk would otherwise
// produce a corrupt archive rather than a legible error. The disagreement is
// still reported — as ErrManifestInconsistent — because it means the store and
// the manifest have diverged.
func (c *Cache) writeBlobEntry(tw *tar.Writer, b exportBlob) error {
	name, err := blobEntryNameFor(b.digest)
	if err != nil {
		return err
	}
	f, err := c.openBlob(b.digest)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat blob %s: %w", quoteBounded(b.digest, maxDigestLen), err)
	}
	if b.size > 0 && fi.Size() != b.size {
		return fmt.Errorf("%w: %s is %d bytes on disk but its descriptor declares %d",
			ErrManifestInconsistent, quoteBounded(b.digest, maxDigestLen), fi.Size(), b.size)
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o644,
		Size:     fi.Size(),
		ModTime:  exportModTime,
		Format:   tar.FormatUSTAR,
	}); err != nil {
		return fmt.Errorf("write export entry %s: %w", name, err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("write export entry %s: %w", name, err)
	}
	return nil
}

// ImageConfig reads and decodes the config blob e names.
//
// It is the decoded half of an inspect: the Entrypoint/Cmd/Env/User/WorkingDir
// facts live INSIDE the config's JSON and so cannot be carried by a Descriptor.
// It is strictly read-only — no lease, no root, no registry — and reports
// ok=false (with no error) when the config blob is simply not in the store,
// which is the ordinary post-prune state of an entry whose blobs went. A blob
// that IS present but does not decode is an error: that is a damaged store, not
// an absent fact.
func (c *Cache) ImageConfig(e IndexEntry) (*ggcrv1.ConfigFile, bool, error) {
	digest := e.Manifest.GetConfig().GetDigest()
	if digest == "" {
		return nil, false, nil
	}
	if !c.Has(digest) {
		return nil, false, nil
	}
	f, err := c.openBlob(digest)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, maxIndexManifestBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read image config %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if len(buf) > maxIndexManifestBytes {
		return nil, false, fmt.Errorf("image config %s exceeds %d bytes",
			quoteBounded(digest, maxDigestLen), maxIndexManifestBytes)
	}
	var cfg ggcrv1.ConfigFile
	if err := json.Unmarshal(buf, &cfg); err != nil {
		// The config is registry-supplied content and encoding/json echoes the
		// offending byte. Bounded as DATA.
		return nil, false, fmt.Errorf("decode image config %s: %v",
			quoteBounded(digest, maxDigestLen), boundErr(err))
	}
	return &cfg, true, nil
}
