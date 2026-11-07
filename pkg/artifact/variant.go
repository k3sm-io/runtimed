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
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"k3sm.io/runtimed/pkg/image"
)

// AnnotationVariant is the index-entry annotation naming a model variant (a
// quantization such as 4bit, 8bit or bf16). Each variant is its own artifact
// manifest; an OCI image index joins them under one name.
const AnnotationVariant = "io.k3sm.model.variant"

// Index limits. A variant index lists a handful of quantizations, so both caps
// sit far above any real index while bounding what a hostile one can make the
// daemon decode and scan.
const (
	// MaxIndexBytes caps an index body.
	MaxIndexBytes = 256 << 10
	// MaxIndexEntries caps the manifests one index lists.
	MaxIndexEntries = 64
	// MaxVariantLength caps a variant selector: the same bound as the
	// model CRD's variant field, enforced here independently of it.
	MaxVariantLength = 128
)

// Variant refusals.
var (
	// ErrVariantRequired: the reference names an index and no variant was
	// given. It is also ErrIndexRefused.
	ErrVariantRequired = errors.New("artifact: reference names a variant index; a variant selector is required")
	// ErrVariantNotFound: no index entry carries the selected variant.
	ErrVariantNotFound = errors.New("artifact: no index entry carries the selected variant")
	// ErrVariantAmbiguous: two or more index entries carry the selected variant.
	ErrVariantAmbiguous = errors.New("artifact: more than one index entry carries the selected variant")
	// ErrVariantOnManifest: a variant was given for a single manifest, which
	// offers no variants.
	ErrVariantOnManifest = errors.New("artifact: a variant was selected but the reference names a single manifest")
	// ErrVariantInvalid: the selector is longer than MaxVariantLength.
	ErrVariantInvalid = errors.New("artifact: variant selector is invalid")
)

// PullOption adjusts one pull.
type PullOption func(*pullOptions)

type pullOptions struct {
	variant string
}

// WithVariant selects the index entry whose AnnotationVariant equals variant.
// The reference must then name an OCI image index with exactly one such entry;
// the selected manifest goes through every manifest check a direct pull does.
// An empty variant selects nothing: the reference must name one manifest.
func WithVariant(variant string) PullOption {
	return func(o *pullOptions) { o.variant = variant }
}

func applyOptions(opts []PullOption) (pullOptions, error) {
	var o pullOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if len(o.variant) > MaxVariantLength {
		return o, fmt.Errorf("%d bytes, at most %d: %w", len(o.variant), MaxVariantLength, ErrVariantInvalid)
	}
	return o, nil
}

// indexDoc is the part of an OCI image index the selection reads.
type indexDoc struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType,omitempty"`
	Manifests     []descriptor    `json:"manifests"`
	Layers        json.RawMessage `json:"layers,omitempty"`
}

// probe is the part of any manifest document that tells an index apart.
type probe struct {
	MediaType string            `json:"mediaType,omitempty"`
	Manifests []json.RawMessage `json:"manifests,omitempty"`
}

func servedType(served string) string {
	served, _, _ = strings.Cut(served, ";")
	return strings.TrimSpace(served)
}

// isIndex reports whether raw, served as served, is an index or a manifest
// list by its served type or its own body.
func isIndex(raw []byte, served string) (bool, error) {
	switch servedType(served) {
	case mediaTypeOCIIndex, mediaTypeDockerList:
		return true, nil
	}
	var pr probe
	if err := json.Unmarshal(raw, &pr); err != nil {
		return false, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	return pr.MediaType == mediaTypeOCIIndex || pr.MediaType == mediaTypeDockerList || len(pr.Manifests) > 0, nil
}

// resolve turns the document ref names into the one manifest to pull. A
// manifest is returned as is, unless a variant was selected for it. An index
// yields the manifest its single matching entry names, fetched by digest and
// verified against the entry. It returns the manifest, its bytes and digest.
func (p *Puller) resolve(ctx context.Context, ref string, cred *image.RegistryCredential, raw []byte, served, mdigest, variant string) (*manifest, []byte, string, error) {
	idx, err := isIndex(raw, served)
	if err != nil {
		return nil, nil, "", err
	}
	if !idx {
		if variant != "" {
			return nil, nil, "", fmt.Errorf("variant %s: %w", image.QuoteBounded(variant, MaxVariantLength), ErrVariantOnManifest)
		}
		m, err := parseManifest(raw, served)
		return m, raw, mdigest, err
	}
	entry, err := selectEntry(raw, served, variant)
	if err != nil {
		return nil, nil, "", err
	}
	r, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w: %w", image.QuoteBounded(ref, 512), ErrInvalidReference, bound(err))
	}
	entryRef := r.Context().Digest(entry.Digest).String()
	craw, cserved, err := p.fetchManifest(ctx, entryRef, cred)
	if err != nil {
		return nil, nil, "", err
	}
	if len(craw) > MaxManifestBytes {
		return nil, nil, "", fmt.Errorf("variant manifest of %d bytes, at most %d: %w", len(craw), MaxManifestBytes, ErrManifestTooLarge)
	}
	sum := sha256.Sum256(craw)
	cdigest := "sha256:" + hex.EncodeToString(sum[:])
	if cdigest != entry.Digest || int64(len(craw)) != entry.Size {
		return nil, nil, "", fmt.Errorf("variant manifest hashed to %s (%d bytes), index names %s (%d bytes): %w",
			cdigest, len(craw), entry.Digest, entry.Size, ErrManifestDigest)
	}
	m, err := parseManifest(craw, cserved)
	if err != nil {
		return nil, nil, "", fmt.Errorf("variant %s: %w", image.QuoteBounded(variant, MaxVariantLength), err)
	}
	return m, craw, cdigest, nil
}

// IndexEntry is the index entry SelectVariant picked: the variant manifest's
// digest ("sha256:<hex>"), its size in bytes and its media type (always the
// OCI image manifest type).
type IndexEntry struct {
	Digest    string
	Size      int64
	MediaType string
}

// SelectVariant parses index, the raw bytes of an OCI image index, and returns
// the one entry whose AnnotationVariant equals variant. It makes no request:
// the caller fetches the entry by digest and must verify the bytes against
// Digest and Size. mediaType is the type the registry served index as; empty
// means the index body must name the OCI index type itself.
//
// It applies the same rules PullArtifact does: a docker manifest list, an
// empty variant (ErrVariantRequired), a variant over MaxVariantLength
// (ErrVariantInvalid), an index over MaxIndexBytes (ErrManifestTooLarge) or
// MaxIndexEntries, an entry that is not an OCI image manifest (a nested
// index), a malformed digest or a size outside 1..MaxManifestBytes
// (ErrManifestInvalid) are refused, as are no match (ErrVariantNotFound) and
// several matches (ErrVariantAmbiguous).
func SelectVariant(index []byte, mediaType, variant string) (IndexEntry, error) {
	if len(variant) > MaxVariantLength {
		return IndexEntry{}, fmt.Errorf("%d bytes, at most %d: %w", len(variant), MaxVariantLength, ErrVariantInvalid)
	}
	d, err := selectEntry(index, mediaType, variant)
	if err != nil {
		return IndexEntry{}, err
	}
	return IndexEntry{Digest: d.Digest, Size: d.Size, MediaType: d.MediaType}, nil
}

// selectEntry checks the index and returns the one entry carrying variant.
// Only an OCI image index is accepted (a docker manifest list is refused), at
// most MaxIndexBytes and MaxIndexEntries, every entry an OCI image manifest
// (never a nested index) with a well-formed digest and a size within
// MaxManifestBytes.
func selectEntry(raw []byte, served, variant string) (descriptor, error) {
	st := servedType(served)
	if st == mediaTypeDockerList {
		return descriptor{}, fmt.Errorf("served as %s: %w", st, ErrIndexRefused)
	}
	if variant == "" {
		return descriptor{}, fmt.Errorf("%w: %w", ErrIndexRefused, ErrVariantRequired)
	}
	if len(raw) > MaxIndexBytes {
		return descriptor{}, fmt.Errorf("index of %d bytes, at most %d: %w", len(raw), MaxIndexBytes, ErrManifestTooLarge)
	}
	var ix indexDoc
	if err := json.Unmarshal(raw, &ix); err != nil {
		return descriptor{}, fmt.Errorf("index: %w: %v", ErrManifestInvalid, err)
	}
	if ix.MediaType == mediaTypeDockerList {
		return descriptor{}, fmt.Errorf("a docker manifest list: %w", ErrIndexRefused)
	}
	if st != "" && st != mediaTypeOCIIndex {
		return descriptor{}, fmt.Errorf("index served as %s: %w: %w", image.QuoteBounded(st, 256), ErrIndexRefused, ErrManifestInvalid)
	}
	if ix.MediaType != "" && ix.MediaType != mediaTypeOCIIndex {
		return descriptor{}, fmt.Errorf("index mediaType %s: %w", image.QuoteBounded(ix.MediaType, 256), ErrManifestInvalid)
	}
	if st == "" && ix.MediaType == "" {
		return descriptor{}, fmt.Errorf("index names no media type: %w", ErrManifestInvalid)
	}
	if ix.SchemaVersion != 2 {
		return descriptor{}, fmt.Errorf("index: %w: schemaVersion %d", ErrManifestInvalid, ix.SchemaVersion)
	}
	if len(ix.Layers) > 0 {
		return descriptor{}, fmt.Errorf("index carries layers: %w", ErrManifestInvalid)
	}
	if len(ix.Manifests) == 0 {
		return descriptor{}, fmt.Errorf("index lists no manifests: %w", ErrManifestInvalid)
	}
	if len(ix.Manifests) > MaxIndexEntries {
		return descriptor{}, fmt.Errorf("index lists %d manifests, at most %d: %w", len(ix.Manifests), MaxIndexEntries, ErrManifestInvalid)
	}
	var (
		found   descriptor
		matches int
	)
	for i, d := range ix.Manifests {
		if d.MediaType != mediaTypeOCIManifest {
			return descriptor{}, fmt.Errorf("index entry %d %s, want %s: %w", i, image.QuoteBounded(d.MediaType, 256), mediaTypeOCIManifest, ErrManifestInvalid)
		}
		if !sha256Digest.MatchString(d.Digest) {
			return descriptor{}, fmt.Errorf("index entry %d digest %s: %w", i, image.QuoteBounded(d.Digest, 128), ErrManifestInvalid)
		}
		if d.Size <= 0 || d.Size > MaxManifestBytes {
			return descriptor{}, fmt.Errorf("index entry %d declares %d bytes, want 1 to %d: %w", i, d.Size, MaxManifestBytes, ErrManifestInvalid)
		}
		if d.Annotations[AnnotationVariant] == variant {
			found = d
			matches++
		}
	}
	q := image.QuoteBounded(variant, MaxVariantLength)
	switch {
	case matches == 0:
		return descriptor{}, fmt.Errorf("variant %s: %w", q, ErrVariantNotFound)
	case matches > 1:
		return descriptor{}, fmt.Errorf("variant %s on %d entries: %w", q, matches, ErrVariantAmbiguous)
	}
	return found, nil
}
