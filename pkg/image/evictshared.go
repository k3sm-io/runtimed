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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// recordManifest is the part of an artifact record, live or released, that
// names the manifest it was written for. The field name is pkg/artifact's
// Record.ManifestDigest.
type recordManifest struct {
	ManifestDigest string `json:"manifestDigest"`
}

// evictSharedSet returns the blob digests named by every cached manifest other
// than the eviction target manifest: every image index entry whose manifest
// digest is not manifest, every live artifact record and every released copy
// whose manifestDigest is not manifest. Each contributes its manifest digest,
// config and layers. It is PlanEvict's others.
//
// It only protects, so it errs toward naming more: an index entry recorded
// without a manifest descriptor, and a record or copy without a
// manifestDigest, cannot be shown to be the target and count as other.
//
// It fails CLOSED. An index entry, artifact record or released copy that
// cannot be read or decoded returns an error wrapping ErrIndexEntryCorrupt and
// no set, as does a released-directory entry named like a copy that is not
// one: a set silently short of one manifest's blobs would let eviction delete
// a blob that manifest still names. A file a concurrent writer removed between
// the listing and the read is skipped, as List does. Commit temps (names
// starting with ".") and names without the .json suffix are not records. An
// absent index or namespace contributes nothing. A malformed target digest is
// an error.
func (c *Cache) evictSharedSet(ctx context.Context, manifest string) (map[string]struct{}, error) {
	if _, err := parseBlobDigest(manifest); err != nil {
		return nil, fmt.Errorf("evict shared set: target manifest: %w", err)
	}
	out := make(map[string]struct{})
	add := func(ds ...string) {
		for _, d := range ds {
			if d != "" {
				out[d] = struct{}{}
			}
		}
	}
	x := &FileIndex{dir: c.IndexRoot()}

	entries, err := x.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("evict shared set: image index: %w", err)
	}
	for _, e := range entries {
		if e.Descriptor.GetDigest() == manifest {
			continue
		}
		add(e.Descriptor.GetDigest(), e.Manifest.GetConfig().GetDigest())
		for _, l := range e.Manifest.GetLayers() {
			add(l.GetDigest())
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records, err := x.artifactRecords()
	if err != nil {
		return nil, fmt.Errorf("evict shared set: artifact records: %w", err)
	}
	for _, rec := range records {
		m, ds, err := decodeSharedRecord(rec.buf)
		if err != nil {
			return nil, fmt.Errorf("evict shared set: %w: artifact record %q: %v", ErrIndexEntryCorrupt, rec.name, err)
		}
		if m != manifest {
			add(m)
			add(ds...)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := x.releasedShared(manifest, add); err != nil {
		return nil, fmt.Errorf("evict shared set: released artifact records: %w", err)
	}
	return out, nil
}

// releasedShared passes add the manifest digest and blobs of every released
// copy whose manifestDigest is not manifest, failing closed as evictSharedSet
// documents. It reads the directory itself rather than through
// releasedArtifacts, which skips an undecodable copy because it only orders
// eviction.
func (x *FileIndex) releasedShared(manifest string, add func(...string)) error {
	sub, err := x.openReleased()
	if err != nil {
		return err
	}
	if sub == nil {
		return nil
	}
	defer sub.Close()
	dir, err := sub.Open(".")
	if err != nil {
		return fmt.Errorf("open released artifact records: %w", err)
	}
	names, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return fmt.Errorf("read released artifact records: %w", err)
	}
	for _, d := range names {
		name := d.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if !validReleasedName(name) {
			return fmt.Errorf("%w: released copy %q is not named for its bytes", ErrIndexEntryCorrupt, name)
		}
		fi, err := sub.Lstat(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // swept since the listing
			}
			return fmt.Errorf("%w: stat released copy %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: released copy %q is not a regular file (mode %v)", ErrIndexEntryCorrupt, name, fi.Mode().Type())
		}
		buf, err := readAnchoredLimit(sub, name, MaxArtifactRecordBytes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return fmt.Errorf("%w: read released copy %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		m, ds, err := decodeSharedRecord(buf)
		if err != nil {
			return fmt.Errorf("%w: released copy %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		if m != manifest {
			add(m)
			add(ds...)
		}
	}
	return nil
}

// decodeSharedRecord returns the manifest digest and the blobs an artifact
// record (live or released) names, refusing a record DecodeArtifactRoot
// refuses.
func decodeSharedRecord(buf []byte) (manifest string, digests []string, err error) {
	var r artifactRecordRoot
	if err := decodeRecordRoot(buf, &r); err != nil {
		return "", nil, err
	}
	var m recordManifest
	if err := json.Unmarshal(buf, &m); err != nil {
		return "", nil, fmt.Errorf("decode artifact record: %v", boundErr(err))
	}
	return m.ManifestDigest, recordDigests(r), nil
}
