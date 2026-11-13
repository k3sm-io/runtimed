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

// evictSharedPhaseHook, when non-nil, is called by evictSharedSet with the
// name of the phase about to start ("records", then "released"), just before
// the cancellation check that guards it. It is a test seam: nil in production.
var evictSharedPhaseHook func(phase string)

// evictSharedSet returns the blob digests named by every cached manifest other
// than the eviction target manifest, whose own blobs are target: every image
// index entry, live artifact record and released copy. Each contributes its
// manifest digest, config and layers. It is PlanEvict's others.
//
// An entry or record LABELLED with manifest (index descriptor digest or record
// manifestDigest equal to it) is not trusted to be the target on its label
// alone: every blob it names that is not in target, and is not manifest
// itself, is still added, so a planted or corrupt record carrying the target's
// label cannot hide a blob another image needs. Entries labelled otherwise add
// their label and every blob they name. A nil or empty target therefore
// protects every blob a target-labelled entry names.
//
// It only protects, so it errs toward naming more: an index entry recorded
// without a manifest descriptor, and a record or copy without a
// manifestDigest, cannot be shown to be the target and count as other.
//
// It fails CLOSED. An index entry, artifact record or released copy that
// cannot be read or decoded, or a ".json" name in any of the three directories
// that is not a regular file, returns an error wrapping ErrIndexEntryCorrupt and
// no set, as does a released-directory entry named like a copy that is not
// one: a set silently short of one manifest's blobs would let eviction delete
// a blob that manifest still names. The price is availability: one malformed
// record blocks eviction until it is repaired. A file a concurrent writer
// removed between the listing and the read is skipped. Commit temps (names
// starting with ".") and names without the .json suffix are not records. An
// absent index or namespace contributes nothing. A malformed target digest is
// an error.
func (c *Cache) evictSharedSet(ctx context.Context, manifest string, target map[string]struct{}) (map[string]struct{}, error) {
	if _, err := parseBlobDigest(manifest); err != nil {
		return nil, fmt.Errorf("evict shared set: target manifest: %w", err)
	}
	out := make(map[string]struct{})
	// contribute adds what one entry or record labelled label names.
	contribute := func(label string, ds []string) {
		if label == manifest {
			for _, d := range ds {
				if _, own := target[d]; d != "" && d != manifest && !own {
					out[d] = struct{}{}
				}
			}
			return
		}
		if label != "" {
			out[label] = struct{}{}
		}
		for _, d := range ds {
			if d != "" {
				out[d] = struct{}{}
			}
		}
	}
	x := &FileIndex{dir: c.IndexRoot()}

	entries, err := x.sharedEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("evict shared set: image index: %w", err)
	}
	for _, e := range entries {
		ds := []string{e.Manifest.GetConfig().GetDigest()}
		for _, l := range e.Manifest.GetLayers() {
			ds = append(ds, l.GetDigest())
		}
		contribute(e.Descriptor.GetDigest(), ds)
	}

	if evictSharedPhaseHook != nil {
		evictSharedPhaseHook("records")
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
		contribute(m, ds)
	}

	if evictSharedPhaseHook != nil {
		evictSharedPhaseHook("released")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := x.releasedShared(contribute); err != nil {
		return nil, fmt.Errorf("evict shared set: released artifact records: %w", err)
	}
	return out, nil
}

// sharedEntries returns every image index entry, failing closed as
// evictSharedSet documents. It is List with one difference: a ".json" name
// that is not a regular file (a symlink, a directory, a device) is an error
// wrapping ErrIndexEntryCorrupt rather than skipped, because the entry it
// stands for might name a blob nothing else protects. Each name is Lstat'd
// before it is read through the fd-anchored root, so a symlink is refused, not
// followed. The order of the result is unspecified.
func (x *FileIndex) sharedEntries(ctx context.Context) ([]IndexEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open image index %s: %w", x.dir, err)
	}
	names, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("read image index %s: %w", x.dir, err)
	}
	out := make([]IndexEntry, 0, len(names))
	for _, d := range names {
		name := d.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		fi, err := root.Lstat(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // replaced or removed since the listing
			}
			return nil, fmt.Errorf("%w: stat %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %q is not a regular file (mode %v)", ErrIndexEntryCorrupt, name, fi.Mode().Type())
		}
		buf, err := readAnchored(root, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			// LOCAL-ONLY, no boundErr: as in List, an fs.PathError over an entry
			// file name already restricted to "*.json".
			return nil, fmt.Errorf("%w: read %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		e, err := decodeEntry(name, buf)
		if err != nil {
			return nil, err
		}
		if entryName(e.Reference, e.Platform) != name {
			return nil, fmt.Errorf("%w: %q holds the record for %q/%s",
				ErrIndexEntryCorrupt, name, e.Reference, e.Platform)
		}
		out = append(out, e)
	}
	return out, nil
}

// releasedShared passes contribute the manifestDigest and blobs of every
// released copy, failing closed as evictSharedSet documents. It reads the directory itself rather than through
// releasedArtifacts, which skips an undecodable copy because it only orders
// eviction.
func (x *FileIndex) releasedShared(contribute func(label string, ds []string)) error {
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
		contribute(m, ds)
	}
	return nil
}

// ReleasedArtifact returns the manifest digest and the blobs (config and
// layers) of the released artifact copy for manifest, and whether one was
// found. It reads the released directory with the strict reader the evict
// shared set uses (releasedShared), so it fails CLOSED: any released copy that
// cannot be read or decoded, is not named for its bytes, or is not a regular
// file returns ErrIndexEntryCorrupt and nothing found, since the copy a corrupt
// entry hides may be the one asked for. No copy for manifest, or no released
// directory, is found=false with a nil error. Copies of different record bytes
// for one manifest contribute the union of their blobs, in first-seen order. A
// malformed manifest digest is an error.
func (x *FileIndex) ReleasedArtifact(manifest string) (manifestDigest string, blobs []string, found bool, err error) {
	if _, err := parseBlobDigest(manifest); err != nil {
		return "", nil, false, fmt.Errorf("released artifact: manifest: %w", err)
	}
	seen := make(map[string]struct{})
	if err := x.releasedShared(func(m string, ds []string) {
		if m != manifest {
			return
		}
		found = true
		for _, d := range ds {
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				blobs = append(blobs, d)
			}
		}
	}); err != nil {
		return "", nil, false, fmt.Errorf("released artifact %s: %w", manifest, err)
	}
	if !found {
		return "", nil, false, nil
	}
	return manifest, blobs, true, nil
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
