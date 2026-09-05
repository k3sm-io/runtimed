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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// OperatorSubdir is the cache-root-relative directory the OPERATOR reachability
// record lives in: <root>/operator, a sibling of blobs/, pods/ and index/.
//
// It is a sibling of pods/ rather than a pod dir inside it, and that separation
// is the point. Cache.Roots walks pods/ and treats every node there as a pod
// whose record it must be able to read; a pseudo-pod holding operator roots
// would be deleted by the ordinary pod-dir teardown, would collide with a real
// pod that happened to take the name, and would make "which roots are pod-owned"
// unanswerable — the exact question RemoveImage's refusal turns on.
const OperatorSubdir = "operator"

// OperatorReferencesName is the operator record's file name inside
// OperatorSubdir. One file, not one per reference: the record is small (a
// handful of entries on a real node), and a single atomically-rewritten file
// cannot be left half-enumerated by a crash the way a directory of files can.
const OperatorReferencesName = "images.json"

// operatorSchema is the on-disk format version of the operator record. As with
// the index, a record written under a version this binary does not know is an
// ERROR and never an empty root set — an unreadable root set that reported
// "nothing is rooted" would let a prune delete every operator-pinned image.
const operatorSchema = 1

// OperatorImageRoot is one operator-owned reachability root: the blobs one
// (reference x platform) index entry names, pinned because an OPERATOR asked
// for that image by name.
//
// It is the provenance model's operator root: edges are monotone, roots are
// digest-pinned, and root removal is
// AUTHORIZED and LOCAL. A pull driven by `k3sm image pull` and a tag driven by
// `k3sm image tag` each record one; UntagImage is the only thing that removes
// one, because it is the only verb in which an operator names exactly the entry
// they own.
//
// It is keyed by the PAIR, matching the index, so untagging one platform of a
// multi-platform reference unpins only that platform's blobs.
type OperatorImageRoot struct {
	// Reference is the pull reference the operator named.
	Reference string
	// Platform is the platform half of the (reference x platform) key.
	Platform Platform
	// Root is the config + layer digests this entry makes reachable.
	Root ImageRoot
}

// operatorRecord is the on-disk shape of OperatorReferencesName.
type operatorRecord struct {
	// Schema is the envelope version (operatorSchema).
	Schema int `json:"schema"`
	// Images are the operator-owned roots.
	Images []operatorRootEntry `json:"images"`
}

// operatorRootEntry is one root in its on-disk form. Platform is spelled through
// indexPlatform so the operator record and the index agree on how a key's
// platform is written down.
type operatorRootEntry struct {
	Reference string        `json:"reference"`
	Platform  indexPlatform `json:"platform"`
	Config    string        `json:"config"`
	Layers    []string      `json:"layers"`
}

// OperatorRootDir returns the directory the operator reachability record lives
// under (<root>/operator). Like PodsRoot and IndexRoot, it exists so a caller
// that must bound an operation to that tree asks this package where it is
// instead of re-spelling the component.
func (c *Cache) OperatorRootDir() string {
	return filepath.Join(c.root, OperatorSubdir)
}

// operatorRecordPath is the record file itself.
func (c *Cache) operatorRecordPath() string {
	return filepath.Join(c.OperatorRootDir(), OperatorReferencesName)
}

// RecordOperatorImage records that an operator named (ref x platform), pinning
// root's blobs against the image GC until the name is removed.
//
// The union is keyed on the PAIR, so re-recording the same key REPLACES its
// entry rather than accumulating a second one — which is what makes a repeated
// `k3sm image pull` of a moving tag pin the new digest and stop pinning the old.
//
// Ordering, at the caller: this is called AFTER the pull or the index write has
// succeeded and BEFORE that path's lease is released, so the blobs are covered
// by one or the other at every instant. Recording a root for content that is not
// yet committed would pin digests the store does not have, which a prune reads
// as an ordinary miss but which makes the record a lie.
func (c *Cache) RecordOperatorImage(ref string, platform Platform, root ImageRoot) error {
	if ref == "" {
		return errors.New("record operator image root: reference is required")
	}
	p := platform.Normalize()
	if p.OS == "" || p.Architecture == "" {
		return fmt.Errorf("record operator image root %q: incomplete platform %s", ref, p)
	}
	c.operatorMu.Lock()
	defer c.operatorMu.Unlock()
	existing, err := c.readOperatorRecord()
	if err != nil {
		return err
	}
	entry := operatorRootEntry{
		Reference: ref,
		Platform:  toIndexPlatform(p),
		Config:    root.Config,
		Layers:    root.Layers,
	}
	replaced := false
	for i := range existing {
		if existing[i].Reference == ref && existing[i].Platform == entry.Platform {
			existing[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, entry)
	}
	return c.writeOperatorRecord(existing)
}

// RemoveOperatorImage removes the operator root for (ref x platform), reporting
// whether one was there to remove.
//
// It removes a ROOT, never a blob: content is reclaimed only by a prune, which
// re-derives reachability first. An absent root is false with no error — at this
// layer the removal simply had nothing to do, and it is the RPC layer that
// decides whether the caller's request was nonetheless a NOT_FOUND.
func (c *Cache) RemoveOperatorImage(ref string, platform Platform) (bool, error) {
	if ref == "" {
		return false, errors.New("remove operator image root: reference is required")
	}
	key := toIndexPlatform(platform)
	c.operatorMu.Lock()
	defer c.operatorMu.Unlock()
	existing, err := c.readOperatorRecord()
	if err != nil {
		return false, err
	}
	out := make([]operatorRootEntry, 0, len(existing))
	removed := false
	for _, e := range existing {
		if e.Reference == ref && e.Platform == key {
			removed = true
			continue
		}
		out = append(out, e)
	}
	if !removed {
		return false, nil
	}
	if err := c.writeOperatorRecord(out); err != nil {
		return false, err
	}
	return true, nil
}

// OperatorImageRoots returns every operator-owned root, sorted by reference then
// platform.
//
// An ABSENT record is an empty set with no error: a node on which no operator
// has ever named an image has no operator roots, and that is the true answer. An
// UNREADABLE one is ErrRootsIncomplete — see Cache.Roots for why the incomplete
// case inverts a prune's answer rather than degrading it.
func (c *Cache) OperatorImageRoots() ([]OperatorImageRoot, error) {
	c.operatorMu.Lock()
	entries, err := c.readOperatorRecord()
	c.operatorMu.Unlock()
	if err != nil {
		return nil, err
	}
	out := make([]OperatorImageRoot, 0, len(entries))
	for _, e := range entries {
		out = append(out, OperatorImageRoot{
			Reference: e.Reference,
			Platform:  e.Platform.platform(),
			Root:      ImageRoot{Reference: e.Reference, Config: e.Config, Layers: e.Layers},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reference != out[j].Reference {
			return out[i].Reference < out[j].Reference
		}
		return out[i].Platform.String() < out[j].Platform.String()
	})
	return out, nil
}

// readOperatorRecord reads the record, failing CLOSED on anything it cannot
// believe. The caller holds operatorMu.
func (c *Cache) readOperatorRecord() ([]operatorRootEntry, error) {
	path := c.operatorRecordPath()
	buf, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		// LOCAL-ONLY, no boundErr: an fs.PathError over the daemon's own store
		// path plus an errno. No registry-supplied content reaches it.
		return nil, fmt.Errorf("%w: read operator image roots %s: %v", ErrRootsIncomplete, path, err)
	}
	var rec operatorRecord
	if err := json.Unmarshal(buf, &rec); err != nil {
		// The record's fields were filled from registry-supplied references and
		// digests, and encoding/json echoes the offending byte. Bounded as DATA.
		return nil, fmt.Errorf("%w: decode operator image roots: %v", ErrRootsIncomplete, boundErr(err))
	}
	if rec.Schema != operatorSchema {
		return nil, fmt.Errorf("%w: operator image roots were written under schema %d, this daemon speaks %d",
			ErrRootsIncomplete, rec.Schema, operatorSchema)
	}
	for _, e := range rec.Images {
		for _, d := range (ImageRoot{Config: e.Config, Layers: e.Layers}).Digests() {
			if _, perr := parseBlobDigest(d); perr != nil {
				// ALREADY BOUNDED AT THE SOURCE, as in Cache.Roots: parseBlobDigest
				// caps both halves of its own error.
				return nil, fmt.Errorf("%w: operator root %s records unusable digest: %v",
					ErrRootsIncomplete, quoteBounded(e.Reference, maxDigestLen), perr)
			}
		}
	}
	return rec.Images, nil
}

// writeOperatorRecord writes the record atomically (temp + fsync + rename), so a
// crashed write leaves either the previous record or none — never a TRUNCATED
// one, which would read back as "fewer images are pinned than are", the
// corruption that loses data instead of merely refusing to reclaim it. The
// caller holds operatorMu.
func (c *Cache) writeOperatorRecord(entries []operatorRootEntry) error {
	dir := c.OperatorRootDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create operator root dir %s: %w", dir, err)
	}
	if entries == nil {
		entries = []operatorRootEntry{}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Reference != entries[j].Reference {
			return entries[i].Reference < entries[j].Reference
		}
		return entries[i].Platform.platform().String() < entries[j].Platform.platform().String()
	})
	buf, err := json.Marshal(operatorRecord{Schema: operatorSchema, Images: entries})
	if err != nil {
		return fmt.Errorf("encode operator image roots: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".images-*")
	if err != nil {
		return fmt.Errorf("temp operator image roots: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("write operator image roots: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync operator image roots: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close operator image roots: %w", err)
	}
	if err := os.Rename(tmpName, c.operatorRecordPath()); err != nil {
		return fmt.Errorf("commit operator image roots: %w", err)
	}
	return nil
}
