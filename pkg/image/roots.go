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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// PodReferencesName is the per-pod reachability record the daemon writes inside
// each pod dir: <root>/pods/<podID>/images.json.
//
// It is DAEMON-AUTHORED, and that is the whole point. Reachability roots may
// never be derived from registry-supplied bytes — a manifest the registry served
// can contribute edges, never a root, or a hostile (or merely mutable) image
// would get to decide what survives a prune. The daemon writes this file from
// what it itself resolved for a pod it itself created, so the root set is
// authored by the only party entitled to author it.
const PodReferencesName = "images.json"

// ErrRootsIncomplete reports that the reachability root set could NOT be
// enumerated in full, so no deletion decision may be made from it.
//
// This is the load-bearing fail-closed sentinel of the image GC. A prune deletes
// exactly what no root names, so an INCOMPLETE root set does not degrade the
// answer — it inverts it: every blob belonging to the pod whose record could not
// be read looks unreferenced, and the GC would unlink the layers of a live pod.
// So an unreadable, absent, malformed, or unexpected node anywhere under the
// pods tree aborts the whole prune with this error and deletes nothing.
var ErrRootsIncomplete = errors.New("image: reachability root set is incomplete")

// ImageRoot is one daemon-authored reachability root: the blobs one pod
// resolved for one image reference.
//
// It names the CONFIG and LAYER digests only, because those are the only things
// the content-addressed store holds — the pull path writes config + layers and
// never the manifest itself (Puller.Pull). There is deliberately no manifest
// digest, no media type and no size here: every one of those would be a second
// spelling of a fact the store already holds, and a root that carried content
// metadata would invite the GC to start reasoning about content rather than
// about who referenced it.
type ImageRoot struct {
	// Reference is the pull reference this root was recorded for. It is
	// informational — identity for an audit or a listing, never an input to
	// reachability.
	Reference string `json:"reference"`
	// Config is the image config blob's digest ("<algo>:<hex>").
	Config string `json:"config"`
	// Layers are the layer blobs' digests, in apply order.
	Layers []string `json:"layers"`
}

// Digests returns every blob digest this root makes reachable.
func (r ImageRoot) Digests() []string {
	out := make([]string, 0, len(r.Layers)+1)
	if r.Config != "" {
		out = append(out, r.Config)
	}
	out = append(out, r.Layers...)
	return out
}

// podReferences is the on-disk shape of PodReferencesName. It is a struct rather
// than a bare array so a future field (a schema version, a recorded-at stamp)
// does not have to break the file's top-level JSON type.
type podReferences struct {
	Images []ImageRoot `json:"images"`
}

// EnsurePodReferences creates an EMPTY reachability record for podID if none
// exists, and is a no-op if one does.
//
// Every pod dir must carry a record from the moment it exists, including a pod
// that pulls nothing (a native host-binary pod, a vm pod). Absence is what
// Roots reads as "this pod's references are unknown", and an unknown pod aborts
// the prune — so a pod dir with no record is an outage of the GC, not of the
// pod. Creating the empty record at pod-dir creation is what keeps absence rare
// enough to be treated as the anomaly it is.
func (c *Cache) EnsurePodReferences(podID PodID) error {
	dir := c.PodDir(podID)
	if _, err := os.Lstat(filepath.Join(dir, PodReferencesName)); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat pod references %s: %w", podID, err)
	}
	return c.writePodReferences(podID, nil)
}

// RecordPodImage records that podID references root's blobs, unioning it into
// the pod's existing record.
//
// The union is keyed on Reference, so a re-pull of the same reference REPLACES
// its entry rather than accumulating a second one, and a pod with two containers
// from different images keeps both. It is called AFTER a successful pull and
// BEFORE the pull's lease is released, so the blob is covered by one or the
// other at every instant.
func (c *Cache) RecordPodImage(podID PodID, root ImageRoot) error {
	existing, err := c.PodImageRoots(podID)
	if err != nil {
		return err
	}
	replaced := false
	for i := range existing {
		if existing[i].Reference == root.Reference {
			existing[i] = root
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, root)
	}
	return c.writePodReferences(podID, existing)
}

// writePodReferences writes the pod's record atomically (temp + rename inside
// the pod dir), so a crashed write can never leave a TRUNCATED record — which
// would read back as "this pod references fewer blobs than it does", the one
// corruption that loses data instead of merely refusing to reclaim it.
func (c *Cache) writePodReferences(podID PodID, roots []ImageRoot) error {
	dir := c.PodDir(podID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create pod dir %s: %w", dir, err)
	}
	if roots == nil {
		roots = []ImageRoot{}
	}
	buf, err := json.Marshal(podReferences{Images: roots})
	if err != nil {
		return fmt.Errorf("encode pod references %s: %w", podID, err)
	}
	tmp, err := os.CreateTemp(dir, ".images-*")
	if err != nil {
		return fmt.Errorf("temp pod references %s: %w", podID, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("write pod references %s: %w", podID, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync pod references %s: %w", podID, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close pod references %s: %w", podID, err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, PodReferencesName)); err != nil {
		return fmt.Errorf("commit pod references %s: %w", podID, err)
	}
	return nil
}

// PodImageRoots returns the roots recorded for podID. An absent record is an
// empty slice with no error — the caller that is WRITING a record must be able
// to read the absent one first; it is Roots, the GC's enumerator, that treats
// absence as fatal.
func (c *Cache) PodImageRoots(podID PodID) ([]ImageRoot, error) {
	buf, err := os.ReadFile(filepath.Join(c.PodDir(podID), PodReferencesName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pod references %s: %w", podID, err)
	}
	var rec podReferences
	if err := json.Unmarshal(buf, &rec); err != nil {
		return nil, fmt.Errorf("decode pod references %s: %w", podID, err)
	}
	return rec.Images, nil
}

// Roots enumerates the COMPLETE reachability root set for this store: every
// image every pod dir records.
//
// It fails closed and it fails LOUDLY. The pods tree is walked through an
// os.Root anchored at the pods dir, so no symlink can redirect the walk out of
// it, and every one of these conditions returns ErrRootsIncomplete with NO
// roots at all rather than a partial set:
//
//   - a node under the pods tree that is not a directory (a stray file, a
//     symlink planted where a pod dir belongs);
//   - a pod dir with no reachability record — the pod's blobs would look
//     unreferenced;
//   - a record that cannot be read or decoded;
//   - a record naming a digest this store's closed algorithm allowlist cannot
//     parse, since a root the store cannot map to a path cannot protect one.
//
// An ABSENT pods dir is not incomplete: a node with no pods tree has no pods,
// so the empty root set is the true answer and reclaim may proceed.
func (c *Cache) Roots() ([]ImageRoot, error) {
	podsRoot := c.PodsRoot()
	entries, err := os.ReadDir(podsRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		// LOCAL-ONLY, no boundErr (this one and the OpenRoot below): stdlib os
		// errors over the daemon's OWN store root. Their rendering is a path this
		// package composed plus an errno — none of the foreign, unbounded content
		// boundErr exists to cap can reach them.
		return nil, fmt.Errorf("%w: read pods root %s: %v", ErrRootsIncomplete, podsRoot, err)
	}
	root, err := os.OpenRoot(podsRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: open pods root %s: %v", ErrRootsIncomplete, podsRoot, err)
	}
	defer root.Close()

	var out []ImageRoot
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		// Lstat through the anchored root: a symlink is judged on ITSELF, so a
		// link named like a pod dir is an unexpected node, not a followed path.
		fi, err := root.Lstat(name)
		if err != nil {
			// LOCAL-ONLY, no boundErr: an fs.PathError naming a pod directory this
			// daemon created. It reads no record, so no stored content is in it.
			return nil, fmt.Errorf("%w: stat pod dir %q: %v", ErrRootsIncomplete, name, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%w: %q under %s is not a pod directory (mode %v)",
				ErrRootsIncomplete, name, podsRoot, fi.Mode().Type())
		}
		buf, err := readAnchored(root, filepath.Join(name, PodReferencesName))
		if err != nil {
			// LOCAL-ONLY, no boundErr: readAnchored fails with an fs.PathError (or
			// its own not-a-regular-file message) naming a daemon-composed path. The
			// record's CONTENT reaches a message only at the decode below — which is
			// bounded, because that is where foreign bytes actually arrive.
			return nil, fmt.Errorf("%w: pod %q: %v", ErrRootsIncomplete, name, err)
		}
		var rec podReferences
		if err := json.Unmarshal(buf, &rec); err != nil {
			// encoding/json echoes the offending byte of the document it was handed,
			// and this document's fields were filled from registry-supplied image
			// references and digests. Bounded as DATA, never adopted.
			return nil, fmt.Errorf("%w: pod %q: decode %s: %v", ErrRootsIncomplete, name, PodReferencesName, boundErr(err))
		}
		for _, r := range rec.Images {
			for _, d := range r.Digests() {
				if _, perr := parseBlobDigest(d); perr != nil {
					// ALREADY BOUNDED AT THE SOURCE, so no second boundErr: perr is this
					// package's own error, and parseBlobDigest caps both halves of it —
					// quoteBounded on the registry-supplied digest, boundErr on ggcr's
					// parser message. Wrapping again would only re-quote a quoted string.
					return nil, fmt.Errorf("%w: pod %q records unusable digest: %v", ErrRootsIncomplete, name, perr)
				}
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// readAnchored reads rel through root, refusing anything that is not a regular
// file. It exists so the "absent" and "not a regular file" cases both surface as
// errors here rather than as an empty record at the call site.
func readAnchored(root *os.Root, rel string) ([]byte, error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (mode %v)", rel, fi.Mode().Type())
	}
	return io.ReadAll(f)
}
