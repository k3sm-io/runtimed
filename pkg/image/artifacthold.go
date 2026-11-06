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
	"os"
	"slices"
	"sort"
	"strings"
)

// ArtifactHoldIndexSubdir is the index-relative directory a pod's artifact
// holds live in: <root>/index/artifact-hold/<pod-id>.json. A hold names the
// artifact references a pod mounts, from before their fetch to the pod's
// deletion, and each manifest those references resolved to, with its blobs. It
// is under the index, which every pod is denied, rather than in the pod dir,
// which a pod may be able to write.
//
// A held manifest is a reachability root (Cache.Roots) and keeps its views
// (artifact.Views) for as long as the hold exists, whatever the artifact
// records say: a tag that moves to another manifest replaces its record, but
// never takes the files out from under a pod that mounts the old one.
const ArtifactHoldIndexSubdir = "artifact-hold"

// MaxArtifactHoldBytes caps one hold record: a pod names at most a few hundred
// volumes, each with a bounded reference and at most a few thousand layers.
const MaxArtifactHoldBytes = 4 << 20

// ErrArtifactHoldsIncomplete reports that the set of pod holds could not be
// read in full, so nothing may be released or removed on its strength.
var ErrArtifactHoldsIncomplete = errors.New("image: artifact hold set is incomplete")

// ArtifactHold is one pod's hold.
type ArtifactHold struct {
	// References are the image-volume references the pod mounts.
	References []string `json:"references"`
	// Manifests are the manifests those references resolved to for this pod.
	Manifests []HeldManifest `json:"manifests,omitempty"`
}

// HeldManifest is one manifest a pod mounts and the blobs its view is built
// from.
type HeldManifest struct {
	Digest string   `json:"digest"`
	Config string   `json:"config"`
	Layers []string `json:"layers"`
}

// root returns the blobs m names as a reachability root.
func (m HeldManifest) root(id PodID) ImageRoot {
	return ImageRoot{Reference: "artifact-hold:" + id.String() + "@" + m.Digest, Config: m.Config, Layers: m.Layers}
}

// check refuses a held manifest whose digests this store cannot map to a path:
// a root that cannot be read cannot protect anything.
func (m HeldManifest) check() error {
	if _, err := parseBlobDigest(m.Digest); err != nil {
		return fmt.Errorf("held manifest: %w", err)
	}
	for _, d := range append([]string{m.Config}, m.Layers...) {
		if _, err := parseBlobDigest(d); err != nil {
			return fmt.Errorf("held manifest %s: %w", m.Digest, err)
		}
	}
	return nil
}

func artifactHoldName(id PodID) string { return id.String() + ".json" }

// PutArtifactHold records that pod id holds refs, replacing any previous hold
// for it (and the manifests it named), atomically (temp, fsync, rename).
func (x *FileIndex) PutArtifactHold(ctx context.Context, id PodID, refs []string) error {
	refs = append([]string(nil), refs...)
	sort.Strings(refs)
	return x.updateArtifactHold(ctx, id, func(*ArtifactHold) ArtifactHold { return ArtifactHold{References: refs} })
}

// AddArtifactHoldManifest adds m to pod id's hold, keeping what it holds
// already. It is written after the fetch resolved m and before the fetch's
// lease is released, so m's blobs are covered by one or the other throughout.
func (x *FileIndex) AddArtifactHoldManifest(ctx context.Context, id PodID, m HeldManifest) error {
	if err := m.check(); err != nil {
		return err
	}
	return x.updateArtifactHold(ctx, id, func(cur *ArtifactHold) ArtifactHold {
		var h ArtifactHold
		if cur != nil {
			h = *cur
		}
		if !slices.ContainsFunc(h.Manifests, func(o HeldManifest) bool { return o.Digest == m.Digest }) {
			h.Manifests = append(h.Manifests, m)
		}
		return h
	})
}

// updateArtifactHold rewrites pod id's hold to next(current) under the hold's
// lock; current is nil when there is none. A current hold that cannot be read
// is an error, never overwritten.
func (x *FileIndex) updateArtifactHold(ctx context.Context, id PodID, next func(cur *ArtifactHold) ArtifactHold) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := artifactHoldName(id)
	mu := x.stripeFor(ArtifactHoldIndexSubdir + "/" + name)
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(x.dir, 0o700); err != nil {
		return fmt.Errorf("create image index %s: %w", x.dir, err)
	}
	root, err := x.open()
	if err != nil {
		return err
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, true)
	if err != nil {
		return err
	}
	defer sub.Close()
	cur, err := readArtifactHold(sub, name, id)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	buf, err := json.Marshal(next(cur))
	if err != nil {
		return fmt.Errorf("encode artifact hold: %w", err)
	}
	if len(buf) > MaxArtifactHoldBytes {
		return fmt.Errorf("artifact hold for pod %s is %d bytes, at most %d", id, len(buf), MaxArtifactHoldBytes)
	}
	return x.commit(sub, name, buf)
}

// RemoveArtifactHold removes pod id's hold. A missing hold is not an error.
func (x *FileIndex) RemoveArtifactHold(id PodID) error {
	name := artifactHoldName(id)
	mu := x.stripeFor(ArtifactHoldIndexSubdir + "/" + name)
	mu.Lock()
	defer mu.Unlock()
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer sub.Close()
	if err := sub.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove artifact hold of pod %s: %w", id, err)
	}
	return nil
}

// ArtifactHolds returns every pod's hold, keyed by pod. An absent index or
// hold directory is the empty set.
//
// It fails closed, with ErrArtifactHoldsIncomplete: an entry whose name is not
// a pod id, one that is not a regular file, one that cannot be read or decoded,
// and one naming a digest this store cannot map to a path abort the whole set,
// because a set silently short of one pod's hold would release or remove what
// that pod still mounts. A ".index-" temp left by a crashed commit is skipped;
// no hold is stored under a dot name.
func (x *FileIndex) ArtifactHolds(ctx context.Context) (map[PodID]ArtifactHold, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return x.artifactHolds()
}

// HeldManifests returns the digest of every manifest some pod's hold names,
// failing closed as ArtifactHolds does. artifact.Views keeps every view of a
// held manifest.
func (x *FileIndex) HeldManifests(ctx context.Context) (map[string]bool, error) {
	holds, err := x.ArtifactHolds(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, h := range holds {
		for _, m := range h.Manifests {
			out[m.Digest] = true
		}
	}
	return out, nil
}

// artifactHolds is ArtifactHolds without the context check, for the GC's root
// enumerator, which runs under no request context.
func (x *FileIndex) artifactHolds() (map[PodID]ArtifactHold, error) {
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[PodID]ArtifactHold{}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrArtifactHoldsIncomplete, err)
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[PodID]ArtifactHold{}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrArtifactHoldsIncomplete, err)
	}
	defer sub.Close()
	dir, err := sub.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: open artifact holds: %v", ErrArtifactHoldsIncomplete, err)
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: read artifact holds: %v", ErrArtifactHoldsIncomplete, err)
	}
	out := make(map[PodID]ArtifactHold, len(entries))
	for _, d := range entries {
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		id, perr := ParsePodID(strings.TrimSuffix(name, ".json"))
		if perr != nil || !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("%w: entry %s is not a pod's hold", ErrArtifactHoldsIncomplete, QuoteBounded(name, 256))
		}
		h, err := readArtifactHold(sub, name, id)
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed since the read; that pod holds nothing now
		}
		if err != nil {
			return nil, err
		}
		out[id] = *h
	}
	return out, nil
}

// readArtifactHold reads and checks pod id's hold from sub. An absent hold is
// fs.ErrNotExist; anything else wrong with it is ErrArtifactHoldsIncomplete.
func readArtifactHold(sub *os.Root, name string, id PodID) (*ArtifactHold, error) {
	fi, err := sub.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: stat hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxArtifactHoldBytes {
		return nil, fmt.Errorf("%w: hold of pod %s is not a regular file within its cap (mode %v, %d bytes)", ErrArtifactHoldsIncomplete, id, fi.Mode().Type(), fi.Size())
	}
	buf, err := readAnchored(sub, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: read hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, err)
	}
	var h ArtifactHold
	if err := json.Unmarshal(buf, &h); err != nil {
		return nil, fmt.Errorf("%w: decode hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, boundErr(err))
	}
	for _, m := range h.Manifests {
		if err := m.check(); err != nil {
			return nil, fmt.Errorf("%w: hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, err)
		}
	}
	return &h, nil
}

// artifactHoldRoots returns one root per manifest some pod's hold names,
// ErrRootsIncomplete when the holds cannot all be read.
func (c *Cache) artifactHoldRoots() ([]ImageRoot, error) {
	x := &FileIndex{dir: c.IndexRoot()}
	holds, err := x.artifactHolds()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRootsIncomplete, err)
	}
	var out []ImageRoot
	for id, h := range holds {
		for _, m := range h.Manifests {
			out = append(out, m.root(id))
		}
	}
	return out, nil
}
