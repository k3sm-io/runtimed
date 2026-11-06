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
	"path/filepath"
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

// HoldReadError is the ErrArtifactHoldsIncomplete failure for one hold file,
// naming its path so the operator can find it.
type HoldReadError struct {
	Path string
	Err  error
}

func (e *HoldReadError) Error() string {
	return fmt.Sprintf("%v: %s: %v", ErrArtifactHoldsIncomplete, e.Path, e.Err)
}

func (e *HoldReadError) Unwrap() []error { return []error{ErrArtifactHoldsIncomplete, e.Err} }

// holdID returns the pod a hold file name belongs to: <pod-id>.json, with
// the id valid. Any other name can never be a hold.
func holdID(name string) (PodID, bool) {
	base, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return PodID{}, false
	}
	id, err := ParsePodID(base)
	return id, err == nil
}

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

// AddArtifactHoldReferences adds refs to pod id's hold, creating it when
// absent, atomically (temp, fsync, rename). It never drops what the hold
// names already, so a second create of the same pod id merges into the hold
// the first one wrote rather than replacing the manifests it mounts.
func (x *FileIndex) AddArtifactHoldReferences(ctx context.Context, id PodID, refs []string) error {
	return x.updateArtifactHold(ctx, id, func(cur *ArtifactHold) ArtifactHold {
		var h ArtifactHold
		if cur != nil {
			h = *cur
		}
		h.References = append(h.References, refs...)
		sort.Strings(h.References)
		h.References = slices.Compact(h.References)
		return h
	})
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
	cur, err := readArtifactHold(sub, filepath.Join(x.dir, ArtifactHoldIndexSubdir, name), name, id)
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
// It fails closed, with ErrArtifactHoldsIncomplete (a *HoldReadError naming
// the file): a hold that is not a regular file, cannot be read or decoded, or
// names a digest this store cannot map to a path aborts the whole set, because
// a set silently short of one pod's hold would release or remove what that pod
// still mounts. An entry whose name is not <pod-id>.json can never be a hold
// (none is ever written under such a name) and is skipped, as is a ".index-"
// temp left by a crashed commit; SweepArtifactHolds removes the former at
// start-up.
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
		id, ok := holdID(name)
		if !ok {
			continue
		}
		h, err := readArtifactHold(sub, filepath.Join(x.dir, ArtifactHoldIndexSubdir, name), name, id)
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

// readArtifactHold reads and checks pod id's hold from sub; path names it
// for errors. An absent hold is fs.ErrNotExist; anything else wrong with it is
// a *HoldReadError.
func readArtifactHold(sub *os.Root, path, name string, id PodID) (*ArtifactHold, error) {
	bad := func(format string, args ...any) error {
		return &HoldReadError{Path: path, Err: fmt.Errorf("hold of pod %s: "+format, append([]any{id}, args...)...)}
	}
	fi, err := sub.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, bad("stat: %v", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxArtifactHoldBytes {
		return nil, bad("not a regular file within its cap (mode %v, %d bytes)", fi.Mode().Type(), fi.Size())
	}
	buf, err := readAnchored(sub, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, bad("read: %v", err)
	}
	var h ArtifactHold
	if err := json.Unmarshal(buf, &h); err != nil {
		return nil, bad("decode: %v", boundErr(err))
	}
	for _, m := range h.Manifests {
		if err := m.check(); err != nil {
			return nil, bad("%v", err)
		}
	}
	return &h, nil
}

// SweepArtifactHolds removes, at daemon start, every entry of the hold
// directory that is not the hold of a pod keep accepts: an entry whose name is
// not <pod-id>.json (it can never be a hold), and the hold of every pod keep
// rejects, whether or not it can be read. The caller knows the complete pod
// set there, so a hold of a pod outside it holds nothing; a hold of a pod
// inside it is left alone however broken, and keeps failing closed. Dot
// entries (a crashed commit's temp) are left. It returns the names it
// removed.
func (x *FileIndex) SweepArtifactHolds(keep func(PodID) bool) ([]string, error) {
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer sub.Close()
	dir, err := sub.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open artifact holds: %w", err)
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("read artifact holds: %w", err)
	}
	var removed []string
	var errs []error
	for _, d := range entries {
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if id, ok := holdID(name); ok {
			if keep(id) {
				continue
			}
			mu := x.stripeFor(ArtifactHoldIndexSubdir + "/" + name)
			mu.Lock()
			err = sub.RemoveAll(name)
			mu.Unlock()
		} else {
			err = sub.RemoveAll(name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", QuoteBounded(name, 256), err))
			continue
		}
		removed = append(removed, name)
	}
	return removed, errors.Join(errs...)
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
