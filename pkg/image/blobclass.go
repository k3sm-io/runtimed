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
	"strings"
	"time"
)

// The class names StoreBytesByClass reports besides artifact types. An
// artifact's blobs are classed by its artifactType itself (a media type, so it
// always contains a "/"); these names contain none, so a class key is never
// ambiguous between the two.
const (
	// ClassImage is content an image names: the blobs a pull-cache index
	// entry, an operator record or a pod's reachability record names, and
	// every unpacked or snapshot tree.
	ClassImage = "image"
	// ClassArtifact is an artifact blob whose artifactType is unknown: one a
	// pod's hold names with no record, live or released, to type it, or one
	// whose record carries no media-type-shaped artifactType.
	ClassArtifact = "artifact"
	// ClassUnattributed is content nothing names: a blob whose image entry and
	// records are all gone, and an ingest temp.
	ClassUnattributed = "unattributed"
)

// IsArtifactClass reports whether class names artifact content: an
// artifactType, or ClassArtifact.
func IsArtifactClass(class string) bool {
	return class != "" && class != ClassImage && class != ClassUnattributed
}

// artifactClass returns the class of an artifact whose record carries typ. A
// type that is not media-type shaped is ClassArtifact, so a registry-supplied
// type can never pose as ClassImage or ClassUnattributed.
func artifactClass(typ string) string {
	if !strings.Contains(typ, "/") {
		return ClassArtifact
	}
	return typ
}

// releasedClass is the artifactType and release time a released record copy
// gives a blob.
type releasedClass struct {
	class      string
	releasedAt time.Time
}

// blobClasses classes blob digests by what names them. It is ACCOUNTING and
// ORDER only: reachability never reads it, so a class that is wrong or missing
// can change which eligible blob goes first, never whether a blob is eligible.
type blobClasses struct {
	// live maps a digest to the class of a live artifact record naming it.
	live map[string]string
	// held is every digest a pod's artifact hold names.
	held map[string]bool
	// image is every digest an image names (see ClassImage).
	image map[string]bool
	// released maps a digest to the most recent released record copy naming it.
	released map[string]releasedClass
	// copies are the released record copies read, for the sweep.
	copies []releasedArtifact
}

// classOf returns the class of digest. A live record types its blobs first;
// a held blob is an artifact whatever else names it; an image beats a
// released copy, so a blob both share is evicted with the images, later.
func (b *blobClasses) classOf(digest string) string {
	if c, ok := b.live[digest]; ok {
		return c
	}
	if b.held[digest] {
		if r, ok := b.released[digest]; ok {
			return r.class
		}
		return ClassArtifact
	}
	if b.image[digest] {
		return ClassImage
	}
	if r, ok := b.released[digest]; ok {
		return r.class
	}
	return ClassUnattributed
}

// readBlobClasses reads what names each blob: the live artifact records, the
// pods' artifact holds, the pull-cache index, the operator record, the pods'
// reachability records and the released record copies.
//
// It fails on a live record, hold, index entry or operator record it cannot
// read, as the listing and the root set do, because a class read from half of
// them would misreport the store. A pod's reachability record it cannot read,
// and a released copy it cannot read, are skipped: Roots is the authority
// that fails closed on the first, and the second is a hint by construction.
func (c *Cache) readBlobClasses(ctx context.Context) (*blobClasses, error) {
	b := &blobClasses{
		live:     map[string]string{},
		held:     map[string]bool{},
		image:    map[string]bool{},
		released: map[string]releasedClass{},
	}
	x := &FileIndex{dir: c.IndexRoot()}
	records, err := x.artifactRecords()
	if err != nil {
		return nil, fmt.Errorf("artifact records: %w", err)
	}
	for _, rec := range records {
		var r artifactRecordRoot
		if err := decodeRecordRoot(rec.buf, &r); err != nil {
			return nil, fmt.Errorf("artifact record %q: %w", rec.name, err)
		}
		class := artifactClass(r.ArtifactType)
		for _, d := range recordDigests(r) {
			// Two live records of different types naming one blob: the
			// smaller type wins, so the answer does not depend on read order.
			if cur, ok := b.live[d]; !ok || class < cur {
				b.live[d] = class
			}
		}
	}
	holds, err := x.artifactHolds()
	if err != nil {
		return nil, err
	}
	for _, h := range holds {
		for _, m := range h.Manifests {
			b.held[m.Config] = true
			for _, l := range m.Layers {
				b.held[l] = true
			}
		}
	}
	entries, err := x.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("image index: %w", err)
	}
	for _, e := range entries {
		if d := e.Manifest.GetConfig().GetDigest(); d != "" {
			b.image[d] = true
		}
		for _, l := range e.Manifest.GetLayers() {
			if d := l.GetDigest(); d != "" {
				b.image[d] = true
			}
		}
	}
	operator, err := c.OperatorImageRoots()
	if err != nil {
		return nil, err
	}
	for _, r := range operator {
		for _, d := range r.Root.Digests() {
			b.image[d] = true
		}
	}
	for _, d := range c.podImageDigests() {
		b.image[d] = true
	}
	copies, err := x.releasedArtifacts()
	if err != nil {
		return nil, err
	}
	b.copies = copies
	for _, rc := range copies {
		class := artifactClass(rc.root.ArtifactType)
		for _, d := range recordDigests(rc.root) {
			if cur, ok := b.released[d]; !ok || rc.releasedAt.After(cur.releasedAt) {
				b.released[d] = releasedClass{class: class, releasedAt: rc.releasedAt}
			}
		}
	}
	return b, nil
}

// decodeRecordRoot decodes the GC's view of an artifact record, refusing one
// DecodeArtifactRoot refuses, and bounding the decoder's echo of its bytes.
func decodeRecordRoot(buf []byte, r *artifactRecordRoot) error {
	if _, err := DecodeArtifactRoot(buf); err != nil {
		return err
	}
	if err := json.Unmarshal(buf, r); err != nil {
		return fmt.Errorf("decode artifact record: %v", boundErr(err))
	}
	return nil
}

// recordDigests returns the blobs a record root names.
func recordDigests(r artifactRecordRoot) []string {
	return ImageRoot{Config: r.ConfigDigest, Layers: r.LayerDigests}.Digests()
}

// podImageDigests returns every digest the pods' reachability records name,
// skipping any pod dir whose record is absent or unreadable (see
// readBlobClasses for why that is safe here and nowhere in Roots).
func (c *Cache) podImageDigests() []string {
	entries, err := os.ReadDir(c.PodsRoot())
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		id, err := ParsePodID(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		roots, err := c.PodImageRoots(id)
		if err != nil {
			continue
		}
		for _, r := range roots {
			out = append(out, r.Digests()...)
		}
	}
	return out
}

// StoreBytesByClass is StoreBytes split by class: ClassImage, one class per
// artifactType, ClassArtifact and ClassUnattributed (see readBlobClasses for
// what names what). Each blob is one file per digest, so a blob several
// images or artifacts share counts once, under the class classOf gives it.
// The classes sum to StoreBytes over the same inventory.
//
// It carries every caveat StoreBytes does: it is what the store holds, not
// what a prune would reclaim, and a blob whose extents are cloned into a live
// pod or an artifact view counts in full. A class with no content is absent.
func (c *Cache) StoreBytesByClass(ctx context.Context) (map[string]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nodes, err := c.EnumerateBlobs()
	if err != nil {
		return nil, err
	}
	trees, err := c.EnumerateTrees()
	if err != nil {
		return nil, err
	}
	classes, err := c.readBlobClasses(ctx)
	if err != nil {
		return nil, fmt.Errorf("class the image store: %w", err)
	}
	out := map[string]int64{}
	for _, n := range nodes {
		class := ClassUnattributed
		if n.Kind == BlobKindContent && n.Digest != "" {
			class = classes.classOf(n.Digest)
		}
		out[class] += n.Size
	}
	for _, t := range trees {
		out[ClassImage] += t.Size
	}
	return out, nil
}

// orderEvictions splits a delete plan into the eviction order reclaim runs:
// first the blobs of released artifacts, least recently released first (a
// pod-only record is released when its last pod goes, so this is least
// recently mounted first); then the rest, content nothing names before image
// content, each group in its plan (path) order.
//
// It is a permutation of dels and nothing else: every decision in dels comes
// back exactly once in first or rest, unchanged, so the order can never add a
// blob to the plan, drop one, or alter a verdict.
func orderEvictions(dels []PruneDecision, classes *blobClasses) (first, rest []PruneDecision) {
	var unnamed, images []PruneDecision
	for _, d := range dels {
		class := ClassUnattributed
		if d.Node.Kind == BlobKindContent && d.Node.Digest != "" {
			class = classes.classOf(d.Node.Digest)
		}
		switch {
		case IsArtifactClass(class):
			first = append(first, d)
		case class == ClassImage:
			images = append(images, d)
		default:
			unnamed = append(unnamed, d)
		}
	}
	slices.SortStableFunc(first, func(a, b PruneDecision) int {
		return classes.released[a.Node.Digest].releasedAt.Compare(classes.released[b.Node.Digest].releasedAt)
	})
	return first, append(unnamed, images...)
}

// classBytes sums the logical size of the removed digests by class; the
// removed bytes no digest accounts for (ingest temps) are ClassUnattributed.
func classBytes(dels []PruneDecision, removed []string, deleted int64, classes *blobClasses, into map[string]int64) {
	size := make(map[string]int64, len(dels))
	for _, d := range dels {
		if d.Node.Digest != "" {
			size[d.Node.Digest] = d.Node.Size
		}
	}
	var named int64
	for _, dg := range removed {
		into[classes.classOf(dg)] += size[dg]
		named += size[dg]
	}
	if rest := deleted - named; rest > 0 {
		into[ClassUnattributed] += rest
	}
}

// sweepReleased removes the released record copies that class nothing any
// more: every blob they name is gone from the store or named by a live
// record. It is called after a reclaim pass's unlinks.
func (c *Cache) sweepReleased(classes *blobClasses) error {
	var drop []string
	for _, rc := range classes.copies {
		if !slices.ContainsFunc(recordDigests(rc.root), func(d string) bool {
			_, live := classes.live[d]
			return !live && c.Has(d)
		}) {
			drop = append(drop, rc.name)
		}
	}
	x := &FileIndex{dir: c.IndexRoot()}
	if err := x.sweepReleasedArtifacts(drop); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
