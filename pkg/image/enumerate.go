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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// manifestSniffLimit caps how large a blob the enumerator will read while
// deciding whether it is a persisted manifest (or, best-effort, a config). Real
// manifests are a few KiB; a layer blob above the cap is simply never a
// manifest candidate and stays unclassified until an edge names it.
const manifestSniffLimit = 4 << 20

// EnumerateBlobs walks ONLY the blobs/ tree of the cache and returns the prune
// inventory plus the per-image edge records recovered from persisted manifests
// (Puller.Pull writes one per pulled image). It is the production input to
// PlanPrune.
//
// Classification discipline is fail-closed for the SCAN, not just the plan:
//
//   - every node is classified by Lstat — symlinks are never followed;
//   - an unexpected entry (a symlink or directory planted in the tree, an
//     undecodable name, a stray top-level file) is inventoried as
//     BlobKindUnknown — which the planner keeps — never an error that aborts a
//     dry-run scan;
//   - a blob that parses as an OCI/Docker image manifest yields an ImageEdge;
//     one that exists but fails to parse is NOT a manifest to us, so the blobs
//     it would have named stay unnamed and the planner keeps them
//     (kept-unknown-provenance), never deletes them.
//
// Only the top-level read of the blobs dir itself can error (nothing at all can
// be scanned then).
func (c *Cache) EnumerateBlobs() ([]BlobNode, []ImageEdge, error) {
	blobs := c.blobsDir()
	top, err := os.ReadDir(blobs)
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate blobs: read %s: %w", blobs, err)
	}
	// All content reads below go through an fd-anchored root, so a planted
	// symlink cannot redirect the scan outside the blobs tree.
	root, err := os.OpenRoot(blobs)
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate blobs: open root %s: %w", blobs, err)
	}
	defer root.Close()

	var nodes []BlobNode
	for _, de := range top {
		info, ierr := de.Info()
		if ierr != nil {
			continue // vanished mid-scan
		}
		if !de.IsDir() {
			// A stray file (or symlink) at the top level, where only algo dirs
			// belong: unknown provenance.
			nodes = append(nodes, unknownNode(de.Name(), info))
			continue
		}
		sub, serr := os.ReadDir(filepath.Join(blobs, de.Name()))
		if serr != nil {
			nodes = append(nodes, unknownNode(de.Name(), info))
			continue
		}
		for _, e := range sub {
			rel := de.Name() + "/" + e.Name()
			ei, eerr := e.Info() // Lstat semantics: a symlink describes itself
			if eerr != nil {
				continue // vanished mid-scan
			}
			cls, digest := classifyBlobRel(rel)
			switch {
			case !ei.Mode().IsRegular():
				nodes = append(nodes, unknownNode(rel, ei))
			case cls == relTemp:
				nodes = append(nodes, BlobNode{Path: rel, Kind: BlobKindTemp, Size: ei.Size(), ModTime: ei.ModTime()})
			case cls == relContent:
				// Kind is refined below, once every manifest is parsed.
				nodes = append(nodes, BlobNode{Path: rel, Digest: digest, Kind: BlobKindUnknown, Size: ei.Size(), ModTime: ei.ModTime()})
			default:
				nodes = append(nodes, unknownNode(rel, ei))
			}
		}
	}

	// Second pass: sniff persisted manifests among the small content blobs and
	// build the edge records.
	var edges []ImageEdge
	manifestSet := make(map[string]bool)
	configSet := make(map[string]bool)
	layerSet := make(map[string]bool)
	for i := range nodes {
		n := &nodes[i]
		if n.Digest == "" || n.Kind != BlobKindUnknown || n.Size > manifestSniffLimit {
			continue
		}
		raw, rerr := readBlobAt(root, n.Path)
		if rerr != nil {
			continue // unreadable ⇒ stays unknown ⇒ kept
		}
		m, ok := parseManifestBlob(raw)
		if !ok {
			continue
		}
		edge := ImageEdge{Manifest: n.Digest, Config: m.Config.Digest.String()}
		for _, l := range m.Layers {
			edge.Layers = append(edge.Layers, l.Digest.String())
		}
		edge.Platform = sniffPlatform(root, m.Config.Digest)
		edges = append(edges, edge)
		manifestSet[n.Digest] = true
		configSet[edge.Config] = true
		for _, l := range edge.Layers {
			layerSet[l] = true
		}
	}
	for i := range nodes {
		n := &nodes[i]
		if n.Digest == "" || n.Kind != BlobKindUnknown {
			continue
		}
		switch {
		case manifestSet[n.Digest]:
			n.Kind = BlobKindManifest
		case configSet[n.Digest]:
			n.Kind = BlobKindConfig
		case layerSet[n.Digest]:
			n.Kind = BlobKindLayer
		}
		// Named by nothing: stays BlobKindUnknown ⇒ kept-unknown-provenance.
	}
	return nodes, edges, nil
}

// unknownNode inventories an unexpected entry as unknown provenance.
func unknownNode(rel string, fi fs.FileInfo) BlobNode {
	return BlobNode{Path: rel, Kind: BlobKindUnknown, Size: fi.Size(), ModTime: fi.ModTime()}
}

// readBlobAt reads one blob through the fd-anchored root, capped at the sniff
// limit.
func readBlobAt(root *os.Root, rel string) ([]byte, error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, manifestSniffLimit+1))
}

// parseManifestBlob reports whether raw is a persisted image manifest. The
// check is positive-identification: schema version 2, an image (never index)
// media type when one is present, and a well-formed config digest — a config
// blob (no "config" field) or arbitrary JSON does not qualify.
func parseManifestBlob(raw []byte) (*ggcrv1.Manifest, bool) {
	var m ggcrv1.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	if m.SchemaVersion != 2 {
		return nil, false
	}
	if m.MediaType != "" && !m.MediaType.IsImage() {
		return nil, false
	}
	if m.Config.Digest.Algorithm == "" || m.Config.Digest.Hex == "" {
		return nil, false
	}
	return &m, true
}

// sniffPlatform best-effort reads the image's config blob for its declared
// platform ("os/arch[/variant]"). It is informational only (ImageEdge.Platform
// never influences planning), so every failure returns "".
func sniffPlatform(root *os.Root, cfgDigest ggcrv1.Hash) string {
	rel := cfgDigest.Algorithm + "/" + cfgDigest.Hex
	if cls, _ := classifyBlobRel(rel); cls != relContent {
		return ""
	}
	fi, err := root.Lstat(rel)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > manifestSniffLimit {
		return ""
	}
	raw, err := readBlobAt(root, rel)
	if err != nil {
		return ""
	}
	var cf ggcrv1.ConfigFile
	if err := json.Unmarshal(raw, &cf); err != nil || cf.OS == "" || cf.Architecture == "" {
		return ""
	}
	p := cf.OS + "/" + cf.Architecture
	if cf.Variant != "" {
		p += "/" + cf.Variant
	}
	return p
}
