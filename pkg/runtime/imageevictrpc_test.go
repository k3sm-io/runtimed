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

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// evictRPCScene is two cached images A and B sharing one layer, each with an
// artifact view directory left on disk that no record names, served over the
// Images RPC.
type evictRPCScene struct {
	t                  *testing.T
	client             runtimev1.ImagesClient
	rt                 *Runtime
	refA, refB         string
	manA, manB         string
	cfgA, ownA, shared string
	cfgB, ownB         string
	viewA, viewB       string
}

func newEvictRPCScene(t *testing.T) *evictRPCScene {
	t.Helper()
	client, rt := imagesTestClient(t)
	if rt.views == nil {
		t.Fatalf("artifact views disabled in the test runtime: %v", rt.viewsErr)
	}
	s := &evictRPCScene{
		t: t, client: client, rt: rt,
		refA: "registry.test/evict/a:v1", refB: "registry.test/evict/b:v1",
		cfgA: putBlob(t, rt, "evict-rpc-cfg-a"), ownA: putBlob(t, rt, "evict-rpc-own-a"),
		shared: putBlob(t, rt, "evict-rpc-shared"),
		cfgB:   putBlob(t, rt, "evict-rpc-cfg-b"), ownB: putBlob(t, rt, "evict-rpc-own-b"),
	}
	s.manA = s.entry(s.refA, "A", s.cfgA, s.ownA, s.shared)
	s.manB = s.entry(s.refB, "B", s.cfgB, s.ownB, s.shared)
	s.viewA, s.viewB = s.view(s.manA), s.view(s.manB)
	return s
}

// entry records an index entry with a retained manifest naming cfg and layers
// and returns its manifest digest.
func (s *evictRPCScene) entry(ref, tag, cfg string, layers ...string) string {
	s.t.Helper()
	raw := []byte(`{"schemaVersion":2,"fixture":"evict-rpc-` + tag + `"}`)
	sum := sha256.Sum256(raw)
	desc := &runtimev1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Size:      int64(len(raw)),
	}
	m := &runtimev1.ImageManifest{Reference: ref, Config: &runtimev1.Descriptor{Digest: cfg, Size: 1}}
	for _, l := range layers {
		m.Layers = append(m.Layers, &runtimev1.Descriptor{Digest: l, Size: 1})
	}
	if err := s.rt.index.Record(context.Background(), image.IndexEntry{
		Reference: ref, Platform: image.Platform{OS: "linux", Architecture: "arm64"},
		Manifest: m, Descriptor: desc, ManifestRaw: raw,
	}); err != nil {
		s.t.Fatalf("record %s: %v", ref, err)
	}
	return desc.Digest
}

// view plants a views directory for manifest, as a forgotten record leaves
// one, and returns the manifest's views directory.
func (s *evictRPCScene) view(manifest string) string {
	s.t.Helper()
	mdir := filepath.Join(s.rt.cache.Root(), sandbox.ArtifactViewsSubdir, strings.TrimPrefix(manifest, "sha256:"))
	key := filepath.Join(mdir, strings.Repeat("0", 64))
	if err := os.MkdirAll(key, 0o755); err != nil {
		s.t.Fatalf("plant view: %v", err)
	}
	if err := os.WriteFile(filepath.Join(key, "f"), []byte("x"), 0o644); err != nil {
		s.t.Fatalf("plant view file: %v", err)
	}
	return mdir
}

func (s *evictRPCScene) evict(force bool) *runtimev1.EvictImageResponse {
	s.t.Helper()
	resp, err := s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Reference: s.refA, Force: force})
	if err != nil {
		s.t.Fatalf("EvictImage(%s, force=%v): %v", s.refA, force, err)
	}
	return resp
}

// state is everything the eviction may or may not touch, by name.
func (s *evictRPCScene) state() map[string]bool {
	s.t.Helper()
	out := map[string]bool{}
	for name, d := range map[string]string{"cfgA": s.cfgA, "ownA": s.ownA, "shared": s.shared, "cfgB": s.cfgB, "ownB": s.ownB} {
		out["blob "+name] = s.rt.cache.Has(d)
	}
	for name, p := range map[string]string{"A": s.viewA, "B": s.viewB} {
		_, err := os.Lstat(p)
		out["view "+name] = err == nil
	}
	for name, ref := range map[string]string{"A": s.refA, "B": s.refB} {
		_, err := s.rt.index.Resolve(context.Background(), ref, nil)
		out["entry "+name] = err == nil
	}
	return out
}

// wantEvicted is the state after evicting A: only A's unshared blobs and A's
// view are gone.
func wantEvicted() map[string]bool {
	return map[string]bool{
		"blob cfgA": false, "blob ownA": false, "blob shared": true, "blob cfgB": true, "blob ownB": true,
		"view A": false, "view B": true, "entry A": true, "entry B": true,
	}
}

func diffState(t *testing.T, what string, got, want map[string]bool) {
	t.Helper()
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %s present = %v, want %v", what, k, got[k], w)
		}
	}
}

// TestEvictImageRemovesOnlyTheNamedImage is the named gate of EvictImage: two
// images share a layer; evicting one by reference removes only its unshared
// blobs and its view, reports the shared layer kept SHARED, and leaves the
// other image resolving with every blob and its view. A dry run first plans
// the same outcome and changes nothing.
func TestEvictImageRemovesOnlyTheNamedImage(t *testing.T) {
	s := newEvictRPCScene(t)
	before := s.state()
	wantRemoved := []string{s.cfgA, s.ownA}
	slices.Sort(wantRemoved)

	check := func(what string, resp *runtimev1.EvictImageResponse) {
		t.Helper()
		if resp.GetManifestDigest() != s.manA {
			t.Errorf("%s: manifest_digest = %q, want %q", what, resp.GetManifestDigest(), s.manA)
		}
		got := slices.Clone(resp.GetRemovedDigests())
		slices.Sort(got)
		if !slices.Equal(got, wantRemoved) {
			t.Errorf("%s: removed = %v, want %v", what, got, wantRemoved)
		}
		kept := resp.GetKept()
		if len(kept) != 1 || kept[0].GetDigest() != s.shared ||
			kept[0].GetReason() != runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED {
			t.Errorf("%s: kept = %v, want only %s SHARED", what, kept, s.shared)
		}
		if want := uint64(len("evict-rpc-cfg-a") + len("evict-rpc-own-a")); resp.GetReclaimedBytes() != want {
			t.Errorf("%s: reclaimed_bytes = %d, want %d", what, resp.GetReclaimedBytes(), want)
		}
	}

	check("dry run", s.evict(false))
	diffState(t, "after the dry run", s.state(), before)

	check("forced", s.evict(true))
	diffState(t, "after the forced eviction", s.state(), wantEvicted())
}

// TestEvictInterruptedConverges pins that an eviction cut partway, then run
// again, ends in the state an uncut one does. The cut is planted as the
// on-disk state a daemon dying mid-call leaves: after the first own blob's
// unlink, and after every unlink but before the view removal.
func TestEvictInterruptedConverges(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func(s *evictRPCScene) []string
	}{
		{name: "after the first unlink", cut: func(s *evictRPCScene) []string { return []string{s.cfgA} }},
		{name: "before the view removal", cut: func(s *evictRPCScene) []string { return []string{s.cfgA, s.ownA} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEvictRPCScene(t)
			for _, d := range tc.cut(s) {
				p, err := s.rt.cache.BlobPath(d)
				if err != nil {
					t.Fatalf("BlobPath: %v", err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatalf("cut: remove %s: %v", d, err)
				}
			}
			s.evict(true)
			diffState(t, "after the re-run", s.state(), wantEvicted())
			// A further run is a no-op that still reports OK.
			resp := s.evict(true)
			if len(resp.GetRemovedDigests()) != 0 {
				t.Errorf("a converged re-run removed %v", resp.GetRemovedDigests())
			}
			diffState(t, "after a second re-run", s.state(), wantEvicted())
		})
	}
}
