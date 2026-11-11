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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// evictScene is two cached images A and B sharing one layer, a native tree
// for each, a tree backed only by A's own blobs, and a released artifact copy whose blobs are all gone, which a
// normal pass's released sweep would remove.
type evictScene struct {
	f                      *gcFixture
	manifestA              string
	cfgA, ownA, shared     string
	cfgB, ownB             string
	treeA, treeB, treeOwnA string
	released               string
}

func newEvictScene(t *testing.T) *evictScene {
	t.Helper()
	f := newGCFixture(t)
	s := &evictScene{f: f}
	s.cfgA, s.ownA = f.blob("evict-cfg-a", time.Hour), f.blob("evict-own-a", time.Hour)
	s.shared = f.blob("evict-shared", time.Hour)
	s.cfgB, s.ownB = f.blob("evict-cfg-b", time.Hour), f.blob("evict-own-b", time.Hour)
	sf := &sharedFixture{t: t, cache: f.cache, idx: &FileIndex{dir: f.cache.IndexRoot()}}
	s.manifestA = sf.entry("a", "A", false, s.cfgA, s.ownA, s.shared)
	sf.entry("b", "B", false, s.cfgB, s.ownB, s.shared)
	s.treeA = f.nativeTree(s.cfgA, []string{s.ownA, s.shared}, 10, time.Hour).dir
	s.treeOwnA = f.nativeTree(s.cfgA, []string{s.ownA}, 10, time.Hour).dir
	s.treeB = f.nativeTree(s.cfgB, []string{s.ownB, s.shared}, 10, time.Hour).dir
	buf := sf.recordBytes("gone", fakeDigest('9'), fakeDigest('8'), fakeDigest('7'))
	sf.releasedFile("", buf)
	s.released = filepath.Join(f.cache.IndexRoot(), ArtifactReleasedIndexSubdir, releasedName(buf))
	return s
}

func (s *evictScene) evict(t *testing.T, dryRun bool) *EvictResult {
	t.Helper()
	res, err := s.f.cache.Evict(context.Background(), s.manifestA, []string{s.cfgA, s.ownA, s.shared}, ReclaimConfig{
		DryRun:    dryRun,
		FreeBytes: func(string) (uint64, error) { return 1, nil },
	})
	if err != nil {
		t.Fatalf("Evict: %v", err)
	}
	return res
}

// want is the result evicting A must report, dry run or not.
func (s *evictScene) want() *EvictResult {
	removed := []string{s.cfgA, s.ownA}
	sort.Strings(removed)
	return &EvictResult{
		Removed:        removed,
		Kept:           []EvictKept{{Digest: s.shared, Reason: EvictKeptShared}},
		ReclaimedBytes: int64(len("evict-cfg-a") + len("evict-own-a")),
	}
}

func pathExists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("lstat %s: %v", p, err)
	}
	return err == nil
}

// TestEvictRemovesOnlyTheTarget evicts image A of two images sharing a layer:
// A's own blobs and the tree backed only by them go, the shared layer is kept
// as shared, so A's full tree (backed by it too) stays as plan step 5 rules,
// B's blobs and tree stay, and the released sweep does not run (the released copy a
// forced prune removes is still there after the eviction).
func TestEvictRemovesOnlyTheTarget(t *testing.T) {
	t.Parallel()
	s := newEvictScene(t)
	got := s.evict(t, false)
	if want := s.want(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Evict = %+v; want %+v", got, want)
	}
	for _, d := range []string{s.cfgA, s.ownA} {
		if s.f.exists(d) {
			t.Errorf("target blob %s still on disk", d)
		}
	}
	for _, d := range []string{s.shared, s.cfgB, s.ownB} {
		if !s.f.exists(d) {
			t.Errorf("blob %s outside the target was removed", d)
		}
	}
	if pathExists(t, s.treeOwnA) {
		t.Errorf("tree %s backed only by the target's removed blobs still on disk", s.treeOwnA)
	}
	for _, p := range []string{s.treeA, s.treeB} {
		if !pathExists(t, p) {
			t.Errorf("tree %s backed by a kept blob was removed", p)
		}
	}
	if !pathExists(t, s.released) {
		t.Fatalf("released copy %s removed: the eviction ran the released sweep", s.released)
	}

	// Control: a forced prune does run the sweep, so the copy surviving above
	// is the eviction's doing and not the fixture's.
	if _, err := s.f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
		Force:     true,
		FreeBytes: func(string) (uint64, error) { return 1, nil },
	}); err != nil {
		t.Fatalf("ReclaimUnderPressure: %v", err)
	}
	if pathExists(t, s.released) {
		t.Errorf("control: forced prune kept released copy %s; the fixture does not exercise the sweep", s.released)
	}
}

// TestEvictDryRunDeletesNothing runs the same eviction as a dry run: the
// result is the real run's, and every blob, tree and record is still on disk.
func TestEvictDryRunDeletesNothing(t *testing.T) {
	t.Parallel()
	s := newEvictScene(t)
	got := s.evict(t, true)
	if want := s.want(); !reflect.DeepEqual(got, want) {
		t.Fatalf("dry-run Evict = %+v; want %+v", got, want)
	}
	for _, d := range []string{s.cfgA, s.ownA, s.shared, s.cfgB, s.ownB} {
		if !s.f.exists(d) {
			t.Errorf("dry run removed blob %s", d)
		}
	}
	for _, p := range []string{s.treeA, s.treeOwnA, s.treeB, s.released} {
		if !pathExists(t, p) {
			t.Errorf("dry run removed %s", p)
		}
	}
}

// TestEvictPartialResultOnGuardError pins Evict's partial result: the
// released-artifact executor removes the target's config, then the blob
// executor's guard fails (a pod dir with no record makes the roots
// unreadable). Evict returns the error beside a result listing the removed
// config and keeping the layer the failed call never reached.
func TestEvictPartialResultOnGuardError(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	cfgDigest := f.blob("evict-partial-cfg", time.Hour)
	layer := f.blob("evict-partial-layer", time.Hour)
	sf := &sharedFixture{t: t, cache: f.cache, idx: &FileIndex{dir: f.cache.IndexRoot()}}
	// No index entry: an image entry would class the config as an image. A
	// released copy of the target's own artifact classes it as a released
	// artifact, so the first executor call removes it.
	manifest := fakeDigest('a')
	sf.releasedFile("", sf.recordBytes("art", manifest, cfgDigest))

	const treeCall = 2
	calls := 0
	cfg := ReclaimConfig{
		FreeBytes: func(string) (uint64, error) { return 1, nil },
		afterPlan: func() {
			calls++
			if calls != treeCall {
				return
			}
			pid, err := ParsePodID("pod-unrecorded")
			if err != nil {
				t.Errorf("ParsePodID: %v", err)
				return
			}
			if err := os.MkdirAll(f.cache.PodDir(pid), 0o755); err != nil {
				t.Errorf("mkdir pod dir: %v", err)
			}
		},
	}
	res, err := f.cache.Evict(context.Background(), manifest, []string{cfgDigest, layer}, cfg)
	if err == nil {
		t.Fatalf("Evict = %+v, nil; want the blob guard's error", res)
	}
	if res == nil {
		t.Fatalf("Evict = nil, %v; want a partial result beside the error", err)
	}
	if f.exists(cfgDigest) || !f.exists(layer) {
		t.Fatalf("on disk: config %v, layer %v; want the config removed and the layer kept", f.exists(cfgDigest), f.exists(layer))
	}
	want := &EvictResult{
		Removed:        []string{cfgDigest},
		Kept:           []EvictKept{{Digest: layer, Reason: EvictKeptUnlinkFailed}},
		ReclaimedBytes: int64(len("evict-partial-cfg")),
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Evict = %+v; want %+v", res, want)
	}
}
