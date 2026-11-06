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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// putArtifact writes an artifact record naming config and layers under key,
// in the shape pkg/artifact writes.
func putArtifact(t *testing.T, x *FileIndex, key, config string, layers ...string) {
	t.Helper()
	buf, err := json.Marshal(map[string]any{
		"schema": 1, "key": key, "reference": key,
		"configDigest": config, "layerDigests": layers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.PutArtifactRecord(context.Background(), key, buf); err != nil {
		t.Fatalf("PutArtifactRecord: %v", err)
	}
}

// TestPruneKeepsLiveArtifactReclaimsDeadOne pins the artifact lifetime: a
// recorded artifact's blobs are reachability roots, so a forced prune keeps
// them, and once its record is removed the same prune reclaims them.
func TestPruneKeepsLiveArtifactReclaimsDeadOne(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	liveCfg := f.blob("live config", time.Hour)
	liveLayer := f.blob("live weights", time.Hour)
	deadCfg := f.blob("dead config", time.Hour)
	deadLayer := f.blob("dead weights", time.Hour)
	putArtifact(t, x, "live@type", liveCfg, liveLayer)
	putArtifact(t, x, "dead@type", deadCfg, deadLayer)
	if ok, err := x.RemoveArtifactRecord(context.Background(), "dead@type"); err != nil || !ok {
		t.Fatalf("RemoveArtifactRecord = %v, %v; want true", ok, err)
	}

	free := &fakeFree{free: []uint64{0}}
	if _, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
		Force: true, Grace: time.Minute, FreeBytes: free.sample,
	}); err != nil {
		t.Fatalf("ReclaimUnderPressure: %v", err)
	}
	for _, d := range []string{liveCfg, liveLayer} {
		if !f.exists(d) {
			t.Errorf("live artifact blob %s was reclaimed while its record exists", d)
		}
	}
	for _, d := range []string{deadCfg, deadLayer} {
		if f.exists(d) {
			t.Errorf("dead artifact blob %s survived; its record is gone", d)
		}
	}

	// Removing the live record makes its blobs collectable too.
	if ok, err := x.RemoveArtifactRecord(context.Background(), "live@type"); err != nil || !ok {
		t.Fatalf("RemoveArtifactRecord(live) = %v, %v; want true", ok, err)
	}
	if _, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
		Force: true, Grace: time.Minute, FreeBytes: free.sample,
	}); err != nil {
		t.Fatalf("ReclaimUnderPressure: %v", err)
	}
	for _, d := range []string{liveCfg, liveLayer} {
		if f.exists(d) {
			t.Errorf("blob %s survived the removal of its record", d)
		}
	}
}

// TestArtifactRootsFailClosed pins that an artifact record the GC cannot read
// aborts the root set rather than dropping that artifact's blobs.
func TestArtifactRootsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"undecodable", "{ not json"},
		{"an unusable digest", `{"configDigest":"md5:abcd","layerDigests":[]}`},
		{"no blob at all", `{"reference":"r"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCFixture(t)
			x, err := NewFileIndex(f.cache)
			if err != nil {
				t.Fatal(err)
			}
			if err := x.PutArtifactRecord(context.Background(), "k", []byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			roots, err := f.cache.Roots()
			if !errors.Is(err, ErrRootsIncomplete) {
				t.Fatalf("Roots err = %v; want ErrRootsIncomplete", err)
			}
			if roots != nil {
				t.Errorf("Roots returned %v alongside the refusal", roots)
			}
		})
	}

	t.Run("a group-writable artifact namespace", func(t *testing.T) {
		f := newGCFixture(t)
		x, err := NewFileIndex(f.cache)
		if err != nil {
			t.Fatal(err)
		}
		putArtifact(t, x, "k", f.blob("c", time.Hour))
		if err := os.Chmod(filepath.Join(f.cache.IndexRoot(), ArtifactIndexSubdir), 0o770); err != nil {
			t.Fatal(err)
		}
		if _, err := f.cache.Roots(); !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("Roots err = %v; want ErrRootsIncomplete", err)
		}
	})
}

// TestArtifactRootsAbsentIndex pins that a store with no index or no artifact
// namespace has no artifact roots, not an incomplete set.
func TestArtifactRootsAbsentIndex(t *testing.T) {
	f := newGCFixture(t)
	if roots, err := f.cache.Roots(); err != nil || len(roots) != 0 {
		t.Fatalf("Roots = %v, %v; want none", roots, err)
	}
	if _, err := NewFileIndex(f.cache); err != nil {
		t.Fatal(err)
	}
	if roots, err := f.cache.Roots(); err != nil || len(roots) != 0 {
		t.Fatalf("Roots with an empty index = %v, %v; want none", roots, err)
	}
}

// TestArtifactRecordsRefuseNonRegularJSON pins that a *.json entry in the
// artifact namespace that is not a regular file fails the listing, and so the
// GC root set, rather than being skipped: no record is ever stored as one, so
// it is damage, and skipping it could drop a root.
func TestArtifactRecordsRefuseNonRegularJSON(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, path string)
	}{
		{"a directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"a symlink", func(t *testing.T, path string) {
			if err := os.Symlink("/etc/hosts", path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCFixture(t)
			x, err := NewFileIndex(f.cache)
			if err != nil {
				t.Fatal(err)
			}
			putArtifact(t, x, "k", f.blob("c", time.Hour))
			name := strings.Repeat("a", 64) + ".json"
			tc.plant(t, filepath.Join(f.cache.IndexRoot(), ArtifactIndexSubdir, name))
			if _, err := x.ArtifactRecords(context.Background()); !errors.Is(err, ErrIndexEntryCorrupt) {
				t.Errorf("ArtifactRecords err = %v; want ErrIndexEntryCorrupt", err)
			}
			_, err = f.cache.Roots()
			if !errors.Is(err, ErrRootsIncomplete) {
				t.Fatalf("Roots err = %v; want ErrRootsIncomplete", err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("Roots err %q does not name the entry %s", err, name)
			}
		})
	}
}

// TestArtifactRootsNameCorruptRecord pins that a record the GC cannot decode
// is named in the ErrRootsIncomplete error, so the log says which file to
// look at.
func TestArtifactRootsNameCorruptRecord(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.PutArtifactRecord(context.Background(), "k", []byte("{ not json")); err != nil {
		t.Fatal(err)
	}
	_, err = f.cache.Roots()
	if !errors.Is(err, ErrRootsIncomplete) {
		t.Fatalf("Roots err = %v; want ErrRootsIncomplete", err)
	}
	if name := artifactEntryName("k"); !strings.Contains(err.Error(), name) {
		t.Errorf("Roots err %q does not name the record %s", err, name)
	}
}

// TestArtifactHoldRootsKeepHeldBlobs pins the hold half of the root set: a
// manifest a pod's hold names keeps its blobs with no artifact record at all
// (the record a moved tag replaced), they go once the hold does, and a hold
// the store cannot read aborts the root set rather than drop them.
func TestArtifactHoldRootsKeepHeldBlobs(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.blob("held config", time.Hour)
	layer := f.blob("held weights", time.Hour)
	manifest := f.blob("held manifest", time.Hour)
	id, err := ParsePodID("pod-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := x.PutArtifactHold(ctx, id, []string{"reg/m:v1"}); err != nil {
		t.Fatal(err)
	}
	if err := x.AddArtifactHoldManifest(ctx, id, HeldManifest{Digest: manifest, Config: cfg, Layers: []string{layer}}); err != nil {
		t.Fatal(err)
	}
	free := &fakeFree{free: []uint64{0}}
	reclaim := func() error {
		_, err := f.cache.ReclaimUnderPressure(ctx, ReclaimConfig{Force: true, Grace: time.Minute, FreeBytes: free.sample})
		return err
	}
	if err := reclaim(); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	for _, d := range []string{cfg, layer} {
		if !f.exists(d) {
			t.Errorf("held blob %s was reclaimed", d)
		}
	}

	junk := filepath.Join(x.dir, ArtifactHoldIndexSubdir, "pod-b.json")
	if err := os.WriteFile(junk, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reclaim(); !errors.Is(err, ErrRootsIncomplete) {
		t.Fatalf("reclaim with an unreadable hold = %v, want ErrRootsIncomplete", err)
	}
	if err := os.Remove(junk); err != nil {
		t.Fatal(err)
	}

	if err := x.RemoveArtifactHold(id); err != nil {
		t.Fatal(err)
	}
	if err := reclaim(); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	for _, d := range []string{cfg, layer} {
		if f.exists(d) {
			t.Errorf("blob %s survived the end of its hold", d)
		}
	}
}
