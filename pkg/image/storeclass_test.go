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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	testModelType = "application/vnd.cncf.model.manifest.v1+json"
	testWasmType  = "application/vnd.wasm.config.v0+json"
)

// putTypedArtifact writes an artifact record of artifactType naming config and
// layers under key, in the shape pkg/artifact writes.
func putTypedArtifact(t *testing.T, x *FileIndex, key, artifactType, config string, layers ...string) {
	t.Helper()
	buf, err := json.Marshal(map[string]any{
		"schema": 1, "key": key, "reference": key, "artifactType": artifactType,
		"configDigest": config, "layerDigests": layers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.PutArtifactRecord(context.Background(), key, buf); err != nil {
		t.Fatalf("PutArtifactRecord: %v", err)
	}
}

// releaseArtifact removes the record under key, as Forget and ReleasePodOnly do.
func releaseArtifact(t *testing.T, x *FileIndex, key string) {
	t.Helper()
	if ok, err := x.RemoveArtifactRecord(context.Background(), key); err != nil || !ok {
		t.Fatalf("RemoveArtifactRecord(%s) = %v, %v; want true", key, ok, err)
	}
}

// recordImage writes a pull-cache index entry naming config and layers. An
// entry is an edge, never a root: the image's blobs stay reclaim-eligible.
func recordImage(t *testing.T, x *FileIndex, ref, config string, layers ...string) {
	t.Helper()
	raw, desc := manifestBytes(ref)
	m := &runtimev1.ImageManifest{Reference: ref, Config: &runtimev1.Descriptor{Digest: config}}
	for _, l := range layers {
		m.Layers = append(m.Layers, &runtimev1.Descriptor{Digest: l})
	}
	if err := x.Record(context.Background(), IndexEntry{
		Reference: ref, Platform: Platform{OS: "darwin", Architecture: "arm64"},
		Manifest: m, Descriptor: desc, ManifestRaw: raw,
	}); err != nil {
		t.Fatalf("Record(%s): %v", ref, err)
	}
}

// TestStoreBytesByClass pins the per-class accounting of the node cache: an
// image's blobs count as ClassImage, an artifact's under its own artifactType
// (from its live record, or from the released copy once the record is gone),
// a held blob no record types as ClassArtifact, and a blob nothing names as
// ClassUnattributed. A blob two records share counts once, a blob an image and
// a live record share counts under the record, and the classes sum to
// StoreBytes.
func TestStoreBytesByClass(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	blob := func(content string) string { return f.blob(content, time.Hour) }

	imgCfg := blob("image config")    // 12
	imgLayer := blob("image layer 1") // 13
	shared := blob("shared weights")  // 14, an image layer and a model layer
	recordImage(t, x, "registry.example/app:v1", imgCfg, imgLayer, shared)

	modelCfg := blob("model config")  // 12
	modelLayer := blob("model shard") // 11, named by two records
	putTypedArtifact(t, x, "registry.example/models/a:v1@"+testModelType, testModelType, modelCfg, modelLayer, shared)
	putTypedArtifact(t, x, "registry.example/models/a:v2@"+testModelType, testModelType, modelCfg, modelLayer)

	wasmCfg := blob("wasm config")   // 11
	wasmLayer := blob("wasm module") // 11
	putTypedArtifact(t, x, "registry.example/fn/b:v1@"+testWasmType, testWasmType, wasmCfg, wasmLayer)
	releaseArtifact(t, x, "registry.example/fn/b:v1@"+testWasmType)

	heldLayer := blob("held, never recorded") // 20
	pod, err := ParsePodID("pod-held")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("held manifest"))
	if err := x.AddArtifactHoldManifest(ctx, pod, HeldManifest{
		Digest: fmt.Sprintf("sha256:%x", sum), Config: heldLayer, Layers: []string{heldLayer},
	}); err != nil {
		t.Fatal(err)
	}

	blob("stray") // 5

	got, err := f.cache.StoreBytesByClass(ctx)
	if err != nil {
		t.Fatalf("StoreBytesByClass: %v", err)
	}
	want := map[string]int64{
		ClassImage:        12 + 13,
		testModelType:     12 + 11 + 14,
		testWasmType:      11 + 11,
		ClassArtifact:     20,
		ClassUnattributed: 5,
	}
	if !maps.Equal(got, want) {
		t.Fatalf("StoreBytesByClass = %v; want %v", got, want)
	}
	total, err := f.cache.StoreBytes()
	if err != nil {
		t.Fatal(err)
	}
	var sumClasses int64
	for _, n := range got {
		sumClasses += n
	}
	if sumClasses != total {
		t.Fatalf("classes sum to %d; StoreBytes is %d", sumClasses, total)
	}
	for class, wantArtifact := range map[string]bool{
		ClassImage: false, ClassUnattributed: false, ClassArtifact: true, testModelType: true, testWasmType: true,
	} {
		if IsArtifactClass(class) != wantArtifact {
			t.Errorf("IsArtifactClass(%q) = %v; want %v", class, !wantArtifact, wantArtifact)
		}
	}
}

// TestArtifactClassClampsTheKey pins that only a media-type-shaped
// artifactType of at most 255 bytes becomes a class key; anything else is
// ClassArtifact, so a registry-supplied type cannot pose as another class or
// carry arbitrary bytes into a report.
func TestArtifactClassClampsTheKey(t *testing.T) {
	// The longest type the grammar allows is two 127-byte names: 255 bytes.
	atCap := strings.Repeat("a", 127) + "/" + strings.Repeat("b", 127)
	for _, tc := range []struct {
		name, typ, want string
	}{
		{"model media type", testModelType, testModelType},
		{"wasm media type", testWasmType, testWasmType},
		{"empty", "", ClassArtifact},
		{"poses as image", ClassImage, ClassArtifact},
		{"poses as unattributed", ClassUnattributed, ClassArtifact},
		{"no subtype", "application/", ClassArtifact},
		{"two slashes", "application/a/b", ClassArtifact},
		{"parameters", "application/json; charset=utf-8", ClassArtifact},
		{"control byte", "application/x\n", ClassArtifact},
		{"non-ascii", "application/modèle", ClassArtifact},
		{"leading punctuation", "application/+json", ClassArtifact},
		{"name over 127 bytes", "application/" + strings.Repeat("a", 128), ClassArtifact},
		{"over the cap", atCap + "b", ClassArtifact},
		{"at the cap", atCap, atCap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.want) > maxClassBytes {
				t.Fatalf("bad fixture: want is %d bytes", len(tc.want))
			}
			if got := artifactClass(tc.typ); got != tc.want {
				t.Fatalf("artifactClass(%q) = %q; want %q", tc.typ, got, tc.want)
			}
		})
	}
}
