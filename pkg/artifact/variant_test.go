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

package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

const testRepo = testHost + "/models/tiny"

// publishVariant serves an artifact manifest by digest in testRepo, the way a
// registry serves an index entry, and returns its index descriptor.
func (f *fakeFetcher) publishVariant(variant string, layers ...layer) map[string]any {
	raw := f.publishModel("staging", layers...)
	d := digestOfBytes(raw)
	f.mu.Lock()
	delete(f.manifests, "staging")
	f.manifests[testRepo+"@"+d] = served{raw: raw, mt: mediaTypeOCIManifest}
	f.mu.Unlock()
	return map[string]any{
		"mediaType":   mediaTypeOCIManifest,
		"digest":      d,
		"size":        len(raw),
		"annotations": map[string]string{AnnotationVariant: variant},
	}
}

// publishIndex serves an OCI image index of entries at ref.
func (f *fakeFetcher) publishIndex(ref string, entries ...map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex, "manifests": entries})
	f.mu.Lock()
	f.manifests[ref] = served{raw: raw, mt: mediaTypeOCIIndex}
	f.mu.Unlock()
	return raw
}

// TestPullArtifactSelectsVariant: from an index of a 4bit and an 8bit
// manifest, selecting 8bit pulls that manifest and its layers only.
func TestPullArtifactSelectsVariant(t *testing.T) {
	e := newEnv(t)
	l4 := modelLayer("w/model.safetensors", "four-bit weights")
	l8 := modelLayer("w/model.safetensors", "eight-bit weights, larger")
	cfg8 := modelLayer("config.json", `{"bits":8}`)
	e.fetch.publishIndex(testRef,
		e.fetch.publishVariant("4bit", l4),
		e.fetch.publishVariant("8bit", l8, cfg8),
	)
	want := e.fetch.manifests[testRef]
	var ix indexDoc
	if err := json.Unmarshal(want.raw, &ix); err != nil {
		t.Fatal(err)
	}
	want8 := ix.Manifests[1].Digest

	p := e.puller(t)
	res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil, WithVariant("8bit"))
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	defer res.Lease.Release()
	if res.ManifestDigest != want8 {
		t.Errorf("ManifestDigest = %s, want the 8bit entry %s", res.ManifestDigest, want8)
	}
	wantLayers := []string{digestOfBytes(l8.data), digestOfBytes(cfg8.data)}
	if !slices.Equal(res.LayerDigests, wantLayers) {
		t.Errorf("LayerDigests = %v, want %v", res.LayerDigests, wantLayers)
	}
	if !slices.Equal(res.Paths, []string{"w/model.safetensors", "config.json"}) {
		t.Errorf("Paths = %v", res.Paths)
	}
	// The config and the two 8bit layers; never the 4bit layer.
	if got := e.fetch.blobCalls.Load(); got != 3 {
		t.Errorf("blob requests = %d, want 3", got)
	}
	if e.cache.Has(digestOfBytes(l4.data)) {
		t.Error("the 4bit layer reached the cache")
	}
	for _, d := range wantLayers {
		if !e.cache.Has(d) {
			t.Errorf("8bit layer %s not committed", d)
		}
	}
	rec, ok, err := p.LookupRecord(context.Background(), testRef, res.ArtifactType)
	if err != nil || !ok {
		t.Fatalf("LookupRecord = %v, %v", ok, err)
	}
	if rec.ManifestDigest != want8 || digestOfBytes(rec.ManifestRaw) != want8 {
		t.Errorf("record names %s (raw %s), want the 8bit manifest %s", rec.ManifestDigest, digestOfBytes(rec.ManifestRaw), want8)
	}
}

// TestVariantSelectorZeroOrTwoMatchesRefused: a selector no entry carries, a
// selector two entries carry, an index with no selector and a selector for a
// single manifest are each refused before any blob request.
func TestVariantSelectorZeroOrTwoMatchesRefused(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(f *fakeFetcher)
		opts    []PullOption
		want    []error
		entries int32 // entry manifests fetched before the refusal
	}{
		{"zero matches", func(f *fakeFetcher) {
			f.publishIndex(testRef, f.publishVariant("4bit", modelLayer("a.json", "a")), f.publishVariant("8bit", modelLayer("a.json", "b")))
		}, []PullOption{WithVariant("bf16")}, []error{ErrVariantNotFound}, 0},
		{"two matches", func(f *fakeFetcher) {
			f.publishIndex(testRef, f.publishVariant("8bit", modelLayer("a.json", "a")), f.publishVariant("8bit", modelLayer("a.json", "b")))
		}, []PullOption{WithVariant("8bit")}, []error{ErrVariantAmbiguous}, 0},
		{"two matches of one manifest", func(f *fakeFetcher) {
			d := f.publishVariant("8bit", modelLayer("a.json", "a"))
			f.publishIndex(testRef, d, d)
		}, []PullOption{WithVariant("8bit")}, []error{ErrVariantAmbiguous}, 0},
		{"no selector on an index", func(f *fakeFetcher) {
			f.publishIndex(testRef, f.publishVariant("4bit", modelLayer("a.json", "a")))
		}, nil, []error{ErrVariantRequired, ErrIndexRefused}, 0},
		{"empty selector on an index", func(f *fakeFetcher) {
			f.publishIndex(testRef, f.publishVariant("4bit", modelLayer("a.json", "a")))
		}, []PullOption{WithVariant("")}, []error{ErrVariantRequired}, 0},
		{"selector on a plain manifest", func(f *fakeFetcher) {
			f.publishModel(testRef, modelLayer("a.json", "a"))
		}, []PullOption{WithVariant("4bit")}, []error{ErrVariantOnManifest}, 0},
		{"selector over the length cap", func(f *fakeFetcher) {
			f.publishIndex(testRef, f.publishVariant("4bit", modelLayer("a.json", "a")))
		}, []PullOption{WithVariant(strings.Repeat("x", MaxVariantLength+1))}, []error{ErrVariantInvalid}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e.fetch)
			for _, pull := range []func(*Puller) (*Result, error){
				func(p *Puller) (*Result, error) {
					return p.PullArtifact(context.Background(), testRef, nil, volume, nil, tc.opts...)
				},
				func(p *Puller) (*Result, error) {
					return p.PullForPod(context.Background(), testRef, nil, volume, nil, tc.opts...)
				},
			} {
				e.fetch.manifestCalls.Store(0)
				_, err := pull(e.puller(t))
				for _, w := range tc.want {
					if !errors.Is(err, w) {
						t.Errorf("err = %v, want %v", err, w)
					}
				}
				if got := e.fetch.blobCalls.Load(); got != 0 {
					t.Errorf("%d blob requests before the refusal, want 0", got)
				}
				wantManifests := 1 + tc.entries
				if got := e.fetch.manifestCalls.Load(); got != wantManifests {
					t.Errorf("%d manifest requests, want %d", got, wantManifests)
				}
			}
		})
	}
}

// TestVariantIndexBounds pins the index checks: only an OCI index of OCI
// manifests within the caps is read, and the selected manifest must match the
// digest and size its entry declares. Each refusal precedes any blob request.
func TestVariantIndexBounds(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeFetcher)
		want  error
	}{
		{"nested index entry", func(f *fakeFetcher) {
			d := f.publishVariant("8bit", modelLayer("a.json", "a"))
			d["mediaType"] = mediaTypeOCIIndex
			f.publishIndex(testRef, d)
		}, ErrManifestInvalid},
		{"docker manifest list", func(f *fakeFetcher) {
			raw := f.publishIndex(testRef, f.publishVariant("8bit", modelLayer("a.json", "a")))
			f.manifests[testRef] = served{raw: raw, mt: mediaTypeDockerList}
		}, ErrIndexRefused},
		{"too many entries", func(f *fakeFetcher) {
			d := f.publishVariant("4bit", modelLayer("a.json", "a"))
			es := make([]map[string]any, MaxIndexEntries+1)
			for i := range es {
				es[i] = d
			}
			es[0] = f.publishVariant("8bit", modelLayer("a.json", "b"))
			f.publishIndex(testRef, es...)
		}, ErrManifestInvalid},
		{"index over the body cap", func(f *fakeFetcher) {
			d := f.publishVariant("8bit", modelLayer("a.json", "a"))
			d["annotations"] = map[string]string{AnnotationVariant: "8bit", "pad": strings.Repeat("p", MaxIndexBytes)}
			f.publishIndex(testRef, d)
		}, ErrManifestTooLarge},
		{"entry size disagrees", func(f *fakeFetcher) {
			d := f.publishVariant("8bit", modelLayer("a.json", "a"))
			d["size"] = d["size"].(int) + 1
			f.publishIndex(testRef, d)
		}, ErrManifestDigest},
		{"entry bytes swapped", func(f *fakeFetcher) {
			d := f.publishVariant("8bit", modelLayer("a.json", "a"))
			k := testRepo + "@" + d["digest"].(string)
			s := f.manifests[k]
			s.raw = append([]byte(nil), s.raw...)
			s.raw[len(s.raw)-2] ^= 1
			f.manifests[k] = s
			f.publishIndex(testRef, d)
		}, ErrManifestDigest},
		{"entry is itself an index", func(f *fakeFetcher) {
			d := f.publishVariant("8bit", modelLayer("a.json", "a"))
			k := testRepo + "@" + d["digest"].(string)
			inner, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaTypeOCIIndex,
				"manifests": []map[string]any{d}})
			id := digestOfBytes(inner)
			f.manifests[testRepo+"@"+id] = served{raw: inner, mt: mediaTypeOCIManifest}
			delete(f.manifests, k)
			f.publishIndex(testRef, map[string]any{"mediaType": mediaTypeOCIManifest, "digest": id, "size": len(inner),
				"annotations": map[string]string{AnnotationVariant: "8bit"}})
		}, ErrIndexRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e.fetch)
			_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil, WithVariant("8bit"))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if got := e.fetch.blobCalls.Load(); got != 0 {
				t.Errorf("%d blob requests before the refusal, want 0", got)
			}
		})
	}
}
