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
	"errors"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

const wasmRef = testHost + "/wasm/hello:v1"

func wasmLayer(path, data string) layer {
	return layer{mt: artifactv1.MediaTypeWasmLayer, path: path, data: []byte(data)}
}

// TestPullArtifactAcceptsWasmModule pins the CNCF wasm OCI artifact (config
// application/vnd.wasm.config.v0+json, layer application/wasm) as an accepted
// image-volume type, in both the spec's form (no artifactType, so the type is
// the config media type) and with artifactType set to the same value. The
// model allow-set beside it is pinned unchanged.
func TestPullArtifactAcceptsWasmModule(t *testing.T) {
	for _, tc := range []struct {
		name         string
		artifactType string
		layers       []layer
	}{
		{"config media type only", "", []layer{wasmLayer("hello.wasm", "\x00asm\x01\x00\x00\x00")}},
		{"artifactType names the wasm config", artifactv1.MediaTypeWasmConfig, []layer{wasmLayer("hello.wasm", "\x00asm\x01\x00\x00\x00")}},
		{"several modules", "", []layer{wasmLayer("a.wasm", "\x00asm-a"), wasmLayer("lib/b.wasm", "\x00asm-b")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			raw := e.fetch.publish(wasmRef, tc.artifactType, artifactv1.MediaTypeWasmConfig, tc.layers)
			p := e.puller(t)
			res, err := p.PullArtifact(context.Background(), wasmRef, nil, volume, nil)
			if err != nil {
				t.Fatalf("PullArtifact: %v", err)
			}
			defer res.Lease.Release()
			if res.ArtifactType != artifactv1.MediaTypeWasmConfig {
				t.Errorf("type = %q, want %q", res.ArtifactType, artifactv1.MediaTypeWasmConfig)
			}
			if res.ManifestDigest != digestOfBytes(raw) {
				t.Errorf("manifest digest = %s, want %s", res.ManifestDigest, digestOfBytes(raw))
			}
			if len(res.LayerDigests) != len(tc.layers) {
				t.Fatalf("%d layers, want %d", len(res.LayerDigests), len(tc.layers))
			}
			for _, d := range res.LayerDigests {
				if !e.cache.Has(d) {
					t.Errorf("layer %s not committed", d)
				}
			}
			rec, ok, err := p.LookupRecord(context.Background(), wasmRef, artifactv1.MediaTypeWasmConfig)
			if err != nil || !ok || rec.ManifestDigest != res.ManifestDigest || len(rec.LayerDigests) != len(tc.layers) {
				t.Fatalf("record = %+v %v %v", rec, ok, err)
			}
		})
	}

	// Regression: adding the wasm type leaves the model allow-set as it was.
	// The ModelPack weight, weight-config and doc layers pass; code and a wasm
	// layer under the model type are still refused.
	t.Run("model allow-set unchanged", func(t *testing.T) {
		e := newEnv(t)
		e.fetch.publishModel(testRef,
			modelLayer("w/model.safetensors", "weights"),
			layer{mt: artifactv1.MediaTypeModelWeightConfig, path: "config.json", data: []byte(`{"a":1}`)},
			layer{mt: artifactv1.MediaTypeModelDoc, path: "README.md", data: []byte("doc")})
		res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
		if err != nil {
			t.Fatalf("model pull: %v", err)
		}
		res.Lease.Release()
		if res.ArtifactType != artifactv1.ArtifactTypeModel {
			t.Errorf("type = %q, want %q", res.ArtifactType, artifactv1.ArtifactTypeModel)
		}
		for _, mt := range []string{artifactv1.MediaTypeModelCode, artifactv1.MediaTypeWasmLayer} {
			e := newEnv(t)
			e.fetch.publishModel(testRef, modelLayer("a.json", "a"), layer{mt: mt, path: "b.bin", data: []byte("b")})
			if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrLayerTypeRefused) {
				t.Errorf("model with a %s layer: err = %v, want ErrLayerTypeRefused", mt, err)
			}
		}
	})
}

// TestWasmArtifactRefusesNonWasmLayer pins that a wasm artifact carries
// application/wasm layers and nothing else: any other layer media type,
// alone or beside a valid module, is refused with a typed error before any
// blob is fetched and before anything is recorded.
func TestWasmArtifactRefusesNonWasmLayer(t *testing.T) {
	for _, tc := range []struct {
		mt   string
		want error
	}{
		{artifactv1.MediaTypeModelWeight, ErrLayerTypeRefused},
		{artifactv1.MediaTypeModelCode, ErrLayerTypeRefused},
		{artifactv1.MediaTypeModelDoc, ErrLayerTypeRefused},
		{artifactv1.MediaTypeGuestKernel, ErrLayerTypeRefused},
		{"application/octet-stream", ErrLayerTypeRefused},
		// The pre-CNCF wasm-to-oci layer type is not the spec's.
		{"application/vnd.wasm.content.layer.v1+wasm", ErrLayerTypeRefused},
		// Media types are matched exactly: no case folding, no parameters.
		{"application/WASM", ErrLayerTypeRefused},
		{"application/wasm; charset=binary", ErrLayerTypeRefused},
		{"", ErrLayerTypeRefused},
		// An archive layer is refused by the earlier tar rule.
		{"application/vnd.oci.image.layer.v1.tar+gzip", ErrTarLayer},
	} {
		for _, shape := range []struct {
			name   string
			layers []layer
		}{
			{"alone", []layer{{mt: tc.mt, path: "x.bin", data: []byte("x")}}},
			{"beside a module", []layer{wasmLayer("hello.wasm", "\x00asm"), {mt: tc.mt, path: "x.bin", data: []byte("x")}}},
		} {
			t.Run(tc.mt+"/"+shape.name, func(t *testing.T) {
				e := newEnv(t)
				e.fetch.publish(wasmRef, "", artifactv1.MediaTypeWasmConfig, shape.layers)
				p := e.puller(t)
				if _, err := p.PullArtifact(context.Background(), wasmRef, nil, volume, nil); !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				if n := e.fetch.blobCalls.Load(); n != 0 {
					t.Errorf("%d blobs fetched before the refusal", n)
				}
				if _, ok, err := p.LookupRecord(context.Background(), wasmRef, artifactv1.MediaTypeWasmConfig); err != nil || ok {
					t.Errorf("a refused wasm artifact was recorded (ok=%v, err=%v)", ok, err)
				}
			})
		}
	}

	// application/wasm is required: a wasm manifest with no layer is refused.
	t.Run("no layers", func(t *testing.T) {
		e := newEnv(t)
		e.fetch.publish(wasmRef, "", artifactv1.MediaTypeWasmConfig, nil)
		if _, err := e.puller(t).PullArtifact(context.Background(), wasmRef, nil, volume, nil); !errors.Is(err, ErrNoLayers) {
			t.Fatalf("err = %v, want ErrNoLayers", err)
		}
		if n := e.fetch.blobCalls.Load(); n != 0 {
			t.Errorf("%d blobs fetched before the refusal", n)
		}
	})
}
