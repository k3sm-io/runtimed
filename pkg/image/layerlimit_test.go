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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// layerLimitImage is a native-platform image whose manifest names ONE shared
// tiny layer n times: the layer count is what is under test, not the bytes, so
// an oversize manifest costs one blob.
func layerLimitImage(t *testing.T, n int) ggcrv1.Image {
	t.Helper()
	layer := static.NewLayer([]byte("k3sm-layer-limit"), types.DockerLayer)
	one, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	one = withPlatform(t, one, "darwin", "arm64", "")
	// Widen the one-layer image by hand: mutate re-marshals the config per
	// layer, which is quadratic at thousands of entries.
	cf, err := one.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	m, err := one.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	m = m.DeepCopy()
	diff, ld := cf.RootFS.DiffIDs[0], m.Layers[0]
	cf.RootFS.DiffIDs, cf.History, m.Layers = nil, nil, nil
	for range n {
		cf.RootFS.DiffIDs = append(cf.RootFS.DiffIDs, diff)
		m.Layers = append(m.Layers, ld)
	}
	rawCfg, err := json.Marshal(cf)
	if err != nil {
		t.Fatal(err)
	}
	cfgHash, cfgSize, err := ggcrv1.SHA256(bytes.NewReader(rawCfg))
	if err != nil {
		t.Fatal(err)
	}
	m.Config.Digest, m.Config.Size = cfgHash, cfgSize
	rawMfst, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	img, err := partial.CompressedToImage(fixedImage{raw: rawMfst, cfg: rawCfg, mt: m.MediaType, layer: layer})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// fixedImage is an image core over fixed manifest and config bytes whose
// every layer entry is one blob.
type fixedImage struct {
	raw, cfg []byte
	mt       types.MediaType
	layer    ggcrv1.Layer
}

func (f fixedImage) RawConfigFile() ([]byte, error)      { return f.cfg, nil }
func (f fixedImage) MediaType() (types.MediaType, error) { return f.mt, nil }
func (f fixedImage) RawManifest() ([]byte, error)        { return f.raw, nil }
func (f fixedImage) LayerByDigest(h ggcrv1.Hash) (partial.CompressedLayer, error) {
	if d, err := f.layer.Digest(); err == nil && d == h {
		return f.layer, nil
	}
	return nil, fmt.Errorf("no blob %s", h)
}

// pushManyLayerImage publishes img at host/repo:v1 by uploading its unique
// blobs once and then its manifest: remote.Write walks every layer entry, which
// for thousands of entries naming one blob is the slow part of the test.
func pushManyLayerImage(t *testing.T, host, repo string, img ggcrv1.Image) string {
	t.Helper()
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatal(err)
	}
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []ggcrv1.Layer{layers[0], static.NewLayer(rawCfg, types.DockerConfigJSON)} {
		if err := remote.WriteLayer(ref.Context(), l); err != nil {
			t.Fatalf("write blob: %v", err)
		}
	}
	if err := remote.Put(ref, img); err != nil {
		t.Fatalf("put manifest %s: %v", ref, err)
	}
	return ref.String()
}

// storeBlobCount is how many regular files the content store holds.
func storeBlobCount(t *testing.T, c *Cache) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(c.BlobStoreDir(), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type().IsRegular() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the blob store: %v", err)
	}
	return n
}

// TestPullRefusesAManifestOverTheLayerLimit gates B1739: every path that acts on
// a manifest (cold pull, warm serve, load) refuses one naming more than
// MaxManifestLayers layers, and the cold pull does so before the config GET,
// the lease, the space reservation and any layer GET.
func TestPullRefusesAManifestOverTheLayerLimit(t *testing.T) {
	cases := []struct {
		layers  int
		refused bool
	}{
		{layers: MaxManifestLayers, refused: false},
		{layers: MaxManifestLayers + 1, refused: true},
	}

	t.Run("pull", func(t *testing.T) {
		for _, tc := range cases {
			img := layerLimitImage(t, tc.layers)
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ledger := &SpaceLedger{}
			if !tc.refused {
				// The accepted row is served in-process: 4096 GETs of one blob
				// would prove nothing the refused row does not.
				p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{},
					WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(ledger))
				if err != nil {
					t.Fatal(err)
				}
				res, err := p.Pull(context.Background(), "example.com/many:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
				if err != nil {
					t.Fatalf("%d layers: Pull: %v", tc.layers, err)
				}
				res.Lease.Release()
				continue
			}

			reg := newBlobCountingRegistry(t)
			ref := pushManyLayerImage(t, reg.host, "many", img)
			reg.reset()
			mfst, err := img.Manifest()
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{},
				WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(ledger))
			if err != nil {
				t.Fatalf("NewPuller: %v", err)
			}
			_, err = p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
			if !errors.Is(err, ErrTooManyLayers) {
				t.Fatalf("%d layers: Pull error = %v, want ErrTooManyLayers", tc.layers, err)
			}
			if n := reg.layerGets(t, img); n != 0 {
				t.Errorf("%d layers: registry saw %d layer GETs, want 0", tc.layers, n)
			}
			reg.mu.Lock()
			cfgGets := reg.gets[mfst.Config.Digest.String()]
			reg.mu.Unlock()
			if cfgGets != 0 {
				t.Errorf("%d layers: registry saw %d config GETs, want 0", tc.layers, cfgGets)
			}
			if n := leaseCount(cache); n != 0 {
				t.Errorf("%d layers: %d leases held after the refusal, want 0", tc.layers, n)
			}
			if got := ledger.Reserved(); got != 0 {
				t.Errorf("%d layers: ledger holds %d bytes after the refusal, want 0", tc.layers, got)
			}
		}
	})

	t.Run("ingest refuses before the lease", func(t *testing.T) {
		// The ingest guard alone, reached without resolveRemote (a static
		// fetcher stands in for the local, flat and mirror routes).
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ledger := &SpaceLedger{}
		p, err := NewPuller(cache, staticFetch(layerLimitImage(t, MaxManifestLayers+1)), NoLocalIndex{},
			WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(ledger))
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Pull(context.Background(), "example.com/many:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if !errors.Is(err, ErrTooManyLayers) {
			t.Fatalf("Pull error = %v, want ErrTooManyLayers", err)
		}
		if n := leaseCount(cache); n != 0 || ledger.Reserved() != 0 {
			t.Errorf("leases = %d, reserved = %d after the refusal, want 0 and 0", n, ledger.Reserved())
		}
	})

	t.Run("oversized manifest bytes with few layers", func(t *testing.T) {
		img := mutate.Annotations(layerLimitImage(t, 2),
			map[string]string{"k3sm.io/pad": strings.Repeat("a", maxIndexManifestBytes)}).(ggcrv1.Image)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ledger := &SpaceLedger{}
		p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{},
			WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(ledger))
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Pull(context.Background(), "example.com/big:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if !errors.Is(err, ErrManifestTooLarge) {
			t.Fatalf("Pull error = %v, want ErrManifestTooLarge", err)
		}
		if n := leaseCount(cache); n != 0 || ledger.Reserved() != 0 {
			t.Errorf("leases = %d, reserved = %d after the refusal, want 0 and 0", n, ledger.Reserved())
		}
	})

	t.Run("warm serve", func(t *testing.T) {
		const ref = "example.com/many:v1"
		for _, tc := range cases {
			for _, pull := range []runtimev1.ImagePullPolicy{
				runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT,
				runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			} {
				cache, err := NewCache(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}}
				primeLocalImage(t, cache, idx, ref, layerLimitImage(t, MaxManifestLayers), false)
				if tc.refused {
					m := idx.entries[ref]
					m.Layers = append(m.Layers, proto.Clone(m.Layers[0]).(*runtimev1.Descriptor))
				}
				before, leasesBefore := storeBlobCount(t, cache), leaseCount(cache)
				off := &offlineFetch{}
				p := mustPullerIndex(t, cache, off.fetch, idx)
				res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), pull)
				if off.calls != 0 {
					t.Errorf("%d layers %v: %d fetches, want 0", tc.layers, pull, off.calls)
				}
				if !tc.refused {
					if err != nil || !res.CacheHit {
						t.Fatalf("%d layers %v: Pull = %+v, %v; want a cache hit", tc.layers, pull, res, err)
					}
					res.Lease.Release()
					continue
				}
				if !errors.Is(err, ErrTooManyLayers) {
					t.Fatalf("%d layers %v: Pull error = %v, want ErrTooManyLayers", tc.layers, pull, err)
				}
				if errors.Is(err, ErrImageNotPresent) {
					t.Errorf("%d layers %v: refusal %v wraps ErrImageNotPresent", tc.layers, pull, err)
				}
				if n := leaseCount(cache); n != leasesBefore {
					t.Errorf("%d layers %v: %d leases after the refusal, want %d", tc.layers, pull, n, leasesBefore)
				}
				if after := storeBlobCount(t, cache); after != before {
					t.Errorf("%d layers %v: store went from %d to %d blobs", tc.layers, pull, before, after)
				}
			}
		}
	})

	t.Run("presentAs falls through to a valid spelling", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}}
		primeLocalImage(t, cache, idx, "example.com/good:v1", pullPolicyImage(t), false)
		primeLocalImage(t, cache, idx, "example.com/bad:v1", layerLimitImage(t, MaxManifestLayers), false)
		bad := idx.entries["example.com/bad:v1"]
		bad.Layers = append(bad.Layers, proto.Clone(bad.Layers[0]).(*runtimev1.Descriptor))
		p := mustPullerIndex(t, cache, (&offlineFetch{}).fetch, idx)
		leasesBefore := leaseCount(cache)

		entry, lease, ok, err := p.presentAs(context.Background(), nativePolicy(), "example.com/bad:v1", "example.com/good:v1")
		if err != nil || !ok || entry.Reference != "example.com/good:v1" {
			t.Fatalf("presentAs(bad, good) = %q, %v, %v; want the good spelling", entry.Reference, ok, err)
		}
		lease.Release()

		_, _, ok, err = p.presentAs(context.Background(), nativePolicy(), "example.com/bad:v1", "example.com/missing:v1")
		if ok || !errors.Is(err, ErrTooManyLayers) {
			t.Fatalf("presentAs(bad, missing) = %v, %v; want ErrTooManyLayers", ok, err)
		}
		if n := leaseCount(cache); n != leasesBefore {
			t.Errorf("%d leases after presentAs, want %d", n, leasesBefore)
		}
	})

	t.Run("load", func(t *testing.T) {
		const ref = "example.com/many:v1"
		for _, tc := range cases {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			idx := newRecordingIndex()
			l := mustLoader(t, cache, idx)
			// The refused row stores bytes that contradict the layer's claimed
			// digest: had the blobs been re-hashed before the guard, the error
			// would be the mismatch, not ErrTooManyLayers.
			archive := layerLimitOCIArchive(t, tc.layers, tc.refused)
			res, err := l.Load(context.Background(), LoadRequest{
				Reference: ref,
				Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
			}, bytes.NewReader(archive))
			if !tc.refused {
				if err != nil {
					t.Fatalf("%d layers: Load: %v", tc.layers, err)
				}
				if res == nil {
					t.Fatalf("%d layers: Load returned no result", tc.layers)
				}
				continue
			}
			if !errors.Is(err, ErrTooManyLayers) {
				t.Fatalf("%d layers: Load error = %v, want ErrTooManyLayers", tc.layers, err)
			}
			if n := leaseCount(cache); n != 0 || idx.records != 0 || storeBlobCount(t, cache) != 0 {
				t.Errorf("%d layers: leases = %d, records = %d, blobs = %d after the refusal, want 0",
					tc.layers, n, idx.records, storeBlobCount(t, cache))
			}
		}
	})
}

// layerLimitOCIArchive is a tarred OCI layout whose manifest names ONE shared
// tiny layer n times, written by hand so the tar holds one layer entry: a
// per-entry fixture makes every blob open scan thousands of entries. With
// poison, the stored layer bytes contradict the manifest's claim.
func layerLimitOCIArchive(t *testing.T, n int, poison bool) []byte {
	t.Helper()
	cfg := nativeConfig(t)
	layer := []byte("k3sm-layer-limit")
	mfst := ggcrv1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config:        ggcrv1.Descriptor{MediaType: types.OCIConfigJSON, Digest: ggcrHash(t, cfg), Size: int64(len(cfg))},
	}
	ld := ggcrv1.Descriptor{MediaType: types.OCILayer, Digest: ggcrHash(t, layer), Size: int64(len(layer))}
	for range n {
		mfst.Layers = append(mfst.Layers, ld)
	}
	rawMfst, err := json.Marshal(mfst)
	if err != nil {
		t.Fatal(err)
	}
	rawIdx, err := json.Marshal(ggcrv1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []ggcrv1.Descriptor{{
			MediaType: types.OCIManifestSchema1, Digest: ggcrHash(t, rawMfst), Size: int64(len(rawMfst)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := layer
	if poison {
		stored = []byte("k3sm-layer-LIMIT")
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	blobName := func(h ggcrv1.Hash) string { return "blobs/" + h.Algorithm + "/" + h.Hex }
	for _, e := range []struct {
		name string
		body []byte
	}{
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{"index.json", rawIdx},
		{blobName(ggcrHash(t, rawMfst)), rawMfst},
		{blobName(mfst.Config.Digest), cfg},
		{blobName(ld.Digest), stored},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: e.name, Mode: 0o644, Size: int64(len(e.body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRefuseLayerCount(t *testing.T) {
	cases := []struct {
		name string
		n    int
		raw  []byte
		want error
	}{
		{name: "at the limit", n: MaxManifestLayers},
		{name: "over the limit", n: MaxManifestLayers + 1, want: ErrTooManyLayers},
		{name: "no raw bytes", n: 1, raw: nil},
		{name: "raw at the cap", n: 1, raw: make([]byte, maxIndexManifestBytes)},
		{name: "raw over the cap", n: 1, raw: make([]byte, maxIndexManifestBytes+1), want: ErrManifestTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseLayerCount(tc.n, tc.raw)
			if tc.want == nil && err != nil {
				t.Fatalf("refuseLayerCount = %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("refuseLayerCount = %v, want %v", err, tc.want)
			}
		})
	}
}
