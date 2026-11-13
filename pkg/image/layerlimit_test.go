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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// manifestCountingProxy fronts a registry and counts the GET and HEAD requests
// for any manifest, which blobCountingRegistry never sees: a warm error that
// made no registry request leaves this at zero.
type manifestCountingProxy struct {
	host      string
	manifests atomic.Int64
}

func newManifestCountingProxy(t *testing.T, upstreamHost string) *manifestCountingProxy {
	t.Helper()
	p := &manifestCountingProxy{}
	rp := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: upstreamHost})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if (req.Method == http.MethodGet || req.Method == http.MethodHead) && strings.Contains(req.URL.Path, "/manifests/") {
			p.manifests.Add(1)
		}
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy url %q: %v", srv.URL, err)
	}
	p.host = u.Host
	return p
}

// recordingHandler is a slog handler that keeps every record's message.
type recordingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Level.String()+" "+r.Message)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) has(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.msgs {
		if m == msg {
			return true
		}
	}
	return false
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
// any lease and any layer GET. The space-ledger check is a NET count: it
// proves no reservation is left held after the refusal, not that none was
// taken and released before it.
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
			t.Run(fmt.Sprintf("in-process %d layers", tc.layers), func(t *testing.T) {
				// Served by a static fetcher, so ingestVia is the only guard on
				// the way: resolveRemote is not reached.
				img := &configCountingImage{Image: layerLimitImage(t, tc.layers)}
				cache, err := NewCache(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				obs := newAcquireObserver(cache)
				p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{},
					WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(obs.ledger))
				if err != nil {
					t.Fatal(err)
				}
				res, err := p.Pull(context.Background(), "example.com/many:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
				if !tc.refused {
					if err != nil {
						t.Fatalf("Pull: %v", err)
					}
					defer res.Lease.Release()
					requireManifestOf(t, res.Manifest, img)
					obs.requireAcquired(t)
					// Liveness of the config counter: an accepted pull reads
					// the config, so the refused row's zero is not vacuous.
					if n := img.configReads.Load(); n == 0 {
						t.Errorf("accepted pull read the image config %d times, want > 0", n)
					}
					return
				}
				if !errors.Is(err, ErrTooManyLayers) {
					t.Fatalf("Pull error = %v, want ErrTooManyLayers", err)
				}
				if n := img.configReads.Load(); n != 0 {
					t.Errorf("image config read %d times before the refusal, want 0", n)
				}
				obs.requireNoneAcquired(t)
			})
			t.Run(fmt.Sprintf("registry %d layers", tc.layers), func(t *testing.T) {
				pullThroughRegistry(t, layerLimitImage(t, tc.layers), tc.refused, ErrTooManyLayers)
			})
		}
	})

	t.Run("oversized manifest bytes with few layers", func(t *testing.T) {
		padded := func(t *testing.T) ggcrv1.Image {
			return mutate.Annotations(layerLimitImage(t, 2),
				map[string]string{"k3sm.io/pad": strings.Repeat("a", maxIndexManifestBytes)}).(ggcrv1.Image)
		}
		t.Run("in-process", func(t *testing.T) {
			img := &configCountingImage{Image: padded(t)}
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			obs := newAcquireObserver(cache)
			p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{},
				WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(obs.ledger))
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Pull(context.Background(), "example.com/big:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
			if !errors.Is(err, ErrManifestTooLarge) {
				t.Fatalf("Pull error = %v, want ErrManifestTooLarge", err)
			}
			if n := img.configReads.Load(); n != 0 {
				t.Errorf("image config read %d times before the refusal, want 0", n)
			}
			obs.requireNoneAcquired(t)
		})
		t.Run("registry", func(t *testing.T) {
			pullThroughRegistry(t, padded(t), true, ErrManifestTooLarge)
		})
	})

	t.Run("warm serve", func(t *testing.T) {
		// A stored entry over the limit is a MISS, never an error and never
		// deleted: IfNotPresent goes to the cold path, Never reports both facts.
		overLimitEntry := func(t *testing.T, cache *Cache, idx *fakeIndex, ref string) {
			t.Helper()
			primeLocalImage(t, cache, idx, ref, layerLimitImage(t, MaxManifestLayers), false)
			m := idx.entries[ref]
			m.Layers = append(m.Layers, proto.Clone(m.Layers[0]).(*runtimev1.Descriptor))
		}
		for _, served := range cases {
			t.Run(fmt.Sprintf("IfNotPresent, registry serves %d layers", served.layers), func(t *testing.T) {
				reg := newBlobCountingRegistry(t)
				proxy := newManifestCountingProxy(t, reg.host)
				img := layerLimitImage(t, served.layers)
				ref := pushManyLayerImage(t, proxy.host, "many", img)
				mfst, err := img.Manifest()
				if err != nil {
					t.Fatal(err)
				}
				cache, err := NewCache(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}}
				overLimitEntry(t, cache, idx, ref)
				reg.reset()
				proxy.manifests.Store(0)
				obs := newAcquireObserver(cache)
				logs := &recordingHandler{}
				p, err := NewPuller(cache, RemoteFetch, idx,
					WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(obs.ledger),
					WithPullLogger(slog.New(logs)))
				if err != nil {
					t.Fatal(err)
				}
				res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT)
				if _, kept := idx.entries[ref]; !kept {
					t.Fatalf("index entry %s was deleted", ref)
				}
				if !logs.has("WARN stored image entry is over the manifest limit; treating it as a miss") {
					t.Errorf("no warn line for the skipped warm entry; got %q", logs.msgs)
				}
				// Proof the cold path ran: the warm skip makes no request.
				if n := proxy.manifests.Load(); n == 0 {
					t.Errorf("registry saw %d manifest requests, want > 0 from the cold path", n)
				}
				if !served.refused {
					if err != nil {
						t.Fatalf("Pull: %v", err)
					}
					defer res.Lease.Release()
					if res.CacheHit && !res.Fetched {
						t.Errorf("Pull served the over-limit entry warm: %+v", res)
					}
					requireManifestOf(t, res.Manifest, img)
					if idx.records != 1 {
						t.Errorf("index recorded %d times, want 1", idx.records)
					}
					if n := len(idx.entries[ref].GetLayers()); n != MaxManifestLayers {
						t.Errorf("re-recorded entry has %d layers, want %d", n, MaxManifestLayers)
					}
					return
				}
				if !errors.Is(err, ErrTooManyLayers) {
					t.Fatalf("Pull error = %v, want ErrTooManyLayers from the cold path", err)
				}
				if errors.Is(err, ErrImageNotPresent) {
					t.Errorf("IfNotPresent error %v wraps ErrImageNotPresent; want the cold-path refusal", err)
				}
				if n := reg.layerGets(t, img); n != 0 {
					t.Errorf("registry saw %d layer GETs, want 0", n)
				}
				reg.mu.Lock()
				cfgGets := reg.gets[mfst.Config.Digest.String()]
				reg.mu.Unlock()
				if cfgGets != 0 {
					t.Errorf("registry saw %d config GETs, want 0", cfgGets)
				}
				obs.requireNoneAcquired(t)
				if idx.records != 0 {
					t.Errorf("index recorded %d times after the refusal, want 0", idx.records)
				}
				if n := len(idx.entries[ref].GetLayers()); n != MaxManifestLayers+1 {
					t.Errorf("stored entry has %d layers after the refusal, want its original %d", n, MaxManifestLayers+1)
				}
			})
		}

		t.Run("Never", func(t *testing.T) {
			const ref = "example.com/many:v1"
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			idx := &fakeIndex{entries: map[string]*runtimev1.ImageManifest{}}
			overLimitEntry(t, cache, idx, ref)
			before := storeBlobCount(t, cache)
			obs := newAcquireObserver(cache)
			off := &offlineFetch{}
			p := mustPullerIndex(t, cache, off.fetch, idx)
			_, err = p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER)
			if !errors.Is(err, ErrTooManyLayers) || !errors.Is(err, ErrImageNotPresent) {
				t.Fatalf("Pull error = %v, want both ErrTooManyLayers and ErrImageNotPresent", err)
			}
			if off.calls != 0 {
				t.Errorf("%d fetches, want 0", off.calls)
			}
			if n := obs.leasesAcquired(); n != 0 {
				t.Errorf("%d leases acquired, want 0", n)
			}
			if after := storeBlobCount(t, cache); after != before {
				t.Errorf("store went from %d to %d blobs", before, after)
			}
			if _, kept := idx.entries[ref]; !kept {
				t.Errorf("index entry %s was deleted", ref)
			}
		})

		t.Run("within the limit is still a warm hit", func(t *testing.T) {
			const ref = "example.com/many:v1"
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
				off := &offlineFetch{}
				p := mustPullerIndex(t, cache, off.fetch, idx)
				res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), pull)
				if err != nil || !res.CacheHit || off.calls != 0 {
					t.Fatalf("%v: Pull = %+v, %v, %d fetches; want a cache hit", pull, res, err, off.calls)
				}
				res.Lease.Release()
			}
		})
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

		pr, err := p.presentAs(context.Background(), nativePolicy(), "example.com/bad:v1", "example.com/good:v1")
		if err != nil || !pr.ok || pr.entry.Reference != "example.com/good:v1" {
			t.Fatalf("presentAs(bad, good) = %q, %v, %v; want the good spelling", pr.entry.Reference, pr.ok, err)
		}
		pr.lease.Release()

		pr, err = p.presentAs(context.Background(), nativePolicy(), "example.com/bad:v1", "example.com/missing:v1")
		if err != nil || pr.ok || !errors.Is(pr.refused, ErrTooManyLayers) {
			t.Fatalf("presentAs(bad, missing) = %v, refused %v, err %v; want a miss carrying ErrTooManyLayers", pr.ok, pr.refused, err)
		}
		if n := leaseCount(cache); n != leasesBefore {
			t.Errorf("%d leases after presentAs, want %d", n, leasesBefore)
		}
		if _, kept := idx.entries["example.com/bad:v1"]; !kept {
			t.Errorf("over-limit index entry was deleted")
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
				if n := len(res.Manifest.GetLayers()); n != MaxManifestLayers {
					t.Errorf("%d layers: Load result manifest has %d layers, want %d", tc.layers, n, MaxManifestLayers)
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

// configCountingImage counts every read of the image config, so a row can
// prove a refusal came before the config was fetched.
type configCountingImage struct {
	ggcrv1.Image
	configReads atomic.Int64
}

func (c *configCountingImage) ConfigFile() (*ggcrv1.ConfigFile, error) {
	c.configReads.Add(1)
	return c.Image.ConfigFile()
}

func (c *configCountingImage) RawConfigFile() ([]byte, error) {
	c.configReads.Add(1)
	return c.Image.RawConfigFile()
}

// acquireObserver records lease ACQUISITION, not net holdings: the lease
// table's monotonic id counter (Cache.nextLease, bumped by every AcquireLease),
// so a lease taken and released still shows. Reservations have no such
// counter: the only per-pull sample, the FreeBytesFunc, is also read by the
// pull's admission check before any guard, so it cannot isolate Reserve. The
// reservation is therefore read NET (SpaceLedger.Reserved after the call).
type acquireObserver struct {
	cache     *Cache
	ledger    *SpaceLedger
	leaseBase uint64
}

func newAcquireObserver(c *Cache) *acquireObserver {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	return &acquireObserver{cache: c, ledger: &SpaceLedger{}, leaseBase: c.nextLease}
}

func (o *acquireObserver) leasesAcquired() uint64 {
	o.cache.leaseMu.Lock()
	defer o.cache.leaseMu.Unlock()
	return o.cache.nextLease - o.leaseBase
}

// requireNoneAcquired fails if any lease was ever acquired (a lease taken and
// released still fails it) or if the ledger holds bytes after the call. The
// ledger check is NET only: it proves no reservation is left held, NOT that
// none was taken and released before the refusal.
func (o *acquireObserver) requireNoneAcquired(t *testing.T) {
	t.Helper()
	if n := o.leasesAcquired(); n != 0 {
		t.Errorf("%d leases acquired before the refusal, want 0", n)
	}
	if got := o.ledger.Reserved(); got != 0 {
		t.Errorf("ledger holds %d bytes after the refusal, want 0", got)
	}
}

// requireAcquired is the accepted rows' liveness check on the lease counter:
// an accepted pull leases, so a zero here would mean the refused rows' zeros
// prove nothing.
func (o *acquireObserver) requireAcquired(t *testing.T) {
	t.Helper()
	if n := o.leasesAcquired(); n == 0 {
		t.Errorf("accepted pull acquired %d leases, want > 0", n)
	}
}

// requireManifestOf fails unless got is the manifest img was built from.
func requireManifestOf(t *testing.T, got *runtimev1.ImageManifest, img ggcrv1.Image) {
	t.Helper()
	want, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.GetLayers()); n != len(want.Layers) || n != MaxManifestLayers {
		t.Errorf("result manifest has %d layers, want %d (MaxManifestLayers %d)", n, len(want.Layers), MaxManifestLayers)
	}
	if d := got.GetConfig().GetDigest(); d != want.Config.Digest.String() {
		t.Errorf("result manifest config = %s, want %s", d, want.Config.Digest)
	}
}

// pullThroughRegistry pulls img from a counting registry, so resolveRemote's
// guard is the first one reached. Accepted, the result must be img's
// manifest; refused, the error must be want and no config GET, layer GET,
// lease or reservation may have happened.
func pullThroughRegistry(t *testing.T, img ggcrv1.Image, refused bool, want error) {
	t.Helper()
	reg := newBlobCountingRegistry(t)
	ref := pushManyLayerImage(t, reg.host, "many", img)
	reg.reset()
	mfst, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	obs := newAcquireObserver(cache)
	p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{},
		WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(obs.ledger))
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if !refused {
		if err != nil {
			t.Fatalf("Pull: %v", err)
		}
		defer res.Lease.Release()
		requireManifestOf(t, res.Manifest, img)
		obs.requireAcquired(t)
		// Liveness of the config GET counter: an accepted pull fetches the
		// config, so the refused rows' zero is not vacuous.
		reg.mu.Lock()
		cfgGets := reg.gets[mfst.Config.Digest.String()]
		reg.mu.Unlock()
		if cfgGets == 0 {
			t.Errorf("accepted pull made %d config GETs, want > 0", cfgGets)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("Pull error = %v, want %v", err, want)
	}
	if n := reg.layerGets(t, img); n != 0 {
		t.Errorf("registry saw %d layer GETs, want 0", n)
	}
	reg.mu.Lock()
	cfgGets := reg.gets[mfst.Config.Digest.String()]
	reg.mu.Unlock()
	if cfgGets != 0 {
		t.Errorf("registry saw %d config GETs, want 0", cfgGets)
	}
	obs.requireNoneAcquired(t)
}
