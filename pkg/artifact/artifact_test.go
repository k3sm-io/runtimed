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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

const (
	testHost = "registry-k3sm:6450"
	testRef  = testHost + "/models/tiny:v1"
	volume   = runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME
)

func digestOfBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// fakeFetcher is the network-free transport: it serves manifests by reference
// and blobs by digest, honouring a Range offset unless ignoreRange is set.
type fakeFetcher struct {
	mu        sync.Mutex
	manifests map[string]served
	blobs     map[string][]byte
	// cut, when set for a digest, ends that blob's next body after n bytes with
	// an error, once.
	cut         map[string]int64
	ignoreRange bool
	// gate, when non-nil, holds every blob body open until it is closed.
	gate chan struct{}

	manifestCalls atomic.Int32
	blobCalls     atomic.Int32
	offsets       []int64
	active        atomic.Int32
	maxActive     atomic.Int32
}

type served struct {
	raw []byte
	mt  string
}

func newFake() *fakeFetcher {
	return &fakeFetcher{manifests: map[string]served{}, blobs: map[string][]byte{}, cut: map[string]int64{}}
}

func (f *fakeFetcher) Manifest(_ context.Context, ref string, _ *image.RegistryCredential) ([]byte, string, error) {
	f.manifestCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.manifests[ref]
	if !ok {
		return nil, "", errors.New("manifest unknown")
	}
	return s.raw, s.mt, nil
}

func (f *fakeFetcher) Blob(_ context.Context, _ string, _ *image.RegistryCredential, digest string, offset int64) (io.ReadCloser, int64, error) {
	f.blobCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offsets = append(f.offsets, offset)
	b, ok := f.blobs[digest]
	if !ok {
		return nil, 0, errors.New("blob unknown")
	}
	start := offset
	if f.ignoreRange {
		start = 0
	}
	if start > int64(len(b)) {
		return nil, 0, errors.New("range not satisfiable")
	}
	body := b[start:]
	var tail error
	if n, ok := f.cut[digest]; ok {
		delete(f.cut, digest)
		if n < int64(len(body)) {
			body, tail = body[:n], io.ErrUnexpectedEOF
		}
	}
	n := f.active.Add(1)
	for {
		m := f.maxActive.Load()
		if n <= m || f.maxActive.CompareAndSwap(m, n) {
			break
		}
	}
	return &fakeBody{r: bytes.NewReader(body), tail: tail, f: f, gate: f.gate}, start, nil
}

type fakeBody struct {
	r      *bytes.Reader
	tail   error
	f      *fakeFetcher
	gate   chan struct{}
	waited bool
	closed bool
}

func (b *fakeBody) Read(p []byte) (int, error) {
	if b.gate != nil && !b.waited {
		<-b.gate
		b.waited = true
	} else if !b.waited {
		time.Sleep(5 * time.Millisecond) // overlap concurrent transfers
		b.waited = true
	}
	n, err := b.r.Read(p)
	if err == io.EOF && b.tail != nil {
		return n, b.tail
	}
	return n, err
}

func (b *fakeBody) Close() error {
	if !b.closed {
		b.closed = true
		b.f.active.Add(-1)
	}
	return nil
}

// layer is a test layer.
type layer struct {
	mt, path string
	data     []byte
}

func modelLayer(path, data string) layer {
	return layer{mt: artifactv1.MediaTypeModelWeight, path: path, data: []byte(data)}
}

// publish serves an artifact manifest for ref and its blobs, returning the
// manifest bytes.
func (f *fakeFetcher) publish(ref, artifactType, configMT string, layers []layer) []byte {
	cfg := []byte(`{}`)
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIManifest,
		"config":        map[string]any{"mediaType": configMT, "digest": digestOfBytes(cfg), "size": len(cfg)},
	}
	if artifactType != "" {
		m["artifactType"] = artifactType
	}
	var ls []map[string]any
	f.mu.Lock()
	f.blobs[digestOfBytes(cfg)] = cfg
	for _, l := range layers {
		d := map[string]any{"mediaType": l.mt, "digest": digestOfBytes(l.data), "size": len(l.data)}
		if l.path != "" {
			d["annotations"] = map[string]string{artifactv1.AnnotationFilepath: l.path}
		}
		ls = append(ls, d)
		f.blobs[digestOfBytes(l.data)] = l.data
	}
	m["layers"] = ls
	raw, _ := json.Marshal(m)
	f.manifests[ref] = served{raw: raw, mt: mediaTypeOCIManifest}
	f.mu.Unlock()
	return raw
}

func (f *fakeFetcher) publishModel(ref string, layers ...layer) []byte {
	return f.publish(ref, artifactv1.ArtifactTypeModel, artifactv1.MediaTypeModelConfig, layers)
}

type countingReclaimer struct {
	calls atomic.Int32
	free  *atomic.Uint64 // raised by a pass when non-nil
	gain  uint64
}

func (r *countingReclaimer) ReclaimUnderPressure(context.Context, image.ReclaimConfig) (*image.ReclaimReport, error) {
	r.calls.Add(1)
	if r.free != nil {
		r.free.Add(r.gain)
	}
	return &image.ReclaimReport{}, nil
}

type env struct {
	cache   *image.Cache
	index   *image.FileIndex
	fetch   *fakeFetcher
	reclaim *countingReclaimer
	free    *atomic.Uint64
	partial string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	c, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := image.NewFileIndex(c)
	if err != nil {
		t.Fatal(err)
	}
	free := &atomic.Uint64{}
	free.Store(1 << 40)
	return &env{cache: c, index: idx, fetch: newFake(), reclaim: &countingReclaimer{}, free: free,
		partial: filepath.Join(root, "artifact-partial")}
}

func (e *env) puller(t *testing.T) *Puller {
	t.Helper()
	p, err := New(Config{
		RegistryHost: testHost,
		PartialDir:   e.partial,
		StorePath:    e.cache.Root(),
		FreeBytes:    func(string) (uint64, error) { return e.free.Load(), nil },
		FloorBytes:   100,
	}, Deps{Blobs: e.cache, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: e.fetch})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPullArtifactCommitsAndRecords(t *testing.T) {
	e := newEnv(t)
	raw := e.fetch.publishModel(testRef, modelLayer("config.json", "{\"a\":1}"), modelLayer("w/model.safetensors", "weights"))
	p := e.puller(t)
	res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	defer res.Lease.Release()
	if res.ManifestDigest != digestOfBytes(raw) || res.ArtifactType != artifactv1.ArtifactTypeModel {
		t.Errorf("result = %s %s", res.ManifestDigest, res.ArtifactType)
	}
	for _, d := range res.LayerDigests {
		if !e.cache.Has(d) {
			t.Errorf("layer %s not committed", d)
		}
	}
	rec, ok, err := p.LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeModel)
	if err != nil || !ok || rec.ManifestDigest != res.ManifestDigest || len(rec.LayerDigests) != 2 {
		t.Fatalf("record = %+v %v %v", rec, ok, err)
	}
	// The artifact namespace never aliases an image entry.
	if imgs, err := e.index.List(context.Background()); err != nil || len(imgs) != 0 {
		t.Errorf("image index lists %v (%v); an artifact record must not appear there", imgs, err)
	}
	// Idempotent: a second pull fetches no blob byte.
	before := e.fetch.blobCalls.Load()
	res2, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatal(err)
	}
	res2.Lease.Release()
	if e.fetch.blobCalls.Load() != before || res2.Fetched {
		t.Errorf("second pull fetched blobs")
	}
	if entries, _ := os.ReadDir(e.partial); len(entries) != 0 {
		t.Errorf("partials left after commit: %v", entries)
	}
}

func TestPullArtifactRefusesUnspecifiedPolicy(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("a.json", "a"))
	for _, pol := range []runtimev1.ArtifactPolicy{runtimev1.ArtifactPolicy_ARTIFACT_POLICY_UNSPECIFIED, 7} {
		_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, pol, nil)
		if !errors.Is(err, artifactv1.ErrUnknownPolicy) {
			t.Errorf("policy %v: err = %v, want ErrUnknownPolicy", pol, err)
		}
	}
	if e.fetch.manifestCalls.Load() != 0 {
		t.Error("a refused policy reached the registry")
	}
}

func TestPullArtifactRefusesForeignHostBeforeAnyRequest(t *testing.T) {
	e := newEnv(t)
	for _, ref := range []string{"ghcr.io/models/tiny:v1", "registry-k3sm:6451/models/tiny:v1", "localhost:6450/models/tiny:v1", "models/tiny:v1"} {
		e.fetch.publishModel(ref, modelLayer("a.json", "a"))
		_, err := e.puller(t).PullArtifact(context.Background(), ref, nil, volume, nil)
		// A bare name has no registry at all; strict parsing refuses it as such.
		if !errors.Is(err, ErrNotClusterRegistry) && !(ref == "models/tiny:v1" && errors.Is(err, ErrInvalidReference)) {
			t.Errorf("%s: err = %v, want ErrNotClusterRegistry", ref, err)
		}
	}
	if n := e.fetch.manifestCalls.Load() + e.fetch.blobCalls.Load(); n != 0 {
		t.Errorf("%d requests made for a foreign host", n)
	}
}

func TestPullArtifactArtifactTypeFallsBackToConfigMediaType(t *testing.T) {
	e := newEnv(t)
	e.fetch.publish(testRef, "", artifactv1.MediaTypeWasmConfig,
		[]layer{{mt: artifactv1.MediaTypeWasmLayer, path: "module.wasm", data: []byte("\x00asm")}})
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("wasm with empty artifactType: %v", err)
	}
	res.Lease.Release()
	if res.ArtifactType != artifactv1.MediaTypeWasmConfig {
		t.Errorf("type = %q, want the config media type", res.ArtifactType)
	}
	// And artifactType wins over the config media type when set.
	e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, artifactv1.MediaTypeWasmConfig,
		[]layer{{mt: artifactv1.MediaTypeWasmLayer, path: "module.wasm", data: []byte("\x00asm")}})
	if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTypeRefused) {
		t.Errorf("guest artifactType over a wasm config: err = %v, want ErrTypeRefused", err)
	}
}

func TestPullArtifactRefusesImageConfig(t *testing.T) {
	for _, tc := range []struct{ name, artifactType, config string }{
		{"oci image config", "", artifactv1.MediaTypeOCIImageConfig},
		{"oci image config under a model artifactType", artifactv1.ArtifactTypeModel, artifactv1.MediaTypeOCIImageConfig},
		{"docker image config", "", mediaTypeDockerConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publish(testRef, tc.artifactType, tc.config, []layer{modelLayer("a.json", "a")})
			if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrImageNotArtifact) {
				t.Errorf("err = %v, want ErrImageNotArtifact", err)
			}
			if e.fetch.blobCalls.Load() != 0 {
				t.Error("an image's blobs were fetched")
			}
		})
	}
}

func TestPullArtifactRefusesBareIndex(t *testing.T) {
	e := newEnv(t)
	child := e.fetch.publishModel(testRef, modelLayer("a.json", "a"))
	idx, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaTypeOCIIndex,
		"manifests": []map[string]any{{"mediaType": mediaTypeOCIManifest, "digest": digestOfBytes(child), "size": len(child)}},
	})
	for _, mt := range []string{mediaTypeOCIIndex, mediaTypeOCIManifest, ""} {
		e.fetch.manifests[testRef] = served{raw: idx, mt: mt}
		if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrIndexRefused) {
			t.Errorf("index served as %q: err = %v, want ErrIndexRefused", mt, err)
		}
	}
}

func TestPullArtifactRefusesTarLayers(t *testing.T) {
	for _, mt := range []string{
		"application/vnd.cncf.model.weight.v1.tar",
		"application/vnd.cncf.model.weight.v1.tar+gzip",
		"application/vnd.cncf.model.weight.v1.tar+zstd",
		"application/vnd.oci.image.layer.v1.tar+gzip",
	} {
		e := newEnv(t)
		e.fetch.publishModel(testRef, layer{mt: mt, path: "a.json", data: []byte("a")})
		if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTarLayer) {
			t.Errorf("%s: err = %v, want ErrTarLayer", mt, err)
		}
	}
}

func TestPullArtifactRefusesLayerOutsideAllowSet(t *testing.T) {
	for _, mt := range []string{artifactv1.MediaTypeModelCode, artifactv1.MediaTypeWasmLayer, artifactv1.MediaTypeGuestKernel} {
		e := newEnv(t)
		e.fetch.publishModel(testRef, modelLayer("a.json", "a"), layer{mt: mt, path: "b.txt", data: []byte("b")})
		if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrLayerTypeRefused) {
			t.Errorf("%s: err = %v, want ErrLayerTypeRefused", mt, err)
		}
		if e.fetch.blobCalls.Load() != 0 {
			t.Errorf("%s: blobs fetched before the refusal", mt)
		}
	}
}

func TestPullArtifactLayerCap(t *testing.T) {
	e := newEnv(t)
	ls := make([]layer, MaxLayers+1)
	for i := range ls {
		ls[i] = modelLayer(fmt.Sprintf("f%05d.json", i), fmt.Sprint(i))
	}
	e.fetch.publishModel(testRef, ls...)
	if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTooManyLayers) {
		t.Errorf("err = %v, want ErrTooManyLayers", err)
	}
}

func TestPullArtifactManifestCap(t *testing.T) {
	e := newEnv(t)
	e.fetch.manifests[testRef] = served{raw: bytes.Repeat([]byte(" "), MaxManifestBytes+1), mt: mediaTypeOCIManifest}
	if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrManifestTooLarge) {
		t.Errorf("err = %v, want ErrManifestTooLarge", err)
	}
}

func TestArtifactPathValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layers []layer
		want   error
	}{
		{"missing path", []layer{modelLayer("", "a")}, ErrLayerPath},
		{"absolute", []layer{modelLayer("/etc/passwd", "a")}, artifactv1.ErrAbsolutePath},
		{"traversal", []layer{modelLayer("a/../../b", "a")}, artifactv1.ErrPathComponent},
		{"appledouble", []layer{modelLayer("._x", "a")}, artifactv1.ErrReservedComponent},
		{"code file", []layer{modelLayer("model.pkl", "a")}, artifactv1.ErrCodeFile},
		{"duplicate", []layer{modelLayer("a.json", "a"), modelLayer("a.json", "b")}, artifactv1.ErrDuplicatePath},
		{"case collision", []layer{modelLayer("A.json", "a"), modelLayer("a.json", "b")}, artifactv1.ErrCaseCollision},
		{"file and dir", []layer{modelLayer("w", "a"), modelLayer("w/x.json", "b")}, artifactv1.ErrFileDirConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publishModel(testRef, tc.layers...)
			_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
			if !errors.Is(err, tc.want) || !errors.Is(err, ErrLayerPath) {
				t.Errorf("err = %v, want %v under ErrLayerPath", err, tc.want)
			}
		})
	}
	t.Run("title annotation is accepted", func(t *testing.T) {
		e := newEnv(t)
		raw := e.fetch.publishModel(testRef, modelLayer("x", "a"))
		raw = bytes.Replace(raw, []byte(artifactv1.AnnotationFilepath), []byte(annotationTitle), 1)
		e.fetch.manifests[testRef] = served{raw: raw, mt: mediaTypeOCIManifest}
		res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
		if err != nil || res.Paths[0] != "x" {
			t.Fatalf("title path: %v %v", res, err)
		}
		res.Lease.Release()
	})
	t.Run("requested paths are validated", func(t *testing.T) {
		e := newEnv(t)
		e.fetch.publishModel(testRef, modelLayer("a.json", "a"))
		if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, []string{"../a.json"}); !errors.Is(err, artifactv1.ErrPathComponent) {
			t.Errorf("err = %v", err)
		}
		if e.fetch.manifestCalls.Load() != 0 {
			t.Error("an invalid request reached the registry")
		}
	})
}

func TestPullArtifactSubsetPaths(t *testing.T) {
	e := newEnv(t)
	a, b := modelLayer("a.json", "aaa"), modelLayer("w/b.safetensors", "bbb")
	e.fetch.publishModel(testRef, a, b)
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, []string{"w/b.safetensors"})
	if err != nil {
		t.Fatal(err)
	}
	res.Lease.Release()
	if e.cache.Has(digestOfBytes(a.data)) || !e.cache.Has(digestOfBytes(b.data)) {
		t.Error("subset pull did not fetch exactly the requested layer")
	}
	if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, []string{"nope.json"}); !errors.Is(err, ErrPathNotInArtifact) {
		t.Errorf("unknown path: err = %v", err)
	}
}

// TestPullArtifactVerifiesEveryLayer swaps one byte of each blob in turn (the
// config, then each layer) and asserts the pull fails with ErrDigestMismatch,
// commits no swapped blob, leaves no poisoned partial, and records nothing.
func TestPullArtifactVerifiesEveryLayer(t *testing.T) {
	a, b := modelLayer("a.json", "first layer"), modelLayer("b.json", "second layer")
	targets := []string{digestOfBytes([]byte("{}")), digestOfBytes(a.data), digestOfBytes(b.data)}
	for i, d := range targets {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publishModel(testRef, a, b)
			swapped := append([]byte(nil), e.fetch.blobs[d]...)
			swapped[0] ^= 0x01
			e.fetch.blobs[d] = swapped
			_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
			if !errors.Is(err, image.ErrDigestMismatch) {
				t.Fatalf("err = %v, want ErrDigestMismatch", err)
			}
			if e.cache.Has(d) {
				t.Error("the swapped blob was committed")
			}
			if _, err := os.Lstat(filepath.Join(e.partial, strings.Replace(d, ":", "-", 1)+".partial")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("poisoned partial survived: %v", err)
			}
			if _, ok, _ := e.puller(t).LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeModel); ok {
				t.Error("an artifact with a failed layer was recorded")
			}
		})
	}
}

func TestPullArtifactResumesWithRange(t *testing.T) {
	e := newEnv(t)
	w := modelLayer("w.safetensors", strings.Repeat("0123456789", 100))
	e.fetch.publishModel(testRef, w)
	d := digestOfBytes(w.data)
	e.fetch.cut[d] = 300
	p := e.puller(t)
	if _, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrBlobTransfer) {
		t.Fatalf("first pull err = %v, want ErrBlobTransfer", err)
	}
	if fi, err := os.Stat(filepath.Join(e.partial, strings.Replace(d, ":", "-", 1)+".partial")); err != nil || fi.Size() != 300 {
		t.Fatalf("partial after the cut: %v %v", fi, err)
	}
	e.fetch.offsets = nil
	res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("resumed pull: %v", err)
	}
	res.Lease.Release()
	if len(e.fetch.offsets) != 1 || e.fetch.offsets[0] != 300 {
		t.Errorf("resume offsets = %v, want [300]", e.fetch.offsets)
	}
	if !e.cache.Has(d) {
		t.Error("resumed layer not committed")
	}
}

// TestPullArtifactResumesAcrossRestart cuts a transfer, drops the Puller (the
// daemon dies), builds a new one over the same directories, and asserts the
// new process continues from the partial with a Range request.
func TestPullArtifactResumesAcrossRestart(t *testing.T) {
	e := newEnv(t)
	w := modelLayer("w.safetensors", strings.Repeat("abcdefgh", 128))
	e.fetch.publishModel(testRef, w)
	d := digestOfBytes(w.data)
	e.fetch.cut[d] = 512
	if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); err == nil {
		t.Fatal("cut pull succeeded")
	}
	c2, err := image.NewCache(e.cache.Root())
	if err != nil {
		t.Fatal(err)
	}
	idx2, err := image.NewFileIndex(c2)
	if err != nil {
		t.Fatal(err)
	}
	e.cache, e.index = c2, idx2
	e.fetch.offsets = nil
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("pull after restart: %v", err)
	}
	res.Lease.Release()
	if len(e.fetch.offsets) != 1 || e.fetch.offsets[0] != 512 {
		t.Errorf("offsets after restart = %v, want [512]", e.fetch.offsets)
	}
}

func TestPullArtifactRestartsWhenRangeIgnored(t *testing.T) {
	e := newEnv(t)
	w := modelLayer("w.safetensors", strings.Repeat("xyz", 200))
	e.fetch.publishModel(testRef, w)
	d := digestOfBytes(w.data)
	e.fetch.cut[d] = 100
	p := e.puller(t)
	_, _ = p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	e.fetch.ignoreRange = true
	res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("pull against a Range-ignoring server: %v", err)
	}
	res.Lease.Release()
	if !e.cache.Has(d) {
		t.Error("layer not committed")
	}
}

func TestPullArtifactAtMostTwoLayersAtOnce(t *testing.T) {
	e := newEnv(t)
	var ls []layer
	for i := range 8 {
		ls = append(ls, modelLayer(fmt.Sprintf("f%d.json", i), strings.Repeat(fmt.Sprint(i), 64)))
	}
	e.fetch.publishModel(testRef, ls...)
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Lease.Release()
	if got := e.fetch.maxActive.Load(); got > DefaultMaxConcurrentLayers || got < 1 {
		t.Errorf("max concurrent transfers = %d, want 1..%d", got, DefaultMaxConcurrentLayers)
	}
}

func TestPullArtifactChecksSpaceBeforeFirstByte(t *testing.T) {
	e := newEnv(t)
	w := modelLayer("w.safetensors", strings.Repeat("z", 1000))
	e.fetch.publishModel(testRef, w)
	e.free.Store(500) // floor 100: short
	_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if !errors.Is(err, ErrInsufficientSpace) {
		t.Fatalf("err = %v, want ErrInsufficientSpace", err)
	}
	if e.reclaim.calls.Load() != 1 {
		t.Errorf("reclaim passes = %d, want exactly 1", e.reclaim.calls.Load())
	}
	if e.fetch.blobCalls.Load() != 0 {
		t.Error("a byte was fetched before the space check")
	}
	if entries, _ := os.ReadDir(e.partial); len(entries) != 0 {
		t.Error("a partial was created by a refused pull")
	}

	// One reclaim pass that frees enough lets the pull through.
	e.reclaim.free, e.reclaim.gain = e.free, 1<<20
	res, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("after a productive reclaim: %v", err)
	}
	res.Lease.Release()
}

// TestPullArtifactReservationCountsConcurrentPullsAndTemps holds one pull
// mid-transfer and asserts a second pull is refused on the first one's
// reservation, and that bytes already in a partial are not asked for again.
func TestPullArtifactReservationCountsConcurrentPullsAndTemps(t *testing.T) {
	e := newEnv(t)
	big := modelLayer("big.safetensors", strings.Repeat("b", 4000))
	other := modelLayer("o.safetensors", strings.Repeat("o", 4000))
	e.fetch.publishModel(testRef, big)
	ref2 := testHost + "/models/other:v1"
	e.fetch.publishModel(ref2, other)
	p := e.puller(t)
	need1 := p.spaceNeeded([]blob{{digest: digestOfBytes([]byte("{}")), size: 2}, {digest: digestOfBytes(big.data), size: 4000}})
	e.free.Store(100 + need1 + need1/2) // room for one pull, not two
	e.fetch.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		res, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil)
		if err == nil {
			res.Lease.Release()
		}
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for p.Reserved() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.Reserved() != need1 {
		t.Fatalf("reserved = %d, want %d", p.Reserved(), need1)
	}
	if _, err := p.PullArtifact(context.Background(), ref2, nil, volume, nil); !errors.Is(err, ErrInsufficientSpace) {
		t.Errorf("concurrent pull: err = %v, want ErrInsufficientSpace", err)
	}
	close(e.fetch.gate)
	if err := <-done; err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if p.Reserved() != 0 {
		t.Errorf("reservation not released: %d", p.Reserved())
	}

	// Temps: a partial already holding most of a blob shrinks what is reserved.
	e.fetch.gate = nil
	d := digestOfBytes(other.data)
	if err := os.WriteFile(filepath.Join(e.partial, strings.Replace(d, ":", "-", 1)+".partial"), other.data[:3000], 0o600); err != nil {
		t.Fatal(err)
	}
	withPartial := p.spaceNeeded([]blob{{digest: d, size: 4000}})
	if want := uint64(1000 + 4000); withPartial != want {
		t.Errorf("need with a 3000-byte partial = %d, want %d", withPartial, want)
	}
}

func TestPullArtifactRecordsOnlyAfterEveryLayer(t *testing.T) {
	e := newEnv(t)
	a, b := modelLayer("a.json", "a"), modelLayer("b.json", "b")
	e.fetch.publishModel(testRef, a, b)
	delete(e.fetch.blobs, digestOfBytes(b.data))
	p := e.puller(t)
	if _, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil); err == nil {
		t.Fatal("pull with a missing layer succeeded")
	}
	if _, ok, err := p.LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeModel); ok || err != nil {
		t.Errorf("record after a failed layer: ok=%v err=%v", ok, err)
	}
}

func TestPullArtifactRefusesTypeOutsideAllowSet(t *testing.T) {
	for _, typ := range []string{artifactv1.ArtifactTypeGuest, "application/vnd.example.unknown.v1", artifactv1.MediaTypeModelConfig} {
		e := newEnv(t)
		e.fetch.publish(testRef, typ, artifactv1.MediaTypeModelConfig, []layer{modelLayer("a.json", "a")})
		if _, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTypeRefused) {
			t.Errorf("%s: err = %v, want ErrTypeRefused", typ, err)
		}
		if e.fetch.blobCalls.Load() != 0 {
			t.Errorf("%s: blobs fetched for a refused type", typ)
		}
	}
}
