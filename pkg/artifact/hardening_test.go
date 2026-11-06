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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/image"
)

// publishSized serves a model manifest whose layers DECLARE sizes, whatever
// bytes (if any) back them.
func (f *fakeFetcher) publishSized(ref string, sizes []int64) {
	cfg := []byte(`{}`)
	var ls []map[string]any
	for i, s := range sizes {
		ls = append(ls, map[string]any{
			"mediaType": artifactv1.MediaTypeModelWeight, "digest": digestOfBytes([]byte(fmt.Sprint(i))), "size": s,
			"annotations": map[string]string{artifactv1.AnnotationFilepath: fmt.Sprintf("w%d.safetensors", i)},
		})
	}
	raw, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaTypeOCIManifest, "artifactType": artifactv1.ArtifactTypeModel,
		"config": map[string]any{"mediaType": artifactv1.MediaTypeModelConfig, "digest": digestOfBytes(cfg), "size": len(cfg)},
		"layers": ls,
	})
	f.mu.Lock()
	f.blobs[digestOfBytes(cfg)] = cfg
	f.manifests[ref] = served{raw: raw, mt: mediaTypeOCIManifest}
	f.mu.Unlock()
}

// TestPullArtifactRefusesHostileLayerSizes: two layers declared at 2^62 bytes
// wrapped the uint64 space arithmetic to a zero reservation and slipped past
// the floor. Declared sizes are now capped per layer and in total, before any
// arithmetic, and refused before any blob request.
func TestPullArtifactRefusesHostileLayerSizes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int64
	}{
		{"two layers of 2^62", []int64{1 << 62, 1 << 62}},
		{"one layer of 2^63-1", []int64{math.MaxInt64}},
		{"one layer over the per-layer cap", []int64{MaxLayerBytes + 1}},
		{"layers each under the cap, total over", []int64{MaxLayerBytes, MaxLayerBytes, MaxLayerBytes, MaxLayerBytes, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publishSized(testRef, tc.sizes)
			_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
			if !errors.Is(err, ErrSizeCap) {
				t.Fatalf("err = %v, want ErrSizeCap", err)
			}
			if e.fetch.blobCalls.Load() != 0 {
				t.Error("a blob was requested for a refused manifest")
			}
		})
	}
}

func TestSpaceArithmeticRefusesOverflow(t *testing.T) {
	e := newEnv(t)
	p := e.puller(t)
	if _, err := p.spaceNeeded([]blob{{digest: digestOfBytes([]byte("a")), size: 1 << 62}, {digest: digestOfBytes([]byte("b")), size: 1 << 62}}); !errors.Is(err, ErrSizeOverflow) {
		t.Errorf("spaceNeeded over 2^64: err = %v, want ErrSizeOverflow", err)
	}
	// A ledger already near the top must not wrap into "fits".
	p.resv.held = math.MaxUint64 - 10
	if _, err := p.reserve(context.Background(), []blob{{digest: digestOfBytes([]byte("c")), size: 100}}); !errors.Is(err, ErrSizeOverflow) {
		t.Errorf("reserve over a near-full ledger: err = %v, want ErrSizeOverflow", err)
	}
}

// bigErrFetcher fails every call with a 100 KiB message.
type bigErrFetcher struct{ manifestOK *fakeFetcher }

var bigText = strings.Repeat("A", 100<<10)

func (b bigErrFetcher) Manifest(ctx context.Context, ref string, cred *image.RegistryCredential) ([]byte, string, error) {
	if b.manifestOK != nil {
		return b.manifestOK.Manifest(ctx, ref, cred)
	}
	return nil, "", errors.New(bigText)
}

func (b bigErrFetcher) Blob(context.Context, string, *image.RegistryCredential, string, int64) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New(bigText)
}

func TestPullArtifactBoundsErrorText(t *testing.T) {
	ok := newFake()
	ok.publishModel(testRef, modelLayer("a.json", "a"))
	for name, f := range map[string]Fetcher{"manifest": bigErrFetcher{}, "blob": bigErrFetcher{manifestOK: ok}} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			p, err := New(Config{RegistryHost: testHost, PartialDir: e.partial, StorePath: e.cache.Root(),
				FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }},
				Deps{Blobs: e.cache, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: f})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.PullArtifact(context.Background(), testRef, nil, volume, nil)
			if err == nil || len(err.Error()) > 4096 {
				t.Errorf("error of %d bytes; foreign text must be bounded", len(err.Error()))
			}
		})
	}
}

// roundTripFunc is an in-process http.RoundTripper: no socket is opened.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// countingReader counts the bytes the client actually read from a body.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c countingReader) Close() error { return nil }

func TestRegistryFetcherManifestReadIsBounded(t *testing.T) {
	var read atomic.Int64
	body := bytes.Repeat([]byte(" "), 50<<20)
	f := &RegistryFetcher{PlainHTTP: true, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v2/" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
		}
		h := http.Header{}
		h.Set("Content-Type", mediaTypeOCIManifest)
		return &http.Response{StatusCode: 200, Body: countingReader{r: bytes.NewReader(body), n: &read}, Header: h, Request: r}, nil
	})}
	_, _, err := f.Manifest(context.Background(), testRef, nil)
	if !errors.Is(err, ErrManifestTooLarge) {
		t.Fatalf("err = %v, want ErrManifestTooLarge", err)
	}
	if got := read.Load(); got > MaxManifestBytes+64<<10 {
		t.Errorf("read %d bytes of a 50 MiB manifest; the read must stop at the cap", got)
	}
}

// TestRecordConcurrentSubsetsKeepEveryLayer runs many subset pulls of one
// manifest at once; the record's read-modify-write must keep every layer.
func TestRecordConcurrentSubsetsKeepEveryLayer(t *testing.T) {
	e := newEnv(t)
	var ls []layer
	for i := range 16 {
		ls = append(ls, modelLayer(fmt.Sprintf("f%02d.json", i), fmt.Sprint("layer", i)))
	}
	e.fetch.publishModel(testRef, ls...)
	p := e.puller(t)
	var wg sync.WaitGroup
	for _, l := range ls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.PullArtifact(context.Background(), testRef, nil, volume, []string{l.path})
			if err != nil {
				t.Error(err)
				return
			}
			res.Lease.Release()
		}()
	}
	wg.Wait()
	rec, ok, err := p.LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeModel)
	if err != nil || !ok {
		t.Fatalf("record: %v %v", ok, err)
	}
	if len(rec.LayerDigests) != len(ls) {
		t.Errorf("record names %d layers, want %d (a concurrent update was lost)", len(rec.LayerDigests), len(ls))
	}
}
