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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// fileBlobSource is an image.LocalBlobSource over files keyed by digest.
type fileBlobSource struct {
	mu    sync.Mutex
	files map[string]string
}

func (s *fileBlobSource) OpenBlob(digest string) (*os.File, int64, error) {
	s.mu.Lock()
	p, ok := s.files[digest]
	s.mu.Unlock()
	if !ok {
		return nil, 0, image.ErrBlobNotLocal
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// TestConfigLocalBlobSourceReachesThePuller is the wiring gate for
// Config.LocalBlobSource, asserted through a live pull against an in-process
// registry that counts GETs of the layer blob. With the source set, a layer
// the source holds is committed without its blob GET; without it, the same
// pull GETs the layer — the control that proves the counter observes the
// fetch.
func TestConfigLocalBlobSourceReachesThePuller(t *testing.T) {
	var layerGets atomic.Int64
	var layerPath atomic.Value // "/blobs/<digest>", set once the image exists
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lp, ok := layerPath.Load().(string); ok && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, lp) {
			layerGets.Add(1)
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	img, err := random.Image(4096, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = "darwin", "arm64", ""
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(u.Host + "/localblob:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push: %v", err)
	}
	layers, err := img.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("layers = %d, %v", len(layers), err)
	}
	layerDigest, layerBytes := layerContent(t, layers[0])
	layerPath.Store("/blobs/" + layerDigest)

	// The store file sits beside the runtime root, on the same volume.
	base := t.TempDir()
	storeFile := filepath.Join(base, "store-layer")
	if err := os.WriteFile(storeFile, layerBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	policy := image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}

	cases := []struct {
		name     string
		source   image.LocalBlobSource
		wantGets bool
	}{
		{"source set, held layer is not fetched", &fileBlobSource{files: map[string]string{layerDigest: storeFile}}, false},
		{"no source, layer is fetched", nil, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(base, "root"+string(rune('a'+i)))
			rt, err := New(Config{Root: root, LocalBlobSource: tc.source}, testDeps(t, Deps{}))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			before := layerGets.Load()
			res, err := rt.puller.Pull(context.Background(), ref.String(), nil, policy,
				runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED)
			if err != nil {
				t.Fatalf("pull: %v", err)
			}
			res.Lease.Release()
			if !rt.cache.Has(layerDigest) {
				t.Fatal("layer not committed")
			}
			gets := layerGets.Load() - before
			if tc.wantGets && gets == 0 {
				t.Error("control pull never GET the layer; the counter does not observe the fetch")
			}
			if !tc.wantGets && gets != 0 {
				t.Errorf("layer GET %d times; Config.LocalBlobSource did not reach the puller", gets)
			}
		})
	}
}

// layerContent returns a layer's digest and compressed bytes.
func layerContent(t *testing.T, l ggcrv1.Layer) (string, []byte) {
	t.Helper()
	d, err := l.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := l.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return d.String(), b
}
