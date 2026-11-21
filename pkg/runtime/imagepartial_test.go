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
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// rangeRegistry is a loopback registry whose one layer blob it serves itself:
// the first GET of the layer stops after cutAt bytes and drops the
// connection, every later one is served by http.ServeContent (which honours
// Range), and the Range header of every layer GET is recorded in order.
type rangeRegistry struct {
	ref    string
	layer  string
	cutAt  int
	mu     sync.Mutex
	cut    bool
	ranges []string
}

func (r *rangeRegistry) takeRanges() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.ranges
	r.ranges = nil
	return out
}

func newRangeRegistry(t *testing.T, cutAt int) *rangeRegistry {
	t.Helper()
	img, err := random.Image(64<<10, 1)
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
	layers, err := img.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("layers = %d, %v", len(layers), err)
	}
	digest, body := layerContent(t, layers[0])
	if cutAt <= 0 || cutAt >= len(body) {
		t.Fatalf("fixture: cut at %d of a %d-byte layer", cutAt, len(body))
	}
	rr := &rangeRegistry{layer: digest, cutAt: cutAt}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	layerSuffix := "/blobs/" + digest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, layerSuffix) {
			store.ServeHTTP(w, req)
			return
		}
		rr.mu.Lock()
		rr.ranges = append(rr.ranges, req.Header.Get("Range"))
		cut := !rr.cut
		rr.cut = true
		rr.mu.Unlock()
		if cut {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body[:cutAt])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // the connection drops mid-body
		}
		http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(body))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rr.ref = u.Host + "/resume/app:v1"
	ref, err := name.ParseReference(rr.ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push: %v", err)
	}
	// The push itself GETs nothing of the layer, but reset to be exact.
	rr.takeRanges()
	return rr
}

// TestImagePullerResumesFromPartial is the wiring gate for the daemon's
// partial store: the Puller runtime.New builds itself (no injected Puller)
// keeps the bytes of a layer cut mid-body, and the next pull of that image
// asks the registry for only the rest, with a Range header from the cut. A
// daemon whose puller has no partial store or no direct blob route sends no
// Range on the second attempt and refetches the layer from byte 0.
func TestImagePullerResumesFromPartial(t *testing.T) {
	const cutAt = 4096
	rr := newRangeRegistry(t, cutAt)
	root := t.TempDir()
	rt, err := New(Config{Root: root}, testDeps(t, Deps{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	policy := image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	pull := func() (*image.PullResult, error) {
		return rt.puller.Pull(context.Background(), rr.ref, nil, policy,
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	}

	if res, err := pull(); err == nil {
		res.Lease.Release()
		t.Fatal("first pull succeeded through a layer cut mid-body")
	}
	first := rr.takeRanges()
	if len(first) == 0 {
		t.Fatal("first pull never GET the layer; the fake does not observe the fetch")
	}
	if first[0] != "" {
		t.Fatalf("first layer GET carried Range %q; a fresh pull has nothing to resume from", first[0])
	}

	res, err := pull()
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	res.Lease.Release()
	second := rr.takeRanges()
	want := "bytes=" + strconv.Itoa(cutAt) + "-"
	if len(second) != 1 || second[0] != want {
		t.Fatalf("second pull layer Range headers = %q, want exactly [%q]: the daemon-built puller did not resume the cut layer", second, want)
	}
	if !rt.cache.Has(rr.layer) {
		t.Fatal("layer not committed after the resumed pull")
	}
	// The committed partial is gone; the store stays, private, beside blobs/.
	dir := filepath.Join(root, image.PartialSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("partial store dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial store holds %d entries after the commit, want 0", len(entries))
	}
}

// TestPartialStoreOpenedWithInjectedPuller: runtime.New opens the cache's
// partial store whatever the puller, so under an injected Puller its private
// directory still exists beside blobs/ (and is swept and counted).
func TestPartialStoreOpenedWithInjectedPuller(t *testing.T) {
	root := t.TempDir()
	if _, err := New(Config{Root: root}, testDeps(t, Deps{Puller: &fakePuller{}})); err != nil {
		t.Fatalf("New: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, image.PartialSubdir))
	if err != nil {
		t.Fatalf("partial store dir under an injected Puller: %v", err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("partial store dir mode = %v, want a 0700 directory", fi.Mode())
	}
}
