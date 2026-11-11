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
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// layerBodyServer is a registry that serves one layer blob through body, which
// writes the layer's bytes however the row wants; every other path is the real
// in-process registry.
func layerBodyServer(t *testing.T, body func(w http.ResponseWriter, r *http.Request, layer []byte)) string {
	t.Helper()
	img := testImage(t, "darwin", "arm64", "")
	layers, err := img.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("layers: %d, %v", len(layers), err)
	}
	ld, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	layer, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}

	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blobs/"+ld.String()) {
			w.Header().Set("Content-Length", strconv.Itoa(len(layer)))
			w.Header().Set("Docker-Content-Digest", ld.String())
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-done:
			default:
				body(w, r, layer)
			}
			return
		}
		store.ServeHTTP(w, r)
	}))
	// Cleanups run last-in first-out: release any held handler, then close.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(done) })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(u.Host + "/stall/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return ref.String()
}

// TestLayerPullStalledBodyAborts is the gate for the layer-body watchdog: a
// layer whose body stops after a few bytes while the server holds the
// connection fails the pull with ErrLayerBodyStalled within a bound, and a body
// that trickles a byte every quarter window for several windows is never cut.
func TestLayerPullStalledBodyAborts(t *testing.T) {
	const window = 200 * time.Millisecond

	pull := func(t *testing.T, ref string) (time.Duration, error) {
		t.Helper()
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p := mustPullerIndex(t, cache, RemoteFetch, NoLocalIndex{})
		p.layerStallWindow = window
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		start := time.Now()
		res, err := p.Pull(ctx, ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if res != nil && res.Lease != nil {
			res.Lease.Release()
		}
		return time.Since(start), err
	}

	t.Run("a body that stops moving aborts with the sentinel", func(t *testing.T) {
		ref := layerBodyServer(t, func(w http.ResponseWriter, r *http.Request, layer []byte) {
			_, _ = w.Write(layer[:16])
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})
		took, err := pull(t, ref)
		if !errors.Is(err, ErrLayerBodyStalled) {
			t.Fatalf("Pull error = %v, want ErrLayerBodyStalled", err)
		}
		if took >= 5*time.Second {
			t.Fatalf("stalled pull took %s, want well under 5s", took)
		}
	})

	t.Run("a slow body that keeps delivering is never cut", func(t *testing.T) {
		const trickle = 20 // bytes at window/4 each: five windows
		ref := layerBodyServer(t, func(w http.ResponseWriter, r *http.Request, layer []byte) {
			cut := len(layer) - trickle
			_, _ = w.Write(layer[:cut])
			w.(http.Flusher).Flush()
			for i := cut; i < len(layer); i++ {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(window / 4):
				}
				_, _ = w.Write(layer[i : i+1])
				w.(http.Flusher).Flush()
			}
		})
		took, err := pull(t, ref)
		if err != nil {
			t.Fatalf("Pull of a trickling body: %v", err)
		}
		if took < 4*window {
			t.Fatalf("trickling pull took %s, want at least %s: the trickle did not run", took, 4*window)
		}
	})
}
