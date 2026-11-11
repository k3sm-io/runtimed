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
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
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
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/registryfetch"
)

// cutRegistry is a plain-HTTP in-memory registry holding one image whose
// layer blob it serves itself: the first cut GETs of that blob stop after cutAt
// bytes, the first badRange ranged GETs are answered with a Content-Range
// that is not the one asked for, and every layer GET's Range header is
// recorded.
type cutRegistry struct {
	host     string
	ref      string
	layer    ggcrv1.Hash
	size     int64
	cutAt    int64
	body     []byte
	mu       sync.Mutex
	cuts     int      // GETs still to cut
	badRange int      // ranged GETs still to answer with a wrong Content-Range
	ranges   []string // the Range header of every layer GET, in order
}

func newCutRegistry(t *testing.T, cutAt int64) *cutRegistry {
	t.Helper()
	img, err := random.Image(64<<10, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	img = withPlatform(t, img, "darwin", "arm64", "")
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	mfst, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	c := &cutRegistry{layer: mfst.Layers[0].Digest, size: mfst.Layers[0].Size, cutAt: cutAt, body: body}
	if int64(len(body)) != c.size || cutAt <= 0 || cutAt >= c.size {
		t.Fatalf("fixture: layer %d bytes, descriptor %d, cut at %d", len(body), c.size, cutAt)
	}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	layerPath := "/v2/test/app/blobs/" + c.layer.String()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != layerPath || r.Method != http.MethodGet {
			store.ServeHTTP(w, r)
			return
		}
		c.mu.Lock()
		c.ranges = append(c.ranges, r.Header.Get("Range"))
		cut := c.cuts > 0
		if cut {
			c.cuts--
		}
		bad := !cut && c.badRange > 0 && r.Header.Get("Range") != ""
		if bad {
			c.badRange--
		}
		c.mu.Unlock()
		if bad {
			// The whole blob, labelled as a range from 0: not the offset asked for.
			w.Header().Set("Content-Range", "bytes 0-"+strconv.FormatInt(c.size-1, 10)+"/"+strconv.FormatInt(c.size, 10))
			w.Header().Set("Content-Length", strconv.FormatInt(c.size, 10))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(c.body)
			return
		}
		if cut {
			w.Header().Set("Content-Length", strconv.FormatInt(c.size, 10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(c.body[:c.cutAt])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // the connection drops mid-body
		}
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(c.body))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.host = u.Host
	c.ref = c.host + "/test/app:v1"
	r, err := name.ParseReference(c.ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return c
}

func (c *cutRegistry) takeRanges() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.ranges
	c.ranges = nil
	return out
}

// resumePuller is a Puller over c with a direct plain-HTTP blob route and a
// partial store in dir.
func resumePuller(t *testing.T, c *cutRegistry, cache *Cache, partials *registryfetch.PartialStore) *Puller {
	t.Helper()
	fetch := func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, err
		}
		return remoteFetch(ctx, r, ref, cred, policy, remote.WithTransport(http.DefaultTransport))
	}
	blobs := func(ref string, cred *RegistryCredential) (BlobSource, error) {
		r, err := name.ParseReference(ref)
		if err != nil {
			return BlobSource{}, err
		}
		return BlobSource{
			Ref:        r.Name(),
			Registry:   registryfetch.Registry{Transport: http.DefaultTransport, PlainHTTP: true},
			Credential: cred.registryfetchCredential(),
		}, nil
	}
	p, err := NewPuller(cache, fetch, NoLocalIndex{},
		WithFreeBytes(fixedFreeBytes(64<<30)),
		WithRegistryBlobSource(blobs, nil),
		WithPartialStore(partials))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func partialPath(dir string, d ggcrv1.Hash) string {
	return filepath.Join(dir, "sha256-"+d.Hex+".partial")
}

func pullAlways(p *Puller, ref string) (*PullResult, error) {
	return p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
}

// verifyLayer re-hashes the committed layer blob against its digest.
func verifyLayer(t *testing.T, cache *Cache, c *cutRegistry) {
	t.Helper()
	path, err := cache.BlobPath(c.layer.String())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("committed layer: %v", err)
	}
	defer f.Close()
	got, n, err := ggcrv1.SHA256(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != c.layer || n != c.size {
		t.Fatalf("committed layer is %s (%d bytes), want %s (%d)", got, n, c.layer, c.size)
	}
}

// TestPullResumesCutLayerWithRange pins the resumable layer fetch: a pull cut
// mid-layer keeps the bytes it received, the next pull asks for the rest with
// a Range request and completes with the layer verifying, and a partial whose
// bytes are wrong is refused by the digest check, removed, and not resumed.
func TestPullResumesCutLayerWithRange(t *testing.T) {
	const cutAt = 4096

	t.Run("cut layer resumes from the bytes received", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.cuts = 1
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		p := resumePuller(t, c, cache, &registryfetch.PartialStore{Dir: dir})

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		fi, err := os.Stat(partialPath(dir, c.layer))
		if err != nil {
			t.Fatalf("no partial after the cut pull: %v", err)
		}
		if fi.Size() != cutAt {
			t.Fatalf("partial holds %d bytes, want %d", fi.Size(), cutAt)
		}
		if got := c.takeRanges(); len(got) != 1 || got[0] != "" {
			t.Fatalf("first pull layer Range headers = %q, want one GET with none", got)
		}

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("second pull: %v", err)
		}
		res.Lease.Release()
		want := "bytes=" + strconv.FormatInt(cutAt, 10) + "-"
		if got := c.takeRanges(); len(got) != 1 || got[0] != want {
			t.Fatalf("second pull layer Range headers = %q, want [%q]", got, want)
		}
		verifyLayer(t, cache, c)
		if _, err := os.Stat(partialPath(dir, c.layer)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial survived its commit: %v", err)
		}
	})

	t.Run("wrong partial is refused, removed, and restarted from 0", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		store := &registryfetch.PartialStore{Dir: dir}
		if err := store.EnsureDir(); err != nil {
			t.Fatal(err)
		}
		bad := bytes.Repeat([]byte{0xA5}, cutAt)
		if err := os.WriteFile(partialPath(dir, c.layer), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		p := resumePuller(t, c, cache, store)

		_, err = pullAlways(p, c.ref)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("pull over a wrong partial: err = %v, want ErrDigestMismatch", err)
		}
		want := "bytes=" + strconv.FormatInt(cutAt, 10) + "-"
		if got := c.takeRanges(); len(got) != 1 || got[0] != want {
			t.Fatalf("pull over a wrong partial Range headers = %q, want [%q]", got, want)
		}
		if _, err := os.Stat(partialPath(dir, c.layer)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("poisoned partial was not removed: %v", err)
		}
		if cache.Has(c.layer.String()) {
			t.Fatal("a layer that failed its digest check is in the cache")
		}

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("pull after the poisoned partial: %v", err)
		}
		res.Lease.Release()
		if got := c.takeRanges(); len(got) != 1 || got[0] != "" {
			t.Fatalf("pull after the poisoned partial Range headers = %q, want one GET from 0", got)
		}
		verifyLayer(t, cache, c)
	})

	t.Run("wrong range answer removes the partial and fetches the layer whole", func(t *testing.T) {
		c := newCutRegistry(t, cutAt)
		c.cuts = 1
		c.badRange = 1
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "partials")
		store := &registryfetch.PartialStore{Dir: dir}
		p := resumePuller(t, c, cache, store)

		if _, err := pullAlways(p, c.ref); err == nil {
			t.Fatal("first pull succeeded through a cut layer")
		}
		if got := store.Bytes(c.layer.String(), c.size); got != cutAt {
			t.Fatalf("partial holds %d bytes after the cut pull, want %d", got, cutAt)
		}
		c.takeRanges()

		res, err := pullAlways(p, c.ref)
		if err != nil {
			t.Fatalf("pull over a wrong range answer: %v", err)
		}
		res.Lease.Release()
		verifyLayer(t, cache, c)
		part := filepath.Join(dir, strings.Replace(c.layer.String(), ":", "-", 1)+".partial")
		if _, err := os.Lstat(part); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("partial %s after the wrong range answer: err %v, want not exist", part, err)
		}
		ranged := 0
		for _, r := range c.takeRanges() {
			if r != "" {
				ranged++
			}
		}
		if ranged != 1 {
			t.Fatalf("pull over a wrong range answer made %d ranged requests, want 1", ranged)
		}
	})
}
