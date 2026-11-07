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
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

const guestStoreTestVersion = "test-guest-v1"

var (
	guestStoreKernel    = []byte("runtime guest kernel\n")
	guestStoreInitramfs = []byte("runtime guest initramfs\n")
)

// guestStorePin is a pin over the two fixture blobs.
func guestStorePin() guestartifacts.GuestKernelPin {
	return guestartifacts.GuestKernelPin{
		KernelVersion:   "v0.0.0-test",
		ImageSHA256:     strings.TrimPrefix(sha(guestStoreKernel), "sha256:"),
		InitramfsSHA256: strings.TrimPrefix(sha(guestStoreInitramfs), "sha256:"),
		ReleaseURL:      "https://release.invalid/guest",
		Cmdline:         "console=hvc0",
	}
}

// rawManifest is a remote.Taggable over hand-built manifest bytes, so the
// pushed manifest carries the artifactType field the guest allow-set keys on.
type rawManifest []byte

func (m rawManifest) RawManifest() ([]byte, error) { return m, nil }

func (rawManifest) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

// countingRegistryHost is testRegistryHost with a count of the blob GETs it
// serves.
func countingRegistryHost(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var gets atomic.Int32
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/sha256:") {
			gets.Add(1)
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host, &gets
}

// pushGuestArtifact publishes the fixture pair to the registry at host under
// the store names the pin derives, as the server's publisher does. extra
// layers are added to the manifest only; their blobs are never pushed.
func pushGuestArtifact(t *testing.T, host string, art guestartifacts.StoreArtifact, extra ...map[string]any) {
	t.Helper()
	repo, err := name.NewRepository(host + "/" + art.Repository)
	if err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`{}`)
	blobs := []struct {
		mt   string
		data []byte
	}{
		{"application/vnd.oci.empty.v1+json", cfg},
		{art.Layers[0].MediaType, guestStoreKernel},
		{art.Layers[1].MediaType, guestStoreInitramfs},
	}
	for _, b := range blobs {
		if err := remote.WriteLayer(repo, static.NewLayer(b.data, types.MediaType(b.mt))); err != nil {
			t.Fatalf("push blob: %v", err)
		}
	}
	var layers []map[string]any
	for i, l := range art.Layers {
		layers = append(layers, map[string]any{
			"mediaType":   l.MediaType,
			"digest":      l.Digest,
			"size":        len(blobs[i+1].data),
			"annotations": map[string]string{artifactv1.AnnotationFilepath: l.FileName},
		})
	}
	layers = append(layers, extra...)
	m, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     string(types.OCIManifestSchema1),
		"artifactType":  art.ArtifactType,
		"config":        map[string]any{"mediaType": blobs[0].mt, "digest": sha(cfg), "size": len(cfg)},
		"layers":        layers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Put(repo.Tag(art.Tag), rawManifest(m)); err != nil {
		t.Fatalf("push manifest: %v", err)
	}
}

// TestGuestClusterStorePullsThroughTheRuntimeCache drives the worker's ensure
// over the store a Runtime hands out: the pull goes through the puller New
// built over the node's own cache and index, and the installed files are the
// pinned bytes.
func TestGuestClusterStorePullsThroughTheRuntimeCache(t *testing.T) {
	host, gets := countingRegistryHost(t)
	pin := guestStorePin()
	art, err := guestartifacts.NewStoreArtifact(guestStoreTestVersion, pin)
	if err != nil {
		t.Fatal(err)
	}
	pushGuestArtifact(t, host, art)

	flat := image.FlatRegistry{Host: artifactTestHost, Endpoint: image.RegistryEndpoint{Addr: host}}
	rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{FlatRegistry: flat}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	store := rt.GuestClusterStore(nil)
	if store.Puller == nil || store.Puller != rt.artifacts {
		t.Fatalf("store puller = %p, want the runtime's own artifact puller %v", store.Puller, rt.artifacts)
	}
	if store.Blobs != rt.cache {
		t.Fatalf("store blobs = %v, want the runtime's own cache", store.Blobs)
	}

	dir := filepath.Join(t.TempDir(), guestartifacts.GuestArtifactsSubdir)
	got, err := guestartifacts.EnsureGuestArtifactsFromStore(context.Background(), dir, guestStoreTestVersion, pin, artifactTestHost, store)
	if err != nil {
		t.Fatalf("EnsureGuestArtifactsFromStore: %v", err)
	}
	for _, f := range []struct {
		path string
		want []byte
	}{{got.KernelPath, guestStoreKernel}, {got.InitramfsPath, guestStoreInitramfs}} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}
		if !bytes.Equal(b, f.want) {
			t.Errorf("%s = %q, want %q", f.path, b, f.want)
		}
	}
	if gets.Load() == 0 {
		t.Error("no blob GET reached the registry, so the refusal test's zero count proves nothing")
	}
	for _, l := range art.Layers {
		if !rt.cache.Has(l.Digest) {
			t.Errorf("%s (%s) is not in the runtime's blob cache", l.FileName, l.Digest)
		}
	}
	if _, ok, err := rt.guestPuller.LookupRecord(context.Background(), art.Reference(artifactTestHost), artifactv1.ArtifactTypeGuest); err != nil || !ok {
		t.Errorf("the guest record is not in the runtime's index: ok=%v err=%v", ok, err)
	}
}

// TestGuestClusterStoreRefusesAnExtraLayerWithNoBlobGET pins, over a real
// registry, that a manifest declaring a layer the pin does not name is refused
// before the runtime's puller requests a single blob.
func TestGuestClusterStoreRefusesAnExtraLayerWithNoBlobGET(t *testing.T) {
	host, gets := countingRegistryHost(t)
	pin := guestStorePin()
	art, err := guestartifacts.NewStoreArtifact(guestStoreTestVersion, pin)
	if err != nil {
		t.Fatal(err)
	}
	pushGuestArtifact(t, host, art, map[string]any{
		"mediaType":   artifactv1.MediaTypeGuestKernel,
		"digest":      "sha256:" + strings.Repeat("c", 64),
		"size":        int64(200 << 30),
		"annotations": map[string]string{artifactv1.AnnotationFilepath: "junk"},
	})
	flat := image.FlatRegistry{Host: artifactTestHost, Endpoint: image.RegistryEndpoint{Addr: host}}
	rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{FlatRegistry: flat}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gets.Store(0)
	dir := filepath.Join(t.TempDir(), guestartifacts.GuestArtifactsSubdir)
	_, err = guestartifacts.EnsureGuestArtifactsFromStore(context.Background(), dir, guestStoreTestVersion, pin, artifactTestHost, rt.GuestClusterStore(nil))
	if !errors.Is(err, artifact.ErrGuestLayersMismatch) {
		t.Fatalf("err = %v, want ErrGuestLayersMismatch", err)
	}
	if n := gets.Load(); n != 0 {
		t.Errorf("%d blob GETs before the refusal, want 0", n)
	}
}

// TestGuestClusterStoreFailsClosedWithoutClusterRegistry pins that a Runtime
// with no cluster registry hands out a store that refuses to pull.
func TestGuestClusterStoreFailsClosedWithoutClusterRegistry(t *testing.T) {
	rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := rt.GuestClusterStore(nil).PullGuest(context.Background(), artifactTestHost+"/k3sm-system/guest:x"); err == nil {
		t.Fatal("PullGuest succeeded on a runtime with no cluster registry")
	}
}

// settableVMBackend is a fakeVMBackend that takes a locator after
// construction, as *sandbox.VMBackend does.
type settableVMBackend struct {
	fakeVMBackend
	mu      sync.Mutex
	locator sandbox.GuestArtifactLocator
}

func (b *settableVMBackend) SetGuestArtifacts(locator sandbox.GuestArtifactLocator) {
	b.mu.Lock()
	b.locator = locator
	b.mu.Unlock()
}

func (b *settableVMBackend) current() sandbox.GuestArtifactLocator {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locator
}

// writeGuestStoreArtifacts writes the fixture pair to dir.
func writeGuestStoreArtifacts(t *testing.T, dir string) sandbox.GuestArtifacts {
	t.Helper()
	a := sandbox.GuestArtifacts{
		KernelPath:    filepath.Join(dir, guestartifacts.ImageFileName),
		InitramfsPath: filepath.Join(dir, guestartifacts.InitramfsFileName),
		Cmdline:       "console=hvc0",
	}
	for p, b := range map[string][]byte{a.KernelPath: guestStoreKernel, a.InitramfsPath: guestStoreInitramfs} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

// TestRefreshGuestArtifactsFlipsTheVMBackend pins the late wiring: a vm
// backend with no locator gains one that resolves the ensured set, while
// concurrent refreshes and readers race it.
func TestRefreshGuestArtifactsFlipsTheVMBackend(t *testing.T) {
	vm := &settableVMBackend{}
	rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{VMBackend: vm}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	art := writeGuestStoreArtifacts(t, t.TempDir())
	if vm.current() != nil {
		t.Fatal("the vm backend has a locator before any refresh")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- rt.RefreshGuestArtifacts(guestStorePin(), art) })
		wg.Go(func() { _ = vm.current() })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("RefreshGuestArtifacts: %v", err)
		}
	}

	locate := vm.current()
	if locate == nil {
		t.Fatal("no locator after RefreshGuestArtifacts")
	}
	if got, err := locate(); err != nil || got != art {
		t.Fatalf("locator = %+v, %v; want %+v", got, err, art)
	}
}

func TestRefreshGuestArtifactsRefusals(t *testing.T) {
	t.Run("a set that does not verify leaves the backend unwired", func(t *testing.T) {
		vm := &settableVMBackend{}
		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{VMBackend: vm}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		art := writeGuestStoreArtifacts(t, t.TempDir())
		pin := guestStorePin()
		pin.ImageSHA256 = hex.EncodeToString(make([]byte, 32))
		if err := rt.RefreshGuestArtifacts(pin, art); !errors.Is(err, guestartifacts.ErrDigestMismatch) {
			t.Fatalf("err = %v, want ErrDigestMismatch", err)
		}
		if vm.current() != nil {
			t.Error("a refused set was installed")
		}
	})
	t.Run("a vm backend that takes no locator is reported", func(t *testing.T) {
		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		art := writeGuestStoreArtifacts(t, t.TempDir())
		if err := rt.RefreshGuestArtifacts(guestStorePin(), art); !errors.Is(err, ErrGuestArtifactsNotSettable) {
			t.Fatalf("err = %v, want ErrGuestArtifactsNotSettable", err)
		}
	})
	t.Run("the shipped vm backend takes the locator", func(t *testing.T) {
		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{VMBackend: sandbox.NewVMBackend()}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		art := writeGuestStoreArtifacts(t, t.TempDir())
		if err := rt.RefreshGuestArtifacts(guestStorePin(), art); err != nil {
			t.Fatalf("RefreshGuestArtifacts: %v", err)
		}
	})
}
