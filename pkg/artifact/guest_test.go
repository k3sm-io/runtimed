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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
)

var _ guestartifacts.LayerExpectingStore = (*GuestStore)(nil)

const mediaTypeOCIEmpty = "application/vnd.oci.empty.v1+json"

var (
	guestKernel    = []byte("guest kernel bytes\n")
	guestInitramfs = []byte("guest initramfs bytes\n")
)

func guestLayers() []layer {
	return []layer{
		{mt: artifactv1.MediaTypeGuestKernel, path: guestartifacts.ImageFileName, data: guestKernel},
		{mt: artifactv1.MediaTypeGuestInitramfs, path: guestartifacts.InitramfsFileName, data: guestInitramfs},
	}
}

// guestWant is the expected set for guestLayers, as a pin names it.
func guestWant() []GuestLayer {
	var want []GuestLayer
	for _, l := range guestLayers() {
		want = append(want, GuestLayer{Path: l.path, Digest: digestOfBytes(l.data), MaxBytes: guestartifacts.MaxArtifactBytes})
	}
	return want
}

// rawGuestLayer is a manifest layer with a declared size the fake registry
// need not be able to serve.
type rawGuestLayer struct {
	mt, path, digest string
	size             int64
}

// publishRawGuest publishes a guest manifest whose descriptors are written as
// given, for refusals that must fire before any blob is requested. The
// registry serves the config and the fixture pair only.
func publishRawGuest(f *fakeFetcher, ref string, configSize int64, layers []rawGuestLayer) {
	cfg := []byte(`{}`)
	var ls []map[string]any
	for _, l := range layers {
		ls = append(ls, map[string]any{
			"mediaType": l.mt, "digest": l.digest, "size": l.size,
			"annotations": map[string]string{artifactv1.AnnotationFilepath: l.path},
		})
	}
	raw, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeOCIManifest,
		"artifactType":  artifactv1.ArtifactTypeGuest,
		"config":        map[string]any{"mediaType": mediaTypeOCIEmpty, "digest": digestOfBytes(cfg), "size": configSize},
		"layers":        ls,
	})
	f.mu.Lock()
	for _, b := range [][]byte{cfg, guestKernel, guestInitramfs} {
		f.blobs[digestOfBytes(b)] = b
	}
	f.manifests[ref] = served{raw: raw, mt: mediaTypeOCIManifest}
	f.mu.Unlock()
}

// TestPullGuestArtifactRefusesUnexpectedLayersBeforeAnyBlob pins that a guest
// manifest naming anything but the expected layers is refused with no blob
// request, so a hostile registry cannot make a worker download junk, and that
// the expected manifest still pulls.
func TestPullGuestArtifactRefusesUnexpectedLayersBeforeAnyBlob(t *testing.T) {
	kernel := rawGuestLayer{artifactv1.MediaTypeGuestKernel, guestartifacts.ImageFileName, digestOfBytes(guestKernel), int64(len(guestKernel))}
	initramfs := rawGuestLayer{artifactv1.MediaTypeGuestInitramfs, guestartifacts.InitramfsFileName, digestOfBytes(guestInitramfs), int64(len(guestInitramfs))}
	junk := "sha256:" + strings.Repeat("a", 64)
	const big = 200 << 30
	for _, tc := range []struct {
		name       string
		configSize int64
		layers     []rawGuestLayer
	}{
		{"an extra large layer", 2, []rawGuestLayer{kernel, initramfs,
			{artifactv1.MediaTypeGuestKernel, "Image2", junk, big}}},
		{"a substituted large kernel", 2, []rawGuestLayer{
			{artifactv1.MediaTypeGuestKernel, guestartifacts.ImageFileName, junk, big}, initramfs}},
		{"the pinned digest declared oversized", 2, []rawGuestLayer{
			{kernel.mt, kernel.path, kernel.digest, guestartifacts.MaxArtifactBytes + 1}, initramfs}},
		{"a layer under another name", 2, []rawGuestLayer{
			{kernel.mt, "vmlinuz", kernel.digest, kernel.size}, initramfs}},
		{"a missing layer", 2, []rawGuestLayer{kernel}},
		{"an oversized config", MaxGuestConfigBytes + 1, []rawGuestLayer{kernel, initramfs}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			publishRawGuest(e.fetch, testRef, tc.configSize, tc.layers)
			_, err := e.puller(t).PullGuestArtifact(context.Background(), testRef, nil, guestWant())
			if !errors.Is(err, ErrGuestLayersMismatch) {
				t.Fatalf("err = %v, want ErrGuestLayersMismatch", err)
			}
			if n := e.fetch.blobCalls.Load(); n != 0 {
				t.Errorf("%d blob requests before the refusal, want 0", n)
			}
		})
	}

	t.Run("the expected manifest pulls", func(t *testing.T) {
		e := newEnv(t)
		publishRawGuest(e.fetch, testRef, 2, []rawGuestLayer{kernel, initramfs})
		res, err := e.puller(t).PullGuestArtifact(context.Background(), testRef, nil, guestWant())
		if err != nil {
			t.Fatalf("guest pull: %v", err)
		}
		res.Lease.Release()
		for _, d := range []string{kernel.digest, initramfs.digest} {
			if !e.cache.Has(d) {
				t.Errorf("%s not committed", d)
			}
		}
	})
}

func TestPullGuestArtifactRequiresExpectedLayers(t *testing.T) {
	ok := guestWant()
	for _, tc := range []struct {
		name string
		want []GuestLayer
	}{
		{"none", nil},
		{"a malformed digest", []GuestLayer{{Path: "Image", Digest: "sha256:x", MaxBytes: 1}}},
		{"a non-positive size cap", []GuestLayer{{Path: ok[0].Path, Digest: ok[0].Digest}}},
		{"a repeated path", []GuestLayer{ok[0], ok[0]}},
		{"an invalid path", []GuestLayer{{Path: "../Image", Digest: ok[0].Digest, MaxBytes: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, mediaTypeOCIEmpty, guestLayers())
			if _, err := e.puller(t).PullGuestArtifact(context.Background(), testRef, nil, tc.want); !errors.Is(err, ErrGuestLayersRequired) {
				t.Fatalf("err = %v, want ErrGuestLayersRequired", err)
			}
			if n := e.fetch.manifestCalls.Load() + e.fetch.blobCalls.Load(); n != 0 {
				t.Errorf("%d requests, want 0", n)
			}
		})
	}
	if _, _, err := (&GuestStore{}).PullGuest(context.Background(), testRef); !errors.Is(err, ErrGuestLayersRequired) {
		t.Errorf("GuestStore.PullGuest: err = %v, want ErrGuestLayersRequired", err)
	}
}

func TestPullGuestArtifactIsTheOnlyGuestEntry(t *testing.T) {
	e := newEnv(t)
	e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, mediaTypeOCIEmpty, guestLayers())
	p := e.puller(t)

	if _, err := p.PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTypeRefused) {
		t.Fatalf("image-volume pull of a guest artifact: err = %v, want ErrTypeRefused", err)
	}
	if _, err := p.PullForPod(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrTypeRefused) {
		t.Fatalf("pod pull of a guest artifact: err = %v, want ErrTypeRefused", err)
	}
	res, err := p.PullGuestArtifact(context.Background(), testRef, nil, guestWant())
	if err != nil {
		t.Fatalf("guest pull: %v", err)
	}
	res.Lease.Release()
	if res.ArtifactType != artifactv1.ArtifactTypeGuest || len(res.LayerDigests) != 2 {
		t.Errorf("result = %+v", res)
	}
	raw, ok, err := p.LookupRecord(context.Background(), testRef, artifactv1.ArtifactTypeGuest)
	if err != nil || !ok {
		t.Fatalf("guest record: ok=%v err=%v", ok, err)
	}
	if !raw.PodOnly {
		t.Error("the guest record is pinned; it must be PodOnly so its blobs are collectable")
	}

	// The guest entry admits the guest type and its two layer types only.
	e.fetch.publishModel(testRef, modelLayer("a.json", "a"))
	if _, err := p.PullGuestArtifact(context.Background(), testRef, nil, guestWant()); !errors.Is(err, ErrTypeRefused) {
		t.Errorf("guest pull of a model: err = %v, want ErrTypeRefused", err)
	}
	e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, mediaTypeOCIEmpty,
		[]layer{{mt: artifactv1.MediaTypeModelWeight, path: "Image", data: guestKernel}})
	if _, err := p.PullGuestArtifact(context.Background(), testRef, nil, guestWant()); !errors.Is(err, ErrLayerTypeRefused) {
		t.Errorf("guest pull with a model layer: err = %v, want ErrLayerTypeRefused", err)
	}
}

func TestGuestStoreFillsGuestArtifactsCache(t *testing.T) {
	e := newEnv(t)
	sum := func(b []byte) string { return strings.TrimPrefix(digestOfBytes(b), "sha256:") }
	pin := guestartifacts.GuestKernelPin{
		KernelVersion:   "v6.18.48",
		ImageSHA256:     sum(guestKernel),
		InitramfsSHA256: sum(guestInitramfs),
		ReleaseURL:      "https://example.invalid/guest",
		Cmdline:         "console=hvc0",
	}
	const version = "v6.18.48-0123456789ab"
	art, err := guestartifacts.NewStoreArtifact(version, pin)
	if err != nil {
		t.Fatal(err)
	}
	e.fetch.publish(art.Reference(testHost), art.ArtifactType, mediaTypeOCIEmpty, guestLayers())

	dir := filepath.Join(t.TempDir(), guestartifacts.GuestArtifactsSubdir)
	store := &GuestStore{Puller: e.puller(t), Blobs: e.cache}
	got, err := guestartifacts.EnsureGuestArtifactsFromStore(context.Background(), dir, version, pin, testHost, store)
	if err != nil {
		t.Fatalf("ensure from the store: %v", err)
	}
	for path, want := range map[string][]byte{got.KernelPath: guestKernel, got.InitramfsPath: guestInitramfs} {
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s = %q (%v), want %q", path, b, err, want)
		}
	}

	// A store whose manifest adds a layer is refused before any blob request.
	e2 := newEnv(t)
	publishRawGuest(e2.fetch, art.Reference(testHost), 2, []rawGuestLayer{
		{artifactv1.MediaTypeGuestKernel, guestartifacts.ImageFileName, digestOfBytes(guestKernel), int64(len(guestKernel))},
		{artifactv1.MediaTypeGuestInitramfs, guestartifacts.InitramfsFileName, digestOfBytes(guestInitramfs), int64(len(guestInitramfs))},
		{artifactv1.MediaTypeGuestKernel, "extra", "sha256:" + strings.Repeat("b", 64), 100 << 30},
	})
	_, err = guestartifacts.EnsureGuestArtifactsFromStore(context.Background(),
		filepath.Join(t.TempDir(), "g"), version, pin, testHost, &GuestStore{Puller: e2.puller(t), Blobs: e2.cache})
	if !errors.Is(err, ErrGuestLayersMismatch) || !errors.Is(err, guestartifacts.ErrNotInClusterStore) {
		t.Errorf("extra layer: err = %v, want ErrNotInClusterStore wrapping ErrGuestLayersMismatch", err)
	}
	if n := e2.fetch.blobCalls.Load(); n != 0 {
		t.Errorf("extra layer: %d blob requests, want 0", n)
	}

	// A store without the pin is a named refusal.
	_, err = guestartifacts.EnsureGuestArtifactsFromStore(context.Background(),
		filepath.Join(t.TempDir(), "g"), "v6.18.49-0123456789ab", pin, testHost, store)
	if !errors.Is(err, guestartifacts.ErrNotInClusterStore) {
		t.Errorf("missing pin: err = %v, want ErrNotInClusterStore", err)
	}
}

// TestPullGuestArtifactCallersAreConfined fails when any non-test Go file in
// this module names PullGuestArtifact outside the guest adapter and the
// guestartifacts package. The guest allow-set is an internal entry point; a
// new caller (an RPC handler, a pod path) would widen who can make the daemon
// fetch a guest artifact, and must be a reviewed change to this list.
func TestPullGuestArtifactCallersAreConfined(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	allowed := func(rel string) bool {
		return rel == filepath.Join("pkg", "artifact", "guest.go") ||
			strings.HasPrefix(rel, filepath.Join("pkg", "guestartifacts")+string(filepath.Separator))
	}
	fset := token.NewFileSet()
	seen := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		seen++
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "PullGuestArtifact" && !allowed(rel) {
				t.Errorf("%s names PullGuestArtifact; only pkg/artifact/guest.go and pkg/guestartifacts may", fset.Position(sel.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 50 {
		t.Fatalf("walked only %d Go files under %s; the guard is not looking at the module", seen, root)
	}
}

// TestNoPolicySelectsGuestAllowSet asserts the guest allow-set is unreachable
// from an ArtifactPolicy: every declared policy, and values past them, either
// fails or yields a set that refuses the guest type.
func TestNoPolicySelectsGuestAllowSet(t *testing.T) {
	var policies []runtimev1.ArtifactPolicy
	for v := range runtimev1.ArtifactPolicy_name {
		policies = append(policies, runtimev1.ArtifactPolicy(v))
	}
	policies = append(policies, -1, 1<<20)
	for v := int32(0); v < 64; v++ {
		policies = append(policies, runtimev1.ArtifactPolicy(v))
	}
	for _, pol := range policies {
		set, err := artifactv1.AllowSetFor(pol)
		if err != nil {
			continue
		}
		if set.AllowsType(artifactv1.ArtifactTypeGuest) || set.Name() == artifactv1.GuestAllowSet().Name() {
			t.Errorf("policy %v (%d) yields the guest allow-set %q", pol, int32(pol), set.Name())
		}
		for _, mt := range []string{artifactv1.MediaTypeGuestKernel, artifactv1.MediaTypeGuestInitramfs} {
			for _, typ := range set.ArtifactTypes() {
				if set.AllowsLayer(typ, mt) {
					t.Errorf("policy %v admits guest layer %s under %s", pol, mt, typ)
				}
			}
		}
	}
}

// ttlLeaser records the TTL each lease is asked for.
type ttlLeaser struct {
	inner Leaser
	mu    sync.Mutex
	ttls  []time.Duration
}

func (l *ttlLeaser) AcquireLease(digests []string, ttl time.Duration) *image.Lease {
	l.mu.Lock()
	l.ttls = append(l.ttls, ttl)
	l.mu.Unlock()
	return l.inner.AcquireLease(digests, ttl)
}

func TestPullGuestArtifactLeaseOutlivesInstall(t *testing.T) {
	e := newEnv(t)
	e.fetch.publish(testRef, artifactv1.ArtifactTypeGuest, mediaTypeOCIEmpty, guestLayers())
	e.fetch.publishModel(testHost+"/models/other:v1", modelLayer("a.json", "a"))
	lz := &ttlLeaser{inner: e.cache}
	p, err := New(Config{
		RegistryHost: testHost,
		PartialDir:   e.partial,
		StorePath:    e.cache.Root(),
		FreeBytes:    func(string) (uint64, error) { return e.free.Load(), nil },
		FloorBytes:   100,
	}, Deps{Blobs: e.cache, Leases: lz, Reclaimer: e.reclaim, Index: e.index, Fetcher: e.fetch})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.PullGuestArtifact(context.Background(), testRef, nil, guestWant())
	if err != nil {
		t.Fatal(err)
	}
	res.Lease.Release()
	res, err = p.PullArtifact(context.Background(), testHost+"/models/other:v1", nil, volume, nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Lease.Release()
	if len(lz.ttls) != 2 || lz.ttls[0] != GuestLeaseTTL || lz.ttls[1] != 0 {
		t.Errorf("lease TTLs = %v, want [%v 0]: only the guest pull takes the long lease", lz.ttls, GuestLeaseTTL)
	}
	if GuestLeaseTTL < 2*image.DefaultLeaseTTL {
		t.Errorf("GuestLeaseTTL %v is not well above the default %v", GuestLeaseTTL, image.DefaultLeaseTTL)
	}
}

type pathAt string

func (p pathAt) BlobPath(string) (string, error) { return string(p), nil }

func TestGuestStoreOpenBlobRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		ok         bool
	}{
		{"regular file", regular, true},
		{"fifo", fifo, false},
		{"directory", sub, false},
		{"symlink", link, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := (&GuestStore{Blobs: pathAt(tc.path)}).OpenBlob("sha256:" + strings.Repeat("0", 64))
			if tc.ok {
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				b, _ := io.ReadAll(rc)
				_ = rc.Close()
				if string(b) != "ok" {
					t.Errorf("read %q", b)
				}
				return
			}
			if err == nil {
				_ = rc.Close()
				t.Fatal("opened")
			}
		})
	}
}

// hostileFetcher returns a registry error full of control characters from the
// manifest or the blob call.
type hostileFetcher struct {
	*fakeFetcher
	manifestErr, blobErr error
}

func (h *hostileFetcher) Manifest(ctx context.Context, ref string, c *image.RegistryCredential) ([]byte, string, error) {
	if h.manifestErr != nil {
		return nil, "", h.manifestErr
	}
	return h.fakeFetcher.Manifest(ctx, ref, c)
}

func (h *hostileFetcher) Blob(ctx context.Context, ref string, c *image.RegistryCredential, d string, off int64) (io.ReadCloser, int64, error) {
	if h.blobErr != nil {
		return nil, 0, h.blobErr
	}
	return h.fakeFetcher.Blob(ctx, ref, c, d, off)
}

func TestGuestStoreRegistryErrorBoundedAndQuoted(t *testing.T) {
	hostile := errors.New("\x1b[2J\x1b[31mFORGED\nlevel=INFO msg=ok\r\x00\x07" + strings.Repeat("\x1b]8;;evil\x07", 2000))
	sum := func(b []byte) string { return strings.TrimPrefix(digestOfBytes(b), "sha256:") }
	pin := guestartifacts.GuestKernelPin{
		KernelVersion: "v6.18.48", ImageSHA256: sum(guestKernel), InitramfsSHA256: sum(guestInitramfs),
		ReleaseURL: "https://example.invalid/guest", Cmdline: "console=hvc0",
	}
	const version = "v6.18.48-0123456789ab"
	art, err := guestartifacts.NewStoreArtifact(version, pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		manifest, blb error
	}{
		{"manifest error", hostile, nil},
		{"blob error", nil, hostile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publish(art.Reference(testHost), art.ArtifactType, mediaTypeOCIEmpty, guestLayers())
			hf := &hostileFetcher{fakeFetcher: e.fetch, manifestErr: tc.manifest, blobErr: tc.blb}
			p, err := New(Config{
				RegistryHost: testHost, PartialDir: e.partial, StorePath: e.cache.Root(),
				FreeBytes:  func(string) (uint64, error) { return e.free.Load(), nil },
				FloorBytes: 100,
			}, Deps{Blobs: e.cache, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: hf})
			if err != nil {
				t.Fatal(err)
			}
			_, err = guestartifacts.EnsureGuestArtifactsFromStore(context.Background(),
				filepath.Join(t.TempDir(), "g"), version, pin, testHost, &GuestStore{Puller: p, Blobs: e.cache})
			if !errors.Is(err, guestartifacts.ErrNotInClusterStore) || !errors.Is(err, hostile) {
				t.Fatalf("err = %v, want ErrNotInClusterStore wrapping the registry error", err)
			}
			msg := err.Error()
			for i := 0; i < len(msg); i++ {
				if c := msg[i]; c < 0x20 || c == 0x7f {
					t.Fatalf("control byte %#x at %d in %q", c, i, msg)
				}
			}
			if strings.Contains(msg, "\x1b") || strings.Contains(msg, "\n") {
				t.Errorf("raw control text survived: %q", msg)
			}
			if len(msg) > 2048 {
				t.Errorf("message is %d bytes; the registry text is not bounded", len(msg))
			}
			if !strings.Contains(msg, version) {
				t.Errorf("message does not name the pin: %q", msg)
			}
		})
	}
}
