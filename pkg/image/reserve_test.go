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
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// blobCountingRegistry is an in-process OCI registry that counts the GETs of
// each blob path, so a test can prove a refused pull requested no layer.
type blobCountingRegistry struct {
	host string
	mu   sync.Mutex
	gets map[string]int
}

func newBlobCountingRegistry(t *testing.T) *blobCountingRegistry {
	t.Helper()
	r := &blobCountingRegistry{gets: map[string]int{}}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/blobs/") {
			r.mu.Lock()
			r.gets[req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]]++
			r.mu.Unlock()
		}
		store.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse registry url %q: %v", srv.URL, err)
	}
	r.host = u.Host
	return r
}

// layerGets is how many times any layer of img was requested.
func (r *blobCountingRegistry) layerGets(t *testing.T, img ggcrv1.Image) int {
	t.Helper()
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, l := range m.Layers {
		n += r.gets[l.Digest.String()]
	}
	return n
}

func (r *blobCountingRegistry) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gets = map[string]int{}
}

// declaredNeed is what reserveSpace claims for img on an empty store.
func declaredNeed(t *testing.T, img ggcrv1.Image) uint64 {
	t.Helper()
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	blobs := []BlobSpace{{Size: m.Config.Size}}
	for _, l := range m.Layers {
		blobs = append(blobs, BlobSpace{Size: l.Size})
	}
	need, err := SpaceNeeded(blobs, 1)
	if err != nil {
		t.Fatal(err)
	}
	return need
}

// TestPullRefusesWhenDeclaredLayersExceedFreeSpace is the reservation gate:
// a pull whose missing declared layers do not fit in free space minus the
// floor is refused with ErrInsufficientSpace before a single layer request,
// although the admission gate (free >= floor) let it start.
func TestPullRefusesWhenDeclaredLayersExceedFreeSpace(t *testing.T) {
	const floor = 1 << 20
	reg := newBlobCountingRegistry(t)
	img := pullPolicyImage(t)
	ref := pushImage(t, reg.host, "app", img)
	reg.reset()

	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ledger := &SpaceLedger{}
	free := uint64(floor) + declaredNeed(t, img) - 1 // admitted, one byte short of the reservation
	p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{},
		WithPullFloor(floor), WithFreeBytes(fixedFreeBytes(free)), WithSpaceLedger(ledger))
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	_, err = p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if !errors.Is(err, ErrInsufficientSpace) {
		t.Fatalf("Pull error = %v, want ErrInsufficientSpace", err)
	}
	if !errors.Is(err, ErrPullRefusedDiskPressure) {
		t.Errorf("Pull error = %v, want it to also match ErrPullRefusedDiskPressure", err)
	}
	if n := reg.layerGets(t, img); n != 0 {
		t.Errorf("registry saw %d layer requests for a refused pull, want 0", n)
	}
	if got := ledger.Reserved(); got != 0 {
		t.Errorf("ledger holds %d bytes after a refused pull, want 0", got)
	}

	// Positive control: one more byte of free space and the same pull fits,
	// fetches its layers, and leaves the ledger empty.
	p, err = NewPuller(cache, RemoteFetch, NoLocalIndex{},
		WithPullFloor(floor), WithFreeBytes(fixedFreeBytes(free+1)), WithSpaceLedger(ledger))
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if err != nil {
		t.Fatalf("Pull with exactly enough room: %v", err)
	}
	res.Lease.Release()
	if n := reg.layerGets(t, img); n == 0 {
		t.Error("the admitted pull requested no layer")
	}
	if got := ledger.Reserved(); got != 0 {
		t.Errorf("ledger holds %d bytes after the pull, want 0", got)
	}
}

// hookedImage runs onLayer each time a layer's bytes are opened, the moment
// the registry would see a layer request.
type hookedImage struct {
	ggcrv1.Image
	onLayer func() error
}

func (h hookedImage) Layers() ([]ggcrv1.Layer, error) {
	ls, err := h.Image.Layers()
	if err != nil {
		return nil, err
	}
	out := make([]ggcrv1.Layer, len(ls))
	for i, l := range ls {
		out[i] = hookedLayer{Layer: l, on: h.onLayer}
	}
	return out, nil
}

type hookedLayer struct {
	ggcrv1.Layer
	on func() error
}

func (l hookedLayer) Compressed() (io.ReadCloser, error) {
	if err := l.on(); err != nil {
		return nil, err
	}
	return l.Layer.Compressed()
}

func staticFetch(img ggcrv1.Image) FetchFunc {
	return func(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
		return img, nil
	}
}

// TestPullReservationReleasedOnEveryPath: a pull holds its reservation while
// its layers arrive and releases it when it ends, failed or not.
func TestPullReservationReleasedOnEveryPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		layer   error
		wantErr bool
	}{
		{name: "fits_and_succeeds"},
		{name: "fails_mid_pull", layer: errors.New("connection reset"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ledger := &SpaceLedger{}
			base := pullPolicyImage(t)
			var heldDuring atomic.Uint64
			img := hookedImage{Image: base, onLayer: func() error {
				heldDuring.Store(ledger.Reserved())
				return tc.layer
			}}
			p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{},
				WithFreeBytes(fixedFreeBytes(64<<30)), WithSpaceLedger(ledger))
			if err != nil {
				t.Fatal(err)
			}
			res, err := p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy(),
				runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Pull error = %v, want error %v", err, tc.wantErr)
			}
			if err == nil {
				res.Lease.Release()
			}
			if want := declaredNeed(t, base); heldDuring.Load() != want {
				t.Errorf("reserved while a layer arrived = %d, want %d", heldDuring.Load(), want)
			}
			if got := ledger.Reserved(); got != 0 {
				t.Errorf("ledger holds %d bytes after the pull, want 0", got)
			}
		})
	}
}

// TestPullReservationSharedLedgerAdmitsOnlyOne holds one pull mid-layer and
// asserts a second puller on the same ledger, which would fit alone, is
// refused on the first one's reservation without requesting a layer.
func TestPullReservationSharedLedgerAdmitsOnlyOne(t *testing.T) {
	const floor = 1 << 20
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ledger := &SpaceLedger{}
	a, b := pullPolicyImage(t), pullPolicyImage(t)
	needA, needB := declaredNeed(t, a), declaredNeed(t, b)
	free := fixedFreeBytes(floor + needA + needB - 1) // either alone, not both

	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	heldA := hookedImage{Image: a, onLayer: func() error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}}
	var bLayers atomic.Int32
	countedB := hookedImage{Image: b, onLayer: func() error { bLayers.Add(1); return nil }}

	pa, err := NewPuller(cache, staticFetch(heldA), NoLocalIndex{}, WithPullFloor(floor), WithFreeBytes(free), WithSpaceLedger(ledger))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := NewPuller(cache, staticFetch(countedB), NoLocalIndex{}, WithPullFloor(floor), WithFreeBytes(free), WithSpaceLedger(ledger))
	if err != nil {
		t.Fatal(err)
	}
	pull := func(p *Puller, ref string) error {
		res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			res.Lease.Release()
		}
		return err
	}
	done := make(chan error, 1)
	go func() { done <- pull(pa, "example.com/a:v1") }()
	<-entered
	if got := ledger.Reserved(); got != needA {
		t.Fatalf("reserved while the first pull runs = %d, want %d", got, needA)
	}
	if err := pull(pb, "example.com/b:v1"); !errors.Is(err, ErrInsufficientSpace) {
		t.Errorf("second pull: err = %v, want ErrInsufficientSpace", err)
	}
	if n := bLayers.Load(); n != 0 {
		t.Errorf("the refused pull opened %d layers, want 0", n)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if got := ledger.Reserved(); got != 0 {
		t.Errorf("ledger holds %d bytes after the first pull, want 0", got)
	}
	if err := pull(pb, "example.com/b:v1"); err != nil {
		t.Errorf("second pull once the first released: %v", err)
	}
}

// declaredImage is an image whose manifest declares layers of the given sizes,
// so a test can hand ingest a hostile declaration without a registry.
type declaredImage struct {
	ggcrv1.Image
	sizes []int64
}

func (d declaredImage) Manifest() (*ggcrv1.Manifest, error) {
	m, err := d.Image.Manifest()
	if err != nil {
		return nil, err
	}
	m = m.DeepCopy()
	m.Layers = nil
	for i, s := range d.sizes {
		m.Layers = append(m.Layers, ggcrv1.Descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Size:      s,
			Digest:    ggcrv1.Hash{Algorithm: "sha256", Hex: strings.Repeat(string(rune('a'+i)), 64)},
		})
	}
	return m, nil
}

// TestPullRefusesHostileDeclaredSizes: a negative declared size, or sizes
// whose sum wraps uint64, refuse with ErrSizeOverflow before any layer opens,
// instead of wrapping into a small reservation.
func TestPullRefusesHostileDeclaredSizes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int64
	}{
		{name: "negative_size", sizes: []int64{100, -1}},
		{name: "sum_overflows_uint64", sizes: []int64{math.MaxInt64, math.MaxInt64, math.MaxInt64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ledger := &SpaceLedger{}
			var opened atomic.Int32
			img := hookedImage{Image: declaredImage{Image: pullPolicyImage(t), sizes: tc.sizes},
				onLayer: func() error { opened.Add(1); return nil }}
			p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{},
				WithFreeBytes(fixedFreeBytes(math.MaxUint64)), WithSpaceLedger(ledger))
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy(),
				runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
			if !errors.Is(err, ErrSizeOverflow) {
				t.Fatalf("Pull error = %v, want ErrSizeOverflow", err)
			}
			if n := opened.Load(); n != 0 {
				t.Errorf("%d layers opened for a refused pull, want 0", n)
			}
			if got := ledger.Reserved(); got != 0 {
				t.Errorf("ledger holds %d bytes, want 0", got)
			}
		})
	}
}

// countingReclaimer is a SpaceReclaimer that only counts its passes.
type countingReclaimer struct{ passes atomic.Int32 }

func (c *countingReclaimer) ReclaimUnderPressure(context.Context, ReclaimConfig) (*ReclaimReport, error) {
	c.passes.Add(1)
	return &ReclaimReport{}, nil
}

func fixedTotalBytes(n uint64) TotalBytesFunc {
	return func(string) (uint64, error) { return n, nil }
}

// TestReserveRefusesAboveCapacityWithoutReclaim: a claim larger than the
// whole volume is refused with no reclaim pass, since no eviction could make
// it fit; a claim short of free space but within capacity still gets exactly
// one pass; and a capacity that cannot be sampled refuses without a pass.
func TestReserveRefusesAboveCapacityWithoutReclaim(t *testing.T) {
	const floor, free, capacity = 100, 1_000, 10_000
	for _, tc := range []struct {
		name       string
		need       uint64
		total      TotalBytesFunc
		wantErr    error
		wantPasses int32
	}{
		{name: "above_capacity", need: capacity, total: fixedTotalBytes(capacity), wantErr: ErrInsufficientSpace},
		{name: "capacity_unknown", need: free, total: func(string) (uint64, error) { return 0, errors.New("statfs: EIO") }, wantErr: ErrFreeSpaceUnknown},
		{name: "above_free_within_capacity", need: free, total: fixedTotalBytes(capacity), wantErr: ErrInsufficientSpace, wantPasses: 1},
		{name: "exactly_capacity", need: capacity - floor, total: fixedTotalBytes(capacity), wantErr: ErrInsufficientSpace, wantPasses: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &SpaceLedger{}
			rec := &countingReclaimer{}
			_, err := ledger.Reserve(context.Background(), SpaceClaim{
				Need: tc.need, Path: t.TempDir(), FloorBytes: floor,
				FreeBytes: fixedFreeBytes(free), TotalBytes: tc.total, Reclaimer: rec,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Reserve error = %v, want %v", err, tc.wantErr)
			}
			if got := rec.passes.Load(); got != tc.wantPasses {
				t.Errorf("reclaim passes = %d, want %d", got, tc.wantPasses)
			}
			if tc.name == "above_capacity" && !strings.Contains(err.Error(), "exceeds the volume's capacity") {
				t.Errorf("refusal %q does not say the claim exceeds the volume's capacity", err)
			}
			if got := ledger.Reserved(); got != 0 {
				t.Errorf("ledger holds %d bytes after a refusal, want 0", got)
			}
		})
	}
}

// TestPullRefusesAboveCapacityWithoutReclaim drives the same rule through a
// pull: a manifest declaring more than the volume holds is refused before any
// layer request, and free space is sampled only by the admission gate and the
// one reservation check, never by a reclaim pass.
func TestPullRefusesAboveCapacityWithoutReclaim(t *testing.T) {
	const capacity = 1 << 30
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var opened, samples atomic.Int32
	img := hookedImage{Image: declaredImage{Image: pullPolicyImage(t), sizes: []int64{2 * capacity}},
		onLayer: func() error { opened.Add(1); return nil }}
	free := func(string) (uint64, error) { samples.Add(1); return capacity / 2, nil }
	p, err := NewPuller(cache, staticFetch(img), NoLocalIndex{}, WithPullFloor(1<<20),
		WithFreeBytes(free), WithTotalBytes(fixedTotalBytes(capacity)), WithSpaceLedger(&SpaceLedger{}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy(),
		runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if !errors.Is(err, ErrInsufficientSpace) || !errors.Is(err, ErrPullRefusedDiskPressure) {
		t.Fatalf("Pull error = %v, want ErrInsufficientSpace and ErrPullRefusedDiskPressure", err)
	}
	if n := opened.Load(); n != 0 {
		t.Errorf("%d layers opened for a refused pull, want 0", n)
	}
	if n := samples.Load(); n != 2 {
		t.Errorf("free space sampled %d times, want 2 (admission and reservation, no reclaim pass)", n)
	}
}
