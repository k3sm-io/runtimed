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
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// TestPullReservationCountsTheResumablePartial: a layer the pull will resume
// from its partial is charged only the bytes the partial lacks, as the artifact
// pull charges it, because the partial's bytes are already off free space. A
// retry under disk pressure that fits once the partial is counted is served; one
// byte less free space is refused before any layer request.
func TestPullReservationCountsTheResumablePartial(t *testing.T) {
	const (
		cutAt = 4096
		floor = 1 << 20
	)
	c := newCutRegistry(t, cutAt)
	c.arm(1, 0, false)
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &registryfetch.PartialStore{Dir: filepath.Join(t.TempDir(), "partials")}
	if _, err := pullAlways(resumePuller(t, c, cache, store), c.ref); err == nil {
		t.Fatal("first pull succeeded through a cut layer")
	}
	if got := store.Bytes(c.layer.String(), c.size); got != cutAt {
		t.Fatalf("partial holds %d bytes after the cut, want %d", got, cutAt)
	}

	// The full declaration of what the store still misses, partial ignored.
	r, err := name.ParseReference(c.ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(r, remote.WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatal(err)
	}
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	var blobs []BlobSpace
	for _, d := range append([]ggcrv1.Descriptor{m.Config}, m.Layers...) {
		if !cache.Has(d.Digest.String()) {
			blobs = append(blobs, BlobSpace{Size: d.Size})
		}
	}
	full, err := SpaceNeeded(blobs, 1)
	if err != nil {
		t.Fatal(err)
	}
	fits := uint64(floor) + full - cutAt

	pull := func(free uint64) (*SpaceLedger, error) {
		t.Helper()
		ledger := &SpaceLedger{}
		p := resumePuller(t, c, cache, store)
		for _, o := range []PullerOption{WithPullFloor(floor), WithFreeBytes(fixedFreeBytes(free)),
			WithTotalBytes(testCapacity), WithSpaceLedger(ledger)} {
			o(p)
		}
		res, err := pullAlways(p, c.ref)
		if err == nil {
			res.Lease.Release()
		}
		return ledger, err
	}

	c.takeRanges()
	if _, err := pull(fits - 1); !errors.Is(err, ErrInsufficientSpace) {
		t.Fatalf("pull one byte short of the partial-aware need: err = %v, want ErrInsufficientSpace", err)
	}
	if got := c.takeRanges(); len(got) != 0 {
		t.Fatalf("a refused pull made layer GETs with Range headers %q, want none", got)
	}
	ledger, err := pull(fits)
	if err != nil {
		t.Fatalf("pull that fits once the partial is counted: %v", err)
	}
	if got := ledger.Reserved(); got != 0 {
		t.Errorf("ledger holds %d bytes after the pull, want 0", got)
	}
	if got := c.takeRanges(); len(got) != 1 || got[0] != "bytes=4096-" {
		t.Errorf("served pull layer Range headers = %q, want one resumed GET", got)
	}
	verifyLayer(t, cache, c)
}
