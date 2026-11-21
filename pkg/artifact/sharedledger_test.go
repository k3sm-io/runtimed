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
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// gatedImage runs onLayer each time one of its layers' bytes are opened.
type gatedImage struct {
	ggcrv1.Image
	onLayer func()
}

func (g gatedImage) Layers() ([]ggcrv1.Layer, error) {
	ls, err := g.Image.Layers()
	if err != nil {
		return nil, err
	}
	out := make([]ggcrv1.Layer, len(ls))
	for i, l := range ls {
		out[i] = gatedLayer{Layer: l, on: g.onLayer}
	}
	return out, nil
}

type gatedLayer struct {
	ggcrv1.Layer
	on func()
}

func (l gatedLayer) Compressed() (io.ReadCloser, error) {
	l.on()
	return l.Layer.Compressed()
}

// nativeImage is a two-layer image whose config declares darwin/arm64, and the
// bytes an image pull of it reserves on an empty store.
func nativeImage(t *testing.T) (ggcrv1.Image, uint64) {
	t.Helper()
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "darwin", "arm64"
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	blobs := []image.BlobSpace{{Size: m.Config.Size}}
	for _, l := range m.Layers {
		blobs = append(blobs, image.BlobSpace{Size: l.Size})
	}
	need, err := image.SpaceNeeded(blobs, 1)
	if err != nil {
		t.Fatal(err)
	}
	return img, need
}

// TestImageAndArtifactPullsShareOneLedger: with one ledger handed to both
// pullers, as the daemon wires them, a pull of either kind in flight holds
// space the other kind's pull is measured against.
func TestImageAndArtifactPullsShareOneLedger(t *testing.T) {
	const floor = 100
	policy := image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	pullImage := func(p *image.Puller, ref string) error {
		res, err := p.Pull(context.Background(), ref, nil, policy, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			res.Lease.Release()
		}
		return err
	}
	setup := func(t *testing.T, img ggcrv1.Image) (*env, *image.SpaceLedger, *image.Puller, *Puller, uint64) {
		t.Helper()
		e := newEnv(t)
		e.fetch.publishModel(testRef, modelLayer("w.safetensors", strings.Repeat("w", 2000)))
		ledger := &image.SpaceLedger{}
		free := func(string) (uint64, error) { return e.free.Load(), nil }
		ip, err := image.NewPuller(e.cache, func(context.Context, string, *image.RegistryCredential, image.PlatformPolicy) (ggcrv1.Image, error) {
			return img, nil
		}, image.NoLocalIndex{}, image.WithPullFloor(floor), image.WithFreeBytes(free), image.WithSpaceLedger(ledger),
			image.WithTotalBytes(testCapacity))
		if err != nil {
			t.Fatal(err)
		}
		ap, err := New(Config{
			RegistryHost: testHost,
			PartialDir:   e.partial,
			StorePath:    e.cache.Root(),
			FreeBytes:    free,
			TotalBytes:   testCapacity,
			FloorBytes:   floor,
			Ledger:       ledger,
		}, Deps{Blobs: e.cache, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: e.fetch})
		if err != nil {
			t.Fatal(err)
		}
		artNeed, err := ap.spaceNeeded([]blob{
			{digest: digestOfBytes([]byte("{}")), size: 2},
			{digest: digestOfBytes([]byte(strings.Repeat("w", 2000))), size: 2000},
		})
		if err != nil {
			t.Fatal(err)
		}
		return e, ledger, ip, ap, artNeed
	}

	t.Run("image_in_flight_refuses_artifact", func(t *testing.T) {
		base, imgNeed := nativeImage(t)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		img := gatedImage{Image: base, onLayer: func() {
			once.Do(func() { close(entered) })
			<-release
		}}
		e, ledger, ip, ap, artNeed := setup(t, img)
		e.free.Store(floor + imgNeed + artNeed - 1) // either alone, not both

		done := make(chan error, 1)
		go func() { done <- pullImage(ip, "example.com/app:v1") }()
		<-entered
		if got := ap.Reserved(); got != imgNeed {
			t.Fatalf("artifact puller sees %d reserved, want the image pull's %d", got, imgNeed)
		}
		if _, err := ap.PullArtifact(context.Background(), testRef, nil, volume, nil); !errors.Is(err, ErrInsufficientSpace) {
			t.Errorf("artifact pull beside the image pull: err = %v, want ErrInsufficientSpace", err)
		}
		if n := e.fetch.blobCalls.Load(); n != 0 {
			t.Errorf("the refused artifact pull requested %d blobs, want 0", n)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("image pull: %v", err)
		}
		if got := ledger.Reserved(); got != 0 {
			t.Errorf("ledger holds %d bytes after the image pull, want 0", got)
		}
		res, err := ap.PullArtifact(context.Background(), testRef, nil, volume, nil)
		if err != nil {
			t.Fatalf("artifact pull once the image pull released: %v", err)
		}
		res.Lease.Release()
	})

	t.Run("artifact_in_flight_refuses_image", func(t *testing.T) {
		base, imgNeed := nativeImage(t)
		var opened atomic.Int32
		img := gatedImage{Image: base, onLayer: func() { opened.Add(1) }}
		e, ledger, ip, ap, artNeed := setup(t, img)
		e.free.Store(floor + imgNeed + artNeed - 1)
		e.fetch.gate = make(chan struct{})
		e.fetch.held = make(chan struct{}, 1)

		done := make(chan error, 1)
		go func() {
			res, err := ap.PullArtifact(context.Background(), testRef, nil, volume, nil)
			if err == nil {
				res.Lease.Release()
			}
			done <- err
		}()
		<-e.fetch.held
		if err := pullImage(ip, "example.com/app:v1"); !errors.Is(err, image.ErrInsufficientSpace) {
			t.Errorf("image pull beside the artifact pull: err = %v, want ErrInsufficientSpace", err)
		}
		if n := opened.Load(); n != 0 {
			t.Errorf("the refused image pull opened %d layers, want 0", n)
		}
		close(e.fetch.gate)
		if err := <-done; err != nil {
			t.Fatalf("artifact pull: %v", err)
		}
		if got := ledger.Reserved(); got != 0 {
			t.Errorf("ledger holds %d bytes after the artifact pull, want 0", got)
		}
		if err := pullImage(ip, "example.com/app:v1"); err != nil {
			t.Errorf("image pull once the artifact pull released: %v", err)
		}
	})
}
