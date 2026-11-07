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
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
)

// MaxGuestConfigBytes caps the declared config size of a guest manifest. The
// publisher writes the 2-byte OCI empty config; anything near this cap is
// already not the artifact a pin describes.
const MaxGuestConfigBytes int64 = 4 << 10

// ErrGuestLayersRequired reports a guest pull that named no expected layers.
// Compare with errors.Is.
var ErrGuestLayersRequired = errors.New("artifact: a guest pull must name the layers it expects")

// GuestLayer is one layer a guest pull expects, taken from the caller's pin.
type GuestLayer struct {
	// Path is the layer's file path in the artifact.
	Path string
	// Digest is "sha256:<hex>".
	Digest string
	// MaxBytes caps the layer's declared size; it must be positive.
	MaxBytes int64
}

// checkGuestLayers refuses an expected set that cannot bound a pull: empty,
// a malformed digest or path, a non-positive or over-cap size, or a path
// named twice.
func checkGuestLayers(want []GuestLayer) error {
	if len(want) == 0 || len(want) > MaxLayers {
		return fmt.Errorf("%d expected layers: %w", len(want), ErrGuestLayersRequired)
	}
	seen := make(map[string]bool, len(want))
	for i, l := range want {
		if err := artifactv1.ValidatePath(l.Path); err != nil {
			return fmt.Errorf("expected layer %d: %w: %w", i, ErrGuestLayersRequired, err)
		}
		if seen[l.Path] {
			return fmt.Errorf("expected layer %d repeats %s: %w", i, l.Path, ErrGuestLayersRequired)
		}
		seen[l.Path] = true
		if !sha256Digest.MatchString(l.Digest) {
			return fmt.Errorf("expected layer %s digest %s: %w", l.Path, image.QuoteBounded(l.Digest, 128), ErrGuestLayersRequired)
		}
		if l.MaxBytes <= 0 || l.MaxBytes > MaxLayerBytes {
			return fmt.Errorf("expected layer %s size cap %d: %w", l.Path, l.MaxBytes, ErrGuestLayersRequired)
		}
	}
	return nil
}

// matchGuestLayers refuses a guest manifest unless its layers are exactly
// want: the same count, every layer at an expected path with that path's
// digest and a declared size within its cap. Paths are unique on both sides
// (checkManifest, checkGuestLayers), so equal counts and a match per layer
// mean the sets are equal. The config's declared size is capped too, since it
// is fetched alongside the layers.
func matchGuestLayers(config descriptor, layers []descriptor, paths []string, want []GuestLayer) error {
	if config.Size > MaxGuestConfigBytes {
		return fmt.Errorf("config declares %d bytes, at most %d: %w", config.Size, MaxGuestConfigBytes, ErrGuestLayersMismatch)
	}
	if len(layers) != len(want) {
		return fmt.Errorf("%d layers, %d expected: %w", len(layers), len(want), ErrGuestLayersMismatch)
	}
	byPath := make(map[string]GuestLayer, len(want))
	for _, l := range want {
		byPath[l.Path] = l
	}
	for i, l := range layers {
		e, ok := byPath[paths[i]]
		if !ok {
			return fmt.Errorf("layer %d %s is not expected: %w", i, image.QuoteBounded(paths[i], 256), ErrGuestLayersMismatch)
		}
		if l.Digest != e.Digest {
			return fmt.Errorf("layer %s is %s, expected %s: %w", e.Path, l.Digest, e.Digest, ErrGuestLayersMismatch)
		}
		if l.Size > e.MaxBytes {
			return fmt.Errorf("layer %s declares %d bytes, at most %d: %w", e.Path, l.Size, e.MaxBytes, ErrGuestLayersMismatch)
		}
	}
	return nil
}

// ErrBlobNotRegular reports that the path a blob digest names is not a
// regular file. Compare with errors.Is.
var ErrBlobNotRegular = errors.New("artifact: blob is not a regular file")

// BlobPather locates a committed blob; *image.Cache satisfies it.
type BlobPather interface {
	BlobPath(digest string) (string, error)
}

// GuestStore is the worker's view of the cluster store for the guest kernel
// and initramfs: it satisfies guestartifacts.ClusterStore and
// guestartifacts.LayerExpectingStore over a Puller and its blob cache, pulling
// only through PullGuestArtifact.
type GuestStore struct {
	// Puller pulls from the cluster registry. Required.
	Puller *Puller
	// Blobs locates committed blobs; the Puller's own cache. Required.
	Blobs BlobPather
	// Cred authenticates to the cluster registry; nil for anonymous.
	Cred *image.RegistryCredential
}

// PullGuest always fails with ErrGuestLayersRequired: a guest pull must name
// the layers it expects, so that a hostile manifest is refused before any blob
// is fetched. guestartifacts.EnsureGuestArtifactsFromStore calls
// PullGuestLayers instead.
func (g *GuestStore) PullGuest(context.Context, string) (map[string]string, func(), error) {
	return nil, nil, fmt.Errorf("guest store: %w", ErrGuestLayersRequired)
}

// PullGuestLayers pulls ref through the guest entry point, refusing the
// manifest before any blob request unless its layers are exactly want, each
// within guestartifacts.MaxArtifactBytes. It returns the layers as file path
// to digest; release drops the pull's lease.
func (g *GuestStore) PullGuestLayers(ctx context.Context, ref string, want []guestartifacts.StoreLayer) (map[string]string, func(), error) {
	if g == nil || g.Puller == nil || g.Blobs == nil {
		return nil, nil, errors.New("guest store: a puller and a blob cache are required")
	}
	expect := make([]GuestLayer, len(want))
	for i, l := range want {
		expect[i] = GuestLayer{Path: l.FileName, Digest: l.Digest, MaxBytes: guestartifacts.MaxArtifactBytes}
	}
	res, err := g.Puller.PullGuestArtifact(ctx, ref, g.Cred, expect)
	if err != nil {
		return nil, nil, err
	}
	layers := make(map[string]string, len(res.Paths))
	for i, p := range res.Paths {
		layers[p] = res.LayerDigests[i]
	}
	return layers, res.Lease.Release, nil
}

// OpenBlob opens a committed blob read-only. The final component is opened
// O_NOFOLLOW, as BlobPath's contract requires of a reader running as root, and
// O_NONBLOCK so a FIFO planted at the path cannot hang the open; the opened
// file must then be a regular file by fstat, so a directory or device is
// refused rather than read.
func (g *GuestStore) OpenBlob(digest string) (io.ReadCloser, error) {
	if g == nil || g.Blobs == nil {
		return nil, errors.New("guest store: a blob cache is required")
	}
	p, err := g.Blobs.BlobPath(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open blob %s: %w", digest, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat blob %s: %w", digest, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("blob %s is a %v, not a regular file: %w", digest, fi.Mode().Type(), ErrBlobNotRegular)
	}
	return f, nil
}
