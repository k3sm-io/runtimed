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

	"k3sm.io/runtimed/pkg/image"
)

// BlobPather locates a committed blob; *image.Cache satisfies it.
type BlobPather interface {
	BlobPath(digest string) (string, error)
}

// GuestStore is the worker's view of the cluster store for the guest kernel
// and initramfs: it satisfies guestartifacts.ClusterStore over a Puller and
// its blob cache, pulling only through PullGuestArtifact.
type GuestStore struct {
	// Puller pulls from the cluster registry. Required.
	Puller *Puller
	// Blobs locates committed blobs; the Puller's own cache. Required.
	Blobs BlobPather
	// Cred authenticates to the cluster registry; nil for anonymous.
	Cred *image.RegistryCredential
}

// PullGuest pulls ref through the guest entry point and returns its layers as
// file path to digest. release drops the pull's lease.
func (g *GuestStore) PullGuest(ctx context.Context, ref string) (map[string]string, func(), error) {
	if g == nil || g.Puller == nil || g.Blobs == nil {
		return nil, nil, errors.New("guest store: a puller and a blob cache are required")
	}
	res, err := g.Puller.PullGuestArtifact(ctx, ref, g.Cred)
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
// O_NOFOLLOW, as BlobPath's contract requires of a reader running as root.
func (g *GuestStore) OpenBlob(digest string) (io.ReadCloser, error) {
	if g == nil || g.Blobs == nil {
		return nil, errors.New("guest store: a blob cache is required")
	}
	p, err := g.Blobs.BlobPath(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open blob %s: %w", digest, err)
	}
	return f, nil
}
