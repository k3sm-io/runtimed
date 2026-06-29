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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultRoot is the on-disk root for the content-addressed image cache and pod
// rootfs dirs. /var/lib/k3sm is root-owned in production; tests pass a temp root.
const DefaultRoot = "/var/lib/k3sm"

// Cache is the content-addressed on-disk store for pulled image blobs. Blobs
// live under <root>/blobs/<algo>/<hex>, keyed by their content digest, so a
// second pull of identical content is a cache hit. The cache MUST be on the same
// APFS volume as the pod rootfs dirs for clonefile materialization to CoW.
//
// Cache is safe for use by one process; concurrent writers to the same digest
// race on the temp+rename and are harmless (identical content).
type Cache struct {
	root string
}

// NewCache returns a Cache rooted at root (DefaultRoot if empty), creating the
// blobs dir. It errors only if the dir cannot be created.
func NewCache(root string) (*Cache, error) {
	if root == "" {
		root = DefaultRoot
	}
	c := &Cache{root: root}
	if err := os.MkdirAll(c.blobsDir(), 0o755); err != nil {
		return nil, fmt.Errorf("create image cache %s: %w", c.blobsDir(), err)
	}
	return c, nil
}

// Root returns the cache root dir.
func (c *Cache) Root() string { return c.root }

// blobsDir is the content-addressed blob store.
func (c *Cache) blobsDir() string { return filepath.Join(c.root, "blobs") }

// blobPath maps a digest ("<algo>:<hex>") to its on-disk path.
func (c *Cache) blobPath(digest string) (string, error) {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hex == "" || strings.ContainsAny(hex, "/\\.") {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return filepath.Join(c.blobsDir(), algo, hex), nil
}

// Has reports whether the blob for digest is already cached.
func (c *Cache) Has(digest string) bool {
	p, err := c.blobPath(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// PodRootfs returns the per-pod rootfs dir under the cache root:
// <root>/pods/<podID>/rootfs. It does not create it.
func (c *Cache) PodRootfs(podID string) string {
	return filepath.Join(c.root, "pods", podID, "rootfs")
}
