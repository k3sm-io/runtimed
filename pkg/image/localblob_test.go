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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeLocalStore is a LocalBlobSource over files in a directory, keyed by
// digest. It records every digest asked for.
type fakeLocalStore struct {
	mu    sync.Mutex
	files map[string]string
	asked []string
}

func (s *fakeLocalStore) OpenBlob(digest string) (*os.File, int64, error) {
	s.mu.Lock()
	s.asked = append(s.asked, digest)
	p, ok := s.files[digest]
	s.mu.Unlock()
	if !ok {
		return nil, 0, ErrBlobNotLocal
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

func (s *fakeLocalStore) askedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.asked)
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeStoreFile writes content as a store file next to the cache, so both are
// on the same volume.
func writeStoreFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// blobTemps lists the in-flight temp files in the store's sha256 directory.
func blobTemps(t *testing.T, c *Cache) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(c.BlobStoreDir(), "sha256"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".blob-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestCommitFromLocalStoreClonesAndRehashes covers the happy path: a blob the
// local store holds on the cache's volume is committed from it, the committed
// bytes are the blob, and the cache file is its own inode, not the store's.
func TestCommitFromLocalStoreClonesAndRehashes(t *testing.T) {
	root := t.TempDir()
	cache, err := NewCache(filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("layer bytes "), 4096)
	digest := sha256Digest(content)
	srcPath := writeStoreFile(t, root, "store-blob", content)
	store := &fakeLocalStore{files: map[string]string{digest: srcPath}}

	wrote, err := cache.CommitFromLocal(digest, int64(len(content)), store)
	if errors.Is(err, ErrBlobNotLocal) {
		t.Skipf("temp dir volume cannot clone: %v", err)
	}
	if err != nil {
		t.Fatalf("CommitFromLocal: %v", err)
	}
	if !wrote {
		t.Fatal("CommitFromLocal reported a cache hit for an empty cache")
	}
	blobPath, err := cache.BlobPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("committed blob does not hold the source bytes")
	}
	if sha256Digest(got) != digest {
		t.Fatal("committed blob does not hash to its digest")
	}
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	dstInfo, err := os.Lstat(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(srcInfo, dstInfo) {
		t.Fatal("cache blob shares the source inode (a hard link, not a clone)")
	}
	if !dstInfo.Mode().IsRegular() || dstInfo.Mode().Perm() != 0o600 {
		t.Errorf("cache blob mode = %s, want a regular 0600 file", dstInfo.Mode())
	}
	if temps := blobTemps(t, cache); len(temps) != 0 {
		t.Errorf("temp clones left behind: %v", temps)
	}

	// A second commit is a cache hit and does not consult the store.
	asked := store.askedCount()
	wrote, err = cache.CommitFromLocal(digest, int64(len(content)), store)
	if err != nil || wrote {
		t.Fatalf("second CommitFromLocal = (%v, %v), want (false, nil)", wrote, err)
	}
	if store.askedCount() != asked {
		t.Error("cache hit still consulted the local store")
	}
}

// TestLocalStoreTamperedBlobRefused: a store file whose bytes do not hash to
// the digest it is held under is refused with an error naming the digest;
// nothing is committed and the temp clone is removed.
func TestLocalStoreTamperedBlobRefused(t *testing.T) {
	root := t.TempDir()
	cache, err := NewCache(filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("the real layer")
	digest := sha256Digest(content)
	tampered := []byte("the evil layer") // same length, different bytes
	store := &fakeLocalStore{files: map[string]string{
		digest: writeStoreFile(t, root, "store-blob", tampered),
	}}

	wrote, err := cache.CommitFromLocal(digest, int64(len(content)), store)
	if errors.Is(err, ErrBlobNotLocal) {
		t.Skipf("temp dir volume cannot clone: %v", err)
	}
	if err == nil || wrote {
		t.Fatalf("CommitFromLocal = (%v, %v), want a refusal", wrote, err)
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("error %v does not wrap ErrDigestMismatch", err)
	}
	if !strings.Contains(err.Error(), digest) {
		t.Errorf("error %q does not name the digest", err)
	}
	if cache.Has(digest) {
		t.Error("tampered blob was committed")
	}
	if temps := blobTemps(t, cache); len(temps) != 0 {
		t.Errorf("temp clone not removed: %v", temps)
	}
}

// countingLayer counts Compressed calls: the network fetch of a remote layer.
type countingLayer struct {
	ggcrv1.Layer
	mu    *sync.Mutex
	calls *int
}

func (l countingLayer) Compressed() (io.ReadCloser, error) {
	l.mu.Lock()
	*l.calls++
	l.mu.Unlock()
	return l.Layer.Compressed()
}

// countingImage wraps an image so every layer's fetch is counted.
type countingImage struct {
	ggcrv1.Image
	mu    sync.Mutex
	calls int
}

func (i *countingImage) Layers() ([]ggcrv1.Layer, error) {
	ls, err := i.Image.Layers()
	if err != nil {
		return nil, err
	}
	out := make([]ggcrv1.Layer, len(ls))
	for n, l := range ls {
		out[n] = countingLayer{Layer: l, mu: &i.mu, calls: &i.calls}
	}
	return out, nil
}

func (i *countingImage) fetches() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.calls
}

// TestCrossVolumeFallsBackToPull: a store file on another volume is not cloned;
// CommitFromLocal reports ErrBlobNotLocal and the puller fetches every layer
// over the network instead.
func TestCrossVolumeFallsBackToPull(t *testing.T) {
	base, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	img := &countingImage{Image: withPlatform(t, base, "darwin", "arm64", "")}
	layers, err := img.Image.Layers()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	cache, err := NewCache(filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cache.sameVolume = func(_, _ os.FileInfo) bool { return false }

	// The store holds every layer, byte-identical — only the volume differs.
	store := &fakeLocalStore{files: map[string]string{}}
	for n, l := range layers {
		d, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		store.files[d.String()] = writeStoreFile(t, root, "layer-"+string(rune('a'+n)), b)
	}

	t.Run("commit reports not local", func(t *testing.T) {
		d, err := layers[0].Digest()
		if err != nil {
			t.Fatal(err)
		}
		size, err := layers[0].Size()
		if err != nil {
			t.Fatal(err)
		}
		wrote, err := cache.CommitFromLocal(d.String(), size, store)
		if !errors.Is(err, ErrBlobNotLocal) || wrote {
			t.Fatalf("CommitFromLocal = (%v, %v), want ErrBlobNotLocal", wrote, err)
		}
		if cache.Has(d.String()) {
			t.Error("cross-volume blob was committed")
		}
	})

	t.Run("puller fetches", func(t *testing.T) {
		ff := &fakeFetch{img: img}
		p, err := NewPuller(cache, ff.fetch, NoLocalIndex{},
			WithFreeBytes(fixedFreeBytes(64<<30)), WithLocalBlobSource(store))
		if err != nil {
			t.Fatalf("NewPuller: %v", err)
		}
		before := store.askedCount()
		res, err := p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy(),
			runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED)
		if err != nil {
			t.Fatalf("pull: %v", err)
		}
		if store.askedCount() == before {
			t.Error("puller never consulted the local blob source")
		}
		if got := img.fetches(); got != len(layers) {
			t.Errorf("layer fetches = %d, want %d (every layer over the network)", got, len(layers))
		}
		for _, l := range res.Manifest.Layers {
			if !cache.Has(l.Digest) {
				t.Errorf("layer %s not cached", l.Digest)
			}
		}
	})
}
