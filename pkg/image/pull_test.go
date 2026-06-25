package image

import (
	"context"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// fakeFetch returns a fixed in-memory image, counting calls so the test can
// assert the cache hit path does (or does not) re-fetch.
type fakeFetch struct {
	img   ggcrv1.Image
	calls int
}

func (f *fakeFetch) fetch(_ context.Context, _ string) (ggcrv1.Image, error) {
	f.calls++
	return f.img, nil
}

// TestPullCachesAndHits is the unit form of acceptance M1.1-a1: the first pull
// populates the content-addressed cache; a second pull of the same content is a
// cache hit (no blob re-written) and the manifest round-trips into the apis type.
func TestPullCachesAndHits(t *testing.T) {
	img, err := random.Image(1024, 3) // 3 layers
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	ff := &fakeFetch{img: img}

	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := NewPuller(cache, ff.fetch)

	res1, err := p.Pull(context.Background(), "example.com/app:v1")
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if res1.CacheHit {
		t.Error("first pull reported a cache hit")
	}
	if res1.Manifest == nil || res1.Manifest.Reference != "example.com/app:v1" {
		t.Fatalf("manifest not populated: %+v", res1.Manifest)
	}
	if len(res1.Manifest.Layers) != 3 {
		t.Errorf("want 3 layers in manifest, got %d", len(res1.Manifest.Layers))
	}
	// Every layer + the config blob must now be cached by digest.
	if !cache.Has(res1.Manifest.Config.Digest) {
		t.Errorf("config blob %s not cached", res1.Manifest.Config.Digest)
	}
	for _, l := range res1.Manifest.Layers {
		if !cache.Has(l.Digest) {
			t.Errorf("layer blob %s not cached", l.Digest)
		}
	}

	res2, err := p.Pull(context.Background(), "example.com/app:v1")
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if !res2.CacheHit {
		t.Error("second pull of identical content was not a cache hit")
	}
	if ff.calls != 2 {
		t.Errorf("fetch called %d times, want 2 (pull still resolves the manifest)", ff.calls)
	}
}

// TestCacheBlobPathValidation rejects malformed digests (no path traversal).
func TestCacheBlobPathValidation(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{"", "sha256", ":abc", "sha256:", "sha256:../escape", "sha256:a/b"}
	for _, d := range bad {
		if _, err := c.blobPath(d); err == nil {
			t.Errorf("blobPath(%q) should error", d)
		}
	}
	if _, err := c.blobPath("sha256:deadbeef"); err != nil {
		t.Errorf("blobPath(valid) errored: %v", err)
	}
}
