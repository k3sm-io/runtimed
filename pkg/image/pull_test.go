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
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeFetch returns a fixed in-memory image, counting calls so the test can
// assert the cache hit path does (or does not) re-fetch. It also records the last
// credential it received (M2.6) and the last platform policy (B99) so a test can
// assert both reach the pull client.
type fakeFetch struct {
	img        ggcrv1.Image
	calls      int
	lastCred   *RegistryCredential
	lastPolicy PlatformPolicy
}

func (f *fakeFetch) fetch(_ context.Context, _ string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
	f.calls++
	f.lastCred = cred
	f.lastPolicy = policy
	return f.img, nil
}

// nativePolicy is the darwin/arm64-only policy the pkg/image tests pull under.
func nativePolicy() PlatformPolicy {
	return PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
}

// TestPullCachesAndHits is the unit form of acceptance M1.1-a1: the first pull
// populates the content-addressed cache; a second pull of the same content is a
// cache hit (no blob re-written) and the manifest round-trips into the apis type.
func TestPullCachesAndHits(t *testing.T) {
	img, err := random.Image(1024, 3) // 3 layers
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	// Pull verifies the fetched image's own config against the policy at the
	// choke point (B99), so the fixture declares the native platform — a plain
	// random.Image declares none and is refused.
	ff := &fakeFetch{img: withPlatform(t, img, "darwin", "arm64", "")}

	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := mustPuller(t, cache, ff.fetch)

	res1, err := p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy())
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

	res2, err := p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy())
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

// TestPullPassesCredentialToFetch is the image-level half of M2.6-a1: the
// imagePullSecret credential is handed to the pull client (the FetchFunc) and is
// not dropped on the floor. The on-disk confinement (credential never in the pod
// dir) is asserted at the runtime level.
func TestPullPassesCredentialToFetch(t *testing.T) {
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	ff := &fakeFetch{img: withPlatform(t, img, "darwin", "arm64", "")}
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := mustPuller(t, cache, ff.fetch)

	cred := &RegistryCredential{Username: "robot", Password: "s3cret"}
	if _, err := p.Pull(context.Background(), "example.com/private/app:v1", cred, nativePolicy()); err != nil {
		t.Fatalf("pull with cred: %v", err)
	}
	if ff.lastCred == nil {
		t.Fatal("credential was not passed to the fetch client")
	}
	if ff.lastCred.Username != "robot" || ff.lastCred.Password != "s3cret" {
		t.Errorf("fetch received cred %+v, want robot/s3cret", ff.lastCred)
	}
	// B99: the per-call platform policy rides the same seam and is not dropped.
	if ff.lastPolicy != nativePolicy() {
		t.Errorf("fetch received policy %+v, want %+v", ff.lastPolicy, nativePolicy())
	}
}

// TestCacheBlobPathValidation rejects malformed digests (no path traversal).
//
// It attacks the HEX half only; the algorithm half — the one that was actually
// traversable before B129 — is attacked by the gate
// (TestWriteBlobRejectsDigestMismatch/rejects_unsupported_or_malformed_digest).
func TestCacheBlobPathValidation(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"", "sha256", ":abc", "sha256:", "sha256:../escape", "sha256:a/b",
		// B129: the hex body must be the algorithm's exact length. A short body
		// was accepted before, and no real blob can ever hash to one.
		"sha256:deadbeef",
	}
	for _, d := range bad {
		if _, err := c.BlobPath(d); err == nil {
			t.Errorf("blobPath(%q) should error", d)
		}
	}
	if _, err := c.BlobPath(digestOf([]byte("anything"))); err != nil {
		t.Errorf("blobPath(valid) errored: %v", err)
	}
}
