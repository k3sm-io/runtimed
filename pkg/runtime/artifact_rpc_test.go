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

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
)

const artifactTestHost = "registry-k3sm:6450"

// TestImagePathStillRefusesArtifact pins that the artifact path is a
// second entry point, never a relaxation of the image path: a ModelPack
// artifact pushed to a registry and pulled as an IMAGE, through the daemon's
// own RemoteFetch, still fails with image.ErrNoPlatformMatch.
func TestImagePathStillRefusesArtifact(t *testing.T) {
	host := testRegistryHost(t)
	layer := static.NewLayer([]byte("weights"), types.MediaType(artifactv1.MediaTypeModelWeight))
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		Annotations: map[string]string{artifactv1.AnnotationFilepath: "model.safetensors"},
	})
	if err != nil {
		t.Fatal(err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(artifactv1.MediaTypeModelConfig))
	ref, err := name.ParseReference(host + "/models/tiny:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push artifact: %v", err)
	}
	cache, err := image.NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := image.NewPuller(cache, image.RemoteFetch, image.NoLocalIndex{})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []runtimev1.SandboxBackend{
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
	} {
		_, err := p.Pull(context.Background(), ref.String(), nil, image.PlatformPolicy{Backend: backend}, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if !errors.Is(err, image.ErrNoPlatformMatch) {
			t.Errorf("%v: artifact down the image path: err = %v, want ErrNoPlatformMatch", backend, err)
		}
	}
}

// fakeArtifactFetcher is a network-free artifact.Fetcher over in-memory blobs
// that honours a Range offset.
type fakeArtifactFetcher struct {
	manifest []byte
	blobs    map[string][]byte
}

func (f *fakeArtifactFetcher) Manifest(context.Context, string, *image.RegistryCredential) ([]byte, string, error) {
	return f.manifest, "application/vnd.oci.image.manifest.v1+json", nil
}

func (f *fakeArtifactFetcher) Blob(_ context.Context, _ string, _ *image.RegistryCredential, digest string, offset int64) (io.ReadCloser, int64, error) {
	b, ok := f.blobs[digest]
	if !ok || offset > int64(len(b)) {
		return nil, 0, errors.New("blob unknown")
	}
	return io.NopCloser(bytes.NewReader(b[offset:])), offset, nil
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// artifactRPCClient serves Images over a runtime whose ArtifactPuller is the
// real artifact.Puller over the runtime's own cache and index, fed by fetch.
func artifactRPCClient(t *testing.T, fetch artifact.Fetcher) (runtimev1.ImagesClient, *Runtime) {
	t.Helper()
	lazy := &lazyArtifactPuller{}
	client, rt := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}, ArtifactPuller: lazy})
	p, err := artifact.New(artifact.Config{
		RegistryHost: artifactTestHost,
		PartialDir:   filepath.Join(rt.cache.Root(), artifactPartialDir),
		StorePath:    rt.cache.Root(),
		FreeBytes:    func(string) (uint64, error) { return 1 << 40, nil },
	}, artifact.Deps{Blobs: rt.cache, Leases: rt.cache, Reclaimer: rt.cache, Index: rt.index, Fetcher: fetch})
	if err != nil {
		t.Fatal(err)
	}
	lazy.p = p
	return client, rt
}

// lazyArtifactPuller lets the test build the real puller over the runtime's
// own cache, which exists only once the runtime does.
type lazyArtifactPuller struct{ p *artifact.Puller }

func (l *lazyArtifactPuller) PullArtifact(ctx context.Context, ref string, cred *image.RegistryCredential, policy runtimev1.ArtifactPolicy, paths []string) (*artifact.Result, error) {
	return l.p.PullArtifact(ctx, ref, cred, policy, paths)
}

func modelArtifact(layers map[string][]byte, order []string) *fakeArtifactFetcher {
	cfg := []byte(`{}`)
	f := &fakeArtifactFetcher{blobs: map[string][]byte{sha(cfg): cfg}}
	var ls []map[string]any
	for _, p := range order {
		b := layers[p]
		f.blobs[sha(b)] = b
		ls = append(ls, map[string]any{
			"mediaType": artifactv1.MediaTypeModelWeight, "digest": sha(b), "size": len(b),
			"annotations": map[string]string{artifactv1.AnnotationFilepath: p},
		})
	}
	f.manifest, _ = json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"artifactType": artifactv1.ArtifactTypeModel,
		"config":       map[string]any{"mediaType": artifactv1.MediaTypeModelConfig, "digest": sha(cfg), "size": len(cfg)},
		"layers":       ls,
	})
	return f
}

func TestPullArtifactRPCServesThroughThePuller(t *testing.T) {
	f := modelArtifact(map[string][]byte{"a.json": []byte("a"), "w.safetensors": []byte("w")}, []string{"a.json", "w.safetensors"})
	client, rt := artifactRPCClient(t, f)
	resp, err := client.PullArtifact(context.Background(), &runtimev1.PullArtifactRequest{
		Reference:      artifactTestHost + "/models/tiny:v1",
		ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME,
	})
	if err != nil {
		t.Fatalf("PullArtifact: %v", err)
	}
	if resp.GetManifestDigest() != sha(f.manifest) {
		t.Errorf("manifest digest = %s, want %s", resp.GetManifestDigest(), sha(f.manifest))
	}
	want := []string{sha([]byte("a")), sha([]byte("w"))}
	if !slices.Equal(resp.GetLayerDigests(), want) {
		t.Errorf("layer digests = %v, want %v", resp.GetLayerDigests(), want)
	}
	for _, d := range want {
		if !rt.cache.Has(d) {
			t.Errorf("%s not in the node cache", d)
		}
	}
}

// TestPullArtifactRPCRefusesSwappedByte is the RPC face of
// artifact.TestPullArtifactVerifiesEveryLayer: one swapped byte in one layer is
// DATA_LOSS, and the layer is not in the cache.
func TestPullArtifactRPCRefusesSwappedByte(t *testing.T) {
	f := modelArtifact(map[string][]byte{"a.json": []byte("aaaa"), "b.json": []byte("bbbb")}, []string{"a.json", "b.json"})
	f.blobs[sha([]byte("bbbb"))] = []byte("bbbc")
	client, rt := artifactRPCClient(t, f)
	_, err := client.PullArtifact(context.Background(), &runtimev1.PullArtifactRequest{
		Reference:      artifactTestHost + "/models/tiny:v1",
		ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME,
	})
	if status.Code(err) != codes.DataLoss {
		t.Fatalf("err = %v, want DATA_LOSS", err)
	}
	if rt.cache.Has(sha([]byte("bbbb"))) {
		t.Error("the swapped layer was committed")
	}
}

func TestPullArtifactRPCRefusals(t *testing.T) {
	f := modelArtifact(map[string][]byte{"a.json": []byte("a")}, []string{"a.json"})
	client, _ := artifactRPCClient(t, f)
	for _, tc := range []struct {
		name string
		req  *runtimev1.PullArtifactRequest
		want codes.Code
	}{
		{"unspecified policy", &runtimev1.PullArtifactRequest{Reference: artifactTestHost + "/models/m:v1"}, codes.InvalidArgument},
		{"foreign host", &runtimev1.PullArtifactRequest{Reference: "ghcr.io/models/m:v1",
			ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME}, codes.PermissionDenied},
		{"invalid requested path", &runtimev1.PullArtifactRequest{Reference: artifactTestHost + "/models/m:v1",
			ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME, Paths: []string{"/abs"}}, codes.InvalidArgument},
		{"path not in artifact", &runtimev1.PullArtifactRequest{Reference: artifactTestHost + "/models/m:v1",
			ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME, Paths: []string{"b.json"}}, codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.PullArtifact(context.Background(), tc.req)
			if got := status.Code(err); got != tc.want {
				t.Errorf("code = %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

// TestPullArtifactRefusedWithoutClusterRegistry pins the standalone posture: a
// daemon with no FlatRegistry has no host it may fetch artifacts from.
func TestPullArtifactRefusedWithoutClusterRegistry(t *testing.T) {
	client, _ := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}})
	_, err := client.PullArtifact(context.Background(), &runtimev1.PullArtifactRequest{
		Reference:      artifactTestHost + "/models/m:v1",
		ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FAILED_PRECONDITION", err)
	}
}
