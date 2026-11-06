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
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func (l *lazyArtifactPuller) CheckHost(ref string) error { return l.p.CheckHost(ref) }

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

// scriptedArtifactPuller is a fake ArtifactPuller: it can block every pull on
// gate, records the peak number of pulls in flight, and fails with err.
type scriptedArtifactPuller struct {
	gate           chan struct{}
	err            error
	active, peak   atomic.Int32
	entered        chan struct{}
	hostCheckCalls atomic.Int32
}

func (s *scriptedArtifactPuller) CheckHost(ref string) error {
	s.hostCheckCalls.Add(1)
	if !strings.HasPrefix(ref, artifactTestHost+"/") {
		return artifact.ErrNotClusterRegistry
	}
	return nil
}

func (s *scriptedArtifactPuller) PullArtifact(ctx context.Context, ref string, _ *image.RegistryCredential, _ runtimev1.ArtifactPolicy, _ []string) (*artifact.Result, error) {
	if err := s.CheckHost(ref); err != nil {
		return nil, err
	}
	n := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		m := s.peak.Load()
		if n <= m || s.peak.CompareAndSwap(m, n) {
			break
		}
	}
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return &artifact.Result{ManifestDigest: sha([]byte("m"))}, nil
}

func volumeReq(ref string) *runtimev1.PullArtifactRequest {
	return &runtimev1.PullArtifactRequest{Reference: ref, ArtifactPolicy: runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME}
}

// TestPullArtifactRPCChecksHostBeforeCredentials: a foreign host is refused
// before the daemon resolves any imagePullSecret, so naming another registry
// can never make it read a Secret.
func TestPullArtifactRPCChecksHostBeforeCredentials(t *testing.T) {
	creds := &fakeCredentialResolver{cred: &image.RegistryCredential{Username: "u", Password: "p"}}
	client, _ := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}, ArtifactPuller: &scriptedArtifactPuller{}, Credentials: creds})
	req := volumeReq("ghcr.io/models/m:v1")
	req.Namespace = "team"
	req.ImagePullSecrets = []*runtimev1.LocalObjectReference{{Name: "regcred"}}
	_, err := client.PullArtifact(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PERMISSION_DENIED", err)
	}
	if creds.gotNS != "" || creds.gotSecrets != nil {
		t.Errorf("a credential was resolved (%q, %v) for a foreign host", creds.gotNS, creds.gotSecrets)
	}
}

// TestPullArtifactRPCBoundsConcurrency: at most maxConcurrentArtifactPulls
// PullArtifact calls run at once; the rest wait.
func TestPullArtifactRPCBoundsConcurrency(t *testing.T) {
	const callers = 8
	ap := &scriptedArtifactPuller{gate: make(chan struct{}), entered: make(chan struct{}, callers)}
	client, _ := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}, ArtifactPuller: ap})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.PullArtifact(context.Background(), volumeReq(artifactTestHost+"/models/m:v1"))
		}()
	}
	// Wait for the admitted pulls, then give the rest time to (wrongly) enter.
	for range maxConcurrentArtifactPulls {
		<-ap.entered
	}
	time.Sleep(100 * time.Millisecond)
	if got := ap.peak.Load(); got != maxConcurrentArtifactPulls {
		t.Errorf("peak concurrent pulls = %d, want %d", got, maxConcurrentArtifactPulls)
	}
	close(ap.gate)
	wg.Wait()
}

// TestPullArtifactRPCBoundsErrorText: a failure carrying a huge foreign
// message reaches the caller bounded.
func TestPullArtifactRPCBoundsErrorText(t *testing.T) {
	ap := &scriptedArtifactPuller{err: fmt.Errorf("%w: %s", artifact.ErrBlobTransfer, strings.Repeat("B", 100<<10))}
	client, _ := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}, ArtifactPuller: ap})
	_, err := client.PullArtifact(context.Background(), volumeReq(artifactTestHost+"/models/m:v1"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err code = %v, want UNAVAILABLE", status.Code(err))
	}
	if n := len(status.Convert(err).Message()); n > 2048 {
		t.Errorf("status message of %d bytes; it must be bounded", n)
	}
}

// TestPullArtifactRPCSizeRefusalsAreTerminal pins that a manifest declaring a hostile size is
// refused as FailedPrecondition, a terminal verdict on untrusted input, not Internal.
func TestPullArtifactRPCSizeRefusalsAreTerminal(t *testing.T) {
	for _, sentinel := range []error{artifact.ErrSizeCap, artifact.ErrSizeOverflow} {
		t.Run(sentinel.Error(), func(t *testing.T) {
			err := artifactStatusError(fmt.Errorf("layer 0: %w", sentinel))
			if got := status.Code(err); got != codes.FailedPrecondition {
				t.Fatalf("code = %v, want FailedPrecondition", got)
			}
		})
	}
}
