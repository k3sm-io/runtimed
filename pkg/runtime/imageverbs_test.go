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
	"errors"
	"io"
	"os"
	"testing"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// verbRef is the reference the rows below load, tag and export.
const verbRef = "example.com/verbs:v1"

// hexOf is a syntactically valid sha256 body for name. It addresses no real
// blob: the rows using it are about a digest the store must NOT resolve, or
// about a fake puller's reported values, never about content.
func hexOf(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// loadFixture ingests a small OCI-layout image over the wire and returns the
// archive's digests. Going through LoadImage rather than writing the index
// directly is what makes these rows about the SHIPPED store: an entry a test
// hand-wrote would prove the verbs agree with the test, not with the ingest.
func loadFixture(t *testing.T, rt *Runtime, ref string) (manifestDigest, configDigest, layerDigest string) {
	t.Helper()
	archive, manifestDigest, configDigest, layerDigest := ociTarball(t, []byte("verb-layer"), nil)
	resp, err := sendArchive(t, rt, &runtimev1.LoadImageRequest{
		Reference: ref,
		Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
	}, archive)
	if err != nil {
		t.Fatalf("LoadImage(%q): %v", ref, err)
	}
	if got := resp.GetImages()[0].GetManifestDescriptor().GetDigest(); got != manifestDigest {
		t.Fatalf("LoadImage reported manifest digest %s, want %s", got, manifestDigest)
	}
	return manifestDigest, configDigest, layerDigest
}

// wantCode fails unless err carries the expected gRPC code.
func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: error = %v (code %s), want %s", what, err, status.Code(err), want)
	}
}

// ageBlobs back-dates every blob in the store past the reclaim grace window, so
// a prune's verdict reflects REACHABILITY and not the young-blob rule.
func ageBlobs(t *testing.T, rt *Runtime) {
	t.Helper()
	nodes, err := rt.cache.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	old := time.Now().Add(-24 * time.Hour)
	for _, n := range nodes {
		// BlobNode.Path is store-relative; BlobPath is the sanctioned way to a
		// blob's real location (and validates the digest on the way).
		p, err := rt.cache.BlobPath(n.Digest)
		if err != nil {
			t.Fatalf("BlobPath(%s): %v", n.Digest, err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatalf("Chtimes %s: %v", p, err)
		}
	}
}

// TestPullImageDrivesTheDaemonsOwnPuller is the wire half of the CLI pull: the
// RPC must reach the SAME puller a pod-driven pull uses, and it must leave no
// operator root behind: the store is a pull cache that names nothing.
//
// The puller is faked at the runtime's own seam, so no registry is contacted;
// what the row proves is the WIRING and the provenance, which is exactly the
// half a live pull could not isolate.
func TestPullImageDrivesTheDaemonsOwnPuller(t *testing.T) {
	newPull := func(t *testing.T) (runtimev1.ImagesClient, *Runtime, *fakePuller) {
		t.Helper()
		fp := &fakePuller{
			manifest: &runtimev1.ImageManifest{
				Reference: verbRef,
				Config:    &runtimev1.Descriptor{Digest: "sha256:" + hexOf("pull-config"), Size: 12},
				Layers:    []*runtimev1.Descriptor{{Digest: "sha256:" + hexOf("pull-layer"), Size: 34}},
			},
			descriptor: &runtimev1.Descriptor{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    "sha256:" + hexOf("pull-manifest"),
				Size:      56,
			},
		}
		client, rt := imagesTestClientDeps(t, Deps{Puller: fp})
		return client, rt, fp
	}

	t.Run("a pull reports the resolved digest and records no operator root", func(t *testing.T) {
		client, rt, fp := newPull(t)
		resp, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("PullImage: %v", err)
		}
		if got := resp.GetImage().GetManifestDescriptor().GetDigest(); got != fp.descriptor.GetDigest() {
			t.Errorf("resolved digest = %s, want %s", got, fp.descriptor.GetDigest())
		}
		if got := resp.GetImage().GetManifest().GetReference(); got != verbRef {
			t.Errorf("resolved reference = %q, want %q", got, verbRef)
		}
		if !resp.GetAlreadyPresent() {
			t.Error("already_present = false; the fake puller reported a full cache hit")
		}
		// The provenance claim: a pull is a cache warm, so it names nothing and
		// a pulled-but-unused image is reclaimable by the next prune.
		roots, err := rt.cache.OperatorImageRoots()
		if err != nil {
			t.Fatalf("OperatorImageRoots: %v", err)
		}
		if len(roots) != 0 {
			t.Fatalf("OperatorImageRoots = %v after a pull, want none", roots)
		}
	})

	t.Run("the pull policy is forwarded verbatim", func(t *testing.T) {
		client, _, fp := newPull(t)
		if _, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{
			Reference: verbRef,
			Policy:    runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
		}); err != nil {
			t.Fatalf("PullImage: %v", err)
		}
		if fp.lastPullPolicy != runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER {
			t.Errorf("puller saw policy %v, want NEVER — the RPC must not re-derive one", fp.lastPullPolicy)
		}
	})

	t.Run("the platform selects the spine's policy", func(t *testing.T) {
		cases := []struct {
			name         string
			platform     *runtimev1.Platform
			wantBackend  runtimev1.SandboxBackend
			wantOverride *image.Platform
			wantRosetta  bool
			wantCode     codes.Code
		}{
			{
				name:        "unset is the daemon's own host platform",
				wantBackend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
			},
			{
				name:         "darwin/arm64 pins the native spine",
				platform:     &runtimev1.Platform{Os: "darwin", Architecture: "arm64"},
				wantBackend:  runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
				wantOverride: &image.Platform{OS: "darwin", Architecture: "arm64", Variant: "v8"},
			},
			{
				name:         "linux/arm64 pins the vm spine",
				platform:     &runtimev1.Platform{Os: "linux", Architecture: "arm64"},
				wantBackend:  runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
				wantOverride: &image.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
			},
			{
				name:         "linux/amd64 admits the translated candidate",
				platform:     &runtimev1.Platform{Os: "linux", Architecture: "amd64"},
				wantBackend:  runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
				wantOverride: &image.Platform{OS: "linux", Architecture: "amd64"},
				wantRosetta:  true,
			},
			{
				name:     "an os this node stores no images for is refused",
				platform: &runtimev1.Platform{Os: "windows", Architecture: "amd64"},
				wantCode: codes.InvalidArgument,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				client, _, fp := newPull(t)
				_, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{
					Reference: verbRef,
					Platform:  tc.platform,
				})
				if tc.wantCode != codes.OK {
					wantCode(t, err, tc.wantCode, "PullImage")
					return
				}
				if err != nil {
					t.Fatalf("PullImage: %v", err)
				}
				if fp.lastPolicy.Backend != tc.wantBackend {
					t.Errorf("policy backend = %v, want %v", fp.lastPolicy.Backend, tc.wantBackend)
				}
				switch {
				case tc.wantOverride == nil && fp.lastPolicy.Override != nil:
					t.Errorf("policy override = %v, want none for an unset platform", fp.lastPolicy.Override)
				case tc.wantOverride != nil && fp.lastPolicy.Override == nil:
					t.Errorf("policy override = none, want %v", tc.wantOverride)
				case tc.wantOverride != nil && *fp.lastPolicy.Override != tc.wantOverride.Normalize():
					t.Errorf("policy override = %v, want %v", *fp.lastPolicy.Override, tc.wantOverride.Normalize())
				}
				if got := fp.lastPolicy.GuestRosetta || fp.lastPolicy.HostRosetta; got != tc.wantRosetta {
					t.Errorf("rosetta candidate admitted = %v, want %v", got, tc.wantRosetta)
				}
			})
		}
	})

	t.Run("a pull is anonymous", func(t *testing.T) {
		client, _, fp := newPull(t)
		if _, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{Reference: verbRef}); err != nil {
			t.Fatalf("PullImage: %v", err)
		}
		// PullImageRequest carries no credential field, so there is nothing this
		// RPC could pass; the assertion pins that it does not invent one.
		if fp.lastCred != nil {
			t.Errorf("puller saw credential %+v, want nil — the CLI pull surface carries none", fp.lastCred)
		}
	})

	t.Run("the decided verdicts map to codes an operator can act on", func(t *testing.T) {
		cases := []struct {
			name string
			err  error
			want codes.Code
		}{
			{"absent under a policy that forbids fetching", image.ErrImageNotPresent, codes.NotFound},
			{"refused under disk pressure", image.ErrPullRefusedDiskPressure, codes.ResourceExhausted},
			{"no manifest for the platform", image.ErrNoPlatformMatch, codes.FailedPrecondition},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fp := &fakePuller{err: tc.err}
				client, _ := imagesTestClientDeps(t, Deps{Puller: fp})
				_, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{Reference: verbRef})
				wantCode(t, err, tc.want, "PullImage")
			})
		}
	})

	t.Run("an unusable reference is refused before the puller is reached", func(t *testing.T) {
		client, _, fp := newPull(t)
		_, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{Reference: "NOT A REF"})
		wantCode(t, err, codes.InvalidArgument, "PullImage")
		if fp.lastRef != "" {
			t.Errorf("the puller was reached with %q; an unparseable reference must be refused first", fp.lastRef)
		}
	})
}

// TestInspectImageIsLocalOnly pins the read side: what the store knows, read out
// of the index and the config blob, with no registry, no lease and no root.
func TestInspectImageIsLocalOnly(t *testing.T) {
	richConfig := ggcrv1.ConfigFile{
		OS: "darwin", Architecture: "arm64", RootFS: ggcrv1.RootFS{Type: "layers"},
		Created: ggcrv1.Time{Time: time.Unix(1700000000, 0).UTC()},
		Config: ggcrv1.Config{
			Entrypoint: []string{"/bin/app"},
			Cmd:        []string{"--serve"},
			Env:        []string{"PATH=/bin", "PATH=/sbin"},
			User:       "501:20",
			WorkingDir: "/srv",
			Labels:     map[string]string{"k3sm.io/test": "yes"},
		},
	}

	loadRich := func(t *testing.T) (runtimev1.ImagesClient, *Runtime, string) {
		t.Helper()
		client, rt := imagesTestClient(t)
		archive, manifestDigest, _, _ := ociTarballConfig(t, richConfig, []byte("verb-layer"), nil)
		if _, err := sendArchive(t, rt, &runtimev1.LoadImageRequest{
			Reference: verbRef, Format: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, archive); err != nil {
			t.Fatalf("LoadImage: %v", err)
		}
		return client, rt, manifestDigest
	}

	t.Run("by reference and by digest report the same image", func(t *testing.T) {
		client, _, digest := loadRich(t)
		byRef, err := client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("InspectImage(reference): %v", err)
		}
		byDigest, err := client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{Digest: digest})
		if err != nil {
			t.Fatalf("InspectImage(digest): %v", err)
		}
		if byRef.GetImage().GetManifestDescriptor().GetDigest() != digest {
			t.Errorf("inspect by reference reported %s, want %s", byRef.GetImage().GetManifestDescriptor().GetDigest(), digest)
		}
		if byDigest.GetTotalSizeBytes() != byRef.GetTotalSizeBytes() {
			t.Errorf("total_size_bytes differs by lookup path (%d vs %d)", byDigest.GetTotalSizeBytes(), byRef.GetTotalSizeBytes())
		}
	})

	t.Run("the decoded config carries what a descriptor cannot", func(t *testing.T) {
		client, _, _ := loadRich(t)
		resp, err := client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}
		cfg := resp.GetConfig()
		if cfg == nil {
			t.Fatal("InspectImage reported no config for an image whose config blob is in the store")
		}
		if len(cfg.GetEntrypoint()) != 1 || cfg.GetEntrypoint()[0] != "/bin/app" {
			t.Errorf("entrypoint = %v, want [/bin/app]", cfg.GetEntrypoint())
		}
		if len(cfg.GetEnv()) != 2 || cfg.GetEnv()[0] != "PATH=/bin" {
			t.Errorf("env = %v, want the OCI entries verbatim and in order", cfg.GetEnv())
		}
		if cfg.GetUser() != "501:20" || cfg.GetWorkingDir() != "/srv" {
			t.Errorf("user/working_dir = %q/%q", cfg.GetUser(), cfg.GetWorkingDir())
		}
		if cfg.GetLabels()["k3sm.io/test"] != "yes" {
			t.Errorf("labels = %v", cfg.GetLabels())
		}
		if cfg.GetPlatform().GetOs() != "darwin" || cfg.GetPlatform().GetArchitecture() != "arm64" {
			t.Errorf("config platform = %v, want darwin/arm64", cfg.GetPlatform())
		}
		if got := cfg.GetCreated().AsTime(); !got.Equal(richConfig.Created.Time) {
			t.Errorf("created = %v, want %v", got, richConfig.Created.Time)
		}
	})

	t.Run("total_size_bytes counts the distinct blobs once", func(t *testing.T) {
		client, _, _ := loadRich(t)
		resp, err := client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}
		img := resp.GetImage()
		var want uint64
		want += uint64(img.GetManifestDescriptor().GetSize())
		want += uint64(img.GetManifest().GetConfig().GetSize())
		for _, l := range img.GetManifest().GetLayers() {
			want += uint64(l.GetSize())
		}
		if resp.GetTotalSizeBytes() != want {
			t.Errorf("total_size_bytes = %d, want %d (manifest + config + layers)", resp.GetTotalSizeBytes(), want)
		}
	})

	t.Run("an inspect records nothing", func(t *testing.T) {
		client, rt, _ := loadRich(t)
		before, err := rt.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if _, err := client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{Reference: verbRef}); err != nil {
			t.Fatalf("InspectImage: %v", err)
		}
		after, err := rt.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(after) != len(before) {
			t.Errorf("Roots grew from %d to %d across an inspect; a read-only verb records nothing", len(before), len(after))
		}
	})

	t.Run("the targeting clause admits exactly one selector", func(t *testing.T) {
		client, _, digest := loadRich(t)
		_, err := client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{
			Reference: verbRef, Digest: digest,
		})
		wantCode(t, err, codes.InvalidArgument, "InspectImage with both selectors")
		_, err = client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{})
		wantCode(t, err, codes.InvalidArgument, "InspectImage with neither selector")
		_, err = client.InspectImage(context.Background(), &runtimev1.InspectImageRequest{
			Reference: "example.com/verbs:absent",
		})
		wantCode(t, err, codes.NotFound, "InspectImage of an absent reference")
	})
}

// receiveArchive drains a SaveImage stream, returning the archive bytes and the
// terminal frame. It asserts the framing contract as it goes: chunks first, then
// exactly one terminal frame, and no chunk after it.
func receiveArchive(t *testing.T, client runtimev1.ImagesClient, req *runtimev1.SaveImageRequest) ([]byte, *runtimev1.SaveImageResponse, error) {
	t.Helper()
	stream, err := client.SaveImage(context.Background(), req)
	if err != nil {
		t.Fatalf("open SaveImage stream: %v", err)
	}
	var buf bytes.Buffer
	var terminal *runtimev1.SaveImageResponse
	for {
		frame, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			return buf.Bytes(), terminal, nil
		}
		if rerr != nil {
			return buf.Bytes(), terminal, rerr
		}
		if len(frame.GetChunk()) > 0 {
			if terminal != nil {
				t.Fatal("a chunk frame arrived after the terminal frame")
			}
			buf.Write(frame.GetChunk())
			continue
		}
		if terminal != nil {
			t.Fatal("a second terminal frame arrived")
		}
		terminal = frame
	}
}

// assertNoArchiveBytes requires that a refused export delivered no archive
// content, and that any terminal frame it did deliver carries the error.
//
// A terminal frame is PERMITTED here and is not a defect: the wire contract says
// a failure arrives as a terminal frame with error set and no chunk, precisely
// so a client never has to infer failure from a stream that merely stopped. What
// must never happen is CHUNK bytes for an export that then fails — a caller
// would have written a truncated file.
func assertNoArchiveBytes(t *testing.T, archive []byte, terminal *runtimev1.SaveImageResponse) {
	t.Helper()
	if len(archive) != 0 {
		t.Errorf("a refused export sent %d archive bytes; a refusal must precede the first chunk", len(archive))
	}
	if terminal != nil && terminal.GetError() == nil {
		t.Errorf("a refused export sent a terminal frame with no error: %v", terminal)
	}
}

// TestSaveImageRoundTripsOverTheWire is the export surface's load-bearing claim,
// asserted end to end through the RPCs an operator actually drives: an image
// loaded into this node, exported, and loaded back keeps its manifest DIGEST.
//
// The digest is the assertion, not the re-loadability. The store commits no
// manifest blob, so an exporter that re-encoded the recorded descriptors would
// emit a perfectly valid archive under a DIFFERENT id — a silent rename of the
// image, which nothing downstream could detect.
func TestSaveImageRoundTripsOverTheWire(t *testing.T) {
	t.Run("load -> save -> load preserves the digest", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		digest, cfg, layer := loadFixture(t, rt, verbRef)
		blobsAfterLoad := len(storedBlobs(t, rt))

		archive, terminal, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("SaveImage: %v", err)
		}
		if terminal == nil {
			t.Fatal("the stream ended with no terminal frame; a client must treat that as a truncated archive")
		}
		if terminal.GetDigest() != digest {
			t.Errorf("terminal digest = %s, want %s", terminal.GetDigest(), digest)
		}
		if terminal.GetSentBytes() != int64(len(archive)) {
			t.Errorf("terminal sent_bytes = %d, but %d bytes arrived", terminal.GetSentBytes(), len(archive))
		}

		// Re-load the exported archive under a second name, with the format
		// UNSPECIFIED so the server has to DETECT it — an export the daemon's own
		// detector cannot classify is not an interoperable archive.
		const reRef = "example.com/verbs:reimported"
		resp, err := sendArchive(t, rt, &runtimev1.LoadImageRequest{Reference: reRef}, archive)
		if err != nil {
			t.Fatalf("re-load of the exported archive: %v", err)
		}
		got := resp.GetImages()[0]
		if got.GetManifestDescriptor().GetDigest() != digest {
			t.Errorf("re-loaded manifest digest = %s, want %s", got.GetManifestDescriptor().GetDigest(), digest)
		}
		if got.GetManifest().GetConfig().GetDigest() != cfg {
			t.Errorf("re-loaded config digest = %s, want %s", got.GetManifest().GetConfig().GetDigest(), cfg)
		}
		if len(got.GetManifest().GetLayers()) != 1 || got.GetManifest().GetLayers()[0].GetDigest() != layer {
			t.Errorf("re-loaded layers = %v, want the single layer %s", got.GetManifest().GetLayers(), layer)
		}
		// A round trip of identical content writes no new blob.
		if after := len(storedBlobs(t, rt)); after != blobsAfterLoad {
			t.Errorf("the round trip changed the blob count from %d to %d; identical content is one blob",
				blobsAfterLoad, after)
		}
	})

	t.Run("two exports of one image are byte-identical", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		loadFixture(t, rt, verbRef)
		first, _, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("first SaveImage: %v", err)
		}
		second, _, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("second SaveImage: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Errorf("two exports differ (%d vs %d bytes); the archive must be byte-deterministic", len(first), len(second))
		}
	})

	t.Run("an export by digest is the same archive as by reference", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		digest, _, _ := loadFixture(t, rt, verbRef)
		byRef, _, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{Reference: verbRef})
		if err != nil {
			t.Fatalf("SaveImage(reference): %v", err)
		}
		byDigest, terminal, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{Digest: digest})
		if err != nil {
			t.Fatalf("SaveImage(digest): %v", err)
		}
		if terminal.GetDigest() != digest {
			t.Errorf("terminal digest = %s, want %s", terminal.GetDigest(), digest)
		}
		if !bytes.Equal(byRef, byDigest) {
			t.Error("exporting by digest produced a different archive from exporting by reference")
		}
	})

	t.Run("an export records nothing and unlinks nothing", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		loadFixture(t, rt, verbRef)
		before := len(storedBlobs(t, rt))
		roots, err := rt.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if _, _, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{Reference: verbRef}); err != nil {
			t.Fatalf("SaveImage: %v", err)
		}
		if after := len(storedBlobs(t, rt)); after != before {
			t.Errorf("the store held %d blobs before the export and %d after", before, after)
		}
		afterRoots, err := rt.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(afterRoots) != len(roots) {
			t.Errorf("the export changed the root set from %d to %d entries", len(roots), len(afterRoots))
		}
	})

	t.Run("the refusals are decided before a chunk is sent", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		loadFixture(t, rt, verbRef)

		t.Run("an absent reference", func(t *testing.T) {
			archive, terminal, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{
				Reference: "example.com/verbs:absent",
			})
			wantCode(t, err, codes.NotFound, "SaveImage of an absent reference")
			assertNoArchiveBytes(t, archive, terminal)
		})

		t.Run("both selectors set", func(t *testing.T) {
			_, _, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{
				Reference: verbRef, Digest: "sha256:" + hexOf("x"),
			})
			wantCode(t, err, codes.InvalidArgument, "SaveImage with both selectors")
		})

		t.Run("the docker-save format", func(t *testing.T) {
			_, _, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{
				Reference: verbRef, Format: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
			})
			wantCode(t, err, codes.Unimplemented, "SaveImage in the docker-save format")
		})

		t.Run("an image whose blobs the store no longer holds", func(t *testing.T) {
			_, _, layer := loadFixture(t, rt, "example.com/verbs:pruned")
			p, err := rt.cache.BlobPath(layer)
			if err != nil {
				t.Fatalf("BlobPath: %v", err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatalf("remove layer blob: %v", err)
			}
			archive, terminal, err := receiveArchive(t, client, &runtimev1.SaveImageRequest{
				Reference: "example.com/verbs:pruned",
			})
			wantCode(t, err, codes.FailedPrecondition, "SaveImage of an image with a missing blob")
			assertNoArchiveBytes(t, archive, terminal)
		})
	})
}
