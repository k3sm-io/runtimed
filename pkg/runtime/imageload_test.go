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
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// loadRef is the reference every ingest in this file records under.
const loadRef = "example.com/app:v1"

// sendArchive streams archive over LoadImage in small chunks and returns the
// terminal response.
//
// The chunking is deliberately smaller than any fixture: the wire contract says
// chunk boundaries carry no meaning, and a server that only worked when an
// archive arrived in one frame would satisfy every single-frame test and fail
// against a real multi-megabyte upload.
func sendArchive(t *testing.T, client runtimev1.ImagesClient, first *runtimev1.LoadImageRequest, archive []byte) (*runtimev1.LoadImageResponse, error) {
	t.Helper()
	stream, err := client.LoadImage(context.Background())
	if err != nil {
		t.Fatalf("open LoadImage stream: %v", err)
	}
	if err := stream.Send(first); err != nil {
		t.Fatalf("send metadata frame: %v", err)
	}
	const chunk = 64
	for off := 0; off < len(archive); off += chunk {
		end := min(off+chunk, len(archive))
		if err := stream.Send(&runtimev1.LoadImageRequest{Chunk: archive[off:end]}); err != nil {
			// A server-side refusal closes the stream, so a Send can fail with
			// io.EOF; the real status comes from CloseAndRecv below.
			break
		}
	}
	return stream.CloseAndRecv()
}

// ociTarball builds a tarred OCI image layout for one config + one layer.
//
// poison, when non-nil, is stored at the LAYER's claimed blob path in place of
// its real bytes — the manifest's claim about that layer is left untouched. That
// disagreement is only expressible in a layout (on the docker-save path the
// digest is synthesized from the bytes), which is why the mismatch row below
// uses this fixture and not a docker save.
func ociTarball(t *testing.T, layer, poison []byte) (archive []byte, manifestDigest, configDigest, layerDigest string) {
	t.Helper()
	cfg, err := json.Marshal(ggcrv1.ConfigFile{
		OS: "darwin", Architecture: "arm64", RootFS: ggcrv1.RootFS{Type: "layers"},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	sha := func(b []byte) ggcrv1.Hash {
		t.Helper()
		sum := sha256.Sum256(b)
		h, herr := ggcrv1.NewHash("sha256:" + hex.EncodeToString(sum[:]))
		if herr != nil {
			t.Fatalf("parse hash: %v", herr)
		}
		return h
	}
	mfst := ggcrv1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config:        ggcrv1.Descriptor{MediaType: types.OCIConfigJSON, Digest: sha(cfg), Size: int64(len(cfg))},
		Layers:        []ggcrv1.Descriptor{{MediaType: types.OCILayer, Digest: sha(layer), Size: int64(len(layer))}},
	}
	rawMfst, err := json.Marshal(mfst)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	rawIdx, err := json.Marshal(ggcrv1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []ggcrv1.Descriptor{{
			MediaType: types.OCIManifestSchema1, Digest: sha(rawMfst), Size: int64(len(rawMfst)),
		}},
	})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, body []byte) {
		t.Helper()
		if werr := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)),
		}); werr != nil {
			t.Fatalf("tar header %s: %v", name, werr)
		}
		if _, werr := tw.Write(body); werr != nil {
			t.Fatalf("tar body %s: %v", name, werr)
		}
	}
	blob := func(h ggcrv1.Hash) string { return "blobs/" + h.Algorithm + "/" + h.Hex }
	stored := layer
	if poison != nil {
		stored = poison
	}
	write("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	write("index.json", rawIdx)
	write(blob(sha(rawMfst)), rawMfst)
	write(blob(mfst.Config.Digest), cfg)
	write(blob(mfst.Layers[0].Digest), stored)
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes(), sha(rawMfst).String(), mfst.Config.Digest.String(), mfst.Layers[0].Digest.String()
}

// dockerSaveTarball renders a small native-platform image as a `docker save` tar
// under the given tags.
func dockerSaveTarball(t *testing.T, tags ...string) (archive []byte, img ggcrv1.Image) {
	t.Helper()
	base, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cf, err := base.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "darwin", "arm64"
	img, err = mutate.ConfigFile(base, cf)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	refs := make(map[name.Reference]ggcrv1.Image, len(tags))
	for _, tg := range tags {
		ref, rerr := name.NewTag(tg)
		if rerr != nil {
			t.Fatalf("parse tag %q: %v", tg, rerr)
		}
		refs[ref] = img
	}
	var buf bytes.Buffer
	if err := tarball.MultiRefWrite(refs, &buf); err != nil {
		t.Fatalf("tarball.MultiRefWrite: %v", err)
	}
	return buf.Bytes(), img
}

// storedBlobs is every content blob currently in the daemon's store.
func storedBlobs(t *testing.T, rt *Runtime) []image.BlobNode {
	t.Helper()
	nodes, err := rt.cache.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	return nodes
}

// TestLoadImageIngestsOverTheWire is the daemon-side half of the ingest surface:
// the archive arrives as a client stream, the store ends up holding exactly the
// blobs the archive's manifest named, digest-addressed, and the reference is
// recorded in the same on-disk index the pull path answers presence from.
func TestLoadImageIngestsOverTheWire(t *testing.T) {
	t.Run("a docker-save archive lands blobs and the reference", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		archive, img := dockerSaveTarball(t, loadRef)

		resp, err := sendArchive(t, client, &runtimev1.LoadImageRequest{
			Reference: loadRef,
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
		}, archive)
		if err != nil {
			t.Fatalf("LoadImage: %v", err)
		}
		if resp.GetReceivedBytes() != int64(len(archive)) {
			t.Errorf("server counted %d bytes, want %d", resp.GetReceivedBytes(), len(archive))
		}
		if len(resp.GetImages()) != 1 {
			t.Fatalf("response carried %d images, want 1", len(resp.GetImages()))
		}
		want, err := img.Digest()
		if err != nil {
			t.Fatal(err)
		}
		got := resp.GetImages()[0]
		if got.GetManifestDescriptor().GetDigest() != want.String() {
			t.Errorf("reported image digest %q, want %q", got.GetManifestDescriptor().GetDigest(), want.String())
		}
		mfst, err := img.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range append([]string{mfst.Config.Digest.String()}, layerDigests(mfst)...) {
			if !rt.cache.Has(d) {
				t.Errorf("blob %s is not in the store", d)
			}
		}
		// Every stored blob sits at its own digest's path: the store is
		// content-addressed, so a blob under any other name would be one the
		// ingest named rather than hashed.
		for _, n := range storedBlobs(t, rt) {
			if n.Kind != image.BlobKindContent {
				t.Errorf("ingest left a non-content node %q in the blob store", n.Path)
				continue
			}
			if !rt.cache.Has(n.Digest) {
				t.Errorf("blob node %q is not addressable by its digest %q", n.Path, n.Digest)
			}
		}
		// The reference is recorded in the index the PULL path reads, so a warm
		// IfNotPresent resolves a loaded image without a registry.
		assertRecorded(t, rt, loadRef)
	})

	t.Run("an OCI-layout archive lands blobs and the reference", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		archive, mfstDigest, cfgDigest, layerDigest := ociTarball(t, []byte("oci-layer-bytes"), nil)

		resp, err := sendArchive(t, client, &runtimev1.LoadImageRequest{
			Reference: loadRef,
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, archive)
		if err != nil {
			t.Fatalf("LoadImage: %v", err)
		}
		got := resp.GetImages()[0]
		if got.GetManifestDescriptor().GetDigest() != mfstDigest {
			t.Errorf("reported image digest %q, want %q", got.GetManifestDescriptor().GetDigest(), mfstDigest)
		}
		if got.GetManifest().GetConfig().GetDigest() != cfgDigest {
			t.Errorf("reported config digest %q, want %q", got.GetManifest().GetConfig().GetDigest(), cfgDigest)
		}
		for _, d := range []string{cfgDigest, layerDigest} {
			if !rt.cache.Has(d) {
				t.Errorf("blob %s is not in the store", d)
			}
		}
		assertRecorded(t, rt, loadRef)
	})

	t.Run("a digest-mismatched blob is refused and the store is untouched", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		// Same length as the claimed bytes, so the verdict is the DIGEST
		// comparison and not the declared-size guard.
		archive, _, cfgDigest, layerDigest := ociTarball(t, []byte("honest-layer-bytes"), []byte("POISON-layer-bytes"))

		_, err := sendArchive(t, client, &runtimev1.LoadImageRequest{
			Reference: loadRef,
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, archive)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("LoadImage error = %v (code %v); want InvalidArgument", err, status.Code(err))
		}
		// Not admitted, not admitted-then-flagged: the store is exactly as empty
		// as it was, including the config that precedes the bad layer.
		if nodes := storedBlobs(t, rt); len(nodes) != 0 {
			t.Errorf("a refused ingest left %d node(s) in the store: %+v", len(nodes), nodes)
		}
		for _, d := range []string{cfgDigest, layerDigest} {
			if rt.cache.Has(d) {
				t.Errorf("blob %s was admitted by a load that failed", d)
			}
		}
		assertNotRecorded(t, rt, loadRef)
	})

	t.Run("a multi-tag docker-save archive is refused", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		archive, _ := dockerSaveTarball(t, loadRef, "example.com/app:latest")

		_, err := sendArchive(t, client, &runtimev1.LoadImageRequest{
			Reference: loadRef,
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
		}, archive)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("LoadImage error = %v (code %v); want InvalidArgument — v1 refuses rather than dropping a tag",
				err, status.Code(err))
		}
		if nodes := storedBlobs(t, rt); len(nodes) != 0 {
			t.Errorf("a refused ingest left %d node(s) in the store", len(nodes))
		}
		assertNotRecorded(t, rt, loadRef)
	})

	t.Run("a stream with no frames is refused", func(t *testing.T) {
		client, _ := imagesTestClient(t)
		stream, err := client.LoadImage(context.Background())
		if err != nil {
			t.Fatalf("open LoadImage stream: %v", err)
		}
		if _, err := stream.CloseAndRecv(); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("empty-stream error = %v (code %v); want InvalidArgument", err, status.Code(err))
		}
	})
}

// layerDigests is the digest of every layer a go-containerregistry manifest names.
func layerDigests(mfst *ggcrv1.Manifest) []string {
	out := make([]string, 0, len(mfst.Layers))
	for _, l := range mfst.Layers {
		out = append(out, l.Digest.String())
	}
	return out
}

// nativeLoadPolicy is the platform policy a native pod would resolve a loaded
// reference under — the fixtures declare darwin/arm64 in their config.
func nativeLoadPolicy() image.PlatformPolicy {
	return image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
}

// assertRecorded requires ref to be resolvable from the daemon's real on-disk
// index — not from a test double — so the ingest and the pull path are proven to
// share one record.
func assertRecorded(t *testing.T, rt *Runtime, ref string) {
	t.Helper()
	idx, err := image.NewFileIndex(rt.cache)
	if err != nil {
		t.Fatalf("open image index: %v", err)
	}
	mfst, ok, err := idx.Lookup(context.Background(), ref, nativeLoadPolicy())
	if err != nil {
		t.Fatalf("index lookup: %v", err)
	}
	if !ok {
		t.Fatalf("the ingested reference %q was not recorded in the on-disk index", ref)
	}
	if mfst.GetReference() != ref {
		t.Errorf("recorded manifest names %q, want %q", mfst.GetReference(), ref)
	}
}

// assertNotRecorded requires ref to be absent from the on-disk index.
func assertNotRecorded(t *testing.T, rt *Runtime, ref string) {
	t.Helper()
	idx, err := image.NewFileIndex(rt.cache)
	if err != nil {
		t.Fatalf("open image index: %v", err)
	}
	if _, ok, err := idx.Lookup(context.Background(), ref, nativeLoadPolicy()); err != nil {
		t.Fatalf("index lookup: %v", err)
	} else if ok {
		t.Errorf("a refused ingest recorded the reference %q", ref)
	}
}
