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

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// loadRef is the reference every ingest in this file records under.
const loadRef = "example.com/app:v1"

// sendArchive ingests archive into rt's store through the daemon's own
// image.Loader, in process, and reports the result in LoadImage's wire shape.
//
// LoadImage is no longer served (the node store is a pull cache), but the
// loader still writes the store exactly as an ingest always did, so it remains
// the honest way to seed fixtures: an entry a test hand-wrote would prove the
// verbs agree with the test, not with the store's own commit ordering.
func sendArchive(t *testing.T, rt *Runtime, first *runtimev1.LoadImageRequest, archive []byte) (*runtimev1.LoadImageResponse, error) {
	t.Helper()
	loader, err := image.NewLoader(rt.cache, rt.index)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	res, err := loader.Load(context.Background(), image.LoadRequest{
		Reference: first.GetReference(),
		Format:    first.GetFormat(),
		Digest:    first.GetDigest(),
		Size:      first.GetSize(),
	}, bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	return &runtimev1.LoadImageResponse{
		Images:        []*runtimev1.Image{{ManifestDescriptor: res.Descriptor, Manifest: res.Manifest}},
		ReceivedBytes: res.ReceivedBytes,
	}, nil
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
	return ociTarballConfig(t, ggcrv1.ConfigFile{
		OS: "darwin", Architecture: "arm64", RootFS: ggcrv1.RootFS{Type: "layers"},
	}, layer, poison)
}

// ociTarballConfig is ociTarball over a caller-supplied image config, for the
// tests that read the config back out of the store (InspectImage's decoded
// half). The config is otherwise identical fixture machinery.
func ociTarballConfig(t *testing.T, config ggcrv1.ConfigFile, layer, poison []byte) (archive []byte, manifestDigest, configDigest, layerDigest string) {
	t.Helper()
	cfg, err := json.Marshal(config)
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
	entry, ok, err := idx.Lookup(context.Background(), ref, nativeLoadPolicy())
	if err != nil {
		t.Fatalf("index lookup: %v", err)
	}
	if !ok {
		t.Fatalf("the ingested reference %q was not recorded in the on-disk index", ref)
	}
	if entry.Manifest.GetReference() != ref {
		t.Errorf("recorded manifest names %q, want %q", entry.Manifest.GetReference(), ref)
	}
	// The ingest must also retain the manifest's own bytes and digest: they are
	// the only copy this store keeps, and an export reads them back verbatim.
	if entry.Descriptor.GetDigest() == "" || len(entry.ManifestRaw) == 0 {
		t.Errorf("the ingest recorded no manifest descriptor/bytes for %q (descriptor %v, %d raw bytes)",
			ref, entry.Descriptor, len(entry.ManifestRaw))
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
