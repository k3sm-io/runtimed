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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// layerFrom renders specs as an uncompressed tar and returns it as a real
// go-containerregistry layer (gzip-compressed, with a correctly derived diffID),
// so the unpacker's compressed-digest AND diffID checks are exercised against
// values it did not compute itself.
func layerFrom(t *testing.T, specs []tarSpec) ggcrv1.Layer {
	t.Helper()
	raw := buildTar(t, specs)
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatalf("layer from specs: %v", err)
	}
	return l
}

// imageFrom builds a multi-layer image whose config declares darwin/arm64.
func imageFrom(t *testing.T, layers ...ggcrv1.Layer) ggcrv1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatalf("append layers: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "darwin", "arm64"
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return img
}

// commitImage puts img's config and layer blobs into c and returns the apis
// manifest naming them — the same shape Puller.Pull hands the runtime, built
// without a registry.
func commitImage(t *testing.T, c *Cache, img ggcrv1.Image) *runtimev1.ImageManifest {
	t.Helper()
	mfst, err := img.Manifest()
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		t.Fatalf("raw config: %v", err)
	}
	if _, err := c.CommitBlob(mfst.Config.Digest.String(), mfst.Config.Size, func(w io.Writer) error {
		_, werr := w.Write(rawCfg)
		return werr
	}); err != nil {
		t.Fatalf("commit config: %v", err)
	}
	out := &runtimev1.ImageManifest{
		Reference: "example.com/test:v1",
		MediaType: string(mfst.MediaType),
		Config:    descriptorFromGGCR(mfst.Config),
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}
	for i, l := range layers {
		desc := mfst.Layers[i]
		if _, err := c.CommitBlob(desc.Digest.String(), desc.Size, func(w io.Writer) error {
			rc, oerr := l.Compressed()
			if oerr != nil {
				return oerr
			}
			defer rc.Close()
			_, cerr := io.Copy(w, rc)
			return cerr
		}); err != nil {
			t.Fatalf("commit layer %d: %v", i, err)
		}
		out.Layers = append(out.Layers, descriptorFromGGCR(desc))
	}
	return out
}

// newTestUnpacker returns a cache + unpacker over a fresh temp root, byte-copying
// so the unit tier never depends on the temp dir being APFS.
func newTestUnpacker(t *testing.T, opts ...UnpackerOption) (*Cache, *Unpacker) {
	t.Helper()
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUnpacker(c, append([]UnpackerOption{WithCloner(ByteCopier{})}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c, u
}

// TestTreeKey pins the tree's identity: it is a function of the CONFIG digest,
// the layer digests IN ORDER, and the policy — and of nothing else. Every one of
// these subtests is a way the key must change (or must not).
func TestTreeKey(t *testing.T) {
	base := &runtimev1.ImageManifest{
		Reference: "example.com/a:v1",
		Config:    &runtimev1.Descriptor{Digest: "sha256:" + hexOf('a')},
		Layers: []*runtimev1.Descriptor{
			{Digest: "sha256:" + hexOf('1')},
			{Digest: "sha256:" + hexOf('2')},
		},
	}
	key, err := TreeKey(base, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("TreeKey: %v", err)
	}
	if _, err := parseBlobDigest(key); err != nil {
		t.Fatalf("TreeKey returned %q, which is not a usable digest: %v", key, err)
	}

	t.Run("deterministic", func(t *testing.T) {
		again, err := TreeKey(base, NativeUnpackPolicy())
		if err != nil || again != key {
			t.Fatalf("TreeKey = %q (err %v), want the stable %q", again, err, key)
		}
	})

	t.Run("reference_is_not_an_input", func(t *testing.T) {
		// The key is content, not a name: the same content pulled under a second
		// reference must be the same tree, or a re-tagged image would rebuild.
		other := &runtimev1.ImageManifest{
			Reference: "other.example.com/b:latest",
			Config:    base.Config,
			Layers:    base.Layers,
		}
		got, err := TreeKey(other, NativeUnpackPolicy())
		if err != nil || got != key {
			t.Fatalf("TreeKey under a second reference = %q (err %v), want %q", got, err, key)
		}
	})

	t.Run("layer_order_is_an_input", func(t *testing.T) {
		swapped := &runtimev1.ImageManifest{
			Config: base.Config,
			Layers: []*runtimev1.Descriptor{base.Layers[1], base.Layers[0]},
		}
		got, err := TreeKey(swapped, NativeUnpackPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if got == key {
			t.Error("reordering the layers did not change the key, but it changes the tree")
		}
	})

	t.Run("config_digest_is_an_input", func(t *testing.T) {
		other := &runtimev1.ImageManifest{
			Config: &runtimev1.Descriptor{Digest: "sha256:" + hexOf('b')},
			Layers: base.Layers,
		}
		got, err := TreeKey(other, NativeUnpackPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if got == key {
			t.Error("changing the config digest did not change the key")
		}
	})

	t.Run("layer_count_is_an_input", func(t *testing.T) {
		got, err := TreeKey(&runtimev1.ImageManifest{Config: base.Config, Layers: base.Layers[:1]}, NativeUnpackPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if got == key {
			t.Error("dropping a layer did not change the key")
		}
	})

	t.Run("refuses_unusable_input", func(t *testing.T) {
		cases := []struct {
			name   string
			mfst   *runtimev1.ImageManifest
			policy UnpackPolicy
		}{
			{"nil_manifest", nil, NativeUnpackPolicy()},
			{"empty_policy", base, UnpackPolicy{}},
			{"unknown_policy", base, UnpackPolicy{Semantics: "linux"}},
			{"no_config", &runtimev1.ImageManifest{Layers: base.Layers}, NativeUnpackPolicy()},
			{"bad_config_algo", &runtimev1.ImageManifest{
				Config: &runtimev1.Descriptor{Digest: "md5:" + hexOf('a')},
			}, NativeUnpackPolicy()},
			{"bad_layer_digest", &runtimev1.ImageManifest{
				Config: base.Config,
				Layers: []*runtimev1.Descriptor{{Digest: "sha256:not-hex"}},
			}, NativeUnpackPolicy()},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got, err := TreeKey(tc.mfst, tc.policy); err == nil {
					t.Fatalf("TreeKey accepted %s and returned %q", tc.name, got)
				}
			})
		}
	})
}

// TestUnpackMultiLayer is the substrate's core behaviour: layers are applied in
// manifest order into one tree, a later layer wins, and the tree lands under the
// content-addressed key with a daemon-authored record beside it.
func TestUnpackMultiLayer(t *testing.T) {
	c, u := newTestUnpacker(t)
	img := imageFrom(t,
		layerFrom(t, []tarSpec{
			{name: "app", mode: 0o755, data: "V1"},
			{name: "lib", typ: tar.TypeDir, mode: 0o755},
			{name: "lib/only-in-layer-1", mode: 0o644, data: "ONE"},
		}),
		layerFrom(t, []tarSpec{
			{name: "app", mode: 0o755, data: "V2"},
			{name: "extra", mode: 0o644, data: "TWO"},
		}),
	)
	mfst := commitImage(t, c, img)

	tree, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if tree.CacheHit {
		t.Error("first Unpack reported a cache hit")
	}
	if got := readTree(t, tree.Rootfs, "app"); got != "V2" {
		t.Errorf("app = %q, want V2 (the later layer wins)", got)
	}
	if got := readTree(t, tree.Rootfs, "lib/only-in-layer-1"); got != "ONE" {
		t.Errorf("lib/only-in-layer-1 = %q, want ONE", got)
	}
	if got := readTree(t, tree.Rootfs, "extra"); got != "TWO" {
		t.Errorf("extra = %q, want TWO", got)
	}

	// The tree lives at the key, under the store's own unpacked root.
	wantKey, err := TreeKey(mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if tree.Key != wantKey {
		t.Errorf("tree key = %q, want %q", tree.Key, wantKey)
	}
	h, err := parseBlobDigest(wantKey)
	if err != nil {
		t.Fatal(err)
	}
	wantRootfs := filepath.Join(c.UnpackedRoot(), h.Algorithm, h.Hex, TreeRootfsName)
	if tree.Rootfs != wantRootfs {
		t.Errorf("tree rootfs = %q, want %q", tree.Rootfs, wantRootfs)
	}

	// The record is daemon-authored and describes what was built FROM.
	var rec treeRecord
	buf, err := os.ReadFile(filepath.Join(filepath.Dir(wantRootfs), TreeRecordName))
	if err != nil {
		t.Fatalf("read tree record: %v", err)
	}
	if err := json.Unmarshal(buf, &rec); err != nil {
		t.Fatalf("decode tree record: %v", err)
	}
	if rec.Version != treeRecordVersion || rec.Key != wantKey || rec.Policy != NativeUnpackPolicy() {
		t.Errorf("record = %+v, want version %d / key %q / native policy", rec, treeRecordVersion, wantKey)
	}
	if rec.Config != mfst.GetConfig().GetDigest() || len(rec.Layers) != 2 {
		t.Errorf("record names config %q and %d layers, want %q and 2", rec.Config, len(rec.Layers), mfst.GetConfig().GetDigest())
	}
	if rec.Stats.Files == 0 {
		t.Error("record carries no apply stats")
	}
}

// TestUnpackIsIdempotent pins the cache-hit path: a second unpack of the same
// (image x policy) applies nothing, serves the committed tree, and reports the
// stats of the build that actually happened.
func TestUnpackIsIdempotent(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))

	first, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("first Unpack: %v", err)
	}
	// Delete the blobs: a hit must not need them. This is the strongest available
	// proof that nothing was re-applied.
	if err := os.RemoveAll(filepath.Join(c.Root(), "blobs")); err != nil {
		t.Fatal(err)
	}
	second, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("second Unpack: %v", err)
	}
	if !second.CacheHit {
		t.Error("second Unpack did not report a cache hit")
	}
	if second.Key != first.Key || second.Rootfs != first.Rootfs {
		t.Errorf("second Unpack = %q/%q, want %q/%q", second.Key, second.Rootfs, first.Key, first.Rootfs)
	}
	if second.Stats != first.Stats {
		t.Errorf("cache-hit stats = %+v, want the build's %+v", second.Stats, first.Stats)
	}
	// No staging directory may be left behind by either call.
	entries, err := os.ReadDir(c.UnpackedRoot())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name()[0] == '.' {
			t.Errorf("staging directory %q survived the commit", e.Name())
		}
	}
}

// TestUnpackVerifiesContent is the verify-on-read half of the deliverable: the
// unpacker re-checks every blob it reads against the manifest that named it and
// every layer's decompressed content against the config's diffID, and commits
// NOTHING when either check fails.
func TestUnpackVerifiesContent(t *testing.T) {
	t.Run("poisoned_layer_blob", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))
		// Overwrite the committed blob with different (still well-formed) bytes:
		// the CAS only verifies at WRITE time, so this is exactly the corruption
		// the unpack is the natural closer for.
		blobPath, err := c.BlobPath(mfst.GetLayers()[0].GetDigest())
		if err != nil {
			t.Fatal(err)
		}
		other := buildGzipTar(t, []tarSpec{{name: "evil", mode: 0o755, data: "PWNED"}})
		if err := os.WriteFile(blobPath, other, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("Unpack error = %v, want ErrDigestMismatch", err)
		}
		assertNoCommittedTree(t, c, mfst)
	})

	t.Run("config_diffid_disagrees_with_the_layer", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		img := imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}}))
		mfst := commitImage(t, c, img)
		// Re-commit the CONFIG blob under its own (recomputed) digest with a
		// diffID that does not describe the layer. The manifest still names the
		// original config digest, so this is a config that contradicts itself —
		// caught before the manifest/config pair is trusted.
		rewriteConfigDiffIDs(t, c, mfst, []string{"sha256:" + hexOf('9')})
		_, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
		if !errors.Is(err, ErrDiffIDMismatch) {
			t.Fatalf("Unpack error = %v, want ErrDiffIDMismatch", err)
		}
		assertNoCommittedTree(t, c, mfst)
	})

	t.Run("config_layer_count_disagrees_with_the_manifest", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, imageFrom(t,
			layerFrom(t, []tarSpec{{name: "a", mode: 0o644, data: "a"}}),
			layerFrom(t, []tarSpec{{name: "b", mode: 0o644, data: "b"}}),
		))
		rewriteConfigDiffIDs(t, c, mfst, []string{"sha256:" + hexOf('9')})
		_, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
		if !errors.Is(err, ErrManifestInconsistent) {
			t.Fatalf("Unpack error = %v, want ErrManifestInconsistent", err)
		}
	})

	t.Run("poisoned_config_blob", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))
		p, err := c.BlobPath(mfst.GetConfig().GetDigest())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"rootfs":{"diff_ids":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("Unpack error = %v, want ErrDigestMismatch", err)
		}
	})

	t.Run("missing_layer_blob", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))
		p, err := c.BlobPath(mfst.GetLayers()[0].GetDigest())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if _, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy()); err == nil {
			t.Fatal("Unpack succeeded with a missing layer blob")
		}
		assertNoCommittedTree(t, c, mfst)
	})

	t.Run("symlink_blob_is_not_a_blob", func(t *testing.T) {
		// openBlob judges a symlink on ITSELF (Lstat), so a link planted at a blob
		// path is refused rather than followed — the same rule Cache.Has applies.
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))
		p, err := c.BlobPath(mfst.GetLayers()[0].GetDigest())
		if err != nil {
			t.Fatal(err)
		}
		elsewhere := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.WriteFile(elsewhere, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, p); err != nil {
			t.Fatal(err)
		}
		if _, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy()); err == nil {
			t.Fatal("Unpack followed a symlink at a blob path")
		}
	})
}

// TestUnpackRefusesUnsupportedLayerMediaType pins the closed compression
// allowlist: the DECLARED media type chooses the decompressor, and an
// unrecognised one is refused rather than sniffed.
func TestUnpackRefusesUnsupportedLayerMediaType(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))
	mfst.Layers[0].MediaType = "application/vnd.oci.image.layer.v1.tar+zstd"
	_, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if !errors.Is(err, ErrUnsupportedLayerMediaType) {
		t.Fatalf("Unpack error = %v, want ErrUnsupportedLayerMediaType", err)
	}
}

// TestUnpackRefusesAnEscapingLayer proves the containment refusal survives the
// whole pipeline — decompress, verify, apply — and leaves no committed tree.
func TestUnpackRefusesAnEscapingLayer(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, imageFrom(t,
		layerFrom(t, []tarSpec{{name: "ok", mode: 0o644, data: "ok"}}),
		layerFrom(t, []tarSpec{{name: "sh", typ: tar.TypeSymlink, link: "/bin/sh"}}),
	))
	_, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if !errors.Is(err, ErrLayerEscapes) {
		t.Fatalf("Unpack error = %v, want ErrLayerEscapes", err)
	}
	assertNoCommittedTree(t, c, mfst)
}

// TestUnpackRefusesAnInconsistentCommittedTree pins the fail-closed read of a
// committed tree: a record that is absent, undecodable, or disagrees with the
// path is refused, never rebuilt over.
func TestUnpackRefusesAnInconsistentCommittedTree(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, imageFrom(t, layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})))
	tree, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(filepath.Dir(tree.Rootfs), TreeRecordName)

	for _, tc := range []struct {
		name    string
		content string
	}{
		{"undecodable", "{not json"},
		{"wrong_version", `{"version":99,"key":"` + tree.Key + `"}`},
		{"wrong_key", `{"version":1,"key":"sha256:` + hexOf('0') + `"}`},
		{"wrong_policy", `{"version":1,"key":"` + tree.Key + `","policy":{"semantics":"linux"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(recPath, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy()); !errors.Is(err, ErrTreeInconsistent) {
				t.Fatalf("Unpack error = %v, want ErrTreeInconsistent", err)
			}
		})
	}
}

// TestUnpackerMaterializeTree is the seam pkg/runtime consumes: unpack (or hit)
// then clone into the pod rootfs, creating it if absent, idempotently.
func TestUnpackerMaterializeTree(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, imageFrom(t,
		layerFrom(t, []tarSpec{
			{name: "app", mode: 0o755, data: "V1"},
			{name: "usr", typ: tar.TypeDir, mode: 0o755},
			{name: "usr/lib", mode: 0o644, data: "LIB"},
		}),
		layerFrom(t, []tarSpec{
			{name: "app", mode: 0o755, data: "V2"},
			{name: "sh", typ: tar.TypeSymlink, link: "app"},
		}),
	))
	dst := filepath.Join(t.TempDir(), "pods", "pod-1", "rootfs")

	res, err := u.MaterializeTree(context.Background(), mfst, NativeUnpackPolicy(), dst)
	if err != nil {
		t.Fatalf("MaterializeTree: %v", err)
	}
	if res.Tree == nil || res.Tree.Key == "" {
		t.Fatalf("MaterializeTree returned %+v, want a keyed tree", res)
	}
	if got := readTree(t, dst, "app"); got != "V2" {
		t.Errorf("materialized app = %q, want V2", got)
	}
	if got := readTree(t, dst, "usr/lib"); got != "LIB" {
		t.Errorf("materialized usr/lib = %q, want LIB", got)
	}
	// A symlink materializes as a symlink, not as a copy of its target.
	fi, err := os.Lstat(filepath.Join(dst, "sh"))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("materialized sh mode = %v, err %v; want a symlink", fi.Mode(), err)
	}

	t.Run("idempotent", func(t *testing.T) {
		again, err := u.MaterializeTree(context.Background(), mfst, NativeUnpackPolicy(), dst)
		if err != nil {
			t.Fatalf("second MaterializeTree: %v", err)
		}
		if !again.Tree.CacheHit {
			t.Error("second MaterializeTree rebuilt the tree")
		}
		if got := readTree(t, dst, "app"); got != "V2" {
			t.Errorf("app after re-materialize = %q, want V2", got)
		}
	})

	t.Run("requires_a_destination", func(t *testing.T) {
		if _, err := u.MaterializeTree(context.Background(), mfst, NativeUnpackPolicy(), ""); err == nil {
			t.Fatal("MaterializeTree accepted an empty destination")
		}
	})
}

// TestUnpackConcurrent pins the doc comment's concurrency claim: several
// unpacks of one key race only on the final directory rename, and the losers
// ADOPT the winner's tree rather than failing.
//
// Failing a loser would be an outage of exactly the common case — several pods
// of one Deployment starting the same image at once — and it would be an
// arbitrary one, since the key is content-addressed and every racer was building
// byte-equivalent content.
func TestUnpackConcurrent(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, imageFrom(t,
		layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}, {name: "d", typ: tar.TypeDir, mode: 0o755}}),
		layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V2"}}),
	))

	const racers = 8
	var wg sync.WaitGroup
	trees := make([]*Tree, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			trees[i], errs[i] = u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
		}()
	}
	close(start)
	wg.Wait()

	for i := range racers {
		if errs[i] != nil {
			t.Fatalf("racer %d: %v", i, errs[i])
		}
		if trees[i].Rootfs != trees[0].Rootfs {
			t.Errorf("racer %d served tree %q, want the single %q", i, trees[i].Rootfs, trees[0].Rootfs)
		}
	}
	if got := readTree(t, trees[0].Rootfs, "app"); got != "V2" {
		t.Errorf("app = %q, want V2", got)
	}
	// Exactly one committed tree, and no staging leftovers.
	entries, err := os.ReadDir(c.UnpackedRoot())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name()[0] == '.' {
			t.Errorf("staging directory %q survived a losing race", e.Name())
		}
	}
}

// TestNewUnpackerRequiresACache pins the constructor's one required argument:
// the unpacker must read the SAME store the pull committed to, or it could not
// verify a byte it applies.
func TestNewUnpackerRequiresACache(t *testing.T) {
	if _, err := NewUnpacker(nil); err == nil {
		t.Fatal("NewUnpacker accepted a nil cache")
	}
}

// --- helpers -------------------------------------------------------------

// hexOf builds a 64-character sha256 hex body out of one repeated nibble.
func hexOf(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// buildGzipTar renders specs as a gzip-compressed tar (a well-formed layer blob
// of the WRONG content — used to poison a committed blob).
func buildGzipTar(t *testing.T, specs []tarSpec) []byte {
	t.Helper()
	l := layerFrom(t, specs)
	rc, err := l.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	buf, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// rewriteConfigDiffIDs replaces the committed config blob's rootfs.diff_ids in
// place, leaving the manifest still naming the ORIGINAL config digest. It
// bypasses CommitBlob deliberately: the point is a store whose bytes no longer
// match their name, which the commit path exists to prevent.
func rewriteConfigDiffIDs(t *testing.T, c *Cache, mfst *runtimev1.ImageManifest, diffIDs []string) {
	t.Helper()
	p, err := c.BlobPath(mfst.GetConfig().GetDigest())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	ids := make([]any, 0, len(diffIDs))
	for _, d := range diffIDs {
		ids = append(ids, d)
	}
	cfg["rootfs"] = map[string]any{"type": "layers", "diff_ids": ids}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Re-point the manifest at the REWRITTEN config's own digest so the config
	// still self-verifies; only its claim about the layers is now false.
	sum, _, err := ggcrv1.SHA256(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CommitBlob(sum.String(), int64(len(out)), func(w io.Writer) error {
		_, werr := w.Write(out)
		return werr
	}); err != nil {
		t.Fatal(err)
	}
	mfst.Config = &runtimev1.Descriptor{
		MediaType: mfst.GetConfig().GetMediaType(),
		Digest:    sum.String(),
		Size:      int64(len(out)),
	}
}

// assertNoCommittedTree fails if a tree for mfst exists — the atomicity claim:
// a failed unpack commits nothing at the key.
func assertNoCommittedTree(t *testing.T, c *Cache, mfst *runtimev1.ImageManifest) {
	t.Helper()
	key, err := TreeKey(mfst, NativeUnpackPolicy())
	if err != nil {
		return // an unusable key cannot have produced a tree
	}
	h, err := parseBlobDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.UnpackedRoot(), h.Algorithm, h.Hex)
	if _, err := os.Lstat(dir); err == nil {
		t.Fatalf("a failed unpack committed a tree at %s", dir)
	}
	// Nor may a staging directory be left behind.
	entries, err := os.ReadDir(c.UnpackedRoot())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name()[0] == '.' {
			t.Errorf("a failed unpack left the staging directory %q", e.Name())
		}
	}
}
