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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// zstdCompress renders payload as a zstd frame, so the allowlist rows are
// exercised against real compressed bytes rather than a stubbed decompressor.
func zstdCompress(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// linuxImageFrom builds a multi-layer image whose config declares linux/arm64 —
// the platform the vm spine selects (image.Candidates).
func linuxImageFrom(t *testing.T, layers ...ggcrv1.Layer) ggcrv1.Image {
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
	cf.OS, cf.Architecture = "linux", "arm64"
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return img
}

// snapshotDirFor returns the directory a chain id files under in c.
func snapshotDirFor(t *testing.T, c *Cache, chainID string) string {
	t.Helper()
	h, err := parseBlobDigest(chainID)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(c.SnapshotsRoot(), h.Algorithm, h.Hex)
}

// TestChainID pins the OCI chain-id construction against hand-computed vectors.
// It is computed here from the spec's formula rather than from the
// implementation, so the test cannot agree with a wrong implementation by
// construction.
func TestChainID(t *testing.T) {
	d0 := "sha256:" + hexOf('1')
	d1 := "sha256:" + hexOf('2')
	d2 := "sha256:" + hexOf('3')

	sum := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(h[:])
	}
	want1 := d0
	want2 := sum(d0 + " " + d1)
	want3 := sum(want2 + " " + d2)

	cases := []struct {
		name    string
		diffIDs []string
		want    string
	}{
		{"single_layer_is_its_diffid", []string{d0}, want1},
		{"two_layers", []string{d0, d1}, want2},
		{"three_layers", []string{d0, d1, d2}, want3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ChainID(tc.diffIDs)
			if err != nil {
				t.Fatalf("ChainID: %v", err)
			}
			if got != tc.want {
				t.Errorf("ChainID(%v) = %q, want %q", tc.diffIDs, got, tc.want)
			}
		})
	}

	t.Run("order_is_an_input", func(t *testing.T) {
		a, err := ChainID([]string{d0, d1})
		if err != nil {
			t.Fatal(err)
		}
		b, err := ChainID([]string{d1, d0})
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Error("reversing the layer order did not change the chain id")
		}
	})

	t.Run("refuses_unusable_input", func(t *testing.T) {
		for _, in := range [][]string{
			nil,
			{},
			{"not-a-digest"},
			{d0, "md5:" + hexOf('a')},
			{d0, "sha256:not-hex"},
		} {
			if got, err := ChainID(in); err == nil {
				t.Errorf("ChainID(%v) = %q, want an error", in, got)
			}
		}
	})
}

// TestLinuxSnapshotCommitsUnderChainID is the store half of the M11.2-d1 gate:
// a Linux-dialect unpack lands in snapshots/<algo>/<chainid> with the record and
// the ownership sidecar committed beside the payload, and the NATIVE dialect's
// store is untouched by it.
func TestLinuxSnapshotCommitsUnderChainID(t *testing.T) {
	c, u := newTestUnpacker(t)
	img := linuxImageFrom(t,
		layerFrom(t, []tarSpec{
			{name: "etc", typ: tar.TypeDir, mode: 0o755},
			{name: "etc/gone.conf", mode: 0o644, data: "gone"},
			{name: "etc/keep.conf", mode: 0o644, data: "keep"},
		}),
		layerFrom(t, []tarSpec{
			{name: "etc/.wh.gone.conf", mode: 0o644},
			{name: "usr", typ: tar.TypeDir, mode: 0o755, uid: 0, gid: 0},
			{name: "usr/su", mode: 0o4755, data: "setuid", uid: 0, gid: 0},
		}),
	)
	mfst := commitImage(t, c, img)

	tree, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	// The key IS the OCI chain id over the config's diffIDs — computed here
	// from the image's own config, not read back from the unpacker.
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	diffIDs := make([]string, 0, len(cf.RootFS.DiffIDs))
	for _, d := range cf.RootFS.DiffIDs {
		diffIDs = append(diffIDs, d.String())
	}
	wantKey, err := ChainID(diffIDs)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Key != wantKey {
		t.Errorf("snapshot key = %q, want the chain id %q", tree.Key, wantKey)
	}
	dir := snapshotDirFor(t, c, wantKey)
	if tree.Rootfs != filepath.Join(dir, TreeRootfsName) {
		t.Errorf("rootfs = %q, want %q", tree.Rootfs, filepath.Join(dir, TreeRootfsName))
	}
	if tree.Ownership != filepath.Join(dir, SnapshotOwnershipName) {
		t.Errorf("ownership = %q, want %q", tree.Ownership, filepath.Join(dir, SnapshotOwnershipName))
	}

	// The whiteout in layer 2 was applied through the whole pipeline —
	// decompress, verify, apply — not just in the applier's unit tests.
	if _, err := os.Lstat(filepath.Join(tree.Rootfs, "etc/gone.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the whiteout did not survive the unpack pipeline: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(tree.Rootfs, "etc/keep.conf")); err != nil {
		t.Errorf("etc/keep.conf is missing: %v", err)
	}

	// The record names the chain and the sidecar.
	raw, err := os.ReadFile(filepath.Join(dir, SnapshotRecordName))
	if err != nil {
		t.Fatalf("read %s: %v", SnapshotRecordName, err)
	}
	var rec treeRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Key != wantKey || rec.Policy != LinuxUnpackPolicy() || rec.Ownership != SnapshotOwnershipName {
		t.Errorf("record = %+v, want key %q / linux policy / ownership %q", rec, wantKey, SnapshotOwnershipName)
	}
	if len(rec.DiffIDs) != len(diffIDs) {
		t.Errorf("record lists %d diffIDs, want %d", len(rec.DiffIDs), len(diffIDs))
	}
	if rec.Stats.Whiteouts != 1 {
		t.Errorf("record stats = %+v, want one whiteout", rec.Stats)
	}

	// The sidecar carries the setuid mode the host tree cannot.
	own, err := ReadOwnershipSidecar(tree.Ownership)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	byPath := ownershipByPath(own)
	if e, ok := byPath["usr/su"]; !ok || e.Mode != 0o4755 {
		t.Errorf("sidecar entry for usr/su = %+v (present=%v), want mode 04755", e, ok)
	}
	fi, err := os.Lstat(filepath.Join(tree.Rootfs, "usr/su"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid != 0 {
		t.Error("the committed snapshot carries a setuid bit")
	}

	// A native unpack of the SAME image is a DIFFERENT tree in a DIFFERENT
	// store — the whole point of keying the two dialects separately.
	nat, err := u.Unpack(context.Background(), mfst, NativeUnpackPolicy())
	if err != nil {
		t.Fatalf("native Unpack: %v", err)
	}
	if nat.Key == tree.Key {
		t.Error("the native tree and the linux snapshot share a key")
	}
	if nat.Ownership != "" {
		t.Errorf("native tree carries an ownership sidecar at %q", nat.Ownership)
	}
	if !bytes.Contains([]byte(nat.Rootfs), []byte(UnpackedSubdir)) {
		t.Errorf("native rootfs %q is not under %s/", nat.Rootfs, UnpackedSubdir)
	}
	// The native tree keeps the marker as an ordinary file, unchanged.
	if _, err := os.Lstat(filepath.Join(nat.Rootfs, "etc/.wh.gone.conf")); err != nil {
		t.Errorf("the native dialect interpreted a whiteout: %v", err)
	}
}

// TestLinuxSnapshotSharesAChainAcrossImages pins the reason the key is a chain
// id rather than a manifest-derived digest: two DIFFERENT images whose layers
// are identical have one rootfs, so they must share one snapshot.
func TestLinuxSnapshotSharesAChainAcrossImages(t *testing.T) {
	c, u := newTestUnpacker(t)
	layer := layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})

	first := linuxImageFrom(t, layer)
	mfstA := commitImage(t, c, first)

	// The SAME layer under a config that differs in a non-rootfs field: a new
	// config digest, a new manifest, an identical diffID chain.
	cf, err := first.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.Author = "someone else"
	second, err := mutate.ConfigFile(first, cf)
	if err != nil {
		t.Fatal(err)
	}
	mfstB := commitImage(t, c, second)
	if mfstA.GetConfig().GetDigest() == mfstB.GetConfig().GetDigest() {
		t.Fatal("the two images share a config digest; the case is vacuous")
	}

	a, err := u.Unpack(context.Background(), mfstA, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("Unpack A: %v", err)
	}
	b, err := u.Unpack(context.Background(), mfstB, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("Unpack B: %v", err)
	}
	if a.Key != b.Key || a.Rootfs != b.Rootfs {
		t.Errorf("the two images unpacked to %q and %q, want one shared snapshot", a.Rootfs, b.Rootfs)
	}
	if !b.CacheHit {
		t.Error("the second image did not hit the first's snapshot")
	}

	// The same two images under the NATIVE dialect do NOT share a tree: TreeKey
	// folds in the config digest. This is the row that proves the sharing above
	// comes from the chain id and not from the store being sloppy.
	na, err := u.Unpack(context.Background(), mfstA, NativeUnpackPolicy())
	if err != nil {
		t.Fatal(err)
	}
	nb, err := u.Unpack(context.Background(), mfstB, NativeUnpackPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if na.Key == nb.Key {
		t.Error("the native dialect shared a tree between two distinct configs")
	}
}

// TestLinuxSnapshotVerifiesEveryLayerBeforeCommitting pins the self-authenticating
// property the chain-id key claims: a snapshot's path asserts a diffID chain, so
// EVERY layer's decompressed bytes are re-verified against it before the commit,
// and a failure commits NOTHING.
func TestLinuxSnapshotVerifiesEveryLayerBeforeCommitting(t *testing.T) {
	t.Run("poisoned_layer_blob", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, linuxImageFrom(t,
			layerFrom(t, []tarSpec{{name: "a", mode: 0o644, data: "A"}}),
			layerFrom(t, []tarSpec{{name: "b", mode: 0o644, data: "B"}}),
		))
		// Substitute the SECOND layer's blob after it was committed: the CAS
		// verifies at write time only, so this is exactly the corruption the
		// unpack closes.
		blobPath, err := c.BlobPath(mfst.GetLayers()[1].GetDigest())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(blobPath, buildGzipTar(t, []tarSpec{{name: "evil", mode: 0o755, data: "PWNED"}}), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("Unpack error = %v, want ErrDigestMismatch", err)
		}
		assertNoCommittedSnapshot(t, c)
	})

	t.Run("config_diffid_disagrees_with_the_layer", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, linuxImageFrom(t,
			layerFrom(t, []tarSpec{{name: "a", mode: 0o644, data: "A"}}),
		))
		// A config that self-verifies but lies about its layer. The chain id it
		// yields is well-formed, so the ONLY thing standing between the lie and
		// a committed snapshot under that id is the per-layer re-verification.
		rewriteConfigDiffIDs(t, c, mfst, []string{"sha256:" + hexOf('9')})
		_, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
		if !errors.Is(err, ErrDiffIDMismatch) {
			t.Fatalf("Unpack error = %v, want ErrDiffIDMismatch", err)
		}
		assertNoCommittedSnapshot(t, c)
	})

	t.Run("a_collision_commits_nothing", func(t *testing.T) {
		c, u := newTestUnpacker(t)
		mfst := commitImage(t, c, linuxImageFrom(t,
			layerFrom(t, []tarSpec{
				{name: "srv", typ: tar.TypeDir, mode: 0o755},
				{name: "srv/Config", mode: 0o644, data: "upper"},
				{name: "srv/config", mode: 0o644, data: "lower"},
			}),
		))
		_, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
		if !errors.Is(err, ErrPathCollision) {
			t.Fatalf("Unpack error = %v, want ErrPathCollision", err)
		}
		assertNoCommittedSnapshot(t, c)
	})
}

// assertNoCommittedSnapshot proves a failed unpack left neither a committed
// snapshot nor a staging directory behind.
func assertNoCommittedSnapshot(t *testing.T, c *Cache) {
	t.Helper()
	root := c.SnapshotsRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name()[0] == '.' {
			t.Errorf("a failed unpack left the staging directory %s", e.Name())
			continue
		}
		// An algorithm directory may exist from MkdirAll; it must hold nothing.
		sub, serr := os.ReadDir(filepath.Join(root, e.Name()))
		if serr != nil {
			t.Fatal(serr)
		}
		if len(sub) != 0 {
			t.Errorf("a failed unpack committed %d snapshot(s) under %s", len(sub), e.Name())
		}
	}
}

// TestLinuxSnapshotIsIdempotent pins the cache-hit path for the snapshot store,
// including the one asymmetry it has against the native store: a Linux hit MUST
// read the image config (the chain id is a function of the diffIDs), so it needs
// that one blob and no other.
func TestLinuxSnapshotIsIdempotent(t *testing.T) {
	c, u := newTestUnpacker(t)
	mfst := commitImage(t, c, linuxImageFrom(t,
		layerFrom(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}}),
	))
	first, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("first Unpack: %v", err)
	}
	// Delete the LAYER blob only: a hit must not need it.
	layerPath, err := c.BlobPath(mfst.GetLayers()[0].GetDigest())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(layerPath); err != nil {
		t.Fatal(err)
	}
	second, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("second Unpack: %v", err)
	}
	if !second.CacheHit {
		t.Error("second Unpack did not report a cache hit")
	}
	if second.Key != first.Key || second.Rootfs != first.Rootfs || second.Ownership != first.Ownership {
		t.Errorf("second Unpack = %+v, want the first's %+v", second, first)
	}
	if second.Stats != first.Stats {
		t.Errorf("cache-hit stats = %+v, want the build's %+v", second.Stats, first.Stats)
	}

	// A committed snapshot whose SIDECAR is missing is inconsistent, not
	// silently reusable: the ownership the guest would apply is not derivable
	// from the tree.
	if err := os.Remove(first.Ownership); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy()); !errors.Is(err, ErrTreeInconsistent) {
		t.Errorf("Unpack over a sidecar-less snapshot error = %v, want ErrTreeInconsistent", err)
	}
}

// TestDecompressLayerAllowlist pins the CLOSED compression allowlist: the
// DECLARED media type chooses the decompressor and the bytes never get to
// decide. zstd joined it with the Linux dialect — zstd is what buildkit emits
// for a Linux image built with `--compression=zstd`, and a layer this daemon
// cannot decompress is an image it cannot run.
func TestDecompressLayerAllowlist(t *testing.T) {
	payload := buildTar(t, []tarSpec{{name: "app", mode: 0o755, data: "V1"}})

	t.Run("zstd", func(t *testing.T) {
		compressed := zstdCompress(t, payload)
		rc, err := decompressLayer(mediaTypeOCILayerZstd, bytes.NewReader(compressed))
		if err != nil {
			t.Fatalf("decompressLayer: %v", err)
		}
		defer rc.Close()
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("the zstd decompressor did not round-trip the layer")
		}
	})

	t.Run("refused", func(t *testing.T) {
		for _, mt := range []string{
			"application/vnd.oci.image.layer.v1.tar+xz",
			"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
			"",
			"application/octet-stream",
		} {
			if _, err := decompressLayer(mt, bytes.NewReader(nil)); !errors.Is(err, ErrUnsupportedLayerMediaType) {
				t.Errorf("decompressLayer(%q) error = %v, want ErrUnsupportedLayerMediaType", mt, err)
			}
		}
	})

	// A malformed stream is a MALFORMED-LAYER verdict, never an unsupported-media-type
	// one — the operator's remedy differs. gzip reports it at construction (it
	// reads its header eagerly) and zstd at first read (it does not), so the
	// assertion is made where both are observable: at the applier, which wraps
	// any decompressor read failure as ErrLayerMalformed.
	t.Run("malformed_stream_is_a_malformed_layer", func(t *testing.T) {
		for _, mt := range []string{mediaTypeOCILayerZstd, mediaTypeOCILayerGzip} {
			garbage := []byte("this is not a compressed layer at all")
			rc, err := decompressLayer(mt, bytes.NewReader(garbage))
			if err != nil {
				if !errors.Is(err, ErrLayerMalformed) {
					t.Errorf("decompressLayer(%q) error = %v, want ErrLayerMalformed", mt, err)
				}
				continue
			}
			root, oerr := os.OpenRoot(t.TempDir())
			if oerr != nil {
				t.Fatal(oerr)
			}
			a, aerr := NewLayerApplier(root, LinuxUnpackPolicy(), ApplyLimits{})
			if aerr != nil {
				t.Fatal(aerr)
			}
			aerr = a.Apply(context.Background(), rc)
			rc.Close()
			root.Close()
			if !errors.Is(aerr, ErrLayerMalformed) {
				t.Errorf("apply of a malformed %q stream error = %v, want ErrLayerMalformed", mt, aerr)
			}
		}
	})
}

// TestUnpackAppliesAZstdLayer drives a zstd layer through the WHOLE pipeline,
// which is the only thing that proves the compressed-digest and diffID checks
// still wrap the new decompressor correctly.
func TestUnpackAppliesAZstdLayer(t *testing.T) {
	c, u := newTestUnpacker(t)
	plain := buildTar(t, []tarSpec{{name: "app", mode: 0o755, data: "ZSTD"}})
	compressed := zstdCompress(t, plain)

	diffSum, _, err := ggcrv1.SHA256(bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	blobSum, _, err := ggcrv1.SHA256(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CommitBlob(blobSum.String(), int64(len(compressed)), func(w io.Writer) error {
		_, werr := w.Write(compressed)
		return werr
	}); err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + diffSum.String() + `"]}}`)
	cfgSum, _, err := ggcrv1.SHA256(bytes.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CommitBlob(cfgSum.String(), int64(len(cfg)), func(w io.Writer) error {
		_, werr := w.Write(cfg)
		return werr
	}); err != nil {
		t.Fatal(err)
	}
	mfst := &runtimev1.ImageManifest{
		Reference: "example.com/zstd:v1",
		Config:    &runtimev1.Descriptor{Digest: cfgSum.String(), Size: int64(len(cfg))},
		Layers: []*runtimev1.Descriptor{{
			Digest:    blobSum.String(),
			Size:      int64(len(compressed)),
			MediaType: mediaTypeOCILayerZstd,
		}},
	}
	tree, err := u.Unpack(context.Background(), mfst, LinuxUnpackPolicy())
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(tree.Rootfs, "app"))
	if err != nil {
		t.Fatalf("read app: %v", err)
	}
	if string(got) != "ZSTD" {
		t.Errorf("app = %q, want ZSTD", got)
	}
}
