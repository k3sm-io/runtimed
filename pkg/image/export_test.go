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
	"errors"
	"io"
	"os"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// mustOCIArchive renders spec as a tarred OCI layout, discarding the fixture's
// own manifest digest — the tests below read the digest back out of the STORE,
// which is the only place it matters.
func mustOCIArchive(t *testing.T, spec ociSpec) []byte {
	t.Helper()
	archive, _ := buildOCIArchive(t, spec)
	return archive
}

// exportFixture loads specs into a fresh store and returns the recorded entry.
// It goes through the real Loader, so what is exported is exactly what an ingest
// recorded — a hand-built IndexEntry would prove the exporter agrees with the
// test, not with the store.
func exportFixture(t *testing.T, ref string, spec ociSpec) (*Cache, *FileIndex, IndexEntry) {
	t.Helper()
	cache, idx := newIndexedCache(t)
	loader, err := NewLoader(cache, idx)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if _, err := loader.Load(context.Background(), LoadRequest{Reference: ref}, bytes.NewReader(mustOCIArchive(t, spec))); err != nil {
		t.Fatalf("Load: %v", err)
	}
	entry, err := idx.Resolve(context.Background(), ref, nil)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", ref, err)
	}
	return cache, idx, entry
}

// TestExportOCILayoutRoundTrips is the load -> save -> load proof, and it is the
// strongest single claim this path makes: an image that goes out and comes back
// keeps its manifest DIGEST, i.e. its identity.
//
// Digest stability is not free and would not survive the obvious
// implementation. The store commits config and layer blobs and never the
// manifest, so an exporter that re-encoded the recorded descriptors would emit a
// manifest with a different digest — and nothing downstream could tell, because
// the re-encoded archive is perfectly valid. The test therefore asserts the
// digest across the round trip, not merely that the archive re-loads.
func TestExportOCILayoutRoundTrips(t *testing.T) {
	const ref = "example.com/app:v1"
	spec := ociSpec{
		config: []byte(`{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers"}}`),
		layers: [][]byte{[]byte("layer-one"), []byte("layer-two")},
	}
	cache, _, entry := exportFixture(t, ref, spec)

	var first bytes.Buffer
	if err := cache.ExportOCILayout(context.Background(), &first, entry); err != nil {
		t.Fatalf("ExportOCILayout: %v", err)
	}

	// (a) The archive re-loads, into a SECOND store, under a second reference...
	reCache, reIdx := newIndexedCache(t)
	reLoader, err := NewLoader(reCache, reIdx)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	const reRef = "example.com/app:reimported"
	res, err := reLoader.Load(context.Background(), LoadRequest{Reference: reRef}, bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatalf("re-load of the exported archive: %v", err)
	}

	// (b) ...with the SAME manifest digest. This is the load-bearing assertion.
	if got, want := res.Descriptor.GetDigest(), entry.Descriptor.GetDigest(); got != want {
		t.Errorf("re-loaded manifest digest = %s, want %s (the export must not re-encode the manifest)", got, want)
	}
	if got, want := res.Descriptor.GetSize(), entry.Descriptor.GetSize(); got != want {
		t.Errorf("re-loaded manifest size = %d, want %d", got, want)
	}
	// And the same content, blob for blob.
	if got, want := res.Manifest.GetConfig().GetDigest(), entry.Manifest.GetConfig().GetDigest(); got != want {
		t.Errorf("re-loaded config digest = %s, want %s", got, want)
	}
	if len(res.Manifest.GetLayers()) != len(entry.Manifest.GetLayers()) {
		t.Fatalf("re-loaded %d layers, want %d", len(res.Manifest.GetLayers()), len(entry.Manifest.GetLayers()))
	}
	for i, l := range res.Manifest.GetLayers() {
		if got, want := l.GetDigest(), entry.Manifest.GetLayers()[i].GetDigest(); got != want {
			t.Errorf("re-loaded layer %d digest = %s, want %s", i, got, want)
		}
	}

	// (c) The export is byte-DETERMINISTIC. Two exports of one unchanged image
	// must be identical, or no caller can tell a re-export from a re-build.
	var second bytes.Buffer
	if err := cache.ExportOCILayout(context.Background(), &second, entry); err != nil {
		t.Fatalf("second ExportOCILayout: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Errorf("two exports of one image differ (%d vs %d bytes); the archive must be byte-deterministic",
			first.Len(), second.Len())
	}

	// (d) A third generation, to prove the property is not one-shot: an archive
	// re-imported under the ORIGINAL reference re-exports byte-identically.
	//
	// The reference matters and is not incidental. index.json annotates the
	// manifest with org.opencontainers.image.ref.name, so the reRef import above
	// would legitimately produce a different archive — a different NAME for the
	// same image. What must not change is the manifest, which is why (b) compares
	// digests across the renamed round trip and this row compares whole archives
	// across the same-named one.
	thirdCache, thirdIdx := newIndexedCache(t)
	thirdLoader, err := NewLoader(thirdCache, thirdIdx)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if _, err := thirdLoader.Load(context.Background(), LoadRequest{Reference: ref}, bytes.NewReader(first.Bytes())); err != nil {
		t.Fatalf("re-load under the original reference: %v", err)
	}
	thirdEntry, err := thirdIdx.Resolve(context.Background(), ref, nil)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", ref, err)
	}
	var third bytes.Buffer
	if err := thirdCache.ExportOCILayout(context.Background(), &third, thirdEntry); err != nil {
		t.Fatalf("third ExportOCILayout: %v", err)
	}
	if !bytes.Equal(first.Bytes(), third.Bytes()) {
		t.Errorf("re-exporting a re-imported image produced a different archive (%d vs %d bytes); the round trip is not stable",
			first.Len(), third.Len())
	}
}

// TestExportOCILayoutRefuses pins the two states in which an export must refuse
// BEFORE writing a byte, rather than emitting a truncated archive the caller has
// to detect.
func TestExportOCILayoutRefuses(t *testing.T) {
	const ref = "example.com/app:v1"
	spec := ociSpec{
		config: []byte(`{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers"}}`),
		layers: [][]byte{[]byte("layer-one")},
	}

	t.Run("an entry that retained no manifest cannot be exported", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		// The pre-retention shape, written through the real index: a manifest and
		// a key, and no manifest descriptor or bytes.
		if err := idx.Record(context.Background(), IndexEntry{
			Reference: ref,
			Platform:  Platform{OS: "darwin", Architecture: "arm64"},
			Manifest:  &runtimev1.ImageManifest{Reference: ref},
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
		entry, err := idx.Resolve(context.Background(), ref, nil)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		var buf bytes.Buffer
		if err := cache.ExportOCILayout(context.Background(), &buf, entry); !errors.Is(err, ErrManifestNotRetained) {
			t.Fatalf("ExportOCILayout = %v, want ErrManifestNotRetained", err)
		}
		if buf.Len() != 0 {
			t.Errorf("the refusal wrote %d bytes; a refusal the daemon can make up front must write none", buf.Len())
		}
	})

	t.Run("an entry whose blobs the store no longer holds cannot be exported", func(t *testing.T) {
		cache, _, entry := exportFixture(t, ref, spec)
		// An index entry is an EDGE and outlives its blobs, so this is a real
		// post-prune state and not a synthetic one.
		p, err := cache.BlobPath(entry.Manifest.GetLayers()[0].GetDigest())
		if err != nil {
			t.Fatalf("BlobPath: %v", err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove layer blob: %v", err)
		}
		var buf bytes.Buffer
		if err := cache.ExportOCILayout(context.Background(), &buf, entry); !errors.Is(err, ErrExportIncomplete) {
			t.Fatalf("ExportOCILayout = %v, want ErrExportIncomplete", err)
		}
		if buf.Len() != 0 {
			t.Errorf("the refusal wrote %d bytes; the missing blob is knowable before the first chunk", buf.Len())
		}
	})

	t.Run("a cancelled context exports nothing", func(t *testing.T) {
		cache, _, entry := exportFixture(t, ref, spec)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var buf bytes.Buffer
		if err := cache.ExportOCILayout(ctx, &buf, entry); !errors.Is(err, context.Canceled) {
			t.Fatalf("ExportOCILayout = %v, want context.Canceled", err)
		}
	})
}

// TestImageConfigReadsTheStore pins the decoded half of an inspect: the config
// facts that live INSIDE the config blob's JSON and so cannot be carried by a
// descriptor, plus the two absent cases that are facts rather than errors.
func TestImageConfigReadsTheStore(t *testing.T) {
	const ref = "example.com/app:v1"
	const rawConfig = `{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers"},` +
		`"config":{"Entrypoint":["/bin/app"],"Cmd":["--serve"],"Env":["PATH=/bin","PATH=/sbin"],` +
		`"User":"501:20","WorkingDir":"/srv","Labels":{"k3sm.io/test":"yes"}}}`

	t.Run("the decoded config carries what a descriptor cannot", func(t *testing.T) {
		cache, _, entry := exportFixture(t, ref, ociSpec{
			config: []byte(rawConfig),
			layers: [][]byte{[]byte("layer-one")},
		})
		cfg, ok, err := cache.ImageConfig(entry)
		if err != nil || !ok {
			t.Fatalf("ImageConfig = (%v, %v, %v), want the decoded config", cfg, ok, err)
		}
		if got := cfg.Config.Entrypoint; len(got) != 1 || got[0] != "/bin/app" {
			t.Errorf("Entrypoint = %v, want [/bin/app]", got)
		}
		if got := cfg.Config.Cmd; len(got) != 1 || got[0] != "--serve" {
			t.Errorf("Cmd = %v, want [--serve]", got)
		}
		// Env is order-significant and admits repeated keys, which is why it is
		// carried as the OCI list and never as a map.
		if got := cfg.Config.Env; len(got) != 2 || got[0] != "PATH=/bin" || got[1] != "PATH=/sbin" {
			t.Errorf("Env = %v, want the two entries verbatim and in order", got)
		}
		if cfg.Config.User != "501:20" || cfg.Config.WorkingDir != "/srv" {
			t.Errorf("User/WorkingDir = %q/%q, want 501:20 and /srv", cfg.Config.User, cfg.Config.WorkingDir)
		}
		if cfg.Config.Labels["k3sm.io/test"] != "yes" {
			t.Errorf("Labels = %v, want k3sm.io/test=yes", cfg.Config.Labels)
		}
		if cfg.OS != "darwin" || cfg.Architecture != "arm64" {
			t.Errorf("config platform = %s/%s, want darwin/arm64", cfg.OS, cfg.Architecture)
		}
	})

	t.Run("a config the store no longer holds is absent, not an error", func(t *testing.T) {
		cache, _, entry := exportFixture(t, ref, ociSpec{
			config: []byte(rawConfig),
			layers: [][]byte{[]byte("layer-one")},
		})
		p, err := cache.BlobPath(entry.Manifest.GetConfig().GetDigest())
		if err != nil {
			t.Fatalf("BlobPath: %v", err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove config blob: %v", err)
		}
		cfg, ok, err := cache.ImageConfig(entry)
		if err != nil || ok || cfg != nil {
			t.Fatalf("ImageConfig = (%v, %v, %v), want a clean absence — an entry outlives its blobs", cfg, ok, err)
		}
	})
}

// TestExportWritesOneEntryPerDistinctBlob pins the de-duplication, which is a
// correctness requirement and not an optimisation: a tar may not carry two
// entries at one name, and an image may legitimately name one blob twice.
func TestExportWritesOneEntryPerDistinctBlob(t *testing.T) {
	const ref = "example.com/app:dup"
	dup := []byte("shared-layer")
	cache, _, entry := exportFixture(t, ref, ociSpec{
		config: []byte(`{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers"}}`),
		layers: [][]byte{dup, dup},
	})
	if len(entry.Manifest.GetLayers()) != 2 {
		t.Fatalf("fixture recorded %d layers, want the same blob twice", len(entry.Manifest.GetLayers()))
	}
	var buf bytes.Buffer
	if err := cache.ExportOCILayout(context.Background(), &buf, entry); err != nil {
		t.Fatalf("ExportOCILayout: %v", err)
	}
	names := tarEntryNames(t, buf.Bytes())
	seen := make(map[string]int, len(names))
	for _, n := range names {
		seen[n]++
	}
	for n, c := range seen {
		if c != 1 {
			t.Errorf("archive carries %s %d times; a tar may hold one entry per name", n, c)
		}
	}
	// oci-layout, index.json, the manifest, the config, and ONE layer blob.
	if len(names) != 5 {
		t.Errorf("archive holds %d entries (%v), want 5 — the repeated layer must be written once", len(names), names)
	}
}

// tarEntryNames lists an archive's entry names in order.
func tarEntryNames(t *testing.T, archive []byte) []string {
	t.Helper()
	var out []string
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("read exported archive: %v", err)
		}
		out = append(out, hdr.Name)
	}
}
