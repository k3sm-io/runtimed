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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// manifestBytes is a stand-in manifest document. Its CONTENT is irrelevant to
// the index — the index retains bytes and re-checks them against the digest it
// was handed — so a fixture that is not a real manifest keeps these rows about
// the retention rules and nothing else.
func manifestBytes(tag string) ([]byte, *runtimev1.Descriptor) {
	raw := []byte(`{"schemaVersion":2,"fixture":"` + tag + `"}`)
	sum := sha256.Sum256(raw)
	return raw, &runtimev1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Size:      int64(len(raw)),
	}
}

// recordEntry writes one entry with retained manifest bytes and returns it.
func recordEntry(t *testing.T, idx *FileIndex, ref string, p Platform, tag string) IndexEntry {
	t.Helper()
	raw, desc := manifestBytes(tag)
	e := IndexEntry{
		Reference:   ref,
		Platform:    p,
		Manifest:    &runtimev1.ImageManifest{Reference: ref},
		Descriptor:  desc,
		ManifestRaw: raw,
	}
	if err := idx.Record(context.Background(), e); err != nil {
		t.Fatalf("Record(%q, %s): %v", ref, p, err)
	}
	return e
}

// TestIndexRetainsTheManifest pins the retention contract: the descriptor and
// the bytes travel together, the bytes must hash to the digest, and a record
// that keeps half of the pair is unreadable rather than half-believed.
//
// The pair rule is what makes an export safe. A record carrying a digest with no
// bytes would let a reader report an image id it cannot produce; one carrying
// bytes with no digest would let an export emit content nothing checked.
func TestIndexRetainsTheManifest(t *testing.T) {
	const ref = "example.com/app:v1"
	p := Platform{OS: "darwin", Architecture: "arm64"}
	raw, desc := manifestBytes("retained")

	t.Run("a recorded manifest survives a reopen verbatim", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		recordEntry(t, idx, ref, p, "retained")
		reopened, err := NewFileIndex(cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		got, ok, err := reopened.Get(context.Background(), ref, p)
		if err != nil || !ok {
			t.Fatalf("Get = (%v, %v, %v), want the recorded entry", got, ok, err)
		}
		if got.Descriptor.GetDigest() != desc.Digest || got.Descriptor.GetSize() != desc.Size {
			t.Errorf("descriptor = %v, want %v", got.Descriptor, desc)
		}
		if string(got.ManifestRaw) != string(raw) {
			t.Errorf("retained bytes = %q, want %q", got.ManifestRaw, raw)
		}
	})

	t.Run("half a pair is refused at write", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		cases := []struct {
			name string
			e    IndexEntry
		}{
			{"descriptor_without_bytes", IndexEntry{
				Reference: ref, Platform: p,
				Manifest: &runtimev1.ImageManifest{Reference: ref}, Descriptor: desc,
			}},
			{"bytes_without_descriptor", IndexEntry{
				Reference: ref, Platform: p,
				Manifest: &runtimev1.ImageManifest{Reference: ref}, ManifestRaw: raw,
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := idx.Record(context.Background(), tc.e); err == nil {
					t.Error("Record accepted half of the descriptor/bytes pair")
				}
			})
		}
	})

	t.Run("bytes that do not hash to the digest are refused at write", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		other, _ := manifestBytes("other")
		err := idx.Record(context.Background(), IndexEntry{
			Reference: ref, Platform: p,
			Manifest:    &runtimev1.ImageManifest{Reference: ref},
			Descriptor:  &runtimev1.Descriptor{Digest: desc.Digest, Size: int64(len(other))},
			ManifestRaw: other,
		})
		if err == nil {
			t.Fatal("Record accepted manifest bytes that do not hash to the claimed digest")
		}
	})

	t.Run("a record whose bytes were tampered with reads back as corrupt", func(t *testing.T) {
		cache, idx := newIndexedCache(t)
		recordEntry(t, idx, ref, p, "retained")
		// Flip one byte of the RETAINED manifest in place. The consistency check
		// is re-run on every read, so this is caught at Get rather than at the
		// export that would otherwise have shipped it.
		name := entryName(ref, p)
		path := filepath.Join(cache.IndexRoot(), name)
		buf, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read entry: %v", err)
		}
		// Substitute a DIFFERENT valid digest for the retained bytes. That is the
		// realistic shape of the attack the check exists for — a record rewritten
		// so an export would ship these bytes under someone else's id — and it is
		// caught on read rather than at the export that would have shipped it.
		zeroDigest := "sha256:" + hex.EncodeToString(make([]byte, 32))
		mutated := strings.Replace(string(buf), desc.Digest, zeroDigest, 1)
		if mutated == string(buf) {
			t.Fatalf("the fixture digest %s is not present in the record; the tamper did nothing", desc.Digest)
		}
		if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
			t.Fatalf("write entry: %v", err)
		}
		if _, _, err := idx.Get(context.Background(), ref, p); !errors.Is(err, ErrIndexEntryCorrupt) {
			t.Fatalf("Get after tampering = %v, want ErrIndexEntryCorrupt", err)
		}
	})

	t.Run("an entry with no retained manifest is readable and reports no digest", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		// The pre-retention shape: the index must keep reading it, because a
		// daemon upgrade must not orphan every reference the node already has.
		if err := idx.Record(context.Background(), IndexEntry{
			Reference: ref, Platform: p, Manifest: &runtimev1.ImageManifest{Reference: ref},
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
		got, ok, err := idx.Get(context.Background(), ref, p)
		if err != nil || !ok {
			t.Fatalf("Get = (%v, %v, %v), want the pre-retention entry", got, ok, err)
		}
		if got.Descriptor != nil || got.ManifestRaw != nil {
			t.Errorf("entry = %+v, want no descriptor and no bytes", got)
		}
		// And it is unnameable BY DIGEST, rather than matching some invented one.
		if _, err := idx.ResolveDigest(context.Background(), desc.Digest); !errors.Is(err, ErrIndexEntryNotFound) {
			t.Errorf("ResolveDigest = %v, want ErrIndexEntryNotFound for an entry that retained no manifest", err)
		}
	})
}

// TestIndexResolveTargets pins the shared target resolution every image verb
// uses: an exact key, a reference with one entry, a reference with several, an
// absent key, and a digest.
func TestIndexResolveTargets(t *testing.T) {
	darwin := Platform{OS: "darwin", Architecture: "arm64"}
	linux := Platform{OS: "linux", Architecture: "arm64"}
	const ref = "example.com/app:v1"
	ctx := context.Background()

	t.Run("a reference with one entry resolves without a platform", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		want := recordEntry(t, idx, ref, darwin, "one")
		got, err := idx.Resolve(ctx, ref, nil)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got.Descriptor.GetDigest() != want.Descriptor.GetDigest() || got.Platform != darwin.Normalize() {
			t.Errorf("Resolve = %+v, want the single darwin entry", got)
		}
	})

	t.Run("a reference with two entries is ambiguous, never a pick", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		recordEntry(t, idx, ref, darwin, "one")
		recordEntry(t, idx, ref, linux, "two")
		if _, err := idx.Resolve(ctx, ref, nil); !errors.Is(err, ErrIndexEntryAmbiguous) {
			t.Fatalf("Resolve = %v, want ErrIndexEntryAmbiguous", err)
		}
		// Naming the platform disambiguates it.
		got, err := idx.Resolve(ctx, ref, &linux)
		if err != nil {
			t.Fatalf("Resolve(linux): %v", err)
		}
		if got.Platform != linux.Normalize() {
			t.Errorf("Resolve(linux) platform = %s, want linux/arm64", got.Platform)
		}
	})

	t.Run("an absent key and an absent reference are both not-found", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		recordEntry(t, idx, ref, darwin, "one")
		if _, err := idx.Resolve(ctx, ref, &linux); !errors.Is(err, ErrIndexEntryNotFound) {
			t.Errorf("Resolve(absent platform) = %v, want ErrIndexEntryNotFound", err)
		}
		if _, err := idx.Resolve(ctx, "example.com/nothing:v1", nil); !errors.Is(err, ErrIndexEntryNotFound) {
			t.Errorf("Resolve(absent reference) = %v, want ErrIndexEntryNotFound", err)
		}
	})

	t.Run("a digest resolves to the content, whatever it is named", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		want := recordEntry(t, idx, ref, darwin, "one")
		got, err := idx.ResolveDigest(ctx, want.Descriptor.GetDigest())
		if err != nil {
			t.Fatalf("ResolveDigest: %v", err)
		}
		if got.Reference != ref {
			t.Errorf("ResolveDigest reference = %q, want %q", got.Reference, ref)
		}
		if _, err := idx.ResolveDigest(ctx, "sha256:"+hex.EncodeToString(make([]byte, 32))); !errors.Is(err, ErrIndexEntryNotFound) {
			t.Errorf("ResolveDigest(unknown) = %v, want ErrIndexEntryNotFound", err)
		}
		if _, err := idx.ResolveDigest(ctx, "not-a-digest"); err == nil {
			t.Error("ResolveDigest accepted a malformed digest")
		}
	})

	t.Run("Get is exact and never walks a platform policy", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		recordEntry(t, idx, ref, linux, "two")
		// Lookup would serve this entry to a vm policy; Get for the darwin key
		// must not serve it at all — the two questions are different.
		if _, ok, err := idx.Get(ctx, ref, darwin); ok || err != nil {
			t.Fatalf("Get(darwin) = (%v, %v), want a clean miss with a linux entry recorded", ok, err)
		}
	})
}

// TestIndexRemoveTakesOneEntry pins the untag write: exactly one key goes, the
// sibling platform stays, and a second removal is false rather than an error.
func TestIndexRemoveTakesOneEntry(t *testing.T) {
	darwin := Platform{OS: "darwin", Architecture: "arm64"}
	linux := Platform{OS: "linux", Architecture: "arm64"}
	const ref = "example.com/app:v1"
	ctx := context.Background()

	_, idx := newIndexedCache(t)
	recordEntry(t, idx, ref, darwin, "one")
	recordEntry(t, idx, ref, linux, "two")

	removed, err := idx.Remove(ctx, ref, darwin)
	if err != nil || !removed {
		t.Fatalf("Remove = (%v, %v), want (true, nil)", removed, err)
	}
	if _, ok, err := idx.Get(ctx, ref, darwin); ok || err != nil {
		t.Errorf("Get after Remove = (%v, %v), want a clean miss", ok, err)
	}
	if _, ok, err := idx.Get(ctx, ref, linux); !ok || err != nil {
		t.Errorf("Get(linux) after removing darwin = (%v, %v), want the sibling entry intact", ok, err)
	}
	removed, err = idx.Remove(ctx, ref, darwin)
	if err != nil || removed {
		t.Errorf("second Remove = (%v, %v), want (false, nil)", removed, err)
	}
}

// TestIndexEntryTotalSize pins the measurement InspectImage reports: DISTINCT
// blobs, counted once, and a descriptor the entry does not carry contributing
// nothing rather than a guess.
func TestIndexEntryTotalSize(t *testing.T) {
	cases := []struct {
		name string
		e    IndexEntry
		want int64
	}{
		{
			name: "manifest plus config plus layers",
			e: IndexEntry{
				Descriptor: &runtimev1.Descriptor{Digest: "sha256:aa", Size: 10},
				Manifest: &runtimev1.ImageManifest{
					Config: &runtimev1.Descriptor{Digest: "sha256:bb", Size: 100},
					Layers: []*runtimev1.Descriptor{
						{Digest: "sha256:cc", Size: 1000},
						{Digest: "sha256:dd", Size: 10000},
					},
				},
			},
			want: 11110,
		},
		{
			name: "a repeated layer is counted once",
			e: IndexEntry{
				Descriptor: &runtimev1.Descriptor{Digest: "sha256:aa", Size: 10},
				Manifest: &runtimev1.ImageManifest{
					Config: &runtimev1.Descriptor{Digest: "sha256:bb", Size: 100},
					Layers: []*runtimev1.Descriptor{
						{Digest: "sha256:cc", Size: 1000},
						{Digest: "sha256:cc", Size: 1000},
					},
				},
			},
			want: 1110,
		},
		{
			name: "an entry with no retained manifest omits the manifest's bytes",
			e: IndexEntry{
				Manifest: &runtimev1.ImageManifest{
					Config: &runtimev1.Descriptor{Digest: "sha256:bb", Size: 100},
				},
			},
			want: 100,
		},
		{name: "the zero entry measures nothing", e: IndexEntry{}, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.TotalSize(); got != tc.want {
				t.Errorf("TotalSize = %d, want %d", got, tc.want)
			}
		})
	}
}
