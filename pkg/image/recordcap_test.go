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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// padJSON pads a valid JSON document with trailing whitespace to exactly size
// bytes, so only a size cap can refuse it.
func padJSON(t *testing.T, doc string, size int) []byte {
	t.Helper()
	if len(doc) > size {
		t.Fatalf("document is %d bytes, larger than the %d asked for", len(doc), size)
	}
	buf := bytes.Repeat([]byte(" "), size)
	copy(buf, doc)
	return buf
}

// recordCapIndexEntry records a small valid index entry and returns its path.
func recordCapIndexEntry(t *testing.T, idx *FileIndex, ref string, p Platform) string {
	t.Helper()
	raw := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(raw)
	e := IndexEntry{
		Reference: ref,
		Platform:  p,
		Manifest:  &runtimev1.ImageManifest{Reference: ref},
		Descriptor: &runtimev1.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    "sha256:" + hex.EncodeToString(sum[:]),
			Size:      int64(len(raw)),
		},
		ManifestRaw: raw,
	}
	if err := idx.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return filepath.Join(idx.dir, entryName(ref, p))
}

// TestRecordReadsEnforceTheirOwnCap pins, per record kind, that a record at
// its read cap is not refused for size and one byte over is refused with the
// error that kind's callers expect, and that a symlink at the record path is
// refused. Index entries are capped at 64 MiB (maxIndexEntryBytes), a constant
// the reader takes with no seam, so its over-cap row is not pinned here: it
// would allocate 64 MiB per row under -race. Its symlink row is.
func TestRecordReadsEnforceTheirOwnCap(t *testing.T) {
	t.Parallel()

	t.Run("pod references at the cap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), PodReferencesName)
		if err := os.WriteFile(path, padJSON(t, `{}`, maxPodReferencesBytes), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkPodReferences(path); err != nil {
			t.Fatalf("checkPodReferences at the cap = %v; want nil", err)
		}
	})
	t.Run("pod references one byte over the cap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), PodReferencesName)
		if err := os.WriteFile(path, padJSON(t, `{}`, maxPodReferencesBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		err := checkPodReferences(path)
		want := fmt.Sprintf("exceeds %d bytes", maxPodReferencesBytes)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("checkPodReferences one over = %v; want a refusal containing %q", err, want)
		}
	})

	t.Run("bounded read", func(t *testing.T) {
		t.Parallel()
		const limit = 1024
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "at"), bytes.Repeat([]byte("x"), limit), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "over"), bytes.Repeat([]byte("x"), limit+1), 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		buf, err := readAnchored(root, "at", limit)
		if err != nil || len(buf) != limit {
			t.Fatalf("readAnchored at the limit = (%d bytes, %v); want all %d bytes", len(buf), err, limit)
		}
		want := fmt.Sprintf("exceeds %d bytes", limit)
		if _, err := readAnchored(root, "over", limit); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("readAnchored one over = %v; want a refusal containing %q", err, want)
		}
	})

	artifactPath := func(t *testing.T, key string) (*FileIndex, string) {
		t.Helper()
		_, idx := newIndexedCache(t)
		// Create the artifact namespace with a real record, then replace it.
		if err := idx.PutArtifactRecord(context.Background(), key, []byte(`{}`)); err != nil {
			t.Fatalf("PutArtifactRecord: %v", err)
		}
		return idx, filepath.Join(idx.dir, ArtifactIndexSubdir, artifactEntryName(key))
	}
	t.Run("artifact record at the cap", func(t *testing.T) {
		idx, path := artifactPath(t, "k")
		if err := os.WriteFile(path, padJSON(t, `{}`, MaxArtifactRecordBytes), 0o600); err != nil {
			t.Fatal(err)
		}
		buf, ok, err := idx.ArtifactRecord(context.Background(), "k")
		if err != nil || !ok || len(buf) != MaxArtifactRecordBytes {
			t.Fatalf("ArtifactRecord at the cap = (%d bytes, %v, %v); want the whole record", len(buf), ok, err)
		}
	})
	// Pins the caller-visible refusal from the size pre-check; the read's own
	// bound is pinned by the "bounded read" row below.
	t.Run("artifact record one byte over the cap", func(t *testing.T) {
		idx, path := artifactPath(t, "k")
		if err := os.WriteFile(path, padJSON(t, `{}`, MaxArtifactRecordBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := idx.ArtifactRecord(context.Background(), "k")
		if !errors.Is(err, ErrArtifactRecordTooLarge) || !errors.Is(err, ErrIndexEntryCorrupt) {
			t.Fatalf("ArtifactRecord one over = %v; want ErrArtifactRecordTooLarge and ErrIndexEntryCorrupt", err)
		}
	})
	t.Run("artifact record symlink", func(t *testing.T) {
		t.Parallel()
		idx, path := artifactPath(t, "k")
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		buf, ok, err := idx.ArtifactRecord(context.Background(), "k")
		if !errors.Is(err, ErrIndexEntryCorrupt) || ok || buf != nil {
			t.Fatalf("ArtifactRecord via symlink = (%q, %v, %v); want ErrIndexEntryCorrupt", buf, ok, err)
		}
	})

	t.Run("index entry symlink", func(t *testing.T) {
		t.Parallel()
		const ref = "example.com/img:v1"
		p := Platform{OS: "darwin", Architecture: "arm64"}
		_, idx := newIndexedCache(t)
		path := recordCapIndexEntry(t, idx, ref, p)
		// The real record must be readable before it is swapped for a link.
		if _, ok, err := idx.Lookup(context.Background(), ref, nativePolicy()); err != nil || !ok {
			t.Fatalf("Lookup of the planted entry = (%v, %v); want it found", ok, err)
		}
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		_, ok, err := idx.Lookup(context.Background(), ref, nativePolicy())
		if !errors.Is(err, ErrIndexEntryCorrupt) || ok {
			t.Fatalf("Lookup via symlink = (%v, %v); want ErrIndexEntryCorrupt", ok, err)
		}
	})
}
