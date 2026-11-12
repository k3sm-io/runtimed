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
	"runtime"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRecordRefusesEntryOverReadLimit pins that the writer refuses an entry its
// own reader would refuse: an over-limit entry on disk fails List for the whole
// node, so it must never be committed.
func TestRecordRefusesEntryOverReadLimit(t *testing.T) {
	t.Run("the helper refuses only what exceeds the limit", func(t *testing.T) {
		for _, tc := range []struct {
			n       int
			refused bool
		}{
			{n: 0}, {n: 15}, {n: 16}, {n: 17, refused: true}, {n: 1024, refused: true},
		} {
			err := checkEntrySize(make([]byte, tc.n), 16)
			if got := errors.Is(err, ErrIndexEntryTooLarge); got != tc.refused {
				t.Errorf("checkEntrySize(%d bytes, 16) = %v; want refused=%v", tc.n, err, tc.refused)
			}
			if tc.refused && !strings.Contains(err.Error(), "limit 16") {
				t.Errorf("checkEntrySize error %q does not state the limit", err)
			}
		}
	})

	t.Run("record refuses an over-limit entry and writes no file", func(t *testing.T) {
		_, idx := newIndexedCache(t)
		old := indexEntryLimit
		indexEntryLimit = 64
		t.Cleanup(func() { indexEntryLimit = old })

		const ref = "example.com/app:big"
		p := Platform{OS: "darwin", Architecture: "arm64"}
		raw, desc := manifestBytes("over-the-lowered-limit")
		err := idx.Record(context.Background(), IndexEntry{
			Reference:   ref,
			Platform:    p,
			Manifest:    &runtimev1.ImageManifest{Reference: ref},
			Descriptor:  desc,
			ManifestRaw: raw,
		})
		if !errors.Is(err, ErrIndexEntryTooLarge) {
			t.Fatalf("Record over the limit = %v; want ErrIndexEntryTooLarge", err)
		}
		if strings.Contains(err.Error(), idx.dir) {
			t.Errorf("error %q leaks the index path", err)
		}
		if _, err := os.Lstat(filepath.Join(idx.dir, entryName(ref, p))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("entry file after a refused Record: Lstat = %v; want not-exist", err)
		}
		left, err := os.ReadDir(idx.dir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		for _, d := range left {
			if !d.IsDir() {
				t.Errorf("refused Record left %q in the index", d.Name())
			}
		}
	})
}

// TestRecordAcceptsTheEscapeWorstCase pins that the read limit is wide enough
// for the largest entry the writer can legitimately produce: a manifest just
// under maxIndexManifestBytes whose annotation is all '<', which encoding/json
// HTML-escapes to six bytes each in the protojson manifest, while the retained
// raw bytes travel base64-encoded.
func TestRecordAcceptsTheEscapeWorstCase(t *testing.T) {
	_, idx := newIndexedCache(t)
	const ref = "example.com/app:escape"
	p := Platform{OS: "darwin", Architecture: runtime.GOARCH}

	prefix := `{"schemaVersion":2,"annotations":{"a":"`
	suffix := `"}}`
	value := strings.Repeat("<", maxIndexManifestBytes-1-len(prefix)-len(suffix))
	raw := []byte(prefix + value + suffix)
	if len(raw) != maxIndexManifestBytes-1 {
		t.Fatalf("fixture is %d bytes; want %d", len(raw), maxIndexManifestBytes-1)
	}
	sum := sha256.Sum256(raw)
	desc := &runtimev1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Size:      int64(len(raw)),
	}
	e := IndexEntry{
		Reference: ref,
		Platform:  p,
		Manifest: &runtimev1.ImageManifest{
			Reference:   ref,
			Annotations: map[string]string{"a": value},
		},
		Descriptor:  desc,
		ManifestRaw: raw,
	}
	if err := idx.Record(context.Background(), e); err != nil {
		t.Fatalf("Record(worst case): %v", err)
	}
	fi, err := os.Stat(filepath.Join(idx.dir, entryName(ref, p)))
	if err != nil {
		t.Fatalf("stat entry: %v", err)
	}
	t.Logf("worst-case entry: %d bytes on disk (read limit %d)", fi.Size(), maxIndexEntryBytes)

	got, ok, err := idx.Lookup(context.Background(), ref, nativePolicy())
	if err != nil || !ok {
		t.Fatalf("Lookup(worst case) = ok %v, err %v; want found", ok, err)
	}
	if got.Manifest.GetAnnotations()["a"] != value || string(got.ManifestRaw) != string(raw) {
		t.Errorf("Lookup did not read back the recorded manifest verbatim")
	}
	all, err := idx.List(context.Background())
	if err != nil {
		t.Fatalf("List(worst case): %v", err)
	}
	if len(all) != 1 || all[0].Reference != ref {
		t.Errorf("List = %d entries; want the one worst-case entry", len(all))
	}
}
