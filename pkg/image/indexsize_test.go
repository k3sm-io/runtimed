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
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestIndexEntryAtTheWriterLimitIsReadable pins that the read cap on an index
// entry is no tighter than what Record accepts. The manifest carries one large
// annotation, so it appears twice in the entry: base64 in manifestRaw (just
// under maxIndexManifestBytes) and again in the protojson copy. That entry is
// over 8 MiB; a read capped at maxPodReferencesBytes refuses it and List then
// fails for every entry on the node.
func TestIndexEntryAtTheWriterLimitIsReadable(t *testing.T) {
	const ref = "example.com/big:v1"
	p := Platform{OS: "darwin", Architecture: "arm64"}

	const prefix = `{"schemaVersion":2,"annotations":{"pad":"`
	const suffix = `"}}`
	pad := strings.Repeat("a", maxIndexManifestBytes-len(prefix)-len(suffix)-1)
	raw := []byte(prefix + pad + suffix)
	if len(raw) >= maxIndexManifestBytes {
		t.Fatalf("fixture manifest is %d bytes, want under %d", len(raw), maxIndexManifestBytes)
	}
	sum := sha256.Sum256(raw)
	desc := &runtimev1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Size:      int64(len(raw)),
	}

	_, idx := newIndexedCache(t)
	e := IndexEntry{
		Reference:   ref,
		Platform:    p,
		Manifest:    &runtimev1.ImageManifest{Reference: ref, Annotations: map[string]string{"pad": pad}},
		Descriptor:  desc,
		ManifestRaw: raw,
	}
	if err := idx.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// The fixture is only meaningful if the entry the writer accepted is over
	// the old 8 MiB read cap.
	fi, err := os.Stat(filepath.Join(idx.dir, entryName(ref, p)))
	if err != nil {
		t.Fatalf("stat entry: %v", err)
	}
	if fi.Size() <= maxPodReferencesBytes {
		t.Fatalf("entry is %d bytes, want over %d for this row to bite", fi.Size(), maxPodReferencesBytes)
	}

	got, ok, err := idx.Lookup(context.Background(), ref, nativePolicy())
	if err != nil || !ok {
		t.Fatalf("Lookup = (_, %v, %v), want the recorded entry", ok, err)
	}
	if string(got.ManifestRaw) != string(raw) {
		t.Errorf("Lookup retained bytes differ from the recorded manifest")
	}
	list, err := idx.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Reference != ref {
		t.Errorf("List = %d entries, want exactly the recorded one", len(list))
	}
}
