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

package artifact

import (
	"encoding/json"
	"testing"
)

// FuzzSelectVariant fuzzes the index parse and selection over untrusted
// registry bytes, the served media type and the selector. It never panics,
// and a selection it returns is a well-formed OCI manifest descriptor that is
// the one entry of the decoded index carrying the selector. Committed seeds
// live in testdata/fuzz/FuzzSelectVariant.
func FuzzSelectVariant(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":10,"annotations":{"io.k3sm.model.variant":"8bit"}}]}`),
		mediaTypeOCIIndex, "8bit")
	f.Fuzz(func(t *testing.T, index []byte, mediaType, variant string) {
		got, err := SelectVariant(index, mediaType, variant)
		if err != nil {
			return
		}
		if !sha256Digest.MatchString(got.Digest) {
			t.Fatalf("digest %q is not sha256:<64 hex>", got.Digest)
		}
		if got.Size < 1 || got.Size > MaxManifestBytes {
			t.Fatalf("size %d outside 1..%d", got.Size, MaxManifestBytes)
		}
		if got.MediaType != mediaTypeOCIManifest {
			t.Fatalf("media type %q, want %s", got.MediaType, mediaTypeOCIManifest)
		}
		if variant == "" || len(variant) > MaxVariantLength || len(index) > MaxIndexBytes {
			t.Fatalf("selected under a selector of %d bytes or an index of %d bytes", len(variant), len(index))
		}
		var doc struct {
			Manifests []struct {
				Digest      string            `json:"digest"`
				Size        int64             `json:"size"`
				Annotations map[string]string `json:"annotations"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(index, &doc); err != nil {
			t.Fatalf("selected from an index that does not decode: %v", err)
		}
		if len(doc.Manifests) > MaxIndexEntries {
			t.Fatalf("selected from %d entries, at most %d", len(doc.Manifests), MaxIndexEntries)
		}
		matches := 0
		for _, m := range doc.Manifests {
			if m.Annotations[AnnotationVariant] == variant {
				matches++
				if m.Digest != got.Digest || m.Size != got.Size {
					t.Fatalf("selected %s/%d, the matching entry is %s/%d", got.Digest, got.Size, m.Digest, m.Size)
				}
			}
		}
		if matches != 1 {
			t.Fatalf("%d entries carry variant %q, want exactly 1", matches, variant)
		}
	})
}
