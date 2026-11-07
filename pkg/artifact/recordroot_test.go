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
	"slices"
	"testing"

	"k3sm.io/runtimed/pkg/image"
)

// TestRecordDecodesAsGCRoot pins the field-name contract between the record
// this package writes and the GC root pkg/image reads from it: a renamed JSON
// tag would leave every artifact's blobs unrooted.
func TestRecordDecodesAsGCRoot(t *testing.T) {
	cfg := "sha256:" + string(make64('c'))
	layers := []string{"sha256:" + string(make64('a')), "sha256:" + string(make64('b'))}
	buf, err := json.Marshal(Record{Schema: recordSchema, Key: "k", Reference: testRef,
		ArtifactType: "t", ManifestDigest: "sha256:" + string(make64('d')), ConfigDigest: cfg, LayerDigests: layers})
	if err != nil {
		t.Fatal(err)
	}
	root, err := image.DecodeArtifactRoot(buf)
	if err != nil {
		t.Fatalf("DecodeArtifactRoot: %v", err)
	}
	if root.Config != cfg || !slices.Equal(root.Layers, layers) || root.Reference != testRef {
		t.Fatalf("root = %+v; want config %s, layers %v", root, cfg, layers)
	}
	// pkg/image classes a record's blobs by this field (StoreBytesByClass and
	// the reclaim order); a renamed tag would class every artifact as untyped.
	var fields map[string]any
	if err := json.Unmarshal(buf, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["artifactType"] != "t" {
		t.Fatalf("record fields = %v; want artifactType %q", fields, "t")
	}
}

func make64(c byte) []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return b
}
