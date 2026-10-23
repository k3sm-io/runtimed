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
	"context"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestLoadedImageHasNoOperatorRootAndPruneDeletesIt pins CURRENT behaviour on
// purpose: an image ingested through LoadImage records an index entry but no
// operator root, so a prune with no pod using it reclaims its blobs and the
// entry stops resolving. A later change moves load and build onto the
// registry; the loaded-image assertions below are expected to flip then, and
// whoever flips them is changing the contract, not fixing a test.
//
// The control is a pulled image: PullImage records an operator root, so the
// same prune keeps its blobs.
func TestLoadedImageHasNoOperatorRootAndPruneDeletesIt(t *testing.T) {
	const pulledRef = "example.com/verbs:pulled"

	var pulledCfg string
	fp := &fakePuller{}
	client, rt := imagesTestClientDeps(t, Deps{Puller: fp})

	// Loaded image.
	_, cfg, layer := loadFixture(t, client, verbRef)
	list, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{Reference: verbRef})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(list.GetImages()) != 1 {
		t.Fatalf("ListImages(%q) = %v, want the loaded image", verbRef, list.GetImages())
	}
	roots, err := rt.cache.OperatorImageRoots()
	if err != nil {
		t.Fatalf("OperatorImageRoots: %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("OperatorImageRoots = %v after a load, want none", roots)
	}

	// Control: a pulled image whose blobs are really in the store.
	pulledCfg = putBlob(t, rt, "pulled-config")
	pulledLayer := putBlob(t, rt, "pulled-layer")
	fp.manifest = &runtimev1.ImageManifest{
		Reference: pulledRef,
		Config:    &runtimev1.Descriptor{Digest: pulledCfg, Size: int64(len("pulled-config"))},
		Layers:    []*runtimev1.Descriptor{{Digest: pulledLayer, Size: int64(len("pulled-layer"))}},
	}
	fp.descriptor = &runtimev1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:" + hexOf("pulled-manifest"),
		Size:      56,
	}
	if _, err := client.PullImage(context.Background(), &runtimev1.PullImageRequest{Reference: pulledRef}); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	roots, err = rt.cache.OperatorImageRoots()
	if err != nil {
		t.Fatalf("OperatorImageRoots: %v", err)
	}
	if len(roots) != 1 || roots[0].Reference != pulledRef {
		t.Fatalf("OperatorImageRoots = %v, want exactly the pulled image's root", roots)
	}

	ageBlobs(t, rt)
	prune, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{})
	if err != nil {
		t.Fatalf("PruneImages: %v", err)
	}

	for _, d := range []string{cfg, layer} {
		if !contains(prune.GetRemovedDigests(), d) {
			t.Errorf("loaded blob %s not reported removed (%v)", d, prune.GetSkipped())
		}
		if rt.cache.Has(d) {
			t.Errorf("loaded blob %s survived a prune with no root and no pod", d)
		}
	}
	// Prune reclaims blobs, not index entries: the entry is left DANGLING, its
	// manifest naming blobs that are gone. Pinned as observed; it is part of
	// what the registry move is expected to change.
	idx, err := image.NewFileIndex(rt.cache)
	if err != nil {
		t.Fatalf("open image index: %v", err)
	}
	if _, ok, err := idx.Lookup(context.Background(), verbRef, nativeLoadPolicy()); err != nil {
		t.Fatalf("index lookup: %v", err)
	} else if !ok {
		t.Errorf("the index entry for %q was removed by the prune; it was left dangling when this was pinned", verbRef)
	}

	for _, d := range []string{pulledCfg, pulledLayer} {
		if contains(prune.GetRemovedDigests(), d) || !rt.cache.Has(d) {
			t.Errorf("pulled blob %s was reclaimed despite its operator root", d)
		}
	}
}
