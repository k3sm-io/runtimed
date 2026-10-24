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

// TestLoadedImageHasNoOperatorRootAndPruneDeletesIt pins that an image
// ingested into the store records an index entry but no operator root, so a
// prune with no pod using it reclaims its blobs. The pull side of the same
// contract, and the control that a recorded root still keeps its blobs, is
// TestPullImageRecordsNoOperatorRoot.
func TestLoadedImageHasNoOperatorRootAndPruneDeletesIt(t *testing.T) {
	client, rt := imagesTestClient(t)

	// Loaded image.
	_, cfg, layer := loadFixture(t, rt, verbRef)
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

}
