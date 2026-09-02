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

// testPlatform is the platform every index record in this file is keyed under.
var testPlatform = image.Platform{OS: "darwin", Architecture: "arm64"}

// TestListImagesEnumeratesTheIndex is B198's gate: the listing enumerates the
// ref->digest index, so an image this node holds is visible whether or not a
// pod happens to reference it — while the GC's reachability semantics are
// untouched.
//
// # The counterfactual it pins
//
// The M8 lab session loaded an mlx-serve archive: `k3sm image df` measured its
// 1.5 GiB and `k3sm image ls` printed nothing, because the listing walked
// Cache.Roots — the per-pod reachability set — and a freshly imported image has
// no pod behind it. That is not a display bug; it is the listing answering a
// different question from the one asked.
//
// # Why the second half is here
//
// Moving the listing source is only safe if it does not move the GC's. The
// prune subtest is not decoration: it asserts through the same prune seam an
// operator uses that a listed-but-unrooted image is still reclaim-eligible, so
// a future change that "fixed" the listing by making an index entry a root
// would go red here rather than silently turning every `image ls` row into
// content the node can never reclaim.
func TestListImagesEnumeratesTheIndex(t *testing.T) {
	t.Run("an imported image with no pod root is listed", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		cfg := putBlob(t, rt, "imported config")
		layer := putBlob(t, rt, "imported layer")
		recordIndex(t, rt, "example.test/mlx-serve:v1", cfg, layer)

		// The counterfactual, asserted rather than assumed: nothing roots this
		// image, which is precisely why a roots-based listing could not see it.
		roots, err := rt.cache.Roots()
		if err != nil {
			t.Fatalf("Roots: %v", err)
		}
		if len(roots) != 0 {
			t.Fatalf("Roots = %v, want none (the image is imported, not referenced)", roots)
		}

		list, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{})
		if err != nil {
			t.Fatalf("ListImages: %v", err)
		}
		if len(list.GetImages()) != 1 {
			t.Fatalf("ListImages returned %d images; want the imported one", len(list.GetImages()))
		}
		got := list.GetImages()[0].GetManifest()
		if got.GetReference() != "example.test/mlx-serve:v1" || got.GetConfig().GetDigest() != cfg {
			t.Errorf("listed image = %v; want the recorded reference and config digest", got)
		}
		if len(got.GetLayers()) != 1 || got.GetLayers()[0].GetDigest() != layer {
			t.Errorf("listed layers = %v; want the recorded layer digest", got.GetLayers())
		}
	})

	t.Run("an image a pod references is listed too", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		cfg := putBlob(t, rt, "rooted config")
		recordIndex(t, rt, "example.test/app:v1", cfg)
		putPod(t, rt, "pod-a", image.ImageRoot{Reference: "example.test/app:v1", Config: cfg})

		list, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{})
		if err != nil {
			t.Fatalf("ListImages: %v", err)
		}
		if len(list.GetImages()) != 1 || list.GetImages()[0].GetManifest().GetReference() != "example.test/app:v1" {
			t.Fatalf("ListImages = %v; want the referenced image", list.GetImages())
		}
	})

	t.Run("the reference filter is exact", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		a := putBlob(t, rt, "config a")
		b := putBlob(t, rt, "config b")
		recordIndex(t, rt, "example.test/a:v1", a)
		recordIndex(t, rt, "example.test/b:v1", b)

		list, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{Reference: "example.test/b:v1"})
		if err != nil {
			t.Fatalf("ListImages: %v", err)
		}
		if len(list.GetImages()) != 1 || list.GetImages()[0].GetManifest().GetConfig().GetDigest() != b {
			t.Fatalf("filtered listing = %v; want only example.test/b:v1", list.GetImages())
		}
		none, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{Reference: "example.test/absent:v1"})
		if err != nil {
			t.Fatalf("ListImages(absent): %v", err)
		}
		if len(none.GetImages()) != 0 {
			t.Errorf("filter on an unrecorded reference returned %d images; want 0", len(none.GetImages()))
		}
	})

	t.Run("a listed image with no pod root stays reclaim-eligible", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		cfg := putBlob(t, rt, "reclaimable config")
		layer := putBlob(t, rt, "reclaimable layer")
		recordIndex(t, rt, "example.test/mlx-serve:v1", cfg, layer)

		// Listed...
		list, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{})
		if err != nil {
			t.Fatalf("ListImages: %v", err)
		}
		if len(list.GetImages()) != 1 {
			t.Fatalf("ListImages returned %d images; want 1", len(list.GetImages()))
		}

		// ...and still unreferenced, as the GC sees it. The dry run is the
		// operator's own seam, so this is the reachability verdict the real
		// reclaim would act on — not a re-derivation of it.
		prune, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{DryRun: true})
		if err != nil {
			t.Fatalf("PruneImages: %v", err)
		}
		for _, d := range []string{cfg, layer} {
			if !contains(prune.GetRemovedDigests(), d) {
				t.Errorf("prune would keep %s (skipped: %v); a listed image with no root must stay reclaim-eligible",
					d, prune.GetSkipped())
			}
		}
		if !rt.cache.Has(cfg) {
			t.Error("dry run DELETED a blob")
		}
	})
}

// recordIndex records a ref->manifest index entry the way a pull or an archive
// ingest does, and returns the manifest.
//
// It writes through the daemon's own index (rt.index) — the same instance the
// puller and the loader hold — so a test cannot go green against a listing
// bound to a second, private index.
func recordIndex(t *testing.T, rt *Runtime, ref, config string, layers ...string) *runtimev1.ImageManifest {
	t.Helper()
	mfst := &runtimev1.ImageManifest{
		Reference: ref,
		Config:    &runtimev1.Descriptor{Digest: config},
	}
	for _, l := range layers {
		mfst.Layers = append(mfst.Layers, &runtimev1.Descriptor{Digest: l})
	}
	if err := rt.index.Record(context.Background(), image.IndexEntry{
		Reference: ref,
		Platform:  testPlatform,
		Manifest:  mfst,
	}); err != nil {
		t.Fatalf("index.Record(%q): %v", ref, err)
	}
	return mfst
}
