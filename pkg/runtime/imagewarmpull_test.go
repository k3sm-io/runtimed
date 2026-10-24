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
)

// TestWarmPullRecordsNoOperatorRoot pins that a cache_only pull warms the
// store without naming the image: it records no operator root, so a prune
// with no pod using it reclaims its blobs. A normal pull of another image in
// the same run still records its root and survives the same prune, and a
// cache_only pull of an already-rooted reference leaves that root in place
// ("add none", never "drop one").
func TestWarmPullRecordsNoOperatorRoot(t *testing.T) {
	const (
		warmRef   = "example.com/verbs:warm"
		pulledRef = "example.com/verbs:pulled"
	)
	ctx := context.Background()
	fp := &fakePuller{}
	client, rt := imagesTestClientDeps(t, Deps{Puller: fp})

	stage := func(ref, name string) (cfg, layer string) {
		cfg = putBlob(t, rt, name+"-config")
		layer = putBlob(t, rt, name+"-layer")
		fp.manifest = &runtimev1.ImageManifest{
			Reference: ref,
			Config:    &runtimev1.Descriptor{Digest: cfg, Size: int64(len(name + "-config"))},
			Layers:    []*runtimev1.Descriptor{{Digest: layer, Size: int64(len(name + "-layer"))}},
		}
		fp.descriptor = &runtimev1.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    "sha256:" + hexOf(name+"-manifest"),
			Size:      56,
		}
		return cfg, layer
	}
	rootRefs := func() []string {
		t.Helper()
		roots, err := rt.cache.OperatorImageRoots()
		if err != nil {
			t.Fatalf("OperatorImageRoots: %v", err)
		}
		var refs []string
		for _, r := range roots {
			refs = append(refs, r.Reference)
		}
		return refs
	}

	// A cache-only (warm) pull: no operator root.
	warmCfg, warmLayer := stage(warmRef, "warm")
	if _, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: warmRef, CacheOnly: true}); err != nil {
		t.Fatalf("PullImage(cache_only): %v", err)
	}
	if refs := rootRefs(); len(refs) != 0 {
		t.Fatalf("OperatorImageRoots = %v after a cache_only pull, want none", refs)
	}

	// A normal pull still records its root.
	pulledCfg, pulledLayer := stage(pulledRef, "pulled")
	if _, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: pulledRef}); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if refs := rootRefs(); len(refs) != 1 || refs[0] != pulledRef {
		t.Fatalf("OperatorImageRoots = %v after a normal pull, want exactly %q", refs, pulledRef)
	}

	// A cache_only pull of the rooted reference adds none and drops none.
	if _, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: pulledRef, CacheOnly: true}); err != nil {
		t.Fatalf("PullImage(cache_only, rooted ref): %v", err)
	}
	if refs := rootRefs(); len(refs) != 1 || refs[0] != pulledRef {
		t.Fatalf("OperatorImageRoots = %v after a cache_only re-pull, want the existing root %q kept", refs, pulledRef)
	}

	// With no pod holding either image, prune reclaims the warm image only.
	ageBlobs(t, rt)
	prune, err := client.PruneImages(ctx, &runtimev1.PruneImagesRequest{})
	if err != nil {
		t.Fatalf("PruneImages: %v", err)
	}
	for _, d := range []string{warmCfg, warmLayer} {
		if !contains(prune.GetRemovedDigests(), d) {
			t.Errorf("warm blob %s not reported removed (%v)", d, prune.GetSkipped())
		}
		if rt.cache.Has(d) {
			t.Errorf("warm blob %s survived a prune with no root and no pod", d)
		}
	}
	for _, d := range []string{pulledCfg, pulledLayer} {
		if contains(prune.GetRemovedDigests(), d) || !rt.cache.Has(d) {
			t.Errorf("pulled blob %s was reclaimed despite its operator root", d)
		}
	}
}
