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

// TestPullImageRecordsNoOperatorRoot pins that every pull is a cache warm: a
// normal pull and a cache_only pull alike record no operator root, so a prune
// with no pod using either reclaims both. A root an older daemon recorded for a
// reference is neither dropped nor duplicated by a later pull of it ("add none,
// remove none").
func TestPullImageRecordsNoOperatorRoot(t *testing.T) {
	const (
		warmRef   = "example.com/verbs:warm"
		pulledRef = "example.com/verbs:pulled"
		legacyRef = "example.com/verbs:legacy"
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

	warmCfg, warmLayer := stage(warmRef, "warm")
	if _, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: warmRef, CacheOnly: true}); err != nil {
		t.Fatalf("PullImage(cache_only): %v", err)
	}
	if refs := rootRefs(); len(refs) != 0 {
		t.Fatalf("OperatorImageRoots = %v after a cache_only pull, want none", refs)
	}

	pulledCfg, pulledLayer := stage(pulledRef, "pulled")
	if _, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: pulledRef}); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if refs := rootRefs(); len(refs) != 0 {
		t.Fatalf("OperatorImageRoots = %v after a normal pull, want none", refs)
	}

	// A root an older daemon recorded survives a re-pull of its reference.
	legacyCfg, legacyLayer := stage(legacyRef, "legacy")
	if err := rt.cache.RecordOperatorImage(legacyRef, image.Platform{OS: "darwin", Architecture: "arm64"},
		image.ImageRoot{Reference: legacyRef, Config: legacyCfg, Layers: []string{legacyLayer}}); err != nil {
		t.Fatalf("RecordOperatorImage: %v", err)
	}
	if _, err := client.PullImage(ctx, &runtimev1.PullImageRequest{Reference: legacyRef}); err != nil {
		t.Fatalf("PullImage(legacy): %v", err)
	}
	if refs := rootRefs(); len(refs) != 1 || refs[0] != legacyRef {
		t.Fatalf("OperatorImageRoots = %v after re-pulling a rooted reference, want the existing root %q kept", refs, legacyRef)
	}

	// With no pod holding them, prune reclaims both pulled images.
	ageBlobs(t, rt)
	prune, err := client.PruneImages(ctx, &runtimev1.PruneImagesRequest{})
	if err != nil {
		t.Fatalf("PruneImages: %v", err)
	}
	for _, d := range []string{warmCfg, warmLayer, pulledCfg, pulledLayer} {
		if !contains(prune.GetRemovedDigests(), d) {
			t.Errorf("pulled blob %s not reported removed (%v)", d, prune.GetSkipped())
		}
		if rt.cache.Has(d) {
			t.Errorf("pulled blob %s survived a prune with no root and no pod", d)
		}
	}
	for _, d := range []string{legacyCfg, legacyLayer} {
		if !rt.cache.Has(d) {
			t.Errorf("legacy-rooted blob %s was reclaimed despite its operator root", d)
		}
	}
}
