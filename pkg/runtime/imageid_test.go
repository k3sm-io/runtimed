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
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// The rig defect: three Ready pods of registry-k3sm:6450/<run>/app:v1 reported
// the CONFIG digest as image_id while the registry served the manifest at a
// different digest. These two are kept apart so the test can tell them apart.
const (
	testManifestDigest = "sha256:bb2f2681bb2f2681bb2f2681bb2f2681bb2f2681bb2f2681bb2f2681bb2f2681"
	testPinnedDigest   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

// TestContainerStatusImageIDIsRepoDigest is the gate: image_id, read back
// through the real status-assembly path, is "<repository>@<digest>" (containerd's
// CRI image_ref) where <repository> is the pod's reference without its tag in
// the pod's own spelling, and <digest> is the top-level digest the reference
// resolved to at pull. It is never the config digest, which names no manifest a
// registry serves.
func TestContainerStatusImageIDIsRepoDigest(t *testing.T) {
	cases := []struct {
		name        string
		image       string
		indexDigest string
		want        string
	}{
		{
			name:  "a tag reference publishes the manifest digest the tag resolved to",
			image: "registry-k3sm:6450/ois/app:v1",
			want:  "registry-k3sm:6450/ois/app@" + testManifestDigest,
		},
		{
			name:  "a digest-pinned reference keeps its repository and its pinned digest",
			image: "registry-k3sm:6450/ois/app@" + testPinnedDigest,
			want:  "registry-k3sm:6450/ois/app@" + testPinnedDigest,
		},
		{
			name:  "a tag and a digest together drop the tag and keep the pin",
			image: "example.com/ns/app:v1@" + testPinnedDigest,
			want:  "example.com/ns/app@" + testPinnedDigest,
		},
		{
			name:        "a tag resolved through an index publishes the index digest",
			image:       "example.com/app:v1",
			indexDigest: testIndexDigest,
			want:        "example.com/app@" + testIndexDigest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const podID = "pod-repodigest"
			pull := &fakePuller{
				manifest: &runtimev1.ImageManifest{
					Reference:   tc.image,
					MediaType:   "application/vnd.oci.image.manifest.v1+json",
					Config:      &runtimev1.Descriptor{Digest: testConfigDigest, Size: 11},
					Layers:      []*runtimev1.Descriptor{{Digest: testLayerDigest, Size: 22}},
					IndexDigest: tc.indexDigest,
				},
				descriptor: &runtimev1.Descriptor{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Digest:    testManifestDigest,
					Size:      33,
				},
			}
			rt := newTestRuntime(t, Deps{Waiter: newBlockingWaiter(), Puller: pull})
			box := pulledImageBox(t, rt, podID)
			box.Containers[0].Image = tc.image
			mustCreatePod(t, rt, box)

			st := containerStatusNamed(t, rt, podID, "main")
			if got := st.GetImageId(); got != tc.want {
				t.Errorf("image_id = %q, want %q", got, tc.want)
			}
			if got := st.GetImageId(); strings.HasSuffix(got, testConfigDigest) {
				t.Errorf("image_id = %q carries the config digest, which names no manifest", got)
			}
			if got := st.GetImage(); got != tc.image {
				t.Errorf("image = %q, want the pod's reference %q verbatim", got, tc.image)
			}
		})
	}
}

// TestSplitRepoDigest pins the reference split the image_id is built from: a
// registry port is never mistaken for a tag, and the spelling is never
// normalized.
func TestSplitRepoDigest(t *testing.T) {
	cases := []struct {
		ref, repo, digest string
	}{
		{"registry-k3sm:6450/ois/app:v1", "registry-k3sm:6450/ois/app", ""},
		{"registry-k3sm:6450/ois/app", "registry-k3sm:6450/ois/app", ""},
		{"nginx", "nginx", ""},
		{"nginx:1.27", "nginx", ""},
		{"docker.io/library/nginx:1.27", "docker.io/library/nginx", ""},
		{"localhost:5000/app@" + testPinnedDigest, "localhost:5000/app", testPinnedDigest},
		{"example.com/app:v1@" + testPinnedDigest, "example.com/app", testPinnedDigest},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			repo, digest := splitRepoDigest(tc.ref)
			if repo != tc.repo || digest != tc.digest {
				t.Errorf("splitRepoDigest(%q) = (%q, %q), want (%q, %q)", tc.ref, repo, digest, tc.repo, tc.digest)
			}
		})
	}
}

// TestRepoDigestImageIDEmptyWithoutDigest: an index entry that recorded no
// manifest descriptor yields no digest, and image_id is then empty rather than
// a config digest standing in for one.
func TestRepoDigestImageIDEmptyWithoutDigest(t *testing.T) {
	res := &image.PullResult{Manifest: &runtimev1.ImageManifest{Config: &runtimev1.Descriptor{Digest: testConfigDigest}}}
	if got := repoDigestImageID("example.com/app:v1", res); got != "" {
		t.Errorf("repoDigestImageID with no descriptor = %q, want empty", got)
	}
}
