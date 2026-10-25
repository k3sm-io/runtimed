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

	"k3sm.io/runtimed/pkg/image"
)

// repoDigestImageID is the value ContainerStatus.image_id publishes for a
// container whose image was pulled: "<repository>@<digest>", the digested
// reference containerd's CRI reports as image_ref and a kubelet copies into
// status.containerStatuses[].imageID.
//
// <repository> is ref without its tag or digest, in the spelling the pod asked
// for: no registry or library/ normalization is applied, because the field
// names what the pod pulled, and a rewritten spelling would name a reference
// the pod never used.
//
// <digest> is the top-level digest ref resolved to at pull, taken in this order:
//   - the digest ref is pinned to, when it is pinned: that IS the top-level
//     digest, whether it names a manifest or an index, and the pull resolved it
//     by that digest;
//   - the manifest's index_digest, when the pull recorded one: the index is
//     what a tag pointed at;
//   - the resolved manifest's own descriptor digest, which is what the registry
//     serves for a single-platform tag and what the node image listing shows.
//
// It is empty when none of the three is known (an index entry written before
// the store retained manifest descriptors): an empty field degrades visibly,
// and the config digest in its place would be a different kind of value in a
// field consumers read as a pullable digested reference.
func repoDigestImageID(ref string, res *image.PullResult) string {
	repo, pinned := splitRepoDigest(ref)
	digest := pinned
	if digest == "" {
		digest = res.Manifest.GetIndexDigest()
	}
	if digest == "" {
		digest = res.Descriptor.GetDigest()
	}
	if repo == "" || digest == "" {
		return ""
	}
	return repo + "@" + digest
}

// splitRepoDigest splits an image reference into its repository (tag and digest
// removed, spelling kept) and the digest it is pinned to, if any.
//
// A tag is the text after the last ':' that follows the last '/': a ':' before
// the last '/' is a registry port (registry:6450/ns/app), never a tag.
func splitRepoDigest(ref string) (repo, digest string) {
	repo = ref
	if at := strings.IndexByte(repo, '@'); at >= 0 {
		repo, digest = repo[:at], repo[at+1:]
	}
	if c := strings.LastIndexByte(repo, ':'); c > strings.LastIndexByte(repo, '/') {
		repo = repo[:c]
	}
	return repo, digest
}
