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
	"k3sm.io/runtimed/pkg/image"
)

// repoDigestImageID is the value ContainerStatus.image_id publishes for a
// container whose image was pulled: "<repository>@<digest>", the digested
// reference containerd's CRI reports as image_ref and a kubelet copies into
// status.containerStatuses[].imageID. image.RepoDigest builds it: the
// repository normalized as containerd and the pull both read it, and the digest
// ref is pinned to when it is pinned.
//
// For a tag, the digest is the top-level digest the tag resolved to at pull:
//   - the manifest's index_digest, when the tag pointed at a multi-platform
//     index (the pull records it with the manifest, so a warm serve reports
//     the same value);
//   - otherwise the resolved manifest's own descriptor digest, which is what
//     the registry serves for a single-platform tag and what the node image
//     listing shows. An index entry recorded before index digests were kept
//     falls back here too.
//
// It is empty when the reference does not parse, no digest is known (an entry
// recorded before the store kept manifest descriptors), or the digest is not a
// well-formed "<algo>:<hex>": an empty field degrades visibly, and the config
// digest in its place would be a different kind of value in a field consumers
// read as a pullable digested reference.
func repoDigestImageID(ref string, res *image.PullResult) string {
	resolved := res.Manifest.GetIndexDigest()
	if resolved == "" {
		resolved = res.Descriptor.GetDigest()
	}
	id, ok := image.RepoDigest(ref, resolved)
	if !ok {
		return ""
	}
	return id
}
