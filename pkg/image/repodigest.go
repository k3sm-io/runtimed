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

package image

import (
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// RepoDigest returns the digested reference "<repository>@<digest>" for the
// image reference ref — the value containerd's CRI reports as image_ref and a
// kubelet copies into a container status's imageID. ok is false when ref does
// not parse or the digest is not a well-formed "<algo>:<hex>".
//
// <repository> is ref's repository, normalized by the same parser every pull
// uses (name.ParseReference, as RemoteFetch calls it), so it names the
// repository that was actually fetched: a name with no registry is a Docker Hub
// name ("alpine:3.20" is "docker.io/library/alpine", "user/app" is
// "docker.io/user/app"), Docker Hub is spelled "docker.io" as containerd spells
// it, and a reference whose first component carries a '.' or a ':' keeps that
// registry verbatim ("registry-k3sm:6450/ois/app"). The tag is dropped.
//
// <digest> is the digest ref is pinned to when it is pinned — that is the
// digest it resolved to, whether it names a manifest or an index — and
// otherwise resolved, the top-level digest the pull resolved the tag to.
func RepoDigest(ref, resolved string) (string, bool) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", false
	}
	digest := resolved
	if d, ok := r.(name.Digest); ok {
		digest = d.DigestStr()
	}
	h, err := ggcrv1.NewHash(digest)
	if err != nil {
		return "", false
	}
	registry := r.Context().RegistryStr()
	if registry == name.DefaultRegistry {
		registry = dockerHubMirrorHost
	}
	return registry + "/" + r.Context().RepositoryStr() + "@" + h.String(), true
}
