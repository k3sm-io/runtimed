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
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
)

// WithLocalRegistry names this node's own ingest registry, which a pull for a
// BARE image name then consults before the upstream registry.
//
// An empty host — the default, and what the STANDALONE daemon always has —
// switches the whole behavior off: every reference resolves exactly as it did
// before this option existed. There is no other way to enable it, and no
// implicit default host, because the behavior below is a deliberate divergence
// from stock reference resolution and a node must not acquire it by accident.
//
// # The divergence, stated plainly
//
// A reference with no registry authority ("app:v1", "team/app:v1") normalises to
// Docker Hub. With a local registry configured, this node tries
// "<host>/app:v1" FIRST and falls through to the normalised upstream reference
// on a miss — so a bare name that exists in the node's registry SHADOWS the
// Docker Hub image of the same name. That is a real, load-bearing difference
// from an unconfigured Kubernetes node, and it is chosen rather than inherited:
// it is the local-image precedent kind and k3d set (`kind load docker-image`,
// `k3d image import`), where a locally imported image is what a bare name in a
// Pod spec resolves to, because the alternative — every locally built image
// needing a registry prefix nobody's manifests carry — is the friction those
// tools exist to remove.
//
// The cost is bounded in three ways, all structural rather than advisory:
//
//   - It applies ONLY to a reference that names no registry at all. Any
//     explicit authority, including "docker.io/library/app:v1", is untouched —
//     so a manifest that says where it wants its image from always gets it.
//   - The fall-through is the mirrorFallbackEligible taxonomy, not a bare
//     "if err != nil". The local registry ANSWERING — an auth refusal, a
//     malformed request, a rate limit — is a definitive answer and stands; only
//     a miss (404), an unserving registry (5xx) or an unreachable one falls
//     through. A node whose registry says "denied" never silently re-asks
//     Docker Hub, which would be the confused-deputy move.
//   - The image is recorded in the local index under the reference the USER
//     wrote, never the "<host>/…" spelling. So `imagePullPolicy: IfNotPresent`
//     finds it by that name on the next start, and a listing shows the operator
//     what they asked for rather than an internal rewrite.
//
// host is validated at construction (NewPuller) and must be cluster-local: a
// loopback spelling, or an authority admitted by WithClusterRegistries. That is
// what makes the two properties this path documents true by construction rather
// than by convention — the attempt is dialled with the transport that authority
// calls for, and a miss against it is brokered to the cluster mirrors exactly as
// any other cluster-local miss is.
func WithLocalRegistry(host string) PullerOption {
	return func(p *Puller) { p.localRegistry = host }
}

// errLocalRegistryMiss is the INTERNAL signal that the local-registry attempt
// did not answer and the pull must continue to the upstream reference. It never
// escapes Pull: a caller sees either the image, or the upstream reference's own
// verdict, or the local registry's definitive refusal — never a sentinel about a
// step it did not ask for.
var errLocalRegistryMiss = errors.New("the node's ingest registry does not have this reference")

// localRegistryApplies reports whether the local-first attempt runs for ref: the
// node has an ingest registry configured AND ref names no registry of its own.
func (p *Puller) localRegistryApplies(ref string) bool {
	return p.localRegistry != "" && bareName(ref)
}

// bareName reports whether ref names no registry authority — the shape
// go-containerregistry would normalise to docker.io/library/….
//
// It is authorityOf's complement on purpose: the test for "this reference names
// no registry" must be the exact negation of the test for "this is the registry
// it names", or a reference could fall in neither bucket (or both) and be
// resolved twice.
func bareName(ref string) bool {
	_, ok := authorityOf(ref)
	return !ok
}

// localRegistryRef renders ref as the reference to ask the node's own ingest
// registry for: host, then ref byte for byte.
//
// It is a PREFIX, not a parse-and-reassemble, for the reason rewriteRegistryHost
// is a splice: reassembly normalises (a bare repository gains a "library/"
// prefix, an omitted tag gains ":latest"), and a normalised local reference
// would ask the node's registry for something other than what the pod wrote.
//
// It reports ok=false rather than an error when the result is not a reference
// go-containerregistry will accept, and that direction is deliberate: the
// local-first attempt is an OPTIMISATION over a reference that is about to be
// resolved upstream anyway, so a spelling this node cannot form locally must
// SKIP the attempt, never fail the pull.
func localRegistryRef(host, ref string) (string, bool) {
	if ref == "" {
		return "", false
	}
	candidate := host + "/" + ref
	r, err := name.ParseReference(candidate)
	if err != nil {
		return "", false
	}
	// The prefix must have produced a reference whose registry IS the local
	// host. It cannot fail for a validated host and a bare name, and it is
	// asserted anyway because the whole point of the attempt is that it reaches
	// this node and nothing else.
	if r.Context().RegistryStr() != host {
		return "", false
	}
	return candidate, true
}

// pullFromLocalRegistry attempts ref against the node's own ingest registry and
// ingests the result under the ORIGINAL reference.
//
// It returns errLocalRegistryMiss (wrapping the cause) when the caller must fall
// through to the upstream reference, and any other error when the local registry
// gave a definitive answer that stands.
//
// No CREDENTIAL is forwarded, deliberately, and the argument is the one
// MirrorFetchFunc makes: a credential reaching this path is an imagePullSecret
// resolved for the pod's own reference — a BARE name, whose registry is Docker
// Hub. Replaying it to this node's ingest registry would send a secret scoped to
// one host to a different host that the pod's author never named. The node's own
// ingest registry is reached over the loopback or cluster-local transport this
// puller was configured with, so an anonymous fetch is also the working one.
//
// An ingest FAILURE is not a fall-through. If the local registry served the
// reference and this node then refused the content — a blob that does not hash
// to the digest its manifest claims, a platform this node cannot run — that is a
// verdict about the image, and re-asking Docker Hub would hide a broken node
// registry behind a public image that happens to share the name.
func (p *Puller) pullFromLocalRegistry(ctx context.Context, ref string, policy PlatformPolicy, want []Platform) (*PullResult, error) {
	localRef, ok := localRegistryRef(p.localRegistry, ref)
	if !ok {
		return nil, fmt.Errorf("%w: %s cannot be spelled against %s", errLocalRegistryMiss,
			quoteBounded(ref, maxReferenceLen), quoteBounded(p.localRegistry, maxMirrorHostLen))
	}
	img, err := p.primaryFetch(ctx, localRef, nil, policy)
	if err == nil {
		return p.ingest(ctx, ref, img, want)
	}
	// CLUSTER MIRRORS, on the LOCAL reference. The local registry is cluster-local
	// by construction (see WithLocalRegistry), so a miss against it is exactly the
	// miss the mirror fallback exists for — and a peer that has the image answers
	// a bare name here just as it answers an explicitly node-relative one. The
	// recorded reference stays the user's original either way.
	if mirrors := p.mirrorCandidates(localRef, err); len(mirrors) > 0 {
		if res, merr := p.pullFromMirrors(ctx, localRef, ref, policy, want, mirrors, err); merr == nil {
			return res, nil
		}
	}
	if !mirrorFallbackEligible(err) {
		return nil, fmt.Errorf("pull %s from the node's ingest registry: %w",
			quoteBounded(localRef, maxReferenceLen), err)
	}
	return nil, fmt.Errorf("%w: %w", errLocalRegistryMiss, err)
}
