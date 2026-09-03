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
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// WithClusterRegistries admits ADDITIONAL registry authorities as cluster-local
// — spellings of this cluster's own ingest registry that are not a loopback
// address — and names the fetcher used to contact them.
//
// It exists because a loopback authority is not the only way a pod can name this
// cluster's registry. A workload that reaches the registry through a Service DNS
// name or a Service VIP writes that authority into its image reference, and such
// a reference is every bit as node-relative as "localhost:6450/team/app:v1": it
// resolves against content this cluster ingested, replicated across peers by
// construction. The loopback gate alone cannot see that, so those pulls were
// brokered differently from the identical pull spelled on loopback. Everything
// downstream of the gate — mirror brokering, per-candidate transport, the
// digest-verified commit — then applies to both spellings identically.
//
// It never widens the gate to a public registry: only the authorities the
// consumer names are admitted, one exact host[:port] at a time, and each is
// validated at construction (see NewPuller) rather than silently never matching.
//
// # Both halves are required
//
// fetch is not optional, and the reason is a sharp edge in
// go-containerregistry: name.Registry.Scheme() infers http only for localhost,
// *.localhost, 127.0.0.1, ::1 and the three RFC 1918 ranges. A Service DNS name
// or a mesh-range VIP is in none of those, so a reference carrying one is dialled
// as HTTPS and fails the TLS handshake against a plain-HTTP ingest registry —
// which is exactly the failure a caller wiring this option is trying to remove.
// So the option pairs the set with the fetcher that dials it, in the same shape
// WithMirrors pairs a source with a mirror fetcher, and NewPuller refuses a
// half-wiring rather than accepting a set nothing can reach.
//
// The production fetcher is RemoteInsecureFetch, and it is named at the call
// site that decides to admit these authorities (runtime.New) rather than
// defaulted here — for the same reason RemoteFetch and RemoteMirrorFetch are.
// The plaintext is scoped to EXACTLY these authorities and is never a
// package-wide default: a reference naming any other registry keeps the primary
// fetcher and its TLS.
//
// An empty or nil hosts with a nil fetch is the default and a complete
// no-op — the pre-existing loopback-only behavior, unchanged.
func WithClusterRegistries(hosts []string, fetch FetchFunc) PullerOption {
	return func(p *Puller) {
		p.clusterRegistryHosts = hosts
		p.clusterFetch = fetch
	}
}

// RemoteInsecureFetch fetches ref over PLAIN HTTP. It is the production
// FetchFunc for the authorities WithClusterRegistries admits, and it is
// RemoteFetch with exactly one difference: the reference is parsed with
// name.Insecure, so name.Registry.Scheme() answers "http" for an authority
// go-containerregistry would otherwise dial as HTTPS.
//
// Every other property of the primary path is retained unchanged — no implicit
// platform default can fire, an index is traversed explicitly, the selected
// child is re-resolved by digest, and the resolved image's own config is
// verified against the policy — because it shares remoteFetch with RemoteFetch
// and RemoteMirrorFetch.
//
// Plaintext here is a considered posture, in the same terms as Mirror.PlainHTTP:
// the authorities it applies to are this cluster's own ingest registry, reached
// over the cluster's own network, and INTEGRITY was never delegated to the
// transport — every blob is re-hashed against the digest its manifest descriptor
// claims before it is committed (Cache.CommitBlob). What is forgone is
// confidentiality on that hop, which is why the consumer names the exact
// authorities rather than the package assuming any.
//
// cred is forwarded: unlike a mirror candidate, the authority here is the one
// the reference itself names, so an imagePullSecret resolved for that reference
// is scoped to the host being dialled.
func RemoteInsecureFetch(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, boundErr(err))
	}
	return remoteFetch(ctx, r, ref, cred, policy)
}

// clusterRegistrySet is the normalised membership test for the authorities
// WithClusterRegistries admitted. Registry authorities are case-insensitive in
// their host portion, so keys are lowercased on the way in and lookups on the
// way out — matching loopbackAuthority, which already lowercases before it
// compares "localhost".
type clusterRegistrySet map[string]struct{}

// newClusterRegistrySet validates every host and returns the membership set.
//
// Validation happens HERE, at construction, and not at the first pull: an
// authority that carries a path, a scheme or userinfo, or that
// go-containerregistry would not read as a registry at all, can never match a
// parsed reference — so admitting it would produce a node that believes it is
// brokering a spelling it silently never sees. A misconfigured authority is a
// control-plane fault, and it is reported when the control plane wires it.
func newClusterRegistrySet(hosts []string) (clusterRegistrySet, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	set := make(clusterRegistrySet, len(hosts))
	for _, h := range hosts {
		if err := validateRegistryAuthority("cluster registry", h); err != nil {
			return nil, err
		}
		set[strings.ToLower(h)] = struct{}{}
	}
	return set, nil
}

// has reports whether authority is one of the admitted cluster registries.
func (s clusterRegistrySet) has(authority string) bool {
	if len(s) == 0 {
		return false
	}
	_, ok := s[strings.ToLower(authority)]
	return ok
}

// configuredClusterRegistry reports whether ref names one of the authorities
// WithClusterRegistries admitted.
//
// It reads the authority with authorityOf — the same splice clusterLocalRef
// uses — so the two gates agree on what "the registry portion of a reference"
// means, and neither can admit a first path element go-containerregistry would
// read as part of a Docker Hub repository.
func (p *Puller) configuredClusterRegistry(ref string) bool {
	authority, ok := authorityOf(ref)
	return ok && p.clusterRegistries.has(authority)
}

// clusterLocal is the FULL cluster-local test: a loopback spelling, always, or
// one of the authorities the consumer admitted.
//
// It is the mirror fallback's second precondition (mirrorCandidates), and it is
// deliberately the ONE place the two admissions are joined: a Service-DNS
// spelling of this cluster's registry is brokered exactly as the loopback
// spelling of the same pull is, or the uniformity this seam exists for would be
// only skin deep.
func (p *Puller) clusterLocal(ref string) bool {
	return clusterLocalRef(ref) || p.configuredClusterRegistry(ref)
}

// primaryFetch performs the pull's PRIMARY fetch, choosing the transport the
// reference's own authority calls for: the plain-HTTP fetcher for an authority
// WithClusterRegistries admitted, and the ordinary fetcher — with its TLS — for
// every other reference, including a loopback one (go-containerregistry already
// infers http there, so no second fetcher is needed and none is used).
//
// The choice is made HERE rather than inside a fetcher because the fetcher is a
// SEAM a test replaces: routing at the seam keeps "which host gets plaintext" a
// property of the Puller's configuration, which is assertable, instead of a
// property of whichever implementation happened to be injected.
func (p *Puller) primaryFetch(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
	if p.configuredClusterRegistry(ref) {
		return p.clusterFetch(ctx, ref, cred, policy)
	}
	return p.fetch(ctx, ref, cred, policy)
}
