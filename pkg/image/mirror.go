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
	"log/slog"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Mirror is one CLUSTER MIRROR candidate: a peer node's ingest registry,
// reachable from this node over the wireguard mesh. It is plain data supplied by
// the embedding consumer (k3sm), which learns the peers; this package only
// consumes it.
//
// It names a REGISTRY AUTHORITY, never a repository: the fallback rewrites only
// the registry host portion of a reference and leaves the repository path, tag
// and digest byte-identical, so a mirror candidate can change WHERE bytes come
// from and can never change WHICH bytes are asked for.
type Mirror struct {
	// Host is the registry authority — host[:port], e.g. "100.64.1.1:6450".
	// A value carrying a path ("peer/evil"), a scheme, or userinfo is refused
	// (see rewriteRegistryHost).
	Host string

	// PlainHTTP selects http:// rather than https:// when this candidate is
	// contacted, by constructing the reference with name.Insecure.
	//
	// It is REQUIRED for a mesh peer, and the reason is a sharp edge in
	// go-containerregistry: name.Registry.Scheme() infers http only for
	// localhost, *.localhost, 127.0.0.1, ::1 and the three RFC 1918 ranges
	// (10/8, 172.16/12, 192.168/16). The k3sm mesh addresses a peer on
	// 100.64.0.0/10 — RFC 6598 CGNAT, which is NOT in that list — so a mesh
	// candidate would otherwise be dialled as HTTPS and fail the TLS handshake
	// against a plain-HTTP ingest registry.
	//
	// Plaintext here is a considered posture, not an oversight. The wireguard
	// mesh already encrypts and authenticates the transport between peers, so
	// TLS would re-encrypt an encrypted link; and INTEGRITY was never delegated
	// to the transport in the first place — every blob is re-hashed against the
	// digest its manifest descriptor claims before it is committed
	// (Cache.CommitBlob), from a mirror exactly as from the primary registry.
	// What a plaintext hop does forgo is confidentiality OUTSIDE the mesh, which
	// is why this is a per-candidate flag the consumer sets rather than a
	// package-wide default: a candidate that is not mesh-local should be false.
	PlainHTTP bool
}

// MirrorSource supplies the cluster-mirror candidates for a reference — the
// peer ingest registries this node may consult when its own does not have it.
//
// It is a CONSUMER-SIDE seam per the standards: runtimed neither reads the
// apiserver nor speaks the mesh, so the embedding control plane (k3sm) supplies
// an implementation backed by whatever it advertises peers through, and unit
// tests supply a fixed list. A nil MirrorSource is the explicit "this node has
// no cluster to fall back to", and it restores exactly the pre-mirror behavior:
// no candidate is ever produced, so no fallback can run.
//
// The STANDALONE DAEMON (cmd/k3sm-runtimed) has no mirrors, by construction and
// permanently: it is built through runtime.New with Deps.ImageMirrors unset, and
// the gRPC runtime contract in k3sm.io/apis carries no mirror field for a client
// to populate. Cluster mirroring is a property of the EMBEDDED path, where the
// process that knows the peers builds the runtime in-process.
//
// Candidates are returned in PREFERENCE ORDER and are tried in that order. The
// ref is passed so a source may answer per-reference (a peer that advertises
// only some images); a source that keeps no such record returns the same list
// for every reference.
type MirrorSource interface {
	// Mirrors returns the candidate peers for ref, best first. An empty or nil
	// result means "no candidate", which is not an error: the primary failure
	// stands.
	Mirrors(ref string) []Mirror
}

// MirrorFetchFunc resolves an ALREADY-REWRITTEN mirror reference to an image.
// RemoteMirrorFetch is the production implementation; tests inject an in-memory
// fetcher so the fallback mechanics run with no network.
//
// ref is the mirror reference the PULLER built — the original reference with
// only its registry authority replaced (rewriteRegistryHost). The rewrite is
// deliberately NOT delegated to this seam: doing it at the one choke point means
// a substituted fetcher can change the transport it uses and can never change
// the repository, tag or digest that is asked for. mirror is the candidate ref
// was rewritten to; an implementation reads its PlainHTTP transport decision,
// and must not re-derive the host from it (ref already carries it).
//
// It takes NO RegistryCredential, deliberately. A credential reaching this path
// is an imagePullSecret resolved for the pod's own reference, whose registry the
// fallback has already established to be a LOOPBACK spelling — this node's own
// ingest registry. Replaying it to a peer would send a secret scoped to one host
// to a different host, over a link the pod's author never named. Peer ingest
// registries inside the mesh are unauthenticated, so an anonymous fetch is also
// the working one.
type MirrorFetchFunc func(ctx context.Context, ref string, mirror Mirror, policy PlatformPolicy) (ggcrv1.Image, error)

// RemoteMirrorFetch fetches ref from a cluster mirror. It is the production
// MirrorFetchFunc and is RemoteFetch with exactly one difference: the reference
// is constructed with name.Insecure when the candidate is PlainHTTP (see
// Mirror.PlainHTTP for why a mesh peer requires it).
//
// Every other property of the primary path is retained unchanged, because they
// are the properties that make a mirror safe to consult at all: no implicit
// platform default can fire, an index is traversed explicitly, the selected
// child is re-resolved by digest, and the resolved image's own config is
// verified against the policy before the caller writes a byte.
func RemoteMirrorFetch(ctx context.Context, ref string, mirror Mirror, policy PlatformPolicy) (ggcrv1.Image, error) {
	r, err := mirror.reference(ref)
	if err != nil {
		return nil, err
	}
	return remoteFetch(ctx, r, ref, nil, policy)
}

// reference parses ref for this candidate, selecting the transport its
// PlainHTTP flag asks for. It is the ONE place name.Insecure is applied, so the
// scheme decision is assertable without a dial (Registry.Scheme()).
func (m Mirror) reference(ref string) (name.Reference, error) {
	var opts []name.Option
	if m.PlainHTTP {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("parse mirror reference %q: %w", ref, boundErr(err))
	}
	return r, nil
}

// rewriteRegistryHost returns ref with its registry authority replaced by host,
// leaving the repository path, tag and digest BYTE-IDENTICAL.
//
// It is a string splice on the first "/" rather than a parse-and-reassemble
// through go-containerregistry, and that is the point: reassembly normalises
// (docker.io becomes index.docker.io, a bare repository gains a "library/"
// prefix, an omitted tag gains ":latest"), and any normalisation here would make
// the mirror ask for something other than what the pod asked for. The caller has
// already established that ref's registry is a loopback spelling, which is
// exactly the case in which the authority is explicit and a "/" is present.
//
// host is VALIDATED, because it arrives from the cluster: a value carrying a
// path, a scheme or userinfo would splice into the repository portion of the
// reference and redirect the pull at a repository nobody named. An empty host,
// or one go-containerregistry will not accept as an RFC 3986 authority, is
// refused here so the candidate is skipped before any round trip.
func rewriteRegistryHost(ref, host string) (string, error) {
	if host == "" {
		return "", errors.New("mirror host is empty")
	}
	// Rejected before name.NewRegistry, not instead of it: checkRegistry admits
	// the empty string and its RFC 3986 authority check is not obviously a
	// path/scheme check to a reader. These two are the splices that matter.
	if strings.ContainsAny(host, "/@") || strings.Contains(host, "://") {
		return "", fmt.Errorf("mirror host %s must be a bare host[:port] authority", quoteBounded(host, maxMirrorHostLen))
	}
	// A host go-containerregistry would not RECOGNISE as a registry is refused,
	// and this one is not cosmetic. Its splitting rule is exactly "the first
	// component is the registry iff it contains a '.' or a ':'" (name.NewRepository)
	// — so splicing a dotless, portless host would produce a reference whose
	// first component is read as part of the REPOSITORY and whose registry
	// defaults to Docker Hub. A candidate spelled "peer" would silently redirect
	// a cluster-local pull at a public registry.
	if !registryShaped(host) {
		return "", fmt.Errorf("mirror host %s must carry a port or a dotted name, or it is not read as a registry", quoteBounded(host, maxMirrorHostLen))
	}
	if _, err := name.NewRegistry(host); err != nil {
		return "", fmt.Errorf("mirror host %s: %w", quoteBounded(host, maxMirrorHostLen), boundErr(err))
	}
	i := strings.Index(ref, "/")
	if i < 0 {
		return "", fmt.Errorf("reference %s names no registry", quoteBounded(ref, maxReferenceLen))
	}
	return host + ref[i:], nil
}

// clusterLocalRef reports whether ref's registry authority is a LOOPBACK
// spelling — this node's own ingest registry.
//
// This is the second half of the fallback precondition, and it is what keeps the
// mechanism narrow. A pod that asked for docker.io/library/nginx and got a 404
// wants that answer: no peer of this cluster is a more authoritative source for
// a public registry's namespace, and consulting one would silently satisfy a
// public reference from cluster-local content. A pod that asked for
// localhost:6450/app:v1 is asking for THIS CLUSTER's ingest registry, whose
// content is replicated across peers by construction — the reference is
// node-relative, and resolving it against a peer is resolving it correctly.
//
// Accepted: "localhost:<port>", "*.localhost" (with or without a port), any
// address in 127.0.0.0/8, and the IPv6 loopback "::1" in bracketed form.
//
// The authority must additionally be one go-containerregistry itself reads as a
// registry (registryShaped), and that excludes one shape a reader would expect
// to be here: a BARE "localhost/team/app". ggcr treats a first component with no
// '.' and no ':' as part of the repository, so that reference resolves against
// Docker Hub as the repository "localhost/team/app" — it never names this node
// at all, and rewriting its first component would ask a peer for something the
// pod did not. Excluding it keeps this gate in agreement with the parser the
// pull actually uses.
func clusterLocalRef(ref string) bool {
	i := strings.Index(ref, "/")
	if i < 0 {
		return false
	}
	authority := ref[:i]
	return registryShaped(authority) && loopbackAuthority(authority)
}

// registryShaped reports whether go-containerregistry would read authority as a
// registry rather than as the first path element of a repository: its rule, in
// name.NewRepository, is a '.' or a ':' anywhere in the component.
func registryShaped(authority string) bool {
	return strings.ContainsAny(authority, ".:")
}

// loopbackAuthority reports whether a registry authority (host[:port]) names the
// loopback interface or the localhost name.
func loopbackAuthority(authority string) bool {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// Message bounds for cluster-supplied strings, in the same posture as the
// registry-controlled bounds in platform.go: a mirror host is configuration this
// node did not author, and it reaches slog, a Pod status message and kine.
const (
	// maxMirrorHostLen bounds a rendered mirror authority.
	maxMirrorHostLen = 96
	// maxReferenceLen bounds a rendered image reference.
	maxReferenceLen = 256
)

// mirrorFallbackEligible reports whether a PRIMARY fetch failure is one a
// cluster mirror could legitimately answer. It is the first half of the fallback
// precondition (clusterLocalRef is the second), and it is an ENUMERATION rather
// than a default: a failure this function does not recognise stands as the
// pull's answer, so a new error shape can never quietly widen the fallback.
//
// ELIGIBLE — the reference is absent from the primary, or the primary is not
// answering. A peer may hold the same content, and consulting one changes only
// which host serves bytes that are digest-verified either way:
//
//   - HTTP 404 Not Found — the miss this mechanism exists for. The node's own
//     ingest registry has not been fed this reference yet.
//   - HTTP 500, 502, 503, 504 — the registry process is present but not serving
//     (starting, wedged, or behind a proxy that is). Indistinguishable from a
//     miss to a pod, and a peer that is serving is a correct answer.
//   - a CONNECTION-class failure — connection refused/reset, host or network
//     unreachable, a dial or read timeout, a DNS failure, or any other
//     *net.OpError. The node's own registry is not listening.
//
// NOT ELIGIBLE — the primary ANSWERED, and its answer is the pull's answer.
// Falling back here would be substituting a different host's opinion for a
// decision that was already made:
//
//   - HTTP 401, 403, 407 and any registry diagnostic of UNAUTHORIZED or DENIED —
//     an AUTH failure. The reference exists and this node is not allowed it;
//     asking a peer that may not enforce the same policy is precisely the
//     confused-deputy move a mirror must not make. The diagnostic codes are
//     checked in ADDITION to the status, because a registry may return an auth
//     refusal under a 404 to avoid disclosing existence.
//   - any other 4xx (400, 405, 409, 429, ...) — the request itself is wrong, or
//     the answer is "come back later". Neither is improved by a different host;
//     429 in particular asks for a retry against the SAME registry.
//   - ErrNoPlatformMatch / ErrNestedIndex — the reference RESOLVED and this node
//     cannot run what it resolved to. That verdict is about the image, not about
//     the host that served it.
//   - context cancellation or deadline — the CALLER gave up. Continuing to dial
//     peers after that would burn the caller's budget on work it no longer wants.
//   - this node's own pre-fetch verdicts (ErrPullRefusedDiskPressure,
//     ErrImageNotPresent) — no fetch was attempted at all.
func mirrorFallbackEligible(err error) bool {
	if err == nil {
		return false
	}
	// The caller's own decisions and this node's own verdicts, first: they can
	// wrap or be wrapped by anything below, and none of them is about the host.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrNoPlatformMatch) || errors.Is(err, ErrNestedIndex) ||
		errors.Is(err, ErrPullRefusedDiskPressure) || errors.Is(err, ErrImageNotPresent) {
		return false
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		if authDiagnostic(terr) {
			return false
		}
		switch terr.StatusCode {
		case http.StatusNotFound,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}
	return connectionClass(err)
}

// authDiagnostic reports whether a registry error carries an authorization
// refusal in its OCI error body, whatever status code it rode in on.
func authDiagnostic(terr *transport.Error) bool {
	for _, d := range terr.Errors {
		if d.Code == transport.UnauthorizedErrorCode || d.Code == transport.DeniedErrorCode {
			return true
		}
	}
	return false
}

// connectionClass reports whether err is a transport-level failure to REACH a
// registry, as opposed to an answer from one. The errno set is the one a dial or
// a read against a dead local listener actually produces; net.DNSError and
// *net.OpError catch the same class arriving in a different shape, and the
// net.Error timeout check catches a deadline the http client imposed rather than
// the kernel.
func connectionClass(err error) bool {
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EHOSTUNREACH,
		syscall.EHOSTDOWN,
		syscall.ENETUNREACH,
		syscall.ENETDOWN,
		syscall.ETIMEDOUT,
		syscall.EPIPE,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// WithMirrors wires the CLUSTER MIRROR fallback: src supplies the peer
// candidates for a reference and fetch contacts one.
//
// Both are required together and NewPuller refuses a half-wiring. A source with
// no fetcher would advertise peers nothing can contact; a fetcher with no source
// would be a fetch path nothing can reach. Neither is a state a caller means,
// and both are silent — the whole mechanism would simply never fire.
//
// It is an option rather than a NewPuller argument because its absence is the
// complete, correct, single-node behavior — unlike the cache, the fetcher and
// the index, whose absence has no meaning. What the option must NOT become is a
// silent default: the production fetcher is named at the call site that decides
// to mirror at all (runtime.New passes image.RemoteMirrorFetch), for the same
// reason RemoteFetch is named there.
func WithMirrors(src MirrorSource, fetch MirrorFetchFunc) PullerOption {
	return func(p *Puller) {
		p.mirrors = src
		p.mirrorFetch = fetch
	}
}

// WithPullLogger sets the logger the puller reports mirror fallback on. Nil
// discards, which is the default: this package logs nothing on the primary path,
// so a Puller built without one is silent exactly as before.
func WithPullLogger(log *slog.Logger) PullerOption {
	return func(p *Puller) { p.log = log }
}

// logger returns the puller's logger, or a discarding one.
func (p *Puller) logger() *slog.Logger {
	if p.log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.log
}

// mirrorCandidates returns the peers to consult after primaryErr, or nil when
// the fallback does not apply. Both preconditions are checked here, at one
// place, so "when do we fall back" has a single readable answer.
func (p *Puller) mirrorCandidates(ref string, primaryErr error) []Mirror {
	if p.mirrors == nil || p.mirrorFetch == nil {
		return nil
	}
	if !clusterLocalRef(ref) {
		return nil
	}
	if !mirrorFallbackEligible(primaryErr) {
		return nil
	}
	return p.mirrors.Mirrors(ref)
}

// pullFromMirrors tries each candidate in preference order and returns the first
// one whose content ingests cleanly.
//
// ref is the ORIGINAL reference throughout, and every candidate is ingested
// under it: the pod asked for the node-relative reference, and the mirror is
// TRANSPORT, not identity. So the index records what the pod named, a later
// IfNotPresent serve finds it under that name, and nothing downstream can tell
// which peer the bytes came from — which is the property that makes a peer's
// availability irrelevant to the pod's.
//
// A candidate that serves content failing verification is a PER-MIRROR failure:
// the loop moves to the next peer. It never degrades to trusting the content,
// and it never widens to accepting a second peer's manifest for the first peer's
// blobs — each iteration ingests one image whole (config, manifest, every layer)
// or commits nothing, because Puller.ingest releases its lease and returns on
// the first failure.
func (p *Puller) pullFromMirrors(ctx context.Context, ref string, policy PlatformPolicy, want []Platform, mirrors []Mirror, primaryErr error) (*PullResult, error) {
	log := p.logger()
	consulted := 0
	for _, m := range mirrors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mirrorRef, err := rewriteRegistryHost(ref, m.Host)
		if err != nil {
			// Not counted as consulted: nothing was contacted. A malformed
			// candidate is a control-plane fault, so it is reported at WARN
			// rather than folded into the per-miss debug stream.
			log.Warn("skipping an unusable cluster mirror candidate", "ref", ref, "mirror", m.Host, "error", err)
			continue
		}
		consulted++
		img, err := p.mirrorFetch(ctx, mirrorRef, m, policy)
		if err != nil {
			log.Debug("cluster mirror does not have the image", "ref", ref, "mirror", m.Host, "error", err)
			continue
		}
		res, err := p.ingest(ctx, ref, img, want)
		if err != nil {
			log.Debug("cluster mirror served content this node refused", "ref", ref, "mirror", m.Host, "error", err)
			continue
		}
		log.Info("pulled from a cluster mirror", "ref", ref, "mirror", m.Host, "mirrorRef", mirrorRef)
		return res, nil
	}
	// The PRIMARY error stays the cause: it is what the pod's own registry said,
	// it is what errors.Is downstream keys on, and the mirror count is the
	// operator's evidence that the fallback ran and found nothing — as distinct
	// from a node with no peers advertised at all, which returns the primary
	// error untouched.
	noun := "mirrors"
	if consulted == 1 {
		noun = "mirror"
	}
	return nil, fmt.Errorf("%w (%d cluster %s consulted)", primaryErr, consulted, noun)
}
