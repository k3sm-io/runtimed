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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// The PUBLIC-IMAGE MIRROR: a copy of a public image kept in the cluster's one
// registry (the flat registry, see FlatRegistry), consulted only when the public
// registry cannot be reached at all.
//
// # The name
//
// The copy of "<host>/<path>:<tag>" lives at
// "<flat registry>/<host>/<path>:<tag>", and a digest-pinned reference keeps its
// digest: "<flat registry>/<host>/<path>@<digest>". Docker Hub is spelled
// "docker.io" (what users write and what containerd's mirror configuration
// calls it), and a reference that names no registry is the Docker Hub reference
// it normalises to, so "nginx:1" mirrors at
// "registry-k3sm:6450/docker.io/library/nginx:1". PublicMirrorReference is the
// one place that rule is written; whatever writes the copies uses it too.
//
// # When it is used
//
// The ORIGINAL reference is always tried upstream first, under the pod's own
// credential, exactly as before. The copy is consulted only when that attempt
// failed to REACH the registry (upstreamUnreachable): a DNS failure, a refused
// or timed-out connection, or a TLS handshake that failed for a network reason.
// Any ANSWER from the public registry stands as the pull's answer: a 401, 403,
// 404, a manifest-unknown, a digest mismatch, an image for the wrong platform,
// and a certificate the node does not trust (a trust failure, not an outage).
//
// # What it trusts
//
// The copy is fetched through the flat registry's own endpoint and trust anchor
// (the cluster CA) and through the same remote fetch every pull uses: a
// digest-pinned reference must resolve to that digest from the copy or fail, an
// index is traversed by explicit digest, the config is verified against the
// platform policy, and every blob is re-hashed at commit. No credential is sent
// to the copy: the pod's pull secret is scoped to the public registry. The
// result is recorded under the reference the pod wrote, so the copy is
// transport, never identity.

// dockerHubMirrorHost is the spelling Docker Hub takes inside a mirror name.
const dockerHubMirrorHost = "docker.io"

// PublicMirrorReference returns the name the cluster registry registryHost
// (host:port, e.g. "registry-k3sm:6450") keeps its copy of the public image ref
// under. It returns an error for a reference that has no such name: one that
// does not parse, one whose registry is registryHost itself, and one whose
// registry carries a port (an OCI repository path cannot hold a ':', so
// "host:5000/app" has no faithful spelling under another registry).
func PublicMirrorReference(registryHost, ref string) (string, error) {
	if err := validateRegistryAuthority("mirror registry host", registryHost); err != nil {
		return "", err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse reference %q: %w: %w", ref, ErrInvalidReference, boundErr(err))
	}
	host := strings.ToLower(r.Context().RegistryStr())
	if host == name.DefaultRegistry {
		host = dockerHubMirrorHost
	}
	if strings.EqualFold(host, registryHost) {
		return "", fmt.Errorf("reference %s already names the registry %s", quoteBounded(ref, maxReferenceLen), quoteBounded(registryHost, maxMirrorHostLen))
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("reference %s names a registry with a port, which has no name inside another registry", quoteBounded(ref, maxReferenceLen))
	}
	sep := ":"
	if _, ok := r.(name.Digest); ok {
		sep = "@"
	}
	return registryHost + "/" + host + "/" + r.Context().RepositoryStr() + sep + r.Identifier(), nil
}

// publicMirrorApplies reports whether ref is a PUBLIC reference the cluster
// registry may hold a copy of: the flat registry is mapped, and ref names
// neither the flat registry, one of its aliases, nor any other cluster-local
// registry (those have their own fallbacks, and a copy of a cluster image under
// a public-looking name is not a thing).
func (p *Puller) publicMirrorApplies(ref string) bool {
	if p.flat == nil {
		return false
	}
	if _, ok := p.flatCanonical(ref); ok {
		return false
	}
	return !p.clusterLocal(ref)
}

// fetchUpstreamOrMirror is the primary fetch for a public reference followed,
// only when the public registry was unreachable, by the cluster registry's copy.
// It ingests whichever answered under ref. Every other failure is the primary
// failure, verbatim.
func (p *Puller) fetchUpstreamOrMirror(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy, want []Platform) (*PullResult, error) {
	img, err := p.primaryFetch(ctx, ref, cred, policy)
	if err == nil {
		return p.ingest(ctx, ref, img, want)
	}
	if !p.publicMirrorApplies(ref) || ctx.Err() != nil || !upstreamUnreachable(err) {
		return nil, err
	}
	mirrorRef, merr := PublicMirrorReference(p.flat.host, ref)
	if merr != nil {
		return nil, err
	}
	log := p.logger()
	img, merr = p.flat.fetch(ctx, mirrorRef, nil, policy)
	if merr == nil {
		var res *PullResult
		res, merr = p.ingest(ctx, ref, img, want)
		if merr == nil {
			log.Info("the public registry is unreachable; pulled the cluster registry's copy",
				"ref", ref, "mirrorRef", mirrorRef, "upstreamError", err)
			return res, nil
		}
	}
	log.Debug("the cluster registry's copy could not serve this reference", "ref", ref, "mirrorRef", mirrorRef, "error", merr)
	return nil, fmt.Errorf("%w (the cluster registry's copy %s: %s)", err,
		quoteBounded(mirrorRef, maxReferenceLen), quoteBounded(firstLine(merr.Error()), maxWrappedErrLen))
}

// firstLine is msg up to its first line break.
func firstLine(msg string) string {
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		return msg[:i]
	}
	return msg
}

// upstreamUnreachable reports whether a fetch failure means the registry was
// never REACHED, as opposed to having answered. It is an enumeration, and a
// failure it does not recognise is not unreachable, so a new error shape can
// never quietly widen the fallback.
//
// UNREACHABLE:
//
//   - a DNS failure (*net.DNSError): the name did not resolve;
//   - a refused connection (ECONNREFUSED), or no route to it (EHOSTUNREACH,
//     ENETUNREACH, EHOSTDOWN, ENETDOWN);
//   - a timeout (ETIMEDOUT, or any net.Error whose Timeout() is true: a dial
//     timeout, a TLS handshake timeout, a response-header timeout);
//   - a connection reset or aborted (ECONNRESET, ECONNABORTED), which is how a
//     TLS handshake fails for a network reason short of a timeout: the peer, or
//     a middlebox, dropped the connection mid-handshake.
//
// NEVER UNREACHABLE, checked first because they can wrap or ride inside the
// shapes above:
//
//   - any HTTP answer (*transport.Error): 401, 403, 404, MANIFEST_UNKNOWN, 5xx
//     and every other status are the registry speaking;
//   - a certificate or TLS protocol failure (an unknown authority, a hostname
//     mismatch, an expired certificate, a TLS alert, a non-TLS reply): the
//     registry was reached and could not be trusted, which a copy must not
//     paper over;
//   - anything else, including a digest mismatch, a platform refusal and this
//     node's own verdicts.
//
// The caller's own cancellation is checked by the caller against its context,
// not here: a dial timeout satisfies errors.Is(err, context.DeadlineExceeded)
// too, so the error alone cannot tell the two apart.
func upstreamUnreachable(err error) bool {
	if err == nil {
		return false
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		return false
	}
	if tlsTrustFailure(err) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.EHOSTDOWN,
		syscall.ENETDOWN,
		syscall.ETIMEDOUT,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// tlsTrustFailure reports whether err is a TLS failure that is about trust or
// protocol rather than the network.
func tlsTrustFailure(err error) bool {
	var (
		verifyErr  *tls.CertificateVerificationError
		alertErr   tls.AlertError
		recordErr  tls.RecordHeaderError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
	)
	return errors.As(err, &verifyErr) || errors.As(err, &alertErr) || errors.As(err, &recordErr) ||
		errors.As(err, &unknownCA) || errors.As(err, &hostErr) || errors.As(err, &invalidErr)
}
