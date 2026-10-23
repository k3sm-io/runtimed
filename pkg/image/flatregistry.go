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
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// FlatRegistry maps the cluster's ONE registry name to the endpoint this node
// reaches it at, in the shape k3s's registries.yaml gives a mirrored host: the
// name a reference carries is identity, the endpoint is transport.
//
// # What it changes
//
//   - A reference whose authority is Host ("registry-k3sm:6450/team/app:v1") is
//     fetched from Endpoint, never by resolving Host: a node's own resolver does
//     not know the cluster's Service names, and the name must work identically
//     on every node.
//   - A reference whose authority is one of Aliases ("localhost:6450/team/app:v1")
//     is the same image. It is fetched as Host and recorded under Host, so both
//     spellings are one entry in the index, in ListImages and in a pod's
//     reachability root.
//   - A bare name the node's own ingest registry answers (WithLocalRegistry) is
//     the same image too when that registry is one of Aliases: it is recorded
//     under Host. A bare name that registry does not have still falls through to
//     the upstream registry and is recorded as written.
//
// Presence for IfNotPresent and Never is decided under Host first and then under
// the reference as written, so an entry recorded before this mapping existed
// (under a loopback spelling, or loaded by `k3sm image load`) still serves.
//
// # What it does not change
//
// A reference naming Host WITHOUT its port ("registry-k3sm/team/app:v1") is not
// this registry: by the OCI rule a first component with no '.' and no ':' is part
// of a Docker Hub repository, and it resolves there. Any authority that is
// neither Host nor an alias keeps every pre-existing path, including the
// cluster-mirror fallback; the flat name itself is never brokered to peers,
// because it names the one store, not a node-relative copy of it.
//
// Host is not dialled by name, and Aliases must be cluster-local (a loopback
// spelling, or an authority admitted by WithClusterRegistries), so the mapping can
// never redirect a public registry's namespace. NewPuller validates all of it.
type FlatRegistry struct {
	// Host is the canonical registry authority, host:port, e.g.
	// "registry-k3sm:6450".
	Host string
	// Endpoint is where Host is fetched from.
	Endpoint RegistryEndpoint
	// Aliases are other authorities that spell the same registry, e.g.
	// "localhost:6450" and "127.0.0.1:6450". Each must be cluster-local.
	Aliases []string
}

// RegistryEndpoint is the address a registry name is fetched from, and the
// transport it is fetched over.
type RegistryEndpoint struct {
	// Addr is host:port, dialled directly (no proxy, no name rewrite of the
	// request: the request still names the registry's own authority).
	Addr string
	// TLS selects HTTPS. The serving certificate must chain to CAPEM and name the
	// registry's host (Host without its port). Plain HTTP is accepted only for a
	// loopback Addr, where the hop never leaves this Mac.
	TLS bool
	// CAPEM is the PEM bundle the serving certificate is verified against. It is
	// required with TLS and is the ONLY trust anchor used: the system roots are not
	// consulted, so a public certificate cannot stand in for the cluster's.
	CAPEM []byte
}

// WithFlatRegistry maps the cluster's one registry name to its endpoint; see
// FlatRegistry. The zero value is a no-op.
func WithFlatRegistry(f FlatRegistry) PullerOption {
	return func(p *Puller) { p.flatConfig = f }
}

// flatRegistry is the validated, ready-to-use form of a FlatRegistry.
type flatRegistry struct {
	// host is the canonical authority, lowercased.
	host string
	// aliases is the lowercased alias set.
	aliases map[string]struct{}
	// fetch fetches a reference whose authority is host from the endpoint.
	fetch FetchFunc
}

// flatRegistryDialTimeout bounds one dial to the endpoint.
const flatRegistryDialTimeout = 30 * time.Second

// newFlatRegistry validates f against the puller's cluster-local set and builds
// its fetcher. A zero f yields nil, which switches the mapping off.
func (p *Puller) newFlatRegistry(f FlatRegistry) (*flatRegistry, error) {
	if f.Host == "" && f.Endpoint.Addr == "" && len(f.Aliases) == 0 {
		return nil, nil
	}
	if err := validateRegistryAuthority("flat registry host", f.Host); err != nil {
		return nil, err
	}
	if _, port, err := net.SplitHostPort(f.Host); err != nil || port == "" {
		return nil, fmt.Errorf("flat registry host %s must carry a port: without one it is a Docker Hub repository element",
			quoteBounded(f.Host, maxMirrorHostLen))
	}
	host, _, err := net.SplitHostPort(f.Endpoint.Addr)
	if err != nil || host == "" {
		return nil, fmt.Errorf("flat registry endpoint %s must be host:port", quoteBounded(f.Endpoint.Addr, maxMirrorHostLen))
	}
	var pool *x509.CertPool
	if f.Endpoint.TLS {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(f.Endpoint.CAPEM) {
			return nil, errors.New("flat registry endpoint uses TLS but its CA bundle holds no certificate")
		}
	} else if !loopbackAuthority(f.Endpoint.Addr) {
		return nil, fmt.Errorf("flat registry endpoint %s is plain HTTP but not loopback: plaintext is accepted only for a hop that never leaves this Mac",
			quoteBounded(f.Endpoint.Addr, maxMirrorHostLen))
	}
	fr := &flatRegistry{host: strings.ToLower(f.Host), aliases: make(map[string]struct{}, len(f.Aliases))}
	for _, a := range f.Aliases {
		if err := validateRegistryAuthority("flat registry alias", a); err != nil {
			return nil, err
		}
		if strings.EqualFold(a, f.Host) {
			return nil, fmt.Errorf("flat registry alias %s is the flat name itself", quoteBounded(a, maxMirrorHostLen))
		}
		if !p.clusterLocalAuthority(a) {
			return nil, fmt.Errorf("flat registry alias %s is neither a loopback spelling nor an authority admitted by WithClusterRegistries",
				quoteBounded(a, maxMirrorHostLen))
		}
		fr.aliases[strings.ToLower(a)] = struct{}{}
	}
	fr.fetch = endpointFetch(f.Host, f.Endpoint, pool)
	return fr, nil
}

// endpointFetch returns the FetchFunc that reaches the registry named host at
// ep. The reference keeps host as its authority, so the request, the TLS server
// name and every log line name the registry; only the DIAL is redirected, and
// only for host itself. A dial to anything else (a redirect off the registry) is
// refused: the cluster's own registry has no business sending this node
// elsewhere.
func endpointFetch(host string, ep RegistryEndpoint, pool *x509.CertPool) FetchFunc {
	dialer := &net.Dialer{Timeout: flatRegistryDialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// No Proxy: the endpoint is cluster-internal, and an environment proxy
		// would receive the request instead of the endpoint.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !strings.EqualFold(addr, host) {
				return nil, fmt.Errorf("flat registry %s: refusing to dial %s", quoteBounded(host, maxMirrorHostLen), quoteBounded(addr, maxMirrorHostLen))
			}
			return dialer.DialContext(ctx, network, ep.Addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	var opts []name.Option
	if ep.TLS {
		serverName := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			serverName = h
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
	} else {
		opts = append(opts, name.Insecure)
	}
	return func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
		r, err := name.ParseReference(ref, opts...)
		if err != nil {
			return nil, fmt.Errorf("parse reference %q: %w: %w", ref, ErrInvalidReference, boundErr(err))
		}
		if got := r.Context().RegistryStr(); !strings.EqualFold(got, host) {
			return nil, fmt.Errorf("reference %s names registry %s, not the flat registry %s",
				quoteBounded(ref, maxReferenceLen), quoteBounded(got, maxMirrorHostLen), quoteBounded(host, maxMirrorHostLen))
		}
		return remoteFetch(ctx, r, ref, cred, policy, remote.WithTransport(tr))
	}
}

// flatCanonical reports the canonical spelling of ref when ref names the flat
// registry or one of its aliases: Host, then ref's repository and identifier
// byte for byte (a splice, never a parse-and-reassemble, for the reason
// rewriteRegistryHost gives).
func (p *Puller) flatCanonical(ref string) (string, bool) {
	if p.flat == nil {
		return "", false
	}
	authority, ok := authorityOf(ref)
	if !ok {
		return "", false
	}
	a := strings.ToLower(authority)
	if a == p.flat.host {
		return ref, true
	}
	if _, ok := p.flat.aliases[a]; !ok {
		return "", false
	}
	return p.flat.host + ref[len(authority):], true
}

// flatBareName reports the canonical spelling a BARE ref takes when the node's
// own ingest registry (WithLocalRegistry) is a spelling of the flat registry.
func (p *Puller) flatBareName(ref string) (string, bool) {
	if p.flat == nil || !p.localRegistryApplies(ref) {
		return "", false
	}
	localRef, ok := localRegistryRef(p.localRegistry, ref)
	if !ok {
		return "", false
	}
	return p.flatCanonical(localRef)
}

// CanonicalReference returns the spelling ref is recorded under on this node:
// the flat registry's name for a reference that spells it through an alias, and
// ref unchanged otherwise. A bare name is returned unchanged, because which
// registry answers it is decided only by a pull.
func (p *Puller) CanonicalReference(ref string) string {
	if c, ok := p.flatCanonical(ref); ok {
		return c
	}
	return ref
}

// pullFromFlatRegistry fetches canonical from the flat registry's endpoint and
// ingests it under canonical. No credential is forwarded when the reference was
// a bare name (see pullFromLocalRegistry for why); for an explicit spelling of
// the registry the pod's own pull secret is scoped to it and rides along.
func (p *Puller) pullFromFlatRegistry(ctx context.Context, canonical string, cred *RegistryCredential, policy PlatformPolicy, want []Platform) (*PullResult, error) {
	img, err := p.flat.fetch(ctx, canonical, cred, policy)
	if err != nil {
		return nil, err
	}
	return p.ingest(ctx, canonical, img, want)
}
