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
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// svcRef is the reference a workload gets when it names this cluster's ingest
// registry through a Service DNS name rather than through loopback. It is the
// spelling the loopback-only gate could not see.
const svcRef = "registry.k3sm-system.svc.cluster.local:6450/team/app:v1"

// clusterPuller builds a Puller with an admitted cluster-registry set wired: a
// primary fetcher for every other reference, and a separate fetcher standing in
// for the plain-HTTP one those authorities are dialled with.
func clusterPuller(t *testing.T, cache *Cache, index LocalIndex, primary, cluster FetchFunc, hosts []string, src MirrorSource, mf MirrorFetchFunc, logs *bytes.Buffer) *Puller {
	t.Helper()
	opts := []PullerOption{
		WithFreeBytes(fixedFreeBytes(64 << 30)),
		WithPullLogger(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		WithClusterRegistries(hosts, cluster),
	}
	if src != nil || mf != nil {
		opts = append(opts, WithMirrors(src, mf))
	}
	p, err := NewPuller(cache, primary, index, opts...)
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	return p
}

// TestClusterLocalAdmission is the gate for slice 1: WHICH references count as
// this cluster's own ingest registry once the consumer has named additional
// authorities.
//
// Loopback is unconditional and is asserted here as well as in
// TestClusterLocalRefGate, because the whole risk of adding a configurable set
// is that it becomes the ONLY thing consulted; a node given no set must still
// broker its loopback pulls.
func TestClusterLocalAdmission(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	build := func(t *testing.T, hosts []string) *Puller {
		t.Helper()
		opts := []PullerOption{}
		if len(hosts) > 0 {
			opts = append(opts, WithClusterRegistries(hosts, RemoteInsecureFetch))
		}
		p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{}, opts...)
		if err != nil {
			t.Fatalf("NewPuller: %v", err)
		}
		return p
	}

	hosts := []string{
		"registry.k3sm-system.svc.cluster.local:6450",
		"10.43.0.7:6450",
	}
	for _, tc := range []struct {
		name  string
		hosts []string
		ref   string
		want  bool
		why   string
	}{
		{"loopback with no set configured", nil, localRef, true, "the loopback gate is unconditional"},
		{"loopback with a set configured", hosts, localRef, true, "adding authorities must not narrow the loopback gate"},
		{"a Service DNS authority, admitted", hosts, svcRef, true, "the consumer named this spelling of its own registry"},
		{"a Service VIP authority, admitted", hosts, "10.43.0.7:6450/team/app:v1", true, "an admitted authority is matched exactly"},
		{"the same authority in mixed case", hosts, "Registry.K3sm-System.svc.cluster.local:6450/team/app:v1", true, "a registry authority's host is case-insensitive"},
		{"a Service DNS authority with NO set configured", nil, svcRef, false, "nothing is admitted until the consumer names it"},
		{"an admitted host on a DIFFERENT port", hosts, "10.43.0.7:5000/team/app:v1", false, "the set is host[:port], matched exactly — a different port is a different registry"},
		{"a public registry", hosts, "docker.io/library/nginx:1.27", false, "no peer of this cluster is authoritative for a public namespace"},
		{"a mesh peer address that was never admitted", hosts, "100.64.1.1:6450/team/app:v1", false, "a peer is a mirror candidate, not a cluster-local spelling"},
		{"a reference naming no registry at all", hosts, "app:v1", false, "there is no authority to match"},
		{"a first component ggcr reads as a repository element", hosts, "localhost/team/app:v1", false, "authorityOf agrees with name.NewRepository: no '.' and no ':' is not a registry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := build(t, tc.hosts)
			if got := p.clusterLocal(tc.ref); got != tc.want {
				t.Errorf("clusterLocal(%q) = %v, want %v — %s", tc.ref, got, tc.want, tc.why)
			}
		})
	}
}

// TestClusterRegistrySelectsPlainHTTP is the transport half, asserted the way
// TestMirrorReferenceSelectsItsScheme asserts the mirror's: through
// name.Registry.Scheme() rather than by dialling.
//
// The rows that matter are the Service ones. go-containerregistry infers http
// only for localhost, *.localhost, 127.0.0.1, ::1 and the three RFC 1918 ranges,
// so a cluster Service DNS name — and a VIP out of the 10/8-adjacent ranges a
// distribution may pick — is otherwise dialled as HTTPS and fails the handshake
// against a plain-HTTP ingest registry.
func TestClusterRegistrySelectsPlainHTTP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ref      string
		insecure bool
		want     string
	}{
		{"a Service DNS name WITHOUT the insecure option is https — the trap", svcRef, false, "https"},
		{"a Service DNS name with the insecure option is http", svcRef, true, "http"},
		{"a Service VIP outside RFC 1918 without it is https", "100.64.9.9:6450/team/app:v1", false, "https"},
		{"a Service VIP outside RFC 1918 with it is http", "100.64.9.9:6450/team/app:v1", true, "http"},
		{"loopback needs no option at all", localRef, false, "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []name.Option
			if tc.insecure {
				opts = append(opts, name.Insecure)
			}
			r, err := name.ParseReference(tc.ref, opts...)
			if err != nil {
				t.Fatalf("ParseReference(%q): %v", tc.ref, err)
			}
			if got := r.Context().Registry.Scheme(); got != tc.want {
				t.Errorf("scheme for %q = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// TestPrimaryFetchRoutesByAuthority proves the routing decision is the Puller's
// configuration and not the fetcher's opinion: an admitted authority reaches the
// plain-HTTP fetcher and nothing else does — including a loopback reference,
// which go-containerregistry already dials as http through the ordinary fetcher.
func TestPrimaryFetchRoutesByAuthority(t *testing.T) {
	for _, tc := range []struct {
		name            string
		ref             string
		wantClusterCall bool
	}{
		{"an admitted Service authority takes the plain-HTTP fetcher", svcRef, true},
		{"a loopback reference stays on the primary fetcher", localRef, false},
		{"a public reference stays on the primary fetcher", "docker.io/library/nginx:1.27", false},
		{"an un-admitted authority stays on the primary fetcher", "registry.example:6450/team/app:v1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, index, logs := newFixtureStore(t)
			img := nativeImage(t)
			primary := &stubFetch{img: img}
			cluster := &stubFetch{img: img}
			p := clusterPuller(t, cache, index, primary.fetch, cluster.fetch,
				[]string{"registry.k3sm-system.svc.cluster.local:6450"}, nil, nil, logs)

			if _, err := p.Pull(context.Background(), tc.ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err != nil {
				t.Fatalf("Pull(%q): %v", tc.ref, err)
			}
			gotCluster := cluster.calls == 1
			if gotCluster != tc.wantClusterCall {
				t.Errorf("plain-HTTP fetcher calls = %d, primary calls = %d; want the plain-HTTP fetcher used = %v",
					cluster.calls, primary.calls, tc.wantClusterCall)
			}
			// Exactly one fetcher runs, never both: routing is a choice, not a
			// retry, and a second attempt would double the registry traffic of
			// every pull on the node.
			if primary.calls+cluster.calls != 1 {
				t.Errorf("fetch attempts = %d (primary %d, cluster %d), want exactly 1",
					primary.calls+cluster.calls, primary.calls, cluster.calls)
			}
			// The reference recorded is what the pod asked for, whichever
			// transport served it.
			if _, ok := index.refs[tc.ref]; !ok {
				t.Errorf("index recorded %v, want %q", keysOf(index.refs), tc.ref)
			}
		})
	}
}

// TestAdmittedAuthorityIsBrokeredLikeLoopback is the uniformity claim itself: a
// miss on a Service-spelled reference falls back to the cluster mirrors exactly
// as the loopback spelling of the same pull does, asks the peer for the same
// repository and identifier, and records the ORIGINAL reference.
func TestAdmittedAuthorityIsBrokeredLikeLoopback(t *testing.T) {
	const admitted = "registry.k3sm-system.svc.cluster.local:6450"
	peer := Mirror{Host: "100.64.1.1:6450", PlainHTTP: true}

	t.Run("an admitted authority falls back to the peers", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		cluster := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{peer}}
		mf := newMirrorFetcher()
		mf.byRef[peer.Host+"/team/app:v1"] = nativeImage(t)

		p := clusterPuller(t, cache, index, (&stubFetch{err: registryStatus(http.StatusNotFound)}).fetch,
			cluster.fetch, []string{admitted}, src, mf.fetch, logs)
		res, err := p.Pull(context.Background(), svcRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("Pull(%q): %v", svcRef, err)
		}
		if src.calls != 1 {
			t.Errorf("mirror source consulted %d times, want 1", src.calls)
		}
		if len(mf.asked) != 1 || mf.asked[0] != peer.Host+"/team/app:v1" {
			t.Errorf("peer was asked for %v, want [%q]", mf.asked, peer.Host+"/team/app:v1")
		}
		if got := res.Manifest.GetReference(); got != svcRef {
			t.Errorf("recorded reference = %q, want the original %q", got, svcRef)
		}
	})

	t.Run("negative control: the SAME miss on an un-admitted authority does not", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		src := &fixedMirrors{list: []Mirror{peer}}
		mf := newMirrorFetcher()
		mf.byRef[peer.Host+"/team/app:v1"] = nativeImage(t)

		p := clusterPuller(t, cache, index, (&stubFetch{err: registryStatus(http.StatusNotFound)}).fetch,
			(&stubFetch{}).fetch, []string{"registry.other:6450"}, src, mf.fetch, logs)
		if _, err := p.Pull(context.Background(), svcRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err == nil {
			t.Fatal("pull succeeded for an authority this node was never told is its own")
		}
		if src.calls != 0 {
			t.Errorf("mirror source consulted %d times for an un-admitted authority, want 0", src.calls)
		}
	})
}

// TestNewPullerValidatesClusterRegistries: a half-wiring and a malformed
// authority are both refused at CONSTRUCTION.
//
// A malformed authority cannot match any parsed reference, so admitting it would
// leave a node believing it brokers a spelling it silently never sees — the
// same class of invisible failure the half-wired mirror refusal exists for.
func TestNewPullerValidatesClusterRegistries(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opt  PullerOption
	}{
		{"a set with no fetcher", WithClusterRegistries([]string{"registry.svc:6450"}, nil)},
		{"a fetcher with no set", WithClusterRegistries(nil, RemoteInsecureFetch)},
		{"an empty authority", WithClusterRegistries([]string{""}, RemoteInsecureFetch)},
		{"an authority carrying a path", WithClusterRegistries([]string{"registry.svc:6450/evil"}, RemoteInsecureFetch)},
		{"an authority carrying a scheme", WithClusterRegistries([]string{"http://registry.svc:6450"}, RemoteInsecureFetch)},
		{"an authority carrying userinfo", WithClusterRegistries([]string{"user@registry.svc:6450"}, RemoteInsecureFetch)},
		{"a dotless, portless host ggcr reads as a repository element", WithClusterRegistries([]string{"registry"}, RemoteInsecureFetch)},
		{"one good authority and one bad", WithClusterRegistries([]string{"registry.svc:6450", "evil"}, RemoteInsecureFetch)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{}, tc.opt); err == nil {
				t.Errorf("NewPuller returned %+v, want a refusal", p)
			}
		})
	}

	t.Run("no option at all is the default and is accepted", func(t *testing.T) {
		if _, err := NewPuller(cache, RemoteFetch, NoLocalIndex{}); err != nil {
			t.Errorf("NewPuller with no cluster-registry option: %v", err)
		}
	})
	t.Run("a well-formed set with its fetcher is accepted", func(t *testing.T) {
		if _, err := NewPuller(cache, RemoteFetch, NoLocalIndex{},
			WithClusterRegistries([]string{"registry.k3sm-system.svc.cluster.local:6450", "10.43.0.7:6450"}, RemoteInsecureFetch)); err != nil {
			t.Errorf("NewPuller with a well-formed set: %v", err)
		}
	})
}
