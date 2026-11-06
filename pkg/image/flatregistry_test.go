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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// flatHost is the cluster's one registry name in these rows.
const flatHost = "registry-k3sm:6450"

// testCA is a throwaway certificate authority for the flat registry fixture.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serving issues a serving certificate for dnsName.
func (ca testCA) serving(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate serving key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create serving cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// flatFixture is the server's registry: one in-memory store served over TLS
// with a certificate for "registry-k3sm" (the endpoint under test) and over
// plain loopback HTTP (the seeding path only). requests counts what reached the
// TLS listener, so a row can prove the endpoint was or was not contacted.
type flatFixture struct {
	ca       testCA
	tlsAddr  string
	seedHost string
	requests atomic.Int64
}

func newFlatFixture(t *testing.T) *flatFixture {
	t.Helper()
	f := &flatFixture{ca: newTestCA(t, "test-cluster-ca")}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		store.ServeHTTP(w, r)
	}))
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{f.ca.serving(t, "registry-k3sm")}}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)
	seed := httptest.NewServer(store)
	t.Cleanup(seed.Close)
	f.tlsAddr = tlsSrv.Listener.Addr().String()
	u, err := url.Parse(seed.URL)
	if err != nil {
		t.Fatalf("parse seed url: %v", err)
	}
	f.seedHost = u.Host
	return f
}

// push stores img in the fixture under repoTag ("team/app:v1").
func (f *flatFixture) push(t *testing.T, repoTag string, img ggcrv1.Image) {
	t.Helper()
	ref, err := name.ParseReference(f.seedHost + "/" + repoTag)
	if err != nil {
		t.Fatalf("parse seed ref: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("seed %s: %v", repoTag, err)
	}
}

// endpoint is the fixture's TLS endpoint, trusting caPEM.
func (f *flatFixture) endpoint(caPEM []byte) RegistryEndpoint {
	return RegistryEndpoint{Addr: f.tlsAddr, TLS: true, CAPEM: caPEM}
}

// flatPuller builds a puller with the flat registry mapped, the node's ingest
// registry set to local ("" for none), the primary fetcher and mirrors given.
func flatPuller(t *testing.T, index LocalIndex, cache *Cache, fetch FetchFunc, ep RegistryEndpoint, local string, src MirrorSource, mf MirrorFetchFunc) *Puller {
	t.Helper()
	var logs bytes.Buffer
	opts := []PullerOption{
		WithFreeBytes(fixedFreeBytes(64 << 30)),
		WithPullLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		WithFlatRegistry(FlatRegistry{Host: flatHost, Endpoint: ep, Aliases: []string{"localhost:6450", "127.0.0.1:6450"}}),
	}
	if local != "" {
		opts = append(opts, WithLocalRegistry(local))
	}
	if src != nil || mf != nil {
		opts = append(opts, WithMirrors(src, mf))
	}
	p, err := NewPuller(cache, fetch, index, opts...)
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	return p
}

// listedReferences is every reference the index lists.
func listedReferences(t *testing.T, idx *FileIndex) []string {
	t.Helper()
	entries, err := idx.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Reference)
	}
	return out
}

// TestFlatRegistryReferenceMapsToServerEndpoint is the gate for the flat
// registry name: registry-k3sm:6450 is fetched from the endpoint the embedder
// supplies, its TLS verified against the given CA and nothing else; every
// spelling of the same registry is recorded under that one name; the portless
// name stays Docker Hub; and every other reference keeps its old paths.
func TestFlatRegistryReferenceMapsToServerEndpoint(t *testing.T) {
	const repoTag = "team/app:v1"
	canonical := flatHost + "/" + repoTag
	always := runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS
	ifNotPresent := runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT

	for _, tc := range []struct {
		name string
		// ref is what the pod wrote.
		ref string
		// local is the node's ingest registry ("" = none, the agent shape).
		local string
		// wrongCA makes the puller trust a different CA than the endpoint's.
		wrongCA bool
		// wantErr is a substring the pull error must carry ("" = success).
		wantErr string
		// wantRecorded is the reference the index must list after the pull.
		wantRecorded string
		// wantEndpoint is whether the flat endpoint must have been contacted.
		wantEndpoint bool
		// wantPrimary is the exact primary-fetch sequence.
		wantPrimary []string
	}{
		{
			name: "the flat name is fetched from the endpoint over verified TLS",
			ref:  canonical, wantRecorded: canonical, wantEndpoint: true,
		},
		{
			name: "a wrong CA fails the handshake and records nothing",
			ref:  canonical, wrongCA: true, wantErr: "certificate", wantEndpoint: false,
		},
		{
			name: "localhost:<port> is an alias recorded under the flat name",
			ref:  "localhost:6450/" + repoTag, wantRecorded: canonical, wantEndpoint: true,
		},
		{
			name: "127.0.0.1:<port> is an alias recorded under the flat name",
			ref:  "127.0.0.1:6450/" + repoTag, wantRecorded: canonical, wantEndpoint: true,
		},
		{
			name: "a bare name the node's registry answers is recorded under the flat name",
			ref:  repoTag, local: "localhost:6450", wantRecorded: canonical, wantEndpoint: true,
		},
		{
			name: "the portless name is a Docker Hub repository, never the flat registry",
			ref:  "registry-k3sm/" + repoTag, wantRecorded: "registry-k3sm/" + repoTag,
			wantEndpoint: false, wantPrimary: []string{"registry-k3sm/" + repoTag},
		},
		{
			name: "the portless name stays Docker Hub on a node with a local registry too",
			ref:  "registry-k3sm/" + repoTag, local: "localhost:6450", wantRecorded: "registry-k3sm/" + repoTag,
			// The flat registry is asked for the bare name (it has no such
			// repository), then upstream answers under the name as written.
			wantEndpoint: true, wantPrimary: []string{"registry-k3sm/" + repoTag},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFlatFixture(t)
			fx.push(t, repoTag, nativeImage(t))
			cache, idx := newIndexedCache(t)
			primary := newRefFetch()
			primary.byRef["registry-k3sm/"+repoTag] = nativeImage(t)
			caPEM := fx.ca.pem
			if tc.wrongCA {
				caPEM = newTestCA(t, "some-other-ca").pem
			}
			p := flatPuller(t, idx, cache, primary.fetch, fx.endpoint(caPEM), tc.local, nil, nil)

			res, err := p.Pull(context.Background(), tc.ref, nil, nativePolicy(), always)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Pull(%q) error = %v, want one naming %q", tc.ref, err, tc.wantErr)
				}
				if got := listedReferences(t, idx); len(got) != 0 {
					t.Errorf("index lists %v after a refused handshake, want nothing", got)
				}
				if len(primary.asked) != 0 {
					t.Errorf("primary asked %v; a flat reference must never fall back to name resolution", primary.asked)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pull(%q): %v", tc.ref, err)
			}
			if got := res.Manifest.GetReference(); got != tc.wantRecorded {
				t.Errorf("recorded reference = %q, want %q", got, tc.wantRecorded)
			}
			if got := listedReferences(t, idx); len(got) != 1 || got[0] != tc.wantRecorded {
				t.Errorf("index lists %v, want exactly [%q]", got, tc.wantRecorded)
			}
			if got := fx.requests.Load() > 0; got != tc.wantEndpoint {
				t.Errorf("endpoint contacted = %v, want %v", got, tc.wantEndpoint)
			}
			if strings.Join(primary.asked, ",") != strings.Join(tc.wantPrimary, ",") {
				t.Errorf("primary fetches = %v, want %v", primary.asked, tc.wantPrimary)
			}
		})
	}

	t.Run("a non-flat cluster-local reference still uses the peer fallback", func(t *testing.T) {
		fx := newFlatFixture(t)
		cache, idx := newIndexedCache(t)
		const ref = "localhost:5000/" + repoTag
		primary := newRefFetch() // misses everything: 404
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:5000", PlainHTTP: true}}}
		var mirrorAsked []string
		peerImg := nativeImage(t)
		mf := func(_ context.Context, r string, _ Mirror, _ PlatformPolicy) (ggcrv1.Image, error) {
			mirrorAsked = append(mirrorAsked, r)
			return peerImg, nil
		}
		p := flatPuller(t, idx, cache, primary.fetch, fx.endpoint(fx.ca.pem), "", src, mf)
		res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), always)
		if err != nil {
			t.Fatalf("Pull(%q): %v", ref, err)
		}
		if len(primary.asked) != 1 || primary.asked[0] != ref {
			t.Errorf("primary fetches = %v, want [%q]", primary.asked, ref)
		}
		if len(mirrorAsked) != 1 || mirrorAsked[0] != "100.64.1.1:5000/"+repoTag {
			t.Errorf("mirror fetches = %v, want the peer spelling", mirrorAsked)
		}
		if got := res.Manifest.GetReference(); got != ref {
			t.Errorf("recorded reference = %q, want %q", got, ref)
		}
		if fx.requests.Load() != 0 {
			t.Error("the flat endpoint was contacted for a reference that does not name it")
		}
	})

	t.Run("IfNotPresent is satisfied by the canonical entry whichever spelling the pod used", func(t *testing.T) {
		fx := newFlatFixture(t)
		fx.push(t, repoTag, nativeImage(t))
		cache, idx := newIndexedCache(t)
		primary := newRefFetch()
		p := flatPuller(t, idx, cache, primary.fetch, fx.endpoint(fx.ca.pem), "localhost:6450", nil, nil)
		if _, err := p.Pull(context.Background(), "localhost:6450/"+repoTag, nil, nativePolicy(), always); err != nil {
			t.Fatalf("seed pull: %v", err)
		}
		// Both spellings pulled Always are still ONE entry.
		if _, err := p.Pull(context.Background(), canonical, nil, nativePolicy(), always); err != nil {
			t.Fatalf("canonical pull: %v", err)
		}
		if got := listedReferences(t, idx); len(got) != 1 || got[0] != canonical {
			t.Fatalf("index lists %v after pulling both spellings, want exactly [%q]", got, canonical)
		}
		before := fx.requests.Load()
		for _, spelling := range []string{canonical, "localhost:6450/" + repoTag, "127.0.0.1:6450/" + repoTag, repoTag} {
			res, err := p.Pull(context.Background(), spelling, nil, nativePolicy(), ifNotPresent)
			if err != nil {
				t.Fatalf("IfNotPresent Pull(%q): %v", spelling, err)
			}
			if res.Fetched {
				t.Errorf("IfNotPresent Pull(%q) contacted a registry; the canonical entry must serve it", spelling)
			}
			if got := res.Manifest.GetReference(); got != canonical {
				t.Errorf("IfNotPresent Pull(%q) served %q, want the canonical entry %q", spelling, got, canonical)
			}
		}
		if got := fx.requests.Load(); got != before {
			t.Errorf("the endpoint saw %d requests during warm serves, want none", got-before)
		}
		if len(primary.asked) != 0 {
			t.Errorf("primary fetches = %v, want none", primary.asked)
		}
	})

	t.Run("an entry recorded under the alias before the mapping still serves Never", func(t *testing.T) {
		fx := newFlatFixture(t)
		cache, idx := newIndexedCache(t)
		// Recorded by a puller with no flat mapping, as a node upgraded in place has.
		const alias = "localhost:6450/" + repoTag
		old := newRefFetch()
		old.byRef[alias] = nativeImage(t)
		legacy, err := NewPuller(cache, old.fetch, idx, WithFreeBytes(fixedFreeBytes(64<<30)))
		if err != nil {
			t.Fatalf("NewPuller: %v", err)
		}
		if _, err := legacy.Pull(context.Background(), alias, nil, nativePolicy(), always); err != nil {
			t.Fatalf("legacy pull: %v", err)
		}
		p := flatPuller(t, idx, cache, newRefFetch().fetch, fx.endpoint(fx.ca.pem), "", nil, nil)
		res, err := p.Pull(context.Background(), alias, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER)
		if err != nil {
			t.Fatalf("Never Pull(%q): %v", alias, err)
		}
		if got := res.Manifest.GetReference(); got != alias {
			t.Errorf("served %q, want the pre-existing entry %q", got, alias)
		}
	})
}

// TestNewPullerValidatesFlatRegistry pins the construction refusals: the flat
// mapping can never redirect a public registry, dial a plaintext hop off this
// Mac, or trust nothing.
func TestNewPullerValidatesFlatRegistry(t *testing.T) {
	ca := newTestCA(t, "ca")
	good := RegistryEndpoint{Addr: "100.64.0.1:6450", TLS: true, CAPEM: ca.pem}
	for _, tc := range []struct {
		name    string
		f       FlatRegistry
		wantErr string
	}{
		{"a valid TLS mapping", FlatRegistry{Host: flatHost, Endpoint: good, Aliases: []string{"localhost:6450"}}, ""},
		{"a loopback plaintext endpoint", FlatRegistry{Host: flatHost, Endpoint: RegistryEndpoint{Addr: "127.0.0.1:6450"}}, ""},
		{"a portless host", FlatRegistry{Host: "registry-k3sm", Endpoint: good}, "registry"},
		{"plaintext off loopback", FlatRegistry{Host: flatHost, Endpoint: RegistryEndpoint{Addr: "100.64.0.1:6450"}}, "not loopback"},
		{"TLS with no CA", FlatRegistry{Host: flatHost, Endpoint: RegistryEndpoint{Addr: "100.64.0.1:6450", TLS: true}}, "no certificate"},
		{"an endpoint with no port", FlatRegistry{Host: flatHost, Endpoint: RegistryEndpoint{Addr: "100.64.0.1", TLS: true, CAPEM: ca.pem}}, "host:port"},
		{"a public alias", FlatRegistry{Host: flatHost, Endpoint: good, Aliases: []string{"docker.io"}}, "neither a loopback"},
		{"the name as its own alias", FlatRegistry{Host: flatHost, Endpoint: good, Aliases: []string{flatHost}}, "flat name itself"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, idx := newIndexedCache(t)
			_, err := NewPuller(cache, newRefFetch().fetch, idx, WithFlatRegistry(tc.f))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewPuller: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewPuller error = %v, want one naming %q", err, tc.wantErr)
			}
		})
	}
}

// TestFlatRegistryFetchRefusesAnotherRegistry pins that the endpoint fetcher
// serves only references naming the flat registry: the endpoint is transport
// for that one name, never for a reference that names somewhere else.
func TestFlatRegistryFetchRefusesAnotherRegistry(t *testing.T) {
	fetch := endpointFetch(flatHost, RegistryEndpoint{Addr: "127.0.0.1:1"}, nil)
	_, err := fetch(context.Background(), "ghcr.io/team/app:v1", nil, nativePolicy())
	if err == nil || !strings.Contains(err.Error(), "not the flat registry") {
		t.Fatalf("fetch of a foreign reference = %v, want a refusal", err)
	}
}
