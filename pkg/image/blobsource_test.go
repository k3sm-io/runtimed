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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// blobSourceMirrors is a MirrorSource with one fixed candidate.
type blobSourceMirrors struct{ m Mirror }

func (s blobSourceMirrors) Mirrors(string) []Mirror { return []Mirror{s.m} }

// TestBlobSourcePerPath pins, with no network, that each fetch path yields
// the direct blob route its image fetch uses: the default path ggcr's default
// transport and the converted credential, the flat registry its pinned-CA
// endpoint transport (the very value its fetcher dials over), and a mirror
// the default transport, the candidate's scheme and no credential at all.
func TestBlobSourcePerPath(t *testing.T) {
	ca := newTestCA(t, "blobsource-ca")
	flatEP := RegistryEndpoint{Addr: "100.64.0.1:6450", TLS: true, CAPEM: ca.pem}
	mirror := Mirror{Host: "100.64.1.1:6450", PlainHTTP: true}
	cred := &RegistryCredential{Username: "u", Password: "p", Auth: "YTpi", IdentityToken: "id", RegistryToken: "rt"}
	wantCred := &registryfetch.Credential{Username: "u", Password: "p", Auth: "YTpi", IdentityToken: "id", RegistryToken: "rt"}
	noFetch := func(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
		return nil, errors.New("no fetch in this test")
	}
	noMirrorFetch := func(context.Context, string, Mirror, PlatformPolicy) (ggcrv1.Image, error) {
		return nil, errors.New("no fetch in this test")
	}
	wired := []PullerOption{
		WithFlatRegistry(FlatRegistry{Host: flatHost, Endpoint: flatEP}),
		WithMirrors(blobSourceMirrors{m: mirror}, noMirrorFetch),
		WithClusterRegistries([]string{"10.0.0.5:5000"}, noFetch),
		WithRegistryBlobSource(RemoteBlobSource, RemoteMirrorBlobSource),
	}
	// flatTransport marks a case whose transport must be the flat registry's own.
	var flatTransport http.RoundTripper = &http.Transport{}
	// externalTransport marks a case whose transport must be the image fetch's
	// external transport, the header-timeout clone registryTransport returns.
	var externalTransport http.RoundTripper = &http.Transport{}

	for _, tc := range []struct {
		name          string
		opts          []PullerOption
		route         func(p *Puller) (BlobSource, bool, error)
		wantOK        bool
		wantErr       bool
		wantRef       string
		wantTransport http.RoundTripper
		wantPlainHTTP bool
		wantCred      *registryfetch.Credential
	}{
		{
			name: "default path: ggcr default transport, converted credential",
			opts: wired,
			route: func(p *Puller) (BlobSource, bool, error) {
				return p.primaryBlobSource("registry.example.com/team/app:v1", cred)
			},
			wantOK:        true,
			wantRef:       "registry.example.com/team/app:v1",
			wantTransport: externalTransport,
			wantCred:      wantCred,
		},
		{
			name:          "default path: a short name is fully qualified, anonymous stays nil",
			opts:          wired,
			route:         func(p *Puller) (BlobSource, bool, error) { return p.primaryBlobSource("ubuntu", nil) },
			wantOK:        true,
			wantRef:       "index.docker.io/library/ubuntu:latest",
			wantTransport: externalTransport,
		},
		{
			name:          "flat path: pinned-CA endpoint transport, converted credential",
			opts:          wired,
			route:         func(p *Puller) (BlobSource, bool, error) { return p.flatBlobSource(flatHost+"/team/app:v1", cred) },
			wantOK:        true,
			wantRef:       flatHost + "/team/app:v1",
			wantTransport: flatTransport,
			wantCred:      wantCred,
		},
		{
			name: "flat path: another registry is refused, so no credential is yielded for it",
			opts: wired,
			route: func(p *Puller) (BlobSource, bool, error) {
				return p.flatBlobSource("registry.example.com/team/app:v1", cred)
			},
			wantErr: true,
		},
		{
			name: "mirror path: default transport, candidate scheme, anonymous",
			opts: wired,
			route: func(p *Puller) (BlobSource, bool, error) {
				return p.mirrorBlobSource(mirror.Host+"/team/app:v1", mirror)
			},
			wantOK:        true,
			wantRef:       mirror.Host + "/team/app:v1",
			wantTransport: externalTransport,
			wantPlainHTTP: true,
		},
		{
			name: "admitted cluster registry: no paired route",
			opts: wired,
			route: func(p *Puller) (BlobSource, bool, error) {
				return p.primaryBlobSource("10.0.0.5:5000/team/app:v1", cred)
			},
		},
		{
			name: "no WithRegistryBlobSource: default path yields none",
			route: func(p *Puller) (BlobSource, bool, error) {
				return p.primaryBlobSource("registry.example.com/team/app:v1", cred)
			},
		},
		{
			name: "no WithRegistryBlobSource: mirror path yields none",
			route: func(p *Puller) (BlobSource, bool, error) {
				return p.mirrorBlobSource(mirror.Host+"/team/app:v1", mirror)
			},
		},
		{
			name:  "no flat registry: flat path yields none",
			route: func(p *Puller) (BlobSource, bool, error) { return p.flatBlobSource(flatHost+"/team/app:v1", cred) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := NewCache(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewPuller(cache, noFetch, NoLocalIndex{}, tc.opts...)
			if err != nil {
				t.Fatalf("NewPuller: %v", err)
			}
			src, ok, err := tc.route(p)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				if !reflect.DeepEqual(src, BlobSource{}) {
					t.Fatalf("no route yielded a non-zero source with ref %q", src.Ref)
				}
				return
			}
			if src.Ref != tc.wantRef {
				t.Errorf("Ref = %q, want %q", src.Ref, tc.wantRef)
			}
			if _, err := name.ParseReference(src.Ref, name.StrictValidation); err != nil {
				t.Errorf("Ref %q does not pass registryfetch's strict parse: %v", src.Ref, err)
			}
			if src.Registry.PlainHTTP != tc.wantPlainHTTP {
				t.Errorf("PlainHTTP = %v, want %v", src.Registry.PlainHTTP, tc.wantPlainHTTP)
			}
			if !reflect.DeepEqual(src.Credential, tc.wantCred) {
				t.Errorf("Credential = %s, want %s", describeCredential(src.Credential), describeCredential(tc.wantCred))
			}
			want := tc.wantTransport
			if want == flatTransport {
				want = p.flat.transport
				assertPinnedFlatTransport(t, p.flat.transport, ca)
				if got := p.flat.transport.ResponseHeaderTimeout; got != headerTimeout {
					t.Errorf("flat ResponseHeaderTimeout = %s, want %s", got, headerTimeout)
				}
			}
			if want == externalTransport {
				// The same value the image fetch dials over (RemoteFetch passes
				// registryTransport() to splitFetch), so blobs and manifests
				// share one connection pool and one header bound.
				want = registryTransport()
				ht, ok := src.Registry.Transport.(*http.Transport)
				if !ok {
					t.Fatalf("Transport is %T, want *http.Transport", src.Registry.Transport)
				}
				if ht.ResponseHeaderTimeout != headerTimeout {
					t.Errorf("ResponseHeaderTimeout = %s, want %s", ht.ResponseHeaderTimeout, headerTimeout)
				}
			}
			if src.Registry.Transport != want {
				t.Errorf("Transport = %p, want %p", src.Registry.Transport, want)
			}
		})
	}
}

// assertPinnedFlatTransport checks tr carries the endpoint's CA as its only
// trust anchor, names the registry host for TLS, and bypasses any proxy.
func assertPinnedFlatTransport(t *testing.T, tr *http.Transport, ca testCA) {
	t.Helper()
	if tr == nil || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("flat transport has no pinned trust anchor: %+v", tr)
	}
	if tr.Proxy != nil {
		t.Error("flat transport consults a proxy")
	}
	if got, want := tr.TLSClientConfig.ServerName, "registry-k3sm"; got != want {
		t.Errorf("ServerName = %q, want %q", got, want)
	}
	pool := tr.TLSClientConfig.RootCAs
	if _, err := ca.cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("the endpoint CA does not verify against the pinned pool: %v", err)
	}
}

// describeCredential names whether c is present without printing a secret.
func describeCredential(c *registryfetch.Credential) string {
	if c == nil {
		return "<none>"
	}
	return "<present>"
}

// TestBlobSourceScheme pins the scheme, host-case and credential edges of the
// flat and mirror routes with no network.
func TestBlobSourceScheme(t *testing.T) {
	ca := newTestCA(t, "blobsource-edge-ca")
	tlsEP := RegistryEndpoint{Addr: "100.64.0.1:6450", TLS: true, CAPEM: ca.pem}
	plainEP := RegistryEndpoint{Addr: "127.0.0.1:6450"}
	cred := &RegistryCredential{Username: "u", Password: "p", Auth: "YTpi", IdentityToken: "id", RegistryToken: "rt"}
	noFetch := func(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
		return nil, errors.New("no fetch in this test")
	}
	noMirrorFetch := func(context.Context, string, Mirror, PlatformPolicy) (ggcrv1.Image, error) {
		return nil, errors.New("no fetch in this test")
	}
	puller := func(t *testing.T, ep RegistryEndpoint, m Mirror) *Puller {
		t.Helper()
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p, err := NewPuller(cache, noFetch, NoLocalIndex{}, WithFlatRegistry(FlatRegistry{Host: flatHost, Endpoint: ep}),
			WithMirrors(blobSourceMirrors{m: m}, noMirrorFetch),
			WithRegistryBlobSource(RemoteBlobSource, RemoteMirrorBlobSource))
		if err != nil {
			t.Fatalf("NewPuller: %v", err)
		}
		return p
	}

	for _, tc := range []struct {
		name          string
		ep            RegistryEndpoint
		mirror        Mirror
		route         func(p *Puller, m Mirror) (BlobSource, bool, error)
		wantErr       bool
		wantPlainHTTP bool
		wantRef       string
		wantCred      bool
	}{
		{
			name: "flat endpoint without TLS is plain HTTP",
			ep:   plainEP,
			route: func(p *Puller, _ Mirror) (BlobSource, bool, error) {
				return p.flatBlobSource(flatHost+"/team/app:v1", cred)
			},
			wantPlainHTTP: true,
			wantRef:       flatHost + "/team/app:v1",
			wantCred:      true,
		},
		{
			name: "flat endpoint with TLS is not plain HTTP",
			ep:   tlsEP,
			route: func(p *Puller, _ Mirror) (BlobSource, bool, error) {
				return p.flatBlobSource(flatHost+"/team/app:v1", cred)
			},
			wantRef:  flatHost + "/team/app:v1",
			wantCred: true,
		},
		{
			name:   "mirror with PlainHTTP false is not plain HTTP",
			ep:     tlsEP,
			mirror: Mirror{Host: "100.64.1.1:6450", PlainHTTP: false},
			route: func(p *Puller, m Mirror) (BlobSource, bool, error) {
				return p.mirrorBlobSource(m.Host+"/team/app:v1", m)
			},
			wantRef: "100.64.1.1:6450/team/app:v1",
		},
		{
			name: "flat host in a different letter case than the registry is accepted, ref kept as given",
			ep:   tlsEP,
			route: func(p *Puller, _ Mirror) (BlobSource, bool, error) {
				return p.flatBlobSource(strings.ToUpper(flatHost)+"/team/app:v1", cred)
			},
			wantRef:  strings.ToUpper(flatHost) + "/team/app:v1",
			wantCred: true,
		},
		{
			name:   "mirror-rewritten reference never carries a credential even though the primary lookup had one",
			ep:     tlsEP,
			mirror: Mirror{Host: "100.64.1.1:6450", PlainHTTP: true},
			route: func(p *Puller, m Mirror) (BlobSource, bool, error) {
				primary, ok, err := p.primaryBlobSource("registry.example.com/team/app:v1", cred)
				if err != nil || !ok || primary.Credential == nil {
					t.Fatalf("primary lookup: ok=%v err=%v credential=%s, want a credential", ok, err, describeCredential(primary.Credential))
				}
				return p.mirrorBlobSource(m.Host+"/team/app:v1", m)
			},
			wantPlainHTTP: true,
			wantRef:       "100.64.1.1:6450/team/app:v1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := puller(t, tc.ep, tc.mirror)
			src, ok, err := tc.route(p, tc.mirror)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if !ok {
				t.Fatal("no route yielded")
			}
			if src.Ref != tc.wantRef {
				t.Errorf("Ref = %q, want %q", src.Ref, tc.wantRef)
			}
			if src.Registry.PlainHTTP != tc.wantPlainHTTP {
				t.Errorf("PlainHTTP = %v, want %v", src.Registry.PlainHTTP, tc.wantPlainHTTP)
			}
			if got := src.Credential != nil; got != tc.wantCred {
				t.Errorf("credential present = %v, want %v", got, tc.wantCred)
			}
		})
	}
}

// TestBlobSourceRedaction pins that no formatting of a BlobSource, nor its slog
// form, carries a credential's secret fields, while the ref and the presence of
// a credential stay visible.
func TestBlobSourceRedaction(t *testing.T) {
	secrets := []string{"s3cr3t-password", "s3cr3t-identity-token", "s3cr3t-registry-token", "czNjcjN0LWF1dGg="}
	src := BlobSource{
		Ref:      "registry.example.com/team/app:v1",
		Registry: registryfetch.Registry{PlainHTTP: true},
		Credential: &registryfetch.Credential{
			Username: "user", Password: secrets[0], IdentityToken: secrets[1], RegistryToken: secrets[2], Auth: secrets[3],
		},
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("blob", "src", src, "srcPtr", &src)
	var text bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("blob", "src", src)

	for name, got := range map[string]string{
		"%v":      fmt.Sprintf("%v", src),
		"%+v":     fmt.Sprintf("%+v", src),
		"%#v":     fmt.Sprintf("%#v", src),
		"%v ptr":  fmt.Sprintf("%v", &src),
		"%+v ptr": fmt.Sprintf("%+v", &src),
		"%s":      fmt.Sprintf("%s", src),
		"json":    logged.String(),
		"text":    text.String(),
	} {
		for _, secret := range secrets {
			if strings.Contains(got, secret) {
				t.Errorf("%s output carries a secret", name)
			}
		}
		if !strings.Contains(got, src.Ref) {
			t.Errorf("%s output lost the ref: %q", name, got)
		}
	}
	if !strings.Contains(logged.String(), `"credential":true`) || !strings.Contains(logged.String(), `"plainHTTP":true`) {
		t.Errorf("slog form lost the credential or plain-HTTP flag: %s", logged.String())
	}
}
