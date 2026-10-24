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
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// registryServer is an in-memory OCI registry over TLS for dnsName, signed by
// ca, with a plain-HTTP loopback seeding listener on the same store. tamper
// replaces the body of a request path (a manifest by digest) so a row can serve
// bytes that do not hash to what was asked for. requests counts TLS requests.
type registryServer struct {
	addr     string
	seedHost string
	requests atomic.Int64
	tamper   map[string][]byte
}

func newRegistryServer(t *testing.T, ca testCA, dnsName string, handler http.Handler) *registryServer {
	t.Helper()
	s := &registryServer{tamper: map[string][]byte{}}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	if handler == nil {
		handler = store
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if body, ok := s.tamper[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write(body)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serving(t, dnsName)}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // rows refuse handshakes on purpose
	srv.StartTLS()
	t.Cleanup(srv.Close)
	seed := httptest.NewServer(store)
	t.Cleanup(seed.Close)
	u, err := url.Parse(seed.URL)
	if err != nil {
		t.Fatalf("parse seed url: %v", err)
	}
	s.addr, s.seedHost = srv.Listener.Addr().String(), u.Host
	return s
}

// push stores img under repoTag and returns its manifest digest.
func (s *registryServer) push(t *testing.T, repoTag string, img ggcrv1.Image) string {
	t.Helper()
	ref, err := name.ParseReference(s.seedHost + "/" + repoTag)
	if err != nil {
		t.Fatalf("parse seed ref: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("seed %s: %v", repoTag, err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return d.String()
}

// upstreamFetch is the production remote fetch with only its DIAL replaced: dial
// decides what "reaching the public registry" does in a row, and every error it
// returns travels the same ggcr and net/http wrapping a real outage does.
func upstreamFetch(dial func(ctx context.Context, network, addr string) (net.Conn, error), roots *x509.CertPool) (FetchFunc, *atomic.Int64) {
	var asked atomic.Int64
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 300 * time.Millisecond,
	}
	return func(ctx context.Context, ref string, cred *RegistryCredential, policy PlatformPolicy) (ggcrv1.Image, error) {
		asked.Add(1)
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, err
		}
		// One attempt: ggcr's default retry backoff only slows the timeout rows.
		return remoteFetch(ctx, r, ref, cred, policy, remote.WithTransport(tr),
			remote.WithRetryBackoff(remote.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 1}))
	}, &asked
}

// dialTo dials addr whatever the request named.
func dialTo(addr string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

// statusRegistry answers /v2/ and nothing else: every other path is code.
func statusRegistry(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(code)
	})
}

// TestMirroredReferenceServedOnlyWhenUpstreamUnreachable is the gate for the
// public-image mirror: a public reference is always tried upstream first, the
// cluster registry's copy at registry-k3sm:6450/<host>/<path> is used only when
// the upstream registry could not be reached (DNS, refused, timeout, TLS
// handshake timeout), and never when upstream answered (401, 403, 404,
// manifest unknown, a digest mismatch, an untrusted certificate). A digest-pinned
// reference resolves to that digest from the copy, or fails.
func TestMirroredReferenceServedOnlyWhenUpstreamUnreachable(t *testing.T) {
	const ref = "docker.io/team/app:v1"
	const upstreamName = "index.docker.io"
	always := runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS

	type world struct {
		mirror   *registryServer
		mirrorCA testCA
		pinned   string // ref pinned to the copy's digest
		other    ggcrv1.Image
	}
	newWorld := func(t *testing.T) *world {
		w := &world{mirrorCA: newTestCA(t, "cluster-ca")}
		w.mirror = newRegistryServer(t, w.mirrorCA, "registry-k3sm", nil)
		d := w.mirror.push(t, "docker.io/team/app:v1", nativeImage(t))
		w.pinned = "docker.io/team/app@" + d
		w.other = nativeImage(t)
		return w
	}

	// Each row builds the upstream it needs; dial and roots configure the
	// public fetch, and pullRef is what the pod asks for.
	type upstream struct {
		dial  func(ctx context.Context, network, addr string) (net.Conn, error)
		roots *x509.CertPool
	}
	unreachable := []struct {
		name string
		up   func(t *testing.T) upstream
	}{
		{"a DNS failure", func(t *testing.T) upstream {
			return upstream{dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: upstreamName, IsNotFound: true}}
			}}
		}},
		{"a refused connection", func(t *testing.T) upstream {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			_ = l.Close() // nothing listens there now
			return upstream{dial: dialTo(addr)}
		}},
		{"a dial timeout", func(t *testing.T) upstream {
			return upstream{dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Nanosecond}
				return d.DialContext(ctx, network, "192.0.2.1:443")
			}}
		}},
		{"a TLS handshake that times out", func(t *testing.T) upstream {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { _ = c.Close() }) // accepted, never answered
				}
			}()
			return upstream{dial: dialTo(l.Addr().String())}
		}},
	}
	for _, tc := range unreachable {
		t.Run("unreachable upstream, "+tc.name+", serves the copy", func(t *testing.T) {
			w := newWorld(t)
			for _, pullRef := range []string{ref, w.pinned} {
				cache, idx := newIndexedCache(t)
				up := tc.up(t)
				fetch, asked := upstreamFetch(up.dial, up.roots)
				p := flatPuller(t, idx, cache, fetch, RegistryEndpoint{Addr: w.mirror.addr, TLS: true, CAPEM: w.mirrorCA.pem}, "", nil, nil)
				before := w.mirror.requests.Load()
				res, err := p.Pull(context.Background(), pullRef, nil, nativePolicy(), always)
				if err != nil {
					t.Fatalf("Pull(%q): %v", pullRef, err)
				}
				if asked.Load() != 1 {
					t.Errorf("upstream asked %d times, want 1 (upstream always first)", asked.Load())
				}
				if w.mirror.requests.Load() == before {
					t.Error("the cluster registry's copy was not contacted")
				}
				if got := res.Manifest.GetReference(); got != pullRef {
					t.Errorf("recorded reference = %q, want the pod's %q", got, pullRef)
				}
				if got := listedReferences(t, idx); len(got) != 1 || got[0] != pullRef {
					t.Errorf("index lists %v, want exactly [%q]", got, pullRef)
				}
				if pullRef == w.pinned {
					want := pullRef[strings.Index(pullRef, "@")+1:]
					if got := res.Descriptor.GetDigest(); got != want {
						t.Errorf("pinned pull resolved %s, want %s", got, want)
					}
				}
			}
		})
	}

	t.Run("unreachable upstream, a pinned digest the copy serves different bytes for, fails", func(t *testing.T) {
		w := newWorld(t)
		otherDigest, err := w.other.Digest()
		if err != nil {
			t.Fatal(err)
		}
		pinned := "docker.io/team/app@" + otherDigest.String()
		body, err := nativeImage(t).RawManifest()
		if err != nil {
			t.Fatal(err)
		}
		w.mirror.tamper["/v2/docker.io/team/app/manifests/"+otherDigest.String()] = body
		cache, idx := newIndexedCache(t)
		up := unreachable[0].up(t)
		fetch, _ := upstreamFetch(up.dial, nil)
		p := flatPuller(t, idx, cache, fetch, RegistryEndpoint{Addr: w.mirror.addr, TLS: true, CAPEM: w.mirrorCA.pem}, "", nil, nil)
		_, err = p.Pull(context.Background(), pinned, nil, nativePolicy(), always)
		if err == nil || !strings.Contains(err.Error(), "does not match requested digest") {
			t.Fatalf("Pull(%q) = %v, want a digest mismatch from the copy", pinned, err)
		}
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) {
			t.Errorf("error %v does not carry the upstream failure as its cause", err)
		}
		if got := listedReferences(t, idx); len(got) != 0 {
			t.Errorf("index lists %v after a refused copy, want nothing", got)
		}
	})

	t.Run("unreachable upstream, a pinned digest the copy lacks, fails with the upstream cause", func(t *testing.T) {
		w := newWorld(t)
		otherDigest, err := w.other.Digest()
		if err != nil {
			t.Fatal(err)
		}
		pinned := "docker.io/team/app@" + otherDigest.String()
		cache, idx := newIndexedCache(t)
		up := unreachable[0].up(t)
		fetch, _ := upstreamFetch(up.dial, nil)
		p := flatPuller(t, idx, cache, fetch, RegistryEndpoint{Addr: w.mirror.addr, TLS: true, CAPEM: w.mirrorCA.pem}, "", nil, nil)
		_, err = p.Pull(context.Background(), pinned, nil, nativePolicy(), always)
		var dnsErr *net.DNSError
		if err == nil || !errors.As(err, &dnsErr) {
			t.Fatalf("Pull(%q) = %v, want the upstream DNS failure as the cause", pinned, err)
		}
		if got := listedReferences(t, idx); len(got) != 0 {
			t.Errorf("index lists %v, want nothing", got)
		}
	})

	// Upstream ANSWERED in every row below: its answer is the pull's answer and
	// the copy is never contacted.
	upCA := newTestCA(t, "public-ca")
	upRoots := x509.NewCertPool()
	upRoots.AddCert(upCA.cert)
	answered := []struct {
		name    string
		handler func(t *testing.T, w *world) (http.Handler, string)
		roots   *x509.CertPool
		check   func(t *testing.T, err error)
	}{
		{"401", func(*testing.T, *world) (http.Handler, string) { return statusRegistry(http.StatusUnauthorized), ref }, upRoots, wantStatus(http.StatusUnauthorized)},
		{"403", func(*testing.T, *world) (http.Handler, string) { return statusRegistry(http.StatusForbidden), ref }, upRoots, wantStatus(http.StatusForbidden)},
		{"404", func(*testing.T, *world) (http.Handler, string) { return statusRegistry(http.StatusNotFound), ref }, upRoots, wantStatus(http.StatusNotFound)},
		{"manifest unknown", nil, upRoots, func(t *testing.T, err error) {
			var terr *transport.Error
			if !errors.As(err, &terr) || len(terr.Errors) == 0 || terr.Errors[0].Code != transport.ManifestUnknownErrorCode {
				t.Errorf("error %v is not the upstream MANIFEST_UNKNOWN", err)
			}
		}},
		{"a digest mismatch", nil, upRoots, func(t *testing.T, err error) {
			if !strings.Contains(fmt.Sprint(err), "does not match requested digest") {
				t.Errorf("error %v is not the upstream digest mismatch", err)
			}
		}},
		{"an untrusted certificate", func(*testing.T, *world) (http.Handler, string) { return statusRegistry(http.StatusOK), ref }, x509.NewCertPool(), func(t *testing.T, err error) {
			if !strings.Contains(fmt.Sprint(err), "certificate") {
				t.Errorf("error %v is not the certificate failure", err)
			}
		}},
	}
	for _, tc := range answered {
		t.Run("upstream answered "+tc.name+", the copy is not used", func(t *testing.T) {
			w := newWorld(t)
			var up *registryServer
			pullRef := ref
			if tc.handler == nil {
				// A real registry that holds the repository under another tag
				// only, so a request for v1 is MANIFEST_UNKNOWN; the copy holds
				// v1, so a fallback would "succeed".
				up = newRegistryServer(t, upCA, upstreamName, nil)
				up.push(t, "team/app:other", w.other)
				if tc.name == "a digest mismatch" {
					// A digest-pinned pull whose upstream serves other bytes.
					body, err := w.other.RawManifest()
					if err != nil {
						t.Fatal(err)
					}
					pullRef = w.pinned
					up.tamper["/v2/team/app/manifests/"+pullRef[strings.Index(pullRef, "@")+1:]] = body
				}
			} else {
				var h http.Handler
				h, pullRef = tc.handler(t, w)
				up = newRegistryServer(t, upCA, upstreamName, h)
			}
			cache, idx := newIndexedCache(t)
			fetch, asked := upstreamFetch(dialTo(up.addr), tc.roots)
			p := flatPuller(t, idx, cache, fetch, RegistryEndpoint{Addr: w.mirror.addr, TLS: true, CAPEM: w.mirrorCA.pem}, "", nil, nil)
			before := w.mirror.requests.Load()
			_, err := p.Pull(context.Background(), pullRef, nil, nativePolicy(), always)
			if err == nil {
				t.Fatalf("Pull(%q) succeeded, want the upstream answer", pullRef)
			}
			tc.check(t, err)
			if strings.Contains(err.Error(), "cluster registry's copy") {
				t.Errorf("error %v mentions the copy; the upstream answer must surface as it is", err)
			}
			if asked.Load() != 1 {
				t.Errorf("upstream asked %d times, want 1", asked.Load())
			}
			if n := w.mirror.requests.Load() - before; n != 0 {
				t.Errorf("the cluster registry's copy was contacted %d times after upstream answered", n)
			}
			if got := listedReferences(t, idx); len(got) != 0 {
				t.Errorf("index lists %v, want nothing", got)
			}
		})
	}

	t.Run("a cluster-local reference never consults a public copy", func(t *testing.T) {
		w := newWorld(t)
		cache, idx := newIndexedCache(t)
		up := unreachable[0].up(t)
		fetch, _ := upstreamFetch(up.dial, nil)
		p := flatPuller(t, idx, cache, fetch, RegistryEndpoint{Addr: w.mirror.addr, TLS: true, CAPEM: w.mirrorCA.pem}, "", nil, nil)
		before := w.mirror.requests.Load()
		if _, err := p.Pull(context.Background(), "localhost:5000/docker.io/team/app:v1", nil, nativePolicy(), always); err == nil {
			t.Fatal("Pull succeeded, want the primary failure")
		}
		if w.mirror.requests.Load() != before {
			t.Error("the flat registry was contacted for a cluster-local reference")
		}
	})
}

// wantStatus checks that err is the upstream HTTP answer code.
func wantStatus(code int) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var terr *transport.Error
		if !errors.As(err, &terr) || terr.StatusCode != code {
			t.Errorf("error %v is not the upstream %d", err, code)
		}
	}
}

func TestPublicMirrorReference(t *testing.T) {
	for _, tc := range []struct {
		ref, want string
		wantErr   bool
	}{
		{ref: "nginx:1", want: "registry-k3sm:6450/docker.io/library/nginx:1"},
		{ref: "nginx", want: "registry-k3sm:6450/docker.io/library/nginx:latest"},
		{ref: "docker.io/library/nginx:1", want: "registry-k3sm:6450/docker.io/library/nginx:1"},
		{ref: "index.docker.io/team/app:v2", want: "registry-k3sm:6450/docker.io/team/app:v2"},
		{ref: "ghcr.io/org/app:v1", want: "registry-k3sm:6450/ghcr.io/org/app:v1"},
		{ref: "quay.io/org/app@sha256:" + strings.Repeat("a", 64), want: "registry-k3sm:6450/quay.io/org/app@sha256:" + strings.Repeat("a", 64)},
		{ref: "ghcr.io/org/app:v1@sha256:" + strings.Repeat("b", 64), want: "registry-k3sm:6450/ghcr.io/org/app@sha256:" + strings.Repeat("b", 64)},
		{ref: "registry.example.com:5000/app:v1", wantErr: true},
		{ref: "registry-k3sm:6450/app:v1", wantErr: true},
		{ref: "Not A Reference", wantErr: true},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			got, err := PublicMirrorReference(flatHost, tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("PublicMirrorReference(%q) = %q, want an error", tc.ref, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("PublicMirrorReference(%q) = %q, %v; want %q", tc.ref, got, err, tc.want)
			}
		})
	}
}

func TestUpstreamUnreachableClassifies(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("pull %q: %w", "x", &url.Error{Op: "Get", URL: "https://x/v2/", Err: err})
	}
	op := func(e error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: e} }
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"DNS failure", wrap(op(&net.DNSError{Err: "no such host", IsNotFound: true})), true},
		{"DNS temporary failure", wrap(op(&net.DNSError{Err: "server misbehaving", IsTemporary: true})), true},
		{"connection refused", wrap(op(syscall.ECONNREFUSED)), true},
		{"host unreachable", wrap(op(syscall.EHOSTUNREACH)), true},
		{"network unreachable", wrap(op(syscall.ENETUNREACH)), true},
		{"ETIMEDOUT", wrap(op(syscall.ETIMEDOUT)), true},
		{"reset in the handshake", wrap(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), true},
		{"404", wrap(&transport.Error{StatusCode: 404}), false},
		{"401", &transport.Error{StatusCode: 401}, false},
		{"403", &transport.Error{StatusCode: 403}, false},
		{"503", &transport.Error{StatusCode: 503}, false},
		{"unknown authority", wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), false},
		{"hostname mismatch", wrap(x509.HostnameError{Certificate: &x509.Certificate{}, Host: "x"}), false},
		{"tls alert", wrap(&net.OpError{Op: "remote error", Err: tls.AlertError(40)}), false},
		{"not TLS", wrap(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), false},
		{"digest mismatch", errors.New(`manifest digest: "sha256:a" does not match requested digest: "sha256:b"`), false},
		{"platform refusal", fmt.Errorf("pull: %w", ErrNoPlatformMatch), false},
		{"plain EOF", wrap(io.EOF), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := upstreamUnreachable(tc.err); got != tc.want {
				t.Errorf("upstreamUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
