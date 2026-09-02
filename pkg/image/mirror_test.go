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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ---------------------------------------------------------------------------
// Fixtures. Nothing here dials: the primary and mirror fetchers are both seams,
// and the one scheme assertion reads name.Registry.Scheme() rather than
// observing a connection.
// ---------------------------------------------------------------------------

// localRef is the node-relative reference a pod gets when the cluster's own
// ingest registry is the source — the only shape the mirror fallback applies to.
const localRef = "localhost:6450/team/app:v1"

// fixedMirrors is a MirrorSource that answers with one fixed candidate list,
// counting the calls so a test can prove the source was NOT consulted on a path
// that must not fall back.
type fixedMirrors struct {
	list    []Mirror
	calls   int
	lastRef string
}

func (f *fixedMirrors) Mirrors(ref string) []Mirror {
	f.calls++
	f.lastRef = ref
	return f.list
}

// stubFetch is a FetchFunc returning a fixed image or a fixed error — the
// PRIMARY registry, whose answer decides whether the fallback is eligible.
type stubFetch struct {
	img   ggcrv1.Image
	err   error
	calls int
}

func (s *stubFetch) fetch(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.img, nil
}

// mirrorFetcher is a MirrorFetchFunc backed by a map keyed on the REWRITTEN
// reference, so a test states which peer holds which content and then asserts
// exactly which references were asked for, in order.
type mirrorFetcher struct {
	byRef map[string]ggcrv1.Image
	asked []string
	// creds is unused by construction: MirrorFetchFunc takes no credential.
	// plain records the transport decision each candidate carried.
	plain []bool
}

func newMirrorFetcher() *mirrorFetcher {
	return &mirrorFetcher{byRef: make(map[string]ggcrv1.Image)}
}

func (m *mirrorFetcher) fetch(_ context.Context, ref string, mirror Mirror, _ PlatformPolicy) (ggcrv1.Image, error) {
	m.asked = append(m.asked, ref)
	m.plain = append(m.plain, mirror.PlainHTTP)
	img, ok := m.byRef[ref]
	if !ok {
		return nil, registryStatus(http.StatusNotFound)
	}
	return img, nil
}

// registryStatus is a go-containerregistry transport error carrying code — the
// exact type a real registry answer arrives as.
func registryStatus(code int) error {
	return &transport.Error{StatusCode: code}
}

// registryDiagnostic is a registry answer that carries an OCI error code, which
// may disagree with the status it rode in on.
func registryDiagnostic(code int, diag transport.ErrorCode) error {
	return &transport.Error{StatusCode: code, Errors: []transport.Diagnostic{{Code: diag}}}
}

// corruptLayer serves bytes that do not hash to the digest its own manifest
// descriptor claims — a peer that returns damaged or substituted content.
type corruptLayer struct{ ggcrv1.Layer }

func (c corruptLayer) Compressed() (io.ReadCloser, error) {
	rc, err := c.Layer.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("fixture layer is empty, so it cannot be corrupted")
	}
	// Same LENGTH, different bytes: the size guard must not be what catches
	// this. The digest comparison in Cache.CommitBlob must.
	b[len(b)-1] ^= 0xff
	return io.NopCloser(bytes.NewReader(b)), nil
}

// tamperedImage is img with its first layer's BYTES corrupted while its manifest
// — and therefore every digest it claims — is untouched.
type tamperedImage struct{ ggcrv1.Image }

func (t tamperedImage) Layers() ([]ggcrv1.Layer, error) {
	ls, err := t.Image.Layers()
	if err != nil {
		return nil, err
	}
	if len(ls) == 0 {
		return nil, errors.New("fixture image has no layers")
	}
	out := make([]ggcrv1.Layer, len(ls))
	copy(out, ls)
	out[0] = corruptLayer{out[0]}
	return out, nil
}

// nativeImage is a runnable darwin/arm64 fixture image.
func nativeImage(t *testing.T) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	return withPlatform(t, img, "darwin", "arm64", "")
}

// mirrorPuller builds a Puller with the cluster-mirror fallback wired, its
// disk-pressure sampler pinned roomy, and its log captured.
func mirrorPuller(t *testing.T, cache *Cache, index LocalIndex, fetch FetchFunc, src MirrorSource, mf MirrorFetchFunc, logs *bytes.Buffer) *Puller {
	t.Helper()
	opts := []PullerOption{
		WithFreeBytes(fixedFreeBytes(64 << 30)),
		WithPullLogger(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
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

// ---------------------------------------------------------------------------
// The gate: the fallback rule.
// ---------------------------------------------------------------------------

// TestPullFallsBackToClusterMirrors is the behavioural gate for the cluster
// mirror fallback: WHEN it engages, what it asks a peer for, what it records,
// and — the half that matters more — every case in which it must not engage.
func TestPullFallsBackToClusterMirrors(t *testing.T) {
	t.Run("a primary HIT consults no mirror at all", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		primary := &stubFetch{img: nativeImage(t)}
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}
		mf := newMirrorFetcher()

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		if _, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err != nil {
			t.Fatalf("pull: %v", err)
		}
		if src.calls != 0 {
			t.Errorf("the mirror source was consulted %d times on a successful primary pull; want 0", src.calls)
		}
		if len(mf.asked) != 0 {
			t.Errorf("a mirror was contacted on a successful primary pull: %v", mf.asked)
		}
	})

	t.Run("a primary MISS pulls from the peer and records the ORIGINAL reference", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		img := nativeImage(t)
		primary := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}
		mf := newMirrorFetcher()
		mf.byRef["100.64.1.1:6450/team/app:v1"] = img

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		res, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("pull through a cluster mirror: %v", err)
		}
		// Only the registry authority moved.
		if want := []string{"100.64.1.1:6450/team/app:v1"}; len(mf.asked) != 1 || mf.asked[0] != want[0] {
			t.Fatalf("mirror was asked for %v, want %v (only the registry host may be rewritten)", mf.asked, want)
		}
		if src.lastRef != localRef {
			t.Errorf("the mirror source was asked about %q, want the original %q", src.lastRef, localRef)
		}
		// The pod asked for the node-relative reference; the mirror is transport,
		// not identity, so that is what the manifest and the index must say.
		if res.Manifest.GetReference() != localRef {
			t.Errorf("manifest reference = %q, want the original %q", res.Manifest.GetReference(), localRef)
		}
		if _, ok := index.refs[localRef]; !ok {
			t.Errorf("index recorded %v, want an entry under the original reference %q", keysOf(index.refs), localRef)
		}
		for ref := range index.refs {
			if strings.Contains(ref, "100.64.1.1") {
				t.Errorf("index recorded the MIRROR reference %q; the peer must never become the image's identity", ref)
			}
		}
		// Every blob it named landed in the store, through the same commit path.
		if !cache.Has(res.Manifest.GetConfig().GetDigest()) {
			t.Error("config blob from the mirror pull is not in the store")
		}
		for _, l := range res.Manifest.GetLayers() {
			if !cache.Has(l.GetDigest()) {
				t.Errorf("layer blob %s from the mirror pull is not in the store", l.GetDigest())
			}
		}
		// One INFO naming the peer.
		if !strings.Contains(logs.String(), "pulled from a cluster mirror") || !strings.Contains(logs.String(), "100.64.1.1:6450") {
			t.Errorf("no INFO line naming the peer in:\n%s", logs.String())
		}
	})

	t.Run("an AUTH refusal never falls back", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"401 unauthorized", registryStatus(http.StatusUnauthorized)},
			{"403 forbidden", registryStatus(http.StatusForbidden)},
			{"407 proxy auth required", registryStatus(http.StatusProxyAuthRequired)},
			{"404 carrying an UNAUTHORIZED diagnostic", registryDiagnostic(http.StatusNotFound, transport.UnauthorizedErrorCode)},
			{"404 carrying a DENIED diagnostic", registryDiagnostic(http.StatusNotFound, transport.DeniedErrorCode)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cache, index, logs := newFixtureStore(t)
				primary := &stubFetch{err: tc.err}
				src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}
				mf := newMirrorFetcher()
				mf.byRef["100.64.1.1:6450/team/app:v1"] = nativeImage(t)

				p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
				_, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
				if err == nil {
					t.Fatal("an auth refusal was satisfied from a peer; the reference exists and this node is not allowed it")
				}
				if src.calls != 0 {
					t.Errorf("the mirror source was consulted %d times after an auth refusal; want 0", src.calls)
				}
				if len(mf.asked) != 0 {
					t.Errorf("a peer was contacted after an auth refusal: %v", mf.asked)
				}
				if !errors.Is(err, tc.err) {
					t.Errorf("pull error = %v, want the primary error unchanged", err)
				}
				if strings.Contains(err.Error(), "cluster") {
					t.Errorf("pull error %q mentions the fallback, which never ran", err)
				}
			})
		}
	})

	t.Run("a peer serving TAMPERED content is refused and the next peer is tried", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		img := nativeImage(t)
		primary := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{
			{Host: "100.64.1.1:6450", PlainHTTP: true},
			{Host: "100.64.1.2:6450", PlainHTTP: true},
		}}
		mf := newMirrorFetcher()
		mf.byRef["100.64.1.1:6450/team/app:v1"] = tamperedImage{img}
		mf.byRef["100.64.1.2:6450/team/app:v1"] = img

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		res, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("pull: %v, want the second peer to have served it", err)
		}
		if len(mf.asked) != 2 {
			t.Fatalf("peers contacted = %v, want both (the tampering peer must not end the loop)", mf.asked)
		}
		if res.Manifest.GetReference() != localRef {
			t.Errorf("manifest reference = %q, want %q", res.Manifest.GetReference(), localRef)
		}
		// A refusal, never a downgrade: the failure is logged and walked past.
		if !strings.Contains(logs.String(), "cluster mirror served content this node refused") {
			t.Errorf("the tampering peer's refusal was not logged:\n%s", logs.String())
		}
		// Exactly one record, and it is the CLEAN pull's.
		if index.records != 1 {
			t.Errorf("index recorded %d times, want 1 (a refused candidate records nothing)", index.records)
		}
		for _, l := range res.Manifest.GetLayers() {
			if !cache.Has(l.GetDigest()) {
				t.Errorf("layer %s missing from the store after the clean peer served it", l.GetDigest())
			}
		}
	})

	t.Run("a tampering peer with no successor fails the pull", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		primary := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}
		mf := newMirrorFetcher()
		mf.byRef["100.64.1.1:6450/team/app:v1"] = tamperedImage{nativeImage(t)}

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		if _, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err == nil {
			t.Fatal("a pull served only tampered content succeeded")
		}
		if index.records != 0 {
			t.Errorf("index recorded %d times after a wholly refused fallback; want 0", index.records)
		}
	})

	t.Run("when every peer misses, the error names how many were consulted", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		primaryErr := registryStatus(http.StatusNotFound)
		primary := &stubFetch{err: primaryErr}
		src := &fixedMirrors{list: []Mirror{
			{Host: "100.64.1.1:6450", PlainHTTP: true},
			{Host: "100.64.1.2:6450", PlainHTTP: true},
		}}
		mf := newMirrorFetcher()

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		_, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			t.Fatal("pull succeeded with no peer holding the image")
		}
		if !errors.Is(err, primaryErr) {
			t.Errorf("pull error = %v; the PRIMARY error must stay the cause", err)
		}
		if !strings.Contains(err.Error(), "2 cluster mirrors consulted") {
			t.Errorf("pull error %q does not name how many peers were consulted", err)
		}
	})

	t.Run("one consulted peer is named in the singular", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		primary := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}

		p := mirrorPuller(t, cache, index, primary.fetch, src, newMirrorFetcher().fetch, logs)
		_, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil || !strings.Contains(err.Error(), "1 cluster mirror consulted") {
			t.Errorf("pull error = %v, want it to name 1 consulted cluster mirror", err)
		}
	})

	t.Run("a malformed candidate is skipped, is not counted as consulted, and does not stop the loop", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		img := nativeImage(t)
		primary := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{
			// A candidate carrying a PATH would splice into the repository and
			// redirect the pull at a repository nobody named.
			{Host: "attacker.example/evil", PlainHTTP: true},
			{Host: "100.64.1.2:6450", PlainHTTP: true},
		}}
		mf := newMirrorFetcher()
		mf.byRef["100.64.1.2:6450/team/app:v1"] = img

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		if _, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err != nil {
			t.Fatalf("pull: %v, want the well-formed candidate to have served it", err)
		}
		if want := "100.64.1.2:6450/team/app:v1"; len(mf.asked) != 1 || mf.asked[0] != want {
			t.Fatalf("peers contacted = %v, want only %q", mf.asked, want)
		}
		if !strings.Contains(logs.String(), "skipping an unusable cluster mirror candidate") {
			t.Errorf("the malformed candidate was not reported:\n%s", logs.String())
		}
	})

	t.Run("a reference into a PUBLIC registry never falls back", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		primary := &stubFetch{err: registryStatus(http.StatusNotFound)}
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}
		mf := newMirrorFetcher()

		p := mirrorPuller(t, cache, index, primary.fetch, src, mf.fetch, logs)
		_, err := p.Pull(context.Background(), "docker.io/library/nginx:1.27", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			t.Fatal("a public reference was satisfied from a cluster peer")
		}
		if src.calls != 0 {
			t.Errorf("the mirror source was consulted %d times for a public reference; want 0", src.calls)
		}
		if len(mf.asked) != 0 {
			t.Errorf("a peer was contacted for a public reference: %v", mf.asked)
		}
	})

	t.Run("a source advertising NO peer leaves the primary error untouched", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		primaryErr := registryStatus(http.StatusNotFound)
		primary := &stubFetch{err: primaryErr}
		src := &fixedMirrors{}

		p := mirrorPuller(t, cache, index, primary.fetch, src, newMirrorFetcher().fetch, logs)
		_, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			t.Fatal("pull succeeded with no peers")
		}
		if src.calls != 1 {
			t.Errorf("mirror source consulted %d times, want exactly 1", src.calls)
		}
		if strings.Contains(err.Error(), "cluster") {
			t.Errorf("pull error %q mentions a fallback that had no candidate to run", err)
		}
	})
}

// TestPullWithoutMirrorsIsUnchanged pins the pre-mirror behavior as a
// BEHAVIOUR DIFF, not as an intention: the same fixtures are pulled by a Puller
// with no MirrorSource and by one with peers wired but not reachable by the rule,
// and both must answer identically.
func TestPullWithoutMirrorsIsUnchanged(t *testing.T) {
	t.Run("a failing fetch returns the fetcher's error verbatim", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		fetchErr := registryStatus(http.StatusNotFound)
		primary := &stubFetch{err: fetchErr}

		p := mirrorPuller(t, cache, index, primary.fetch, nil, nil, logs)
		_, err := p.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			t.Fatal("pull succeeded against a failing fetcher")
		}
		if err.Error() != fetchErr.Error() {
			t.Errorf("pull error = %q, want the fetcher's own %q — a nil MirrorSource must not decorate it", err, fetchErr)
		}
		if logs.Len() != 0 {
			t.Errorf("a puller with no mirrors logged:\n%s", logs.String())
		}
	})

	t.Run("a successful pull is identical with and without a mirror source", func(t *testing.T) {
		img := nativeImage(t)

		plainCache, plainIndex, plainLogs := newFixtureStore(t)
		plain := mirrorPuller(t, plainCache, plainIndex, (&stubFetch{img: img}).fetch, nil, nil, plainLogs)
		plainRes, err := plain.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("pull without mirrors: %v", err)
		}

		mirroredCache, mirroredIndex, mirroredLogs := newFixtureStore(t)
		src := &fixedMirrors{list: []Mirror{{Host: "100.64.1.1:6450", PlainHTTP: true}}}
		mirrored := mirrorPuller(t, mirroredCache, mirroredIndex, (&stubFetch{img: img}).fetch, src, newMirrorFetcher().fetch, mirroredLogs)
		mirroredRes, err := mirrored.Pull(context.Background(), localRef, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("pull with mirrors wired: %v", err)
		}

		if plainRes.Descriptor.GetDigest() != mirroredRes.Descriptor.GetDigest() {
			t.Errorf("image id differs: %s without mirrors, %s with", plainRes.Descriptor.GetDigest(), mirroredRes.Descriptor.GetDigest())
		}
		if plainRes.Manifest.GetReference() != mirroredRes.Manifest.GetReference() {
			t.Errorf("reference differs: %q vs %q", plainRes.Manifest.GetReference(), mirroredRes.Manifest.GetReference())
		}
		if plainRes.CacheHit != mirroredRes.CacheHit || plainRes.Platform != mirroredRes.Platform {
			t.Errorf("result differs: %+v vs %+v", plainRes, mirroredRes)
		}
		if plainIndex.records != mirroredIndex.records {
			t.Errorf("index writes differ: %d vs %d", plainIndex.records, mirroredIndex.records)
		}
	})
}

// TestNewPullerRefusesAHalfWiredFallback: either half of the fallback alone
// disables the whole mechanism silently, which is the failure mode a node would
// discover only when a peer's image failed to start.
func TestNewPullerRefusesAHalfWiredFallback(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := &fixedMirrors{}
	for _, tc := range []struct {
		name string
		opt  PullerOption
	}{
		{"a source with no fetcher", WithMirrors(src, nil)},
		{"a fetcher with no source", WithMirrors(nil, newMirrorFetcher().fetch)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{}, tc.opt); err == nil {
				t.Errorf("NewPuller returned %+v; a half-wired mirror fallback must be refused", p)
			}
		})
	}
	t.Run("neither half is the default and is accepted", func(t *testing.T) {
		if _, err := NewPuller(cache, RemoteFetch, NoLocalIndex{}); err != nil {
			t.Errorf("NewPuller with no mirror options: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// The rule's pieces, driven directly.
// ---------------------------------------------------------------------------

// TestMirrorFallbackEligibility drives the error-class enumeration. It is the
// half of the rule that decides whether a peer may be asked at all, and every
// row states WHY, so a future error shape has to be classified deliberately
// rather than inherited by a default.
func TestMirrorFallbackEligibility(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		// Eligible: the reference is absent, or the registry is not answering.
		{"404 not found", registryStatus(http.StatusNotFound), true},
		{"500 internal server error", registryStatus(http.StatusInternalServerError), true},
		{"502 bad gateway", registryStatus(http.StatusBadGateway), true},
		{"503 service unavailable", registryStatus(http.StatusServiceUnavailable), true},
		{"504 gateway timeout", registryStatus(http.StatusGatewayTimeout), true},
		{"404 wrapped by this package", fmt.Errorf("pull %q: %w", localRef, registryStatus(http.StatusNotFound)), true},
		{"connection refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"connection reset", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"host unreachable", fmt.Errorf("dial: %w", syscall.EHOSTUNREACH), true},
		{"network unreachable", fmt.Errorf("dial: %w", syscall.ENETUNREACH), true},
		{"connection timed out", fmt.Errorf("dial: %w", syscall.ETIMEDOUT), true},
		{"broken pipe", fmt.Errorf("write: %w", syscall.EPIPE), true},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "peer"}, true},
		{"a dial timeout", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, true},

		// Not eligible: the primary ANSWERED, or this node already decided.
		{"401 unauthorized", registryStatus(http.StatusUnauthorized), false},
		{"403 forbidden", registryStatus(http.StatusForbidden), false},
		{"407 proxy authentication required", registryStatus(http.StatusProxyAuthRequired), false},
		{"an UNAUTHORIZED diagnostic under a 404", registryDiagnostic(http.StatusNotFound, transport.UnauthorizedErrorCode), false},
		{"a DENIED diagnostic under a 503", registryDiagnostic(http.StatusServiceUnavailable, transport.DeniedErrorCode), false},
		{"400 bad request", registryStatus(http.StatusBadRequest), false},
		{"405 method not allowed", registryStatus(http.StatusMethodNotAllowed), false},
		{"429 too many requests (retry the SAME registry)", registryStatus(http.StatusTooManyRequests), false},
		{"no runnable platform", fmt.Errorf("pull: %w", ErrNoPlatformMatch), false},
		{"a nested index", fmt.Errorf("pull: %w", ErrNestedIndex), false},
		{"refused under disk pressure", fmt.Errorf("pull: %w", ErrPullRefusedDiskPressure), false},
		{"the pull policy forbids fetching", fmt.Errorf("image: %w", ErrImageNotPresent), false},
		{"the caller cancelled", fmt.Errorf("fetch: %w", context.Canceled), false},
		{"the caller's deadline expired", fmt.Errorf("fetch: %w", context.DeadlineExceeded), false},
		{"an unrecognised failure", errors.New("something else went wrong"), false},
		{"no error at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mirrorFallbackEligible(tc.err); got != tc.want {
				t.Errorf("mirrorFallbackEligible(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestClusterLocalRefGate drives the second precondition: only a reference into
// THIS node's own ingest registry may be answered by a peer.
func TestClusterLocalRefGate(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		want bool
	}{
		{"localhost:6450/team/app:v1", true},
		{"LocalHost:6450/team/app:v1", true},
		{"127.0.0.1:6450/team/app:v1", true},
		{"127.1.2.3:6450/team/app:v1", true},
		{"127.0.0.1/team/app:v1", true},
		{"[::1]:6450/team/app:v1", true},
		{"registry.localhost:6450/team/app:v1", true},
		{"registry.localhost/team/app:v1", true},
		// A BARE "localhost" carries neither a '.' nor a ':', so
		// go-containerregistry reads it as the first element of a Docker Hub
		// repository, not as this node. It names no local registry to miss.
		{"localhost/team/app:v1", false},
		{"docker.io/library/nginx:1.27", false},
		{"ghcr.io/k3sm-io/app@sha256:0000000000000000000000000000000000000000000000000000000000000000", false},
		{"100.64.1.1:6450/team/app:v1", false},
		{"192.168.1.10:6450/team/app:v1", false},
		{"localhostess.example/team/app:v1", false},
		{"notlocalhost/team/app:v1", false},
		{"app:v1", false},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			if got := clusterLocalRef(tc.ref); got != tc.want {
				t.Errorf("clusterLocalRef(%q) = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

// TestRewriteRegistryHost pins the one rewrite: the registry authority moves and
// NOTHING else does — and a candidate that tries to move anything else is
// refused before a round trip.
func TestRewriteRegistryHost(t *testing.T) {
	t.Run("only the authority changes", func(t *testing.T) {
		for _, tc := range []struct{ ref, host, want string }{
			{"localhost:6450/team/app:v1", "100.64.1.1:6450", "100.64.1.1:6450/team/app:v1"},
			{"localhost:6450/team/sub/app", "100.64.1.1:6450", "100.64.1.1:6450/team/sub/app"},
			{
				"localhost:6450/app@sha256:1111111111111111111111111111111111111111111111111111111111111111",
				"100.64.1.1:6450",
				"100.64.1.1:6450/app@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			},
			// No normalisation: an untagged reference must NOT gain ":latest",
			// and a single-segment repository must NOT gain "library/".
			{"localhost:6450/app", "peer.internal:6450", "peer.internal:6450/app"},
		} {
			t.Run(tc.ref+" -> "+tc.host, func(t *testing.T) {
				got, err := rewriteRegistryHost(tc.ref, tc.host)
				if err != nil {
					t.Fatalf("rewriteRegistryHost(%q, %q): %v", tc.ref, tc.host, err)
				}
				if got != tc.want {
					t.Errorf("rewriteRegistryHost(%q, %q) = %q, want %q", tc.ref, tc.host, got, tc.want)
				}
			})
		}
	})

	t.Run("a candidate that is not a bare authority is refused", func(t *testing.T) {
		for _, tc := range []struct{ name, host string }{
			{"empty", ""},
			{"a path", "peer.internal:6450/evil"},
			{"a dotless, portless host ggcr reads as a repository element", "evil"},
			{"a scheme", "http://peer.internal:6450"},
			{"userinfo", "user@peer.internal:6450"},
			{"a space", "peer internal:6450"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got, err := rewriteRegistryHost(localRef, tc.host); err == nil {
					t.Errorf("rewriteRegistryHost(%q, %q) = %q, want an error", localRef, tc.host, got)
				}
			})
		}
	})

	t.Run("a reference naming no registry is refused", func(t *testing.T) {
		if got, err := rewriteRegistryHost("app:v1", "100.64.1.1:6450"); err == nil {
			t.Errorf("rewriteRegistryHost on a registry-less reference = %q, want an error", got)
		}
	})
}

// TestMirrorReferenceSelectsItsScheme is the name.Insecure assertion, made
// through the seam the production fetcher uses rather than by dialling.
//
// The row that matters is the mesh one: go-containerregistry infers http for
// localhost and for the three RFC 1918 ranges, but 100.64.0.0/10 is RFC 6598
// CGNAT and is NOT in that list — so without PlainHTTP a mesh peer is dialled
// as HTTPS and the handshake fails against a plain-HTTP ingest registry.
func TestMirrorReferenceSelectsItsScheme(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mirror Mirror
		ref    string
		want   string
	}{
		{"a mesh peer WITHOUT PlainHTTP is https — the trap", Mirror{Host: "100.64.1.1:6450"}, "100.64.1.1:6450/team/app:v1", "https"},
		{"a mesh peer with PlainHTTP is http", Mirror{Host: "100.64.1.1:6450", PlainHTTP: true}, "100.64.1.1:6450/team/app:v1", "http"},
		{"an RFC 1918 peer is http either way", Mirror{Host: "192.168.1.10:6450"}, "192.168.1.10:6450/team/app:v1", "http"},
		{"a public host stays https", Mirror{Host: "registry.example:443"}, "registry.example:443/team/app:v1", "https"},
		{"a public host with PlainHTTP is http", Mirror{Host: "registry.example:80", PlainHTTP: true}, "registry.example:80/team/app:v1", "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := tc.mirror.reference(tc.ref)
			if err != nil {
				t.Fatalf("reference(%q): %v", tc.ref, err)
			}
			if got := r.Context().Registry.Scheme(); got != tc.want {
				t.Errorf("scheme for %+v = %q, want %q", tc.mirror, got, tc.want)
			}
			if got := r.Context().RegistryStr(); got != tc.mirror.Host {
				t.Errorf("registry = %q, want %q", got, tc.mirror.Host)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

// newFixtureStore returns a fresh cache, a recording index and a log buffer.
func newFixtureStore(t *testing.T) (*Cache, *recordingIndex, *bytes.Buffer) {
	t.Helper()
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return cache, newRecordingIndex(), &bytes.Buffer{}
}

// keysOf renders a recorded index's references for a failure message.
func keysOf(m map[string]*runtimev1.ImageManifest) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
