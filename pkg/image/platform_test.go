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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ---------------------------------------------------------------------------
// Fixtures. The end-to-end cases run against go-containerregistry's in-module
// pkg/registry over httptest, and name.Registry.Scheme() returns http for a
// 127.0.0.1:PORT authority (reLoopback), so no TLS fixture is needed. Every
// response is a 200 or a 404 — never a retryable 5xx, which ggcr would retry
// with a 1s backoff and turn a 10ms assertion into a multi-second "flake".
//
// Its dependency COST, stated honestly: pkg/registry's own code pulls in only
// stdlib + ggcr-internal packages, so go.mod gained no requirement — but go.sum
// gained 4 lines (golang.org/x/mod, golang.org/x/tools). That is not
// pkg/registry itself: its depcheck_test.go imports ggcr's internal/depcheck,
// which imports golang.org/x/tools/go/packages, and `go mod tidy` records the
// checksums needed to build the tests of every imported package (`go test all`).
// Nothing new is linked into the daemon.
// ---------------------------------------------------------------------------

// testRegistry starts an in-process OCI registry and returns its host:port.
func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test registry url %q: %v", srv.URL, err)
	}
	return u.Host
}

// rawResponse is one canned registry reply: the Content-Type header (which is
// where go-containerregistry reads a manifest's media type from) and the exact
// bytes.
type rawResponse struct {
	mediaType string
	body      []byte
}

// rawRegistry serves a fixed path → rawResponse map, so a test can choose a
// hostile or malformed reply byte for byte. ggcr's pkg/registry only publishes
// WELL-FORMED artifacts, so the fail-closed verdicts that fire on a malformed
// one — a 200 kB digest algorithm, an unsupported manifest media type, a child
// SERVED as an index after its parent descriptor promised an image — are
// unreachable through it. Unknown paths 404 and every served path is a 200, so
// no reply is retryable (see the fixture header).
func rawRegistry(t *testing.T, responses map[string]rawResponse) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" { // the ggcr ping: anonymous, no auth challenge
			return
		}
		resp, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", resp.mediaType)
		w.Header().Set("Docker-Content-Digest", digestOf(resp.body))
		_, _ = w.Write(resp.body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse raw registry url %q: %v", srv.URL, err)
	}
	return u.Host
}

// digestOf is the sha256 descriptor digest of some served bytes — ggcr verifies
// it whenever the fixture is fetched by digest.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// testImage builds a one-layer image whose CONFIG declares the given platform —
// the config is what VerifyConfigPlatform reads, so it is what the fixture must
// control.
func testImage(t *testing.T, os, arch, variant string) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	return withPlatform(t, img, os, arch, variant)
}

// withPlatform rewrites img's CONFIG to declare the given platform. Every
// fixture that must survive a Pull needs one, because Pull verifies the config
// against the policy at the choke point and a plain random.Image declares no
// platform at all.
func withPlatform(t *testing.T, img ggcrv1.Image, os, arch, variant string) ggcrv1.Image {
	t.Helper()
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = os, arch, variant
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatalf("mutate config file: %v", err)
	}
	return img
}

// child is an index entry whose descriptor declares p (nil ⇒ the descriptor
// carries NO platform field at all, the attestation shape).
func child(img ggcrv1.Image, p *ggcrv1.Platform) mutate.IndexAddendum {
	return mutate.IndexAddendum{Add: img, Descriptor: ggcrv1.Descriptor{Platform: p}}
}

// ggcrPlatform is the go-containerregistry platform an index descriptor carries.
func ggcrPlatform(os, arch, variant string) *ggcrv1.Platform {
	return &ggcrv1.Platform{OS: os, Architecture: arch, Variant: variant}
}

// pushIndex publishes an image index at host/repo:v1 and returns the reference.
func pushIndex(t *testing.T, host, repo string, adds ...mutate.IndexAddendum) string {
	t.Helper()
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	if err := remote.WriteIndex(ref, mutate.AppendManifests(empty.Index, adds...)); err != nil {
		t.Fatalf("write index %s: %v", ref, err)
	}
	return ref.String()
}

// pushImage publishes a single (non-index) manifest at host/repo:v1.
func pushImage(t *testing.T, host, repo string, img ggcrv1.Image) string {
	t.Helper()
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("write image %s: %v", ref, err)
	}
	return ref.String()
}

// resolvedPlatform reports the platform of a fetched image, read from its OWN
// config — the only claim about an image that its digest actually covers.
func resolvedPlatform(t *testing.T, img ggcrv1.Image) Platform {
	t.Helper()
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file of fetched image: %v", err)
	}
	return Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}.Normalize()
}

// mustDigest is the image digest, used to prove WHICH child was selected.
func mustDigest(t *testing.T, img ggcrv1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return d.String()
}

// indexOf builds an index manifest in memory for the pure-selector cases (no
// registry, no IO).
func indexOf(descs ...ggcrv1.Descriptor) *ggcrv1.IndexManifest {
	return &ggcrv1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     descs,
	}
}

// desc is one in-memory index child. digest is a short label; it only has to be
// a well-formed hash so error rendering stays honest.
func desc(digest string, mt types.MediaType, p *ggcrv1.Platform) ggcrv1.Descriptor {
	d := ggcrv1.Descriptor{MediaType: mt, Size: 1}
	d.Digest = ggcrv1.Hash{Algorithm: "sha256", Hex: strings.Repeat(digest, 64/len(digest))}
	d.Platform = p
	return d
}

// imageDesc is an image-typed index child declaring p.
func imageDesc(digest, os, arch, variant string) ggcrv1.Descriptor {
	return desc(digest, types.OCIManifestSchema1, ggcrPlatform(os, arch, variant))
}

func nativePolicyRosetta() PlatformPolicy {
	return PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, HostRosetta: true}
}

func vmPolicy() PlatformPolicy {
	return PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM}
}

func vmPolicyRosetta() PlatformPolicy {
	return PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, GuestRosetta: true}
}

// mustPuller builds a Puller or fails the test — NewPuller has no implicit
// fetcher, so every caller names the one it means.
func mustPuller(t *testing.T, cache *Cache, fetch FetchFunc) *Puller {
	t.Helper()
	return mustPullerIndex(t, cache, fetch, NoLocalIndex{})
}

// mustPullerIndex is mustPuller with an explicit LocalIndex, for the tests that
// put a reference in the "recorded on this node" state.
//
// It pins the disk-pressure sampler to a fixed roomy value, so every OTHER test
// in this package states a free volume rather than inheriting the developer's
// actual disk — a machine below DefaultPullRefuseFreeBytes would otherwise red
// the whole pull suite for a reason none of those tests is about. The admission
// rule itself is driven, with its own sampler, by TestPullRefusesUnderDiskPressure.
func mustPullerIndex(t *testing.T, cache *Cache, fetch FetchFunc, index LocalIndex) *Puller {
	t.Helper()
	p, err := NewPuller(cache, fetch, index, WithFreeBytes(fixedFreeBytes(64<<30)))
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	return p
}

// fixedFreeBytes is a FreeBytesFunc that always reports n bytes available.
func fixedFreeBytes(n uint64) FreeBytesFunc {
	return func(string) (uint64, error) { return n, nil }
}

// mustCandidates fails the test if the policy has no candidates.
func mustCandidates(t *testing.T, p PlatformPolicy) []Platform {
	t.Helper()
	c, err := Candidates(p)
	if err != nil {
		t.Fatalf("Candidates(%+v): %v", p, err)
	}
	return c
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

// TestManifestListPlatformSelection is the B99 gate: k3sm
// selects the manifest of a multi-platform image by an explicit, fail-closed
// policy, and there is structurally no path left on which
// go-containerregistry's implicit linux/amd64 default can fire.
//
// EVERY assertion the gate makes is a subtest of THIS function — the item is
// run as `go test -run '^TestManifestListPlatformSelection$'`, so anything in a
// sibling Test... would not be gate-proving.
//
// Behaviour at main, measured (not assumed) against pinned ggcr v0.21.6 with the
// same fixtures, for the end-to-end rows below:
//
//	index with a darwin child + an amd64 child → returned linux/amd64  (RED)
//	index with no darwin child                → returned linux/amd64  (RED)
//	index [darwin, platform-less attestation] → returned the ATTESTATION (RED)
//	index with only a darwin child            → errored "no child with
//	                                            platform linux/amd64"  (RED)
//	single manifest whose config is amd64     → returned it unchecked  (RED)
//	single manifest whose config is darwin    → returned it (already green)
func TestManifestListPlatformSelection(t *testing.T) {
	// -----------------------------------------------------------------
	// End-to-end: the production RemoteFetch against a real (in-process)
	// registry. These are the rows that were behaviourally red at main.
	// -----------------------------------------------------------------
	host := testRegistry(t)

	linuxAMD64 := testImage(t, "linux", "amd64", "")
	linuxARM64 := testImage(t, "linux", "arm64", "v8")
	darwinARM64 := testImage(t, "darwin", "arm64", "")
	attestation := testImage(t, "unknown", "unknown", "")

	t.Run("e2e/index_selects_native_darwin_arm64", func(t *testing.T) {
		ref := pushIndex(t, host, "multi",
			child(linuxAMD64, ggcrPlatform("linux", "amd64", "")),
			child(linuxARM64, ggcrPlatform("linux", "arm64", "v8")),
			child(darwinARM64, ggcrPlatform("darwin", "arm64", "")),
		)
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if err != nil {
			t.Fatalf("RemoteFetch: %v", err)
		}
		if got := resolvedPlatform(t, img); got != platDarwinARM64 {
			t.Errorf("resolved platform = %s, want %s", got, platDarwinARM64)
		}
		if got, want := mustDigest(t, img), mustDigest(t, darwinARM64); got != want {
			t.Errorf("resolved digest = %s, want the darwin/arm64 child %s", got, want)
		}
	})

	t.Run("e2e/index_without_native_fails_closed", func(t *testing.T) {
		ref := pushIndex(t, host, "linuxonly",
			child(linuxAMD64, ggcrPlatform("linux", "amd64", "")),
			child(linuxARM64, ggcrPlatform("linux", "arm64", "v8")),
		)
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if img != nil {
			t.Errorf("an image was returned for an unrunnable index: %s", resolvedPlatform(t, img))
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		var mm *PlatformMismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("error %v is not a *PlatformMismatchError", err)
		}
		msg := err.Error()
		for _, wantSub := range []string{"darwin/arm64/v8", "linux/amd64", "linux/arm64/v8"} {
			if !strings.Contains(msg, wantSub) {
				t.Errorf("error %q does not name %q", msg, wantSub)
			}
		}
	})

	t.Run("e2e/index_platformless_attestation_never_selected", func(t *testing.T) {
		ref := pushIndex(t, host, "attested",
			child(darwinARM64, ggcrPlatform("darwin", "arm64", "")),
			child(attestation, nil), // descriptor with NO platform field
		)
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if err != nil {
			t.Fatalf("RemoteFetch: %v", err)
		}
		if got := resolvedPlatform(t, img); got != platDarwinARM64 {
			t.Errorf("resolved platform = %s, want %s", got, platDarwinARM64)
		}
		if got, bad := mustDigest(t, img), mustDigest(t, attestation); got == bad {
			t.Fatalf("the platform-less attestation manifest %s was returned as the image", bad)
		}
	})

	t.Run("e2e/index_native_only_positive_control", func(t *testing.T) {
		ref := pushIndex(t, host, "darwinonly",
			child(darwinARM64, ggcrPlatform("darwin", "arm64", "")),
		)
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if err != nil {
			t.Fatalf("RemoteFetch: %v", err)
		}
		if got := resolvedPlatform(t, img); got != platDarwinARM64 {
			t.Errorf("resolved platform = %s, want %s", got, platDarwinARM64)
		}
	})

	t.Run("e2e/single_manifest_foreign_platform_refused", func(t *testing.T) {
		ref := pushImage(t, host, "singleamd64", linuxAMD64)
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if img != nil {
			t.Errorf("an image was returned for a foreign single manifest: %s", resolvedPlatform(t, img))
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		if !strings.Contains(err.Error(), "linux/amd64") {
			t.Errorf("error %q does not name the image's actual platform", err)
		}
	})

	t.Run("e2e/single_manifest_native_positive_control", func(t *testing.T) {
		ref := pushImage(t, host, "singledarwin", darwinARM64)
		img, err := RemoteFetch(context.Background(), ref, nil, nativePolicy())
		if err != nil {
			t.Fatalf("RemoteFetch: %v", err)
		}
		if got := resolvedPlatform(t, img); got != platDarwinARM64 {
			t.Errorf("resolved platform = %s, want %s", got, platDarwinARM64)
		}
	})

	// The production path itself, not a fake: NewPuller(cache, RemoteFetch) is
	// EXACTLY how runtime.New builds the daemon's puller, so this subtest is the
	// only thing standing between a green table and a green table that never
	// executed RemoteFetch (the pre-B99 pull tests all replaced the fetcher).
	t.Run("e2e/production_puller_fails_closed", func(t *testing.T) {
		ref := pushIndex(t, host, "prodlinuxonly",
			child(linuxAMD64, ggcrPlatform("linux", "amd64", "")),
			child(linuxARM64, ggcrPlatform("linux", "arm64", "v8")),
		)
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p := mustPuller(t, cache, RemoteFetch) // as runtime.New does
		res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED)
		if res != nil {
			t.Errorf("a pull result was returned for an unrunnable index: %+v", res.Manifest)
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
	})

	// The binding itself: a Puller has NO default fetcher (and no default
	// presence index) to fall back to, so a caller cannot acquire one without
	// naming which fetcher and which index it wants.
	t.Run("puller/nil_fetch_is_an_error_not_a_default", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if p, err := NewPuller(cache, nil, NoLocalIndex{}); err == nil {
			t.Errorf("NewPuller(cache, nil, NoLocalIndex{}) returned %+v; a nil fetcher must be refused, not defaulted", p)
		}
		if p, err := NewPuller(nil, RemoteFetch, NoLocalIndex{}); err == nil {
			t.Errorf("NewPuller(nil, RemoteFetch, NoLocalIndex{}) returned %+v; a nil cache must be refused", p)
		}
		if p, err := NewPuller(cache, RemoteFetch, nil); err == nil {
			t.Errorf("NewPuller(cache, RemoteFetch, nil) returned %+v; a nil index must be refused (NoLocalIndex{} is the explicit none)", p)
		}
	})

	// The choke point: Pull verifies the fetched image's own config against the
	// policy, so a FetchFunc that skips the check cannot seed the cache with
	// foreign-platform bytes. The fake below is the in-tree demonstration of that
	// bypass — a plain random.Image declares no platform at all.
	t.Run("puller/verifies_platform_at_the_choke_point", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name string
			img  ggcrv1.Image
		}{
			{"platform_less_image", func() ggcrv1.Image { i, _ := random.Image(64, 1); return i }()},
			{"foreign_platform_image", linuxAMD64},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				p := mustPuller(t, cache, func(context.Context, string, *RegistryCredential, PlatformPolicy) (ggcrv1.Image, error) {
					return tc.img, nil
				})
				res, err := p.Pull(context.Background(), "example.com/app:v1", nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED)
				if res != nil {
					t.Errorf("a pull result was returned for an unrunnable image: %+v", res.Manifest)
				}
				if !errors.Is(err, ErrNoPlatformMatch) {
					t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
				}
			})
		}
	})

	// -----------------------------------------------------------------
	// End-to-end against a registry that serves MALFORMED or hostile bytes —
	// the fail-closed verdicts a conforming registry cannot produce.
	// -----------------------------------------------------------------

	// A 200 kB digest ALGORITHM. go-containerregistry's v1.Hash parser formats
	// the offending string into its error verbatim (hash.go "unsupported hash:
	// %q"), and the index body it came from is capped only by ggcr's 100 MiB
	// manifest limit — so echoing that error with %w hands a registry a
	// megabyte-scale write into slog, the Pod status message and kine.
	hugeAlgorithm := strings.Repeat("z", 200_000)

	t.Run("e2e/index_parse_error_is_bounded", func(t *testing.T) {
		body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[` +
			`{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":2,"digest":"` + hugeAlgorithm + `:abc",` +
			`"platform":{"os":"darwin","architecture":"arm64"}}]}`)
		host := rawRegistry(t, map[string]rawResponse{
			"/v2/badindex/manifests/v1": {mediaType: string(types.OCIImageIndex), body: body},
		})
		img, err := RemoteFetch(context.Background(), host+"/badindex:v1", nil, nativePolicy())
		if img != nil {
			t.Errorf("an image was returned for an unparseable index")
		}
		if err == nil {
			t.Fatal("an unparseable index must fail closed")
		}
		if n := len(err.Error()); n > maxWrappedErrLen*4 {
			t.Errorf("error message is %d bytes for a %d-byte hostile input: registry content is unbounded",
				n, len(hugeAlgorithm))
		}
		// An index that cannot be parsed can never yield a runnable manifest, so
		// the failure is TERMINAL — a consumer must not retry it forever.
		if !IsTerminalPlatformError(err) {
			t.Errorf("error %v is not a terminal platform error", err)
		}
	})

	t.Run("e2e/image_config_parse_error_is_bounded", func(t *testing.T) {
		// Same ggcr hash parser, reached through the CONFIG blob (a config's
		// rootfs.diff_ids are v1.Hash values), i.e. the second unbounded echo.
		cfg := []byte(`{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers","diff_ids":["` +
			hugeAlgorithm + `:abc"]}}`)
		mfst := []byte(fmt.Sprintf(
			`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"size":%d,"digest":%q},"layers":[]}`,
			types.OCIManifestSchema1, types.OCIConfigJSON, len(cfg), digestOf(cfg)))
		host := rawRegistry(t, map[string]rawResponse{
			"/v2/badconfig/manifests/v1":           {mediaType: string(types.OCIManifestSchema1), body: mfst},
			"/v2/badconfig/blobs/" + digestOf(cfg): {mediaType: string(types.OCIConfigJSON), body: cfg},
		})
		img, err := RemoteFetch(context.Background(), host+"/badconfig:v1", nil, nativePolicy())
		if img != nil {
			t.Errorf("an image was returned for an unparseable config")
		}
		if err == nil {
			t.Fatal("an unparseable image config must fail closed")
		}
		if n := len(err.Error()); n > maxWrappedErrLen*4 {
			t.Errorf("error message is %d bytes for a %d-byte hostile input: registry content is unbounded",
				n, len(hugeAlgorithm))
		}
		if !strings.Contains(err.Error(), "image config") {
			t.Errorf("error %q does not say which step failed", err)
		}
	})

	t.Run("e2e/unsupported_manifest_media_type_refused", func(t *testing.T) {
		// A legacy Docker schema-1 manifest (no platform information at all).
		// k3sm REFUSES it rather than guessing; ggcr's own alternative is to
		// assume "image" and warn. The branch is only reachable from a registry
		// that serves a non-image, non-index Content-Type.
		host := rawRegistry(t, map[string]rawResponse{
			"/v2/schema1/manifests/v1": {
				mediaType: string(types.DockerManifestSchema1Signed),
				body:      []byte(`{"schemaVersion":1,"name":"schema1","tag":"v1"}`),
			},
		})
		img, err := RemoteFetch(context.Background(), host+"/schema1:v1", nil, nativePolicy())
		if img != nil {
			t.Errorf("an image was returned for an unsupported manifest media type")
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		if !strings.Contains(err.Error(), "schema1") {
			t.Errorf("error %q does not name the media type, so the case is not diagnosable", err)
		}
	})

	t.Run("e2e/served_child_index_is_refused", func(t *testing.T) {
		// The parent index DESCRIBES the child as an image manifest (so
		// SelectManifest selects it), and the registry then SERVES an index at
		// that digest. The descriptor's media type is unsigned parent metadata,
		// so only re-asserting it on the served child closes this — otherwise
		// Descriptor.Image() would resolve a child of the nested index by
		// ggcr's defaulted platform.
		nested := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
		parent := []byte(fmt.Sprintf(
			`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":%d,"digest":%q,`+
				`"platform":{"os":"darwin","architecture":"arm64"}}]}`,
			types.OCIImageIndex, types.OCIManifestSchema1, len(nested), digestOf(nested)))
		host := rawRegistry(t, map[string]rawResponse{
			"/v2/liarindex/manifests/v1":                  {mediaType: string(types.OCIImageIndex), body: parent},
			"/v2/liarindex/manifests/" + digestOf(nested): {mediaType: string(types.OCIImageIndex), body: nested},
		})
		img, err := RemoteFetch(context.Background(), host+"/liarindex:v1", nil, nativePolicy())
		if img != nil {
			t.Errorf("an image was returned for a child SERVED as an index")
		}
		if !errors.Is(err, ErrNestedIndex) {
			t.Fatalf("error = %v, want ErrNestedIndex", err)
		}
		if !IsTerminalPlatformError(err) {
			t.Errorf("error %v is not a terminal platform error", err)
		}
	})

	// -----------------------------------------------------------------
	// Candidates: the pure policy → platform-list table.
	// -----------------------------------------------------------------
	t.Run("candidates/order_and_membership", func(t *testing.T) {
		cases := []struct {
			name   string
			policy PlatformPolicy
			want   []Platform
		}{
			{"native_no_rosetta", nativePolicy(), []Platform{platDarwinARM64}},
			{"native_host_rosetta", nativePolicyRosetta(), []Platform{platDarwinARM64, platDarwinAMD64}},
			{"vm_no_rosetta", vmPolicy(), []Platform{platLinuxARM64}},
			{"vm_guest_rosetta", vmPolicyRosetta(), []Platform{platLinuxARM64, platLinuxAMD64}},
			{"seatbelt_exec_is_native", PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC}, []Platform{platDarwinARM64}},
			{"uidjail_is_native", PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL}, []Platform{platDarwinARM64}},
			// The vm rows above have no live call site yet (createVMPod never
			// pulls) — they are a contract test, not evidence that vm image
			// selection works end to end.
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := mustCandidates(t, tc.policy)
				if len(got) != len(tc.want) {
					t.Fatalf("Candidates = %v, want %v", got, tc.want)
				}
				// ORDER is asserted, not set membership: the native arch must
				// precede the Rosetta-translated fallback or a translated
				// image would be preferred over a native one.
				for i := range got {
					if got[i] != tc.want[i] {
						t.Fatalf("Candidates[%d] = %s, want %s (full: %v)", i, got[i], tc.want[i], got)
					}
				}
			})
		}
	})

	t.Run("candidates/unresolved_backend_fails_closed", func(t *testing.T) {
		cases := []struct {
			name    string
			backend runtimev1.SandboxBackend
		}{
			{"zero_value", runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED},
			{"unknown_value", runtimev1.SandboxBackend(9999)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := Candidates(PlatformPolicy{Backend: tc.backend})
				if got != nil {
					t.Errorf("Candidates = %v, want nil (an empty slice reads as 'no constraint')", got)
				}
				if !errors.Is(err, ErrNoPlatformMatch) {
					t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
				}
			})
		}
	})

	t.Run("candidates/override", func(t *testing.T) {
		t.Run("pins_exactly_that_platform", func(t *testing.T) {
			p := nativePolicyRosetta()
			p.Override = &Platform{OS: "darwin", Architecture: "amd64"}
			got := mustCandidates(t, p)
			if len(got) != 1 || got[0] != platDarwinAMD64 {
				t.Fatalf("Candidates = %v, want exactly [%s]", got, platDarwinAMD64)
			}
		})
		t.Run("is_normalised", func(t *testing.T) {
			p := vmPolicy()
			p.Override = &Platform{OS: "Linux", Architecture: "ARM64"} // variant absent
			got := mustCandidates(t, p)
			if len(got) != 1 || got[0] != platLinuxARM64 {
				t.Fatalf("Candidates = %v, want exactly [%s]", got, platLinuxARM64)
			}
		})
		t.Run("backend_cannot_run_it_fails_closed", func(t *testing.T) {
			p := nativePolicyRosetta()
			p.Override = &Platform{OS: "linux", Architecture: "amd64"} // native cannot run linux
			got, err := Candidates(p)
			if got != nil {
				t.Errorf("Candidates = %v, want nil", got)
			}
			if !errors.Is(err, ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
			}
		})
		t.Run("rosetta_absent_fails_closed", func(t *testing.T) {
			p := nativePolicy() // HostRosetta false
			p.Override = &Platform{OS: "darwin", Architecture: "amd64"}
			if _, err := Candidates(p); !errors.Is(err, ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
			}
		})
		t.Run("absent_from_index_never_falls_back", func(t *testing.T) {
			p := nativePolicyRosetta()
			p.Override = &Platform{OS: "darwin", Architecture: "amd64"}
			want := mustCandidates(t, p)
			idx := indexOf(imageDesc("a", "darwin", "arm64", "")) // the OTHER candidate
			got, err := SelectManifest(idx, want)
			if err == nil {
				t.Fatalf("SelectManifest returned %s; an override must never fall back to a backend candidate", got.Digest)
			}
			if !errors.Is(err, ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
			}
		})
	})

	// -----------------------------------------------------------------
	// SelectManifest: the pure index-traversal table (no IO).
	// -----------------------------------------------------------------
	t.Run("select/variant_equivalence_both_directions", func(t *testing.T) {
		t.Run("child_variant_empty_matches_v8_candidate", func(t *testing.T) {
			idx := indexOf(imageDesc("a", "linux", "arm64", ""))
			got, err := SelectManifest(idx, mustCandidates(t, vmPolicy()))
			if err != nil {
				t.Fatalf("SelectManifest: %v", err)
			}
			if got.Platform.Variant != "" {
				t.Errorf("selected descriptor mutated: %+v", got.Platform)
			}
		})
		t.Run("child_variant_v8_matches_empty_override", func(t *testing.T) {
			p := vmPolicy()
			p.Override = &Platform{OS: "linux", Architecture: "arm64"} // no variant
			idx := indexOf(imageDesc("a", "linux", "arm64", "v8"))
			if _, err := SelectManifest(idx, mustCandidates(t, p)); err != nil {
				t.Fatalf("SelectManifest: %v", err)
			}
		})
		t.Run("case_is_folded", func(t *testing.T) {
			idx := indexOf(imageDesc("a", "Linux", "ARM64", "V8"))
			if _, err := SelectManifest(idx, mustCandidates(t, vmPolicy())); err != nil {
				t.Fatalf("SelectManifest: %v", err)
			}
		})
	})

	t.Run("select/unknown_variant_never_matched", func(t *testing.T) {
		// Decided verdict: arm64/v9 is NOT accepted for an arm64/v8 candidate.
		// armv9 mandates SVE2, which Apple Silicon does not implement, so a
		// permissive variant match would select binaries that fault at first
		// use — the exact fail-open shape ggcr's Satisfies has.
		idx := indexOf(imageDesc("a", "linux", "arm64", "v9"))
		if _, err := SelectManifest(idx, mustCandidates(t, vmPolicy())); !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
	})

	t.Run("select/nil_platform_child_never_matched", func(t *testing.T) {
		idx := indexOf(desc("a", types.OCIManifestSchema1, nil))
		got, err := SelectManifest(idx, mustCandidates(t, nativePolicy()))
		if err == nil {
			t.Fatalf("SelectManifest returned %s for a platform-less child", got.Digest)
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		if strings.Contains(err.Error(), "amd64") {
			t.Errorf("error %q implies a platform-less child was read as amd64", err)
		}
	})

	t.Run("select/digest_less_child_never_selected", func(t *testing.T) {
		// A child that OMITS the digest key never invokes v1.Hash.UnmarshalJSON
		// (an absent JSON key is not decoded at all), so it keeps the ZERO
		// v1.Hash — which renders as ":" and is otherwise a perfectly selectable
		// image child. Selection is first-match-wins, so a hostile index can
		// place a digest-less darwin/arm64 child AHEAD of the real one and
		// deterministically shadow it. The outcome stays fail-closed downstream
		// (ggcr refuses the malformed reference), but the allowlist is POSITIVE
		// and the OCI spec makes digest REQUIRED, so it is rejected here.
		t.Run("absent_digest_key_parses_as_a_selectable_zero_hash", func(t *testing.T) {
			var idx ggcrv1.IndexManifest
			body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[` +
				`{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":1,` +
				`"platform":{"os":"darwin","architecture":"arm64"}}]}`
			if err := json.Unmarshal([]byte(body), &idx); err != nil {
				t.Fatalf("an index whose child omits digest must still parse: %v", err)
			}
			if got := idx.Manifests[0].Digest.String(); got != ":" {
				t.Fatalf("digest of a digest-less child = %q, want the zero hash %q", got, ":")
			}
			if !idx.Manifests[0].MediaType.IsImage() {
				t.Fatal("the child is not image-typed, so this fixture proves nothing")
			}
			if _, err := SelectManifest(&idx, mustCandidates(t, nativePolicy())); !errors.Is(err, ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
			}
		})
		t.Run("cannot_shadow_the_real_child", func(t *testing.T) {
			shadow := imageDesc("a", "darwin", "arm64", "")
			shadow.Digest = ggcrv1.Hash{}
			genuine := imageDesc("b", "darwin", "arm64", "")
			got, err := SelectManifest(indexOf(shadow, genuine), mustCandidates(t, nativePolicy()))
			if err != nil {
				t.Fatalf("SelectManifest: %v", err)
			}
			if got.Digest != genuine.Digest {
				t.Errorf("selected %q, want the child with a real digest %s", got.Digest, genuine.Digest)
			}
		})
		t.Run("empty_hex_is_rejected_too", func(t *testing.T) {
			half := imageDesc("a", "darwin", "arm64", "")
			half.Digest = ggcrv1.Hash{Algorithm: "sha256"}
			if _, err := SelectManifest(indexOf(half), mustCandidates(t, nativePolicy())); !errors.Is(err, ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
			}
		})
	})

	t.Run("select/unknown_unknown_skipped_and_unlisted", func(t *testing.T) {
		idx := indexOf(
			imageDesc("a", "unknown", "unknown", ""),
			imageDesc("b", "linux", "amd64", ""),
		)
		_, err := SelectManifest(idx, mustCandidates(t, nativePolicy()))
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "linux/amd64") {
			t.Errorf("error %q does not name the real available platform", msg)
		}
		if strings.Contains(msg, "unknown") {
			t.Errorf("error %q names the unknown/unknown attestation marker", msg)
		}
	})

	t.Run("select/attestation_annotation_skipped", func(t *testing.T) {
		// Defence in depth: even a child that LIES about its platform is
		// skipped when it carries buildx's attestation annotation.
		lying := imageDesc("a", "darwin", "arm64", "")
		lying.Annotations = map[string]string{attestationRefType: "attestation-manifest"}
		real := imageDesc("b", "darwin", "arm64", "")
		got, err := SelectManifest(indexOf(lying, real), mustCandidates(t, nativePolicy()))
		if err != nil {
			t.Fatalf("SelectManifest: %v", err)
		}
		if got.Digest != real.Digest {
			t.Errorf("selected %s, want the non-attestation child %s", got.Digest, real.Digest)
		}
	})

	t.Run("select/artifact_type", func(t *testing.T) {
		t.Run("referrer_artifact_skipped", func(t *testing.T) {
			referrer := imageDesc("a", "darwin", "arm64", "")
			referrer.ArtifactType = "application/vnd.example.sbom"
			if _, err := SelectManifest(indexOf(referrer), mustCandidates(t, nativePolicy())); !errors.Is(err, ErrNoPlatformMatch) {
				t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
			}
		})
		// Regression pin: per OCI 1.1 a plain image's artifactType DEFAULTS to
		// its config media type, and go-containerregistry populates it, so a
		// blanket "artifactType set ⇒ skip" rule rejects every real image.
		for _, cfgType := range []types.MediaType{types.DockerConfigJSON, types.OCIConfigJSON} {
			t.Run("image_config_artifact_type_selectable/"+string(cfgType), func(t *testing.T) {
				normal := imageDesc("a", "darwin", "arm64", "")
				normal.ArtifactType = string(cfgType)
				if _, err := SelectManifest(indexOf(normal), mustCandidates(t, nativePolicy())); err != nil {
					t.Fatalf("SelectManifest: %v", err)
				}
			})
		}
	})

	t.Run("select/candidate_order_beats_index_order", func(t *testing.T) {
		// The index lists amd64 FIRST; the arm64 candidate must still win.
		idx := indexOf(
			imageDesc("a", "linux", "amd64", ""),
			imageDesc("b", "linux", "arm64", "v8"),
		)
		got, err := SelectManifest(idx, mustCandidates(t, vmPolicyRosetta()))
		if err != nil {
			t.Fatalf("SelectManifest: %v", err)
		}
		if want := imageDesc("b", "linux", "arm64", "v8"); got.Digest != want.Digest {
			t.Errorf("selected %s (%s), want the arm64 child", got.Digest, got.Platform)
		}
	})

	t.Run("select/duplicate_platforms_first_match_wins", func(t *testing.T) {
		first := imageDesc("a", "darwin", "arm64", "")
		second := imageDesc("b", "darwin", "arm64", "v8")
		for i := 0; i < 8; i++ { // deterministic across runs, not map-ordered
			got, err := SelectManifest(indexOf(first, second), mustCandidates(t, nativePolicy()))
			if err != nil {
				t.Fatalf("SelectManifest: %v", err)
			}
			if got.Digest != first.Digest {
				t.Fatalf("selected %s, want the first matching child %s", got.Digest, first.Digest)
			}
		}
	})

	t.Run("select/empty_index_fails_closed", func(t *testing.T) {
		got, err := SelectManifest(indexOf(), mustCandidates(t, nativePolicy()))
		if err == nil {
			t.Fatalf("SelectManifest returned %s for an empty index", got.Digest)
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		if !strings.Contains(err.Error(), "none") {
			t.Errorf("error %q should report an empty available list", err)
		}
	})

	t.Run("select/nil_index_and_no_candidates_fail_closed", func(t *testing.T) {
		if _, err := SelectManifest(nil, mustCandidates(t, nativePolicy())); !errors.Is(err, ErrNoPlatformMatch) {
			t.Errorf("nil index: error = %v, want ErrNoPlatformMatch", err)
		}
		if _, err := SelectManifest(indexOf(imageDesc("a", "darwin", "arm64", "")), nil); !errors.Is(err, ErrNoPlatformMatch) {
			t.Errorf("nil candidates: error = %v, want ErrNoPlatformMatch", err)
		}
	})

	t.Run("select/nested_index_child_is_refused", func(t *testing.T) {
		// Decided verdict: an index-of-index is REFUSED with its own sentinel,
		// not traversed. The platform IS on offer, so reporting "no match"
		// would misdescribe it; recursion into registry-controlled fan-out is
		// not worth the blast radius for a shape no target registry publishes.
		idx := indexOf(desc("a", types.OCIImageIndex, ggcrPlatform("darwin", "arm64", "")))
		_, err := SelectManifest(idx, mustCandidates(t, nativePolicy()))
		if !errors.Is(err, ErrNestedIndex) {
			t.Fatalf("error = %v, want ErrNestedIndex", err)
		}
		if errors.Is(err, ErrNoPlatformMatch) {
			t.Errorf("ErrNestedIndex must not masquerade as ErrNoPlatformMatch: %v", err)
		}
	})

	t.Run("select/non_matching_nested_index_is_just_unavailable", func(t *testing.T) {
		idx := indexOf(desc("a", types.DockerManifestList, ggcrPlatform("linux", "amd64", "")))
		if _, err := SelectManifest(idx, mustCandidates(t, nativePolicy())); !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
	})

	// -----------------------------------------------------------------
	// VerifyConfigPlatform: the child's OWN config is the authority.
	// -----------------------------------------------------------------
	t.Run("verify/config", func(t *testing.T) {
		cases := []struct {
			name    string
			cfg     *ggcrv1.ConfigFile
			policy  PlatformPolicy
			want    Platform
			wantErr bool
		}{
			{"match", &ggcrv1.ConfigFile{OS: "darwin", Architecture: "arm64"}, nativePolicy(), platDarwinARM64, false},
			{"match_explicit_variant", &ggcrv1.ConfigFile{OS: "darwin", Architecture: "arm64", Variant: "v8"}, nativePolicy(), platDarwinARM64, false},
			{"foreign_os", &ggcrv1.ConfigFile{OS: "linux", Architecture: "arm64"}, nativePolicy(), Platform{}, true},
			{"foreign_arch", &ggcrv1.ConfigFile{OS: "darwin", Architecture: "amd64"}, nativePolicy(), Platform{}, true},
			// Decided verdict: an unstated platform FAILS CLOSED. Treating
			// "not declared" as "compatible" is the bug this item removes.
			{"empty_os", &ggcrv1.ConfigFile{Architecture: "arm64"}, nativePolicy(), Platform{}, true},
			{"empty_arch", &ggcrv1.ConfigFile{OS: "darwin"}, nativePolicy(), Platform{}, true},
			{"empty_both", &ggcrv1.ConfigFile{}, nativePolicy(), Platform{}, true},
			// Decided verdict: os.version pins a kernel ABI k3sm never
			// requests, so a config carrying one is refused, not ignored.
			{"os_version_pinned", &ggcrv1.ConfigFile{OS: "darwin", Architecture: "arm64", OSVersion: "26.0"}, nativePolicy(), Platform{}, true},
			{"nil_config", nil, nativePolicy(), Platform{}, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := VerifyConfigPlatform(tc.cfg, mustCandidates(t, tc.policy))
				if tc.wantErr {
					if !errors.Is(err, ErrNoPlatformMatch) {
						t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
					}
					if got != (Platform{}) {
						t.Errorf("a platform %s was returned alongside an error", got)
					}
					return
				}
				if err != nil {
					t.Fatalf("VerifyConfigPlatform: %v", err)
				}
				if got != tc.want {
					t.Errorf("resolved = %s, want %s", got, tc.want)
				}
			})
		}
	})

	// -----------------------------------------------------------------
	// The error carrier: typed, unwrappable, sanitised and bounded.
	// -----------------------------------------------------------------
	t.Run("error/typed_and_unwrappable", func(t *testing.T) {
		err := error(&PlatformMismatchError{Wanted: []Platform{platDarwinARM64}, Available: []Platform{platLinuxAMD64}})
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Errorf("*PlatformMismatchError does not unwrap to the sentinel")
		}
		var mm *PlatformMismatchError
		if !errors.As(err, &mm) || len(mm.Wanted) != 1 || len(mm.Available) != 1 {
			t.Errorf("errors.As did not recover the carrier: %+v", mm)
		}
		// It survives one more wrap, which is how RemoteFetch returns it.
		wrapped := fmt.Errorf("pull %q: %w", "example.com/x:v1", err)
		if !errors.Is(wrapped, ErrNoPlatformMatch) || !errors.As(wrapped, &mm) {
			t.Errorf("the carrier does not survive wrapping: %v", wrapped)
		}
	})

	t.Run("error/terminality_is_one_predicate", func(t *testing.T) {
		// Both refusals are PERMANENT, so a consumer must treat them alike or it
		// parks a pod in an infinite ImagePullBackOff over the one it forgot.
		// The sentinels stay distinct (each message describes its own failure),
		// which is exactly why the shared verdict is exported as a predicate.
		cases := []struct {
			name string
			err  error
			want bool
		}{
			{"no_platform_match", ErrNoPlatformMatch, true},
			{"nested_index", ErrNestedIndex, true},
			{"typed_carrier", error(&PlatformMismatchError{Wanted: []Platform{platDarwinARM64}}), true},
			{"wrapped", fmt.Errorf("pull %q: %w", "example.com/x:v1", ErrNestedIndex), true},
			{"unrelated", errors.New("connection refused"), false},
			{"nil", nil, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := IsTerminalPlatformError(tc.err); got != tc.want {
					t.Errorf("IsTerminalPlatformError(%v) = %v, want %v", tc.err, got, tc.want)
				}
			})
		}
		// ErrNestedIndex is NOT reachable through ErrNoPlatformMatch, so a
		// consumer testing only the documented sentinel would miss it — the
		// defect the predicate exists to prevent.
		if errors.Is(ErrNestedIndex, ErrNoPlatformMatch) {
			t.Error("ErrNestedIndex must stay distinct from ErrNoPlatformMatch")
		}
	})

	t.Run("error/available_list_is_bounded", func(t *testing.T) {
		var many []ggcrv1.Descriptor
		for i := 0; i < 12; i++ {
			many = append(many, imageDesc(string(rune('a'+i)), "linux", fmt.Sprintf("arch%d", i), ""))
		}
		_, err := SelectManifest(indexOf(many...), mustCandidates(t, nativePolicy()))
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "(+4 more)") {
			t.Errorf("error %q does not collapse the tail of a 12-platform list", msg)
		}
		if strings.Contains(msg, "arch11") {
			t.Errorf("error %q renders past the cap", msg)
		}
	})

	t.Run("error/available_is_deduplicated", func(t *testing.T) {
		// Two children of the same platform are one entry, so a 500-child index
		// of one platform does not exhaust the collection cap with repeats.
		_, err := SelectManifest(indexOf(
			imageDesc("a", "linux", "amd64", ""),
			imageDesc("b", "linux", "amd64", ""),
			imageDesc("c", "linux", "riscv64", ""),
		), mustCandidates(t, nativePolicy()))
		var mm *PlatformMismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("error %v is not a *PlatformMismatchError", err)
		}
		if len(mm.Available) != 2 || mm.Omitted != 0 {
			t.Errorf("Available = %v (omitted %d), want the 2 distinct platforms", mm.Available, mm.Omitted)
		}
	})

	t.Run("error/bounded_third_party_error_keeps_its_chain", func(t *testing.T) {
		// boundErr caps the RENDERING of a foreign error, not the error: a
		// caller must still be able to classify the cause. (ggcr's transport
		// errors are the real case — errors.As on a *transport.Error is how a
		// consumer tells an auth failure from a 404.)
		cause := errors.New("registry said no")
		hostile := fmt.Errorf("%w: %s", cause, strings.Repeat("é", 4096))
		wrapped := fmt.Errorf("pull %q: %w", "example.com/x:v1", boundErr(hostile))
		if !errors.Is(wrapped, cause) {
			t.Error("boundErr dropped the cause: errors.Is no longer reaches it")
		}
		msg := wrapped.Error()
		if len(msg) > maxWrappedErrLen*4 {
			t.Errorf("bounded message is %d bytes for a %d-byte cause", len(msg), len(hostile.Error()))
		}
		if !utf8.ValidString(msg) {
			t.Errorf("bounded message is not valid UTF-8: %q", msg)
		}
		if strings.ContainsAny(msg, "\n\r\x1b") {
			t.Errorf("bounded message carries a raw control character: %q", msg)
		}
	})

	t.Run("error/hand_built_carrier_is_still_capped", func(t *testing.T) {
		// PlatformMismatchError is exported with exported fields, so a consumer
		// (or a future in-repo caller) can build one that never went through
		// availablePlatforms. Rendering therefore keeps its own cap.
		var many []Platform
		for i := 0; i < maxRenderedPlatforms*3; i++ {
			many = append(many, Platform{OS: "linux", Architecture: fmt.Sprintf("arch%d", i)})
		}
		err := error(&PlatformMismatchError{Wanted: []Platform{platDarwinARM64}, Available: many})
		msg := err.Error()
		if want := fmt.Sprintf("(+%d more)", len(many)-maxRenderedPlatforms); !strings.Contains(msg, want) {
			t.Errorf("error %q does not collapse the tail with %q", msg, want)
		}
		if strings.Contains(msg, fmt.Sprintf("arch%d", len(many)-1)) {
			t.Errorf("error %q renders past the render cap", msg)
		}
	})

	t.Run("error/available_is_capped_at_collection", func(t *testing.T) {
		// maxRenderedPlatforms caps what is PRINTED. Without a COLLECTION cap the
		// carrier still retains one Platform per index child — over an index
		// bounded only by ggcr's 100 MiB manifest limit (~700k descriptors), that
		// is hundreds of MB held alive by a single error value.
		const children = 64
		var many []ggcrv1.Descriptor
		for i := 0; i < children; i++ {
			many = append(many, imageDesc("a", "linux", fmt.Sprintf("arch%d", i), strings.Repeat("Z", 4096)))
		}
		_, err := SelectManifest(indexOf(many...), mustCandidates(t, nativePolicy()))
		var mm *PlatformMismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("error %v is not a *PlatformMismatchError", err)
		}
		if len(mm.Available) > maxCollectedPlatforms {
			t.Errorf("Available retains %d platforms, want <= %d", len(mm.Available), maxCollectedPlatforms)
		}
		// Stated absolutely as well as symbolically: retention must not scale
		// with the index, whatever the constants are later tuned to.
		if len(mm.Available) >= children {
			t.Errorf("Available retains %d of %d children — retention scales with the index", len(mm.Available), children)
		}
		if got := len(mm.Available) + mm.Omitted; got != children {
			t.Errorf("Available(%d) + Omitted(%d) = %d, want %d: the children are not accounted for",
				len(mm.Available), mm.Omitted, got, children)
		}
		for _, p := range mm.Available {
			for _, tok := range []string{p.OS, p.Architecture, p.Variant, p.OSVersion} {
				if len(tok) > maxTokenLen+1 {
					t.Errorf("a retained token is %d bytes, want <= %d", len(tok), maxTokenLen+1)
				}
			}
		}
		// The rendered tail still accounts for every child, so capping retention
		// does not cost the human the "there were more" signal.
		if want := fmt.Sprintf("(+%d more)", children-maxRenderedPlatforms); !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not report %q", err, want)
		}
	})

	t.Run("error/registry_content_is_sanitised", func(t *testing.T) {
		// The fixture must be big enough to EXECUTE the whole-message truncation
		// branch: with two hostile children the rendered message stayed under
		// maxErrorLen, so this case passed for a reason unrelated to the
		// mechanism it names. Nine children (each carrying a hostile
		// architecture AND variant) put it comfortably over the cap.
		//
		// The é/あ tokens are PRINTABLE NON-ASCII: strconv.Quote passes them
		// through as raw multi-byte UTF-8, so a byte-boundary cut of the message
		// lands mid-rune and emits an invalid UTF-8 string — which
		// google.golang.org/protobuf then REFUSES to marshal into the proto3
		// string field of the pod's failure status (rpcStatus/google.rpc.Status),
		// letting a hostile registry choose whether the operator sees the typed
		// failure at all. strconv.QuoteToASCII is what makes the cut safe.
		hostile := []ggcrv1.Descriptor{
			imageDesc("a", "linux", "amd64\n2026-07-22 FATAL forged log line \x1b[31mred\x1b[0m", ""),
			imageDesc("b", "linux", strings.Repeat("A", 4096), ""),
		}
		for i := 0; i < 9; i++ {
			hostile = append(hostile, imageDesc(string(rune('c'+i)), "linux",
				fmt.Sprintf("%d%s", i, strings.Repeat("é", 14)), strings.Repeat("あ", 10)))
		}
		_, err := SelectManifest(indexOf(hostile...), mustCandidates(t, nativePolicy()))
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		msg := err.Error()
		if !strings.HasSuffix(msg, truncatedSuffix) {
			t.Fatalf("the truncation branch did not execute (%d bytes): %q", len(msg), msg)
		}
		// The decisive assertion: the truncated message must still be a legal
		// proto3 string. A byte-boundary cut is only safe because every token was
		// rendered ASCII-only.
		if !utf8.ValidString(msg) {
			t.Errorf("truncated message is not valid UTF-8 (tail % x): %q", msg[maxErrorLen-4:], msg)
		}
		// ... and the consequence itself, not a proxy for it: this string is
		// carried to the provider in a google.rpc.Status (pkg/runtime rpcStatus →
		// CreatePodResponse.error), whose Message is a PROTO3 STRING. An invalid
		// UTF-8 byte makes proto.Marshal fail, so a hostile registry would decide
		// whether the operator ever sees the typed IMAGE_PULL failure.
		if _, merr := proto.Marshal(&rpcstatus.Status{Code: 13, Message: msg}); merr != nil {
			t.Errorf("the failure status carrying this message does not marshal: %v", merr)
		}
		if strings.ContainsAny(msg, "\n\r\x1b") {
			t.Errorf("error message carries a raw control character: %q", msg)
		}
		if len(msg) > maxErrorLen+len(truncatedSuffix) {
			t.Errorf("error message is %d bytes, want <= %d", len(msg), maxErrorLen+len(truncatedSuffix))
		}
		if strings.Contains(msg, strings.Repeat("A", maxTokenLen+1)) {
			t.Errorf("error message carries an unbounded token: %q", msg)
		}
	})
}
