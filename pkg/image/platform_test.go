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
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ---------------------------------------------------------------------------
// Fixtures. The end-to-end cases run against go-containerregistry's in-module
// pkg/registry over httptest: it pulls in only stdlib + ggcr-internal packages,
// so it adds no go.mod requirement, and name.Registry.Scheme() returns http for
// a 127.0.0.1:PORT authority (reLoopback), so no TLS fixture is needed. Every
// response is a 200 or a 404 — never a retryable 5xx, which ggcr would retry
// with a 1s backoff and turn a 10ms assertion into a multi-second "flake".
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

// testImage builds a one-layer image whose CONFIG declares the given platform —
// the config is what VerifyConfigPlatform reads, so it is what the fixture must
// control.
func testImage(t *testing.T, os, arch, variant string) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
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

	// The production path itself, not a fake: NewPuller(cache, nil) is EXACTLY
	// how runtime.New builds the daemon's puller, so this subtest is the only
	// thing standing between a green table and a green table that never
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
		p := NewPuller(cache, nil) // nil fetch ⇒ RemoteFetch, as runtime.New does
		res, err := p.Pull(context.Background(), ref, nil, nativePolicy())
		if res != nil {
			t.Errorf("a pull result was returned for an unrunnable index: %+v", res.Manifest)
		}
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
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

	t.Run("error/registry_content_is_sanitised", func(t *testing.T) {
		hostile := imageDesc("a", "linux",
			"amd64\n2026-07-22 FATAL forged log line \x1b[31mred\x1b[0m", "")
		huge := imageDesc("b", "linux", strings.Repeat("A", 4096), "")
		_, err := SelectManifest(indexOf(hostile, huge), mustCandidates(t, nativePolicy()))
		if !errors.Is(err, ErrNoPlatformMatch) {
			t.Fatalf("error = %v, want ErrNoPlatformMatch", err)
		}
		msg := err.Error()
		if strings.ContainsAny(msg, "\n\r\x1b") {
			t.Errorf("error message carries a raw control character: %q", msg)
		}
		if len(msg) > maxErrorLen+len(" (truncated)") {
			t.Errorf("error message is %d bytes, want <= %d", len(msg), maxErrorLen+len(" (truncated)"))
		}
		if strings.Contains(msg, strings.Repeat("A", maxTokenLen+1)) {
			t.Errorf("error message carries an unbounded token: %q", msg)
		}
	})
}
