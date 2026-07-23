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
	"errors"
	"fmt"
	"strconv"
	"strings"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrNoPlatformMatch is the sentinel every fail-closed platform decision wraps:
// no manifest in the image declares a platform this node can run. Compare with
// errors.Is, never by string (GO-STANDARDS §Errors) — k3sm/pkg/provider consumes
// it across the k3sm -> runtimed edge.
//
// The deliberate divergence from upstream Kubernetes (registered
// divergent-by-design, m11-plan §M11.2-d0): containerd pulls a mismatched
// single-manifest image and the container dies at exec with an opaque
// exec-format error; k3sm refuses at PULL with a legible error naming the
// platforms the image actually offers.
var ErrNoPlatformMatch = errors.New("no image manifest matches a runnable platform")

// ErrNestedIndex is the decided verdict for an index whose selected child is
// itself an index (index-of-index). k3sm REFUSES it rather than recursing: a
// recursive traversal is an unbounded, registry-controlled fan-out, and no
// registry in the k3sm target set publishes one. It is deliberately NOT wrapped
// around ErrNoPlatformMatch — the platform may well be present, so reporting "no
// match" would misdescribe the failure. Callers that mean "this image cannot
// run here" must test both sentinels.
var ErrNestedIndex = errors.New("image index child is itself an index (nested index traversal is refused)")

// Platform is the (os, architecture, variant, os.version) tuple k3sm matches an
// OCI manifest against.
//
// It is deliberately a k3sm-owned value type rather than
// go-containerregistry's v1.Platform: it is comparable (so matching is a plain
// ==, and a Platform works as a map key), it carries no OSFeatures/Features
// slices that would silently widen a comparison, and it lets
// PlatformMismatchError cross the k3sm -> runtimed API edge without dragging
// go-containerregistry into consumers.
//
// The zero value is not a platform; it never matches (Candidates never emits one
// and the selectors reject an OS or Architecture that is empty).
type Platform struct {
	// OS is the OCI "os" (GOOS) — darwin or linux for k3sm.
	OS string
	// Architecture is the OCI "architecture" (GOARCH) — arm64 or amd64.
	Architecture string
	// Variant is the OCI "variant" — v8 for arm64 after normalisation.
	Variant string
	// OSVersion is the OCI "os.version". k3sm candidates always leave it empty;
	// a manifest that pins one (a Windows-style kernel-ABI pin) therefore never
	// matches and is refused rather than assumed compatible.
	OSVersion string
}

// String renders the platform as os/arch[/variant][:os.version].
//
// Every token is passed through sanitizeToken because a Platform is frequently
// registry-controlled data (it is parsed out of a manifest we did not author)
// and this string reaches slog, the Pod status message and kine. Rendering is
// the choke point, so no caller can forget to sanitise.
func (p Platform) String() string {
	var b strings.Builder
	b.WriteString(sanitizeToken(p.OS))
	b.WriteString("/")
	b.WriteString(sanitizeToken(p.Architecture))
	if p.Variant != "" {
		b.WriteString("/")
		b.WriteString(sanitizeToken(p.Variant))
	}
	if p.OSVersion != "" {
		b.WriteString(":")
		b.WriteString(sanitizeToken(p.OSVersion))
	}
	return b.String()
}

// Normalize returns p in k3sm's canonical form: tokens trimmed and lowercased,
// and the one OCI equivalence k3sm honours applied — architecture arm64 with an
// empty variant IS arm64/v8 (the containerd/OCI convention).
//
// Normalisation is TWO-SIDED and matching is then plain equality. k3sm never
// uses go-containerregistry's Platform.Satisfies / matchesPlatform, which treat
// an EMPTY required variant as matching ANY variant: that is fail-open in
// exactly the dimension that matters here, because armv9 (arm64/v9) mandates
// SVE2 and Apple Silicon does not implement it — an "arm64 matches everything"
// rule would select a manifest whose binaries fault at first use.
func (p Platform) Normalize() Platform {
	n := Platform{
		OS:           normalizeToken(p.OS),
		Architecture: normalizeToken(p.Architecture),
		Variant:      normalizeToken(p.Variant),
		OSVersion:    strings.TrimSpace(p.OSVersion),
	}
	if n.Architecture == "arm64" && n.Variant == "" {
		n.Variant = "v8"
	}
	return n
}

// isUnknown reports whether the platform is the buildx attestation marker
// (unknown/unknown). Such a child is already excluded from SELECTION by the
// positive allowlist (no candidate is ever "unknown"); this predicate only keeps
// the marker out of the "image provides ..." list a human reads.
func (p Platform) isUnknown() bool {
	return p.OS == "unknown" || p.Architecture == "unknown"
}

// normalizeToken trims and lowercases one platform token. OCI os/architecture
// values are lowercase GOOS/GOARCH strings by convention; folding case here
// cannot cross an ABI boundary (there is no platform that differs from another
// only by case) and makes a sloppily-published manifest usable.
func normalizeToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// The candidate platforms, pre-normalised (arm64 carries its explicit v8
// variant). Kept as package values rather than rebuilt per call so the
// normal-form invariant is stated once.
var (
	platDarwinARM64 = Platform{OS: "darwin", Architecture: "arm64", Variant: "v8"}
	platDarwinAMD64 = Platform{OS: "darwin", Architecture: "amd64"}
	platLinuxARM64  = Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	platLinuxAMD64  = Platform{OS: "linux", Architecture: "amd64"}
)

// PlatformPolicy is the PER-PULL image-platform policy. It is an argument, never
// a Puller field or a package variable, because the effective sandbox backend is
// decided per pod (sandbox.SelectBackend, called from Runtime.createPod) — a
// daemon-global policy could not express a node running both native and vm pods.
//
// Backend is the backend sandbox.SelectBackend RESOLVED for this pod, not the
// one the PodBox requested. The zero value (SANDBOX_BACKEND_UNSPECIFIED) and any
// unknown value FAIL CLOSED with ErrNoPlatformMatch: SelectBackend never returns
// UNSPECIFIED on its success path, so a policy carrying it means nobody set one,
// and "no constraint" is precisely the bug this type exists to remove.
//
// LIVE CALL SITES (be honest about the green test table): only the NATIVE rows
// have one today. Runtime.resolveBinary (pkg/runtime/pod.go) is reached solely
// from the host-process spine — createPod routes a resolved vm backend to
// createVMPod BEFORE resolveBinary, and createVMPod pulls nothing (the OCI ->
// Linux-rootfs builder is m11-plan §M11.2-d1/d7 and vm exec is §M11.2-d6). The
// vm candidate rows and GuestRosetta are therefore exercised by tests only until
// those land; a green table here is NOT evidence that vm image selection works
// end to end.
//
// HostRosetta / GuestRosetta are capability INPUTS, not probes: this file stays
// GOOS-agnostic and cgo-free, and the probes that fill them are B103's job
// (m11-plan §M11.4). Until B103 lands them the call site passes false, so a
// darwin/amd64-only image is refused with a legible error rather than silently
// mis-selected.
type PlatformPolicy struct {
	// Backend is the RESOLVED sandbox backend for this pod.
	Backend runtimev1.SandboxBackend
	// HostRosetta reports that this host can translate darwin/amd64 Mach-O
	// payloads via Rosetta 2 (native backends only).
	HostRosetta bool
	// GuestRosetta reports that the Linux guest can translate linux/amd64 ELF
	// payloads via Rosetta for Linux (vm backend only).
	GuestRosetta bool
	// Override pins the pull to exactly one platform (the future
	// per-pod platform annotation). When set there is NO fallback to the
	// backend's other candidates; the override must itself be runnable by the
	// resolved backend or Candidates fails closed.
	Override *Platform
}

// Candidates returns the platforms this policy will accept, in PREFERENCE
// ORDER — the native architecture first, the Rosetta-translated fallback second.
// Order is load-bearing: selection walks candidates outer, index children inner,
// so an index that lists amd64 before arm64 still yields arm64.
//
// native (any Seatbelt/uidjail rung): darwin/arm64/v8, then darwin/amd64 iff
// HostRosetta. vm: linux/arm64/v8, then linux/amd64 iff GuestRosetta. See
// PlatformPolicy for why the vm rows have no live call site yet.
//
// An Override collapses the result to exactly that one platform, after checking
// it against the backend's runnable set — pinning darwin/amd64 on a host without
// Rosetta, or linux/amd64 on the native backend, is refused here rather than
// discovered at exec.
func Candidates(p PlatformPolicy) ([]Platform, error) {
	runnable, err := backendPlatforms(p)
	if err != nil {
		return nil, err
	}
	if p.Override == nil {
		return runnable, nil
	}
	want := p.Override.Normalize()
	if !containsPlatform(runnable, want) {
		return nil, &PlatformMismatchError{Wanted: []Platform{want}, Available: runnable}
	}
	return []Platform{want}, nil
}

// backendPlatforms maps the resolved sandbox backend to the platforms it can
// execute, honouring the Rosetta capability inputs.
func backendPlatforms(p PlatformPolicy) ([]Platform, error) {
	switch p.Backend {
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL:
		out := []Platform{platDarwinARM64}
		if p.HostRosetta {
			out = append(out, platDarwinAMD64)
		}
		return out, nil
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_VM:
		out := []Platform{platLinuxARM64}
		if p.GuestRosetta {
			out = append(out, platLinuxAMD64)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("sandbox backend %v has no image platform candidates: %w", p.Backend, ErrNoPlatformMatch)
	}
}

// containsPlatform reports whether want (already normalised) is in set (already
// normalised).
func containsPlatform(set []Platform, want Platform) bool {
	for _, p := range set {
		if p == want {
			return true
		}
	}
	return false
}

// normalizeAll returns a normalised copy of ps. Selectors normalise their inputs
// defensively so an externally-built candidate list cannot bypass the two-sided
// normalisation contract Normalize documents.
func normalizeAll(ps []Platform) []Platform {
	out := make([]Platform, len(ps))
	for i, p := range ps {
		out[i] = p.Normalize()
	}
	return out
}

// attestationRefType is the annotation buildx stamps on an attestation child of
// an index. Skipping it is DEFENCE IN DEPTH only — the load-bearing filter is
// the positive allowlist in selectableChild, which already excludes attestation
// manifests because their platform is unknown/unknown (or absent).
const attestationRefType = "vnd.docker.reference.type"

// SelectManifest picks the child manifest of idx to pull, given the candidate
// platforms in preference order. It is pure: no registry, no IO.
//
// Selection is a POSITIVE EXACT-MATCH ALLOWLIST, never "skip the attestations
// and take what is left". A child is selectable ONLY if all of:
//
//   - its media type is an image manifest type (never an index — see
//     ErrNestedIndex — and never an unknown type);
//   - it declares a platform. A child with NO platform field is UNKNOWN and is
//     skipped. go-containerregistry does the opposite: index.go substitutes its
//     package default (linux/amd64) for a nil child platform, which is how a
//     platform-less buildx attestation manifest gets returned AS THE IMAGE;
//   - it is not a referrer artifact (see selectableChild) and carries no
//     attestation annotation;
//   - its normalised platform EQUALS a candidate.
//
// The walk is candidate-major so the policy's preference order wins over the
// index's authoring order. On failure the returned error wraps
// ErrNoPlatformMatch (carrying the platforms the index does offer) or
// ErrNestedIndex.
func SelectManifest(idx *ggcrv1.IndexManifest, want []Platform) (ggcrv1.Descriptor, error) {
	if idx == nil {
		return ggcrv1.Descriptor{}, fmt.Errorf("image index is absent: %w", ErrNoPlatformMatch)
	}
	if len(want) == 0 {
		return ggcrv1.Descriptor{}, fmt.Errorf("no candidate platforms for this node: %w", ErrNoPlatformMatch)
	}
	wanted := normalizeAll(want)

	for _, w := range wanted {
		for _, d := range idx.Manifests {
			if !selectableChild(d) {
				continue
			}
			if platformFromGGCR(*d.Platform) == w {
				return d, nil
			}
		}
	}

	// A matching platform that is an index rather than an image is a distinct,
	// more legible failure than "no match": the platform IS on offer, k3sm just
	// refuses to traverse into it.
	for _, d := range idx.Manifests {
		if !d.MediaType.IsIndex() || d.Platform == nil {
			continue
		}
		if p := platformFromGGCR(*d.Platform); containsPlatform(wanted, p) {
			return ggcrv1.Descriptor{}, fmt.Errorf("child %s advertises %s: %w",
				quoteBounded(d.Digest.String(), maxDigestLen), p, ErrNestedIndex)
		}
	}

	return ggcrv1.Descriptor{}, &PlatformMismatchError{Wanted: wanted, Available: availablePlatforms(idx)}
}

// selectableChild is the positive allowlist SelectManifest applies to one index
// child. See SelectManifest for the rationale of each clause.
//
// The artifactType clause is narrow ON PURPOSE. Per the OCI 1.1 descriptor
// rules a plain image's artifactType defaults to its CONFIG media type — and
// go-containerregistry populates exactly that (partial.Descriptor) — so
// "artifactType is set" does NOT mean "this is a referrer artifact". Only a
// value that is not a known image-config media type (an SBOM, a signature, an
// attestation) disqualifies the child; treating every non-empty artifactType as
// disqualifying would reject every real multi-arch image.
func selectableChild(d ggcrv1.Descriptor) bool {
	if !d.MediaType.IsImage() {
		return false
	}
	if d.Platform == nil {
		return false
	}
	if d.ArtifactType != "" && !types.MediaType(d.ArtifactType).IsConfig() {
		return false
	}
	if _, ok := d.Annotations[attestationRefType]; ok {
		return false
	}
	return true
}

// platformFromGGCR converts a go-containerregistry platform to the normalised
// k3sm form. OSFeatures/Features are deliberately dropped: k3sm never REQUESTS
// one, and a manifest offering extra features is still ABI-compatible with the
// exact (os, arch, variant) that was asked for. os.version is NOT dropped — it
// pins a kernel ABI, so it stays part of the equality key.
func platformFromGGCR(p ggcrv1.Platform) Platform {
	return Platform{
		OS:           p.OS,
		Architecture: p.Architecture,
		Variant:      p.Variant,
		OSVersion:    p.OSVersion,
	}.Normalize()
}

// availablePlatforms lists, de-duplicated and in index order, the platforms idx
// actually offers — the "image provides ..." half of a mismatch error. Children
// with no platform contribute nothing (there is no name to report) and the
// unknown/unknown attestation markers are excluded so the message a human reads
// names only real platforms.
func availablePlatforms(idx *ggcrv1.IndexManifest) []Platform {
	seen := make(map[Platform]struct{}, len(idx.Manifests))
	out := make([]Platform, 0, len(idx.Manifests))
	for _, d := range idx.Manifests {
		if d.Platform == nil {
			continue
		}
		p := platformFromGGCR(*d.Platform)
		if p.isUnknown() {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// VerifyConfigPlatform checks an image's OWN CONFIG against the candidates and
// returns the platform it resolved to. It is pure: cfg is already fetched.
//
// This is the single verification used on BOTH pull paths — the child selected
// out of an index and the single (non-index) manifest — and it is what makes the
// decision trustworthy. An index descriptor's "platform" field is UNSIGNED
// parent metadata: it is not covered by the child digest, so an index may
// truthfully name a digest while lying about what that digest contains. Only the
// config blob, reached through the digest actually resolved, is covered.
// go-containerregistry performs NO os/arch check at all for a single
// schema2/OCI manifest (descriptor.go never consults its platform for an image
// media type), which is the second half of the silent-linux/amd64 bug.
//
// It costs no extra round trip on the success path: go-containerregistry
// memoises the config per remote image and Puller.Pull fetches it anyway.
func VerifyConfigPlatform(cfg *ggcrv1.ConfigFile, want []Platform) (Platform, error) {
	if cfg == nil {
		return Platform{}, fmt.Errorf("image config is absent: %w", ErrNoPlatformMatch)
	}
	if len(want) == 0 {
		return Platform{}, fmt.Errorf("no candidate platforms for this node: %w", ErrNoPlatformMatch)
	}
	got := Platform{
		OS:           cfg.OS,
		Architecture: cfg.Architecture,
		Variant:      cfg.Variant,
		OSVersion:    cfg.OSVersion,
	}.Normalize()
	// Decided verdict: a config that states no os or no architecture FAILS
	// CLOSED. "Unstated" must not read as "compatible" — treating an absent
	// declaration as a match is the exact shape of the bug being removed.
	if got.OS == "" || got.Architecture == "" {
		return Platform{}, fmt.Errorf("image config declares no platform (os=[%s] architecture=[%s]): %w",
			sanitizeToken(cfg.OS), sanitizeToken(cfg.Architecture), ErrNoPlatformMatch)
	}
	if !containsPlatform(normalizeAll(want), got) {
		return Platform{}, &PlatformMismatchError{Wanted: normalizeAll(want), Available: []Platform{got}}
	}
	return got, nil
}

// Message bounds for registry-controlled content. A mismatch error reaches
// slog, the Pod status message and kine, so its size and charset are capped at
// the render boundary rather than trusted.
const (
	// maxTokenLen bounds one os/architecture/variant token.
	maxTokenLen = 32
	// maxRenderedPlatforms bounds how many platforms one list names before it
	// collapses to a "(+N more)" tail.
	maxRenderedPlatforms = 8
	// maxErrorLen bounds the whole rendered message.
	maxErrorLen = 512
	// maxMediaTypeLen bounds a rendered media type.
	maxMediaTypeLen = 96
	// maxDigestLen bounds a rendered digest (algorithm:hex).
	maxDigestLen = 96
)

// PlatformMismatchError is the typed carrier for a fail-closed platform
// decision: what the node can run, and what the image actually offers. It
// Unwraps to ErrNoPlatformMatch so errors.Is keeps working, and it is the shape
// k3sm/pkg/provider reads to render a Pod status (m11-plan §M11.2-d0,
// m12-plan §M12.1-d3) without string-matching an error.
//
// Available is REGISTRY-CONTROLLED. Error() is therefore the sanitising choke
// point: every token is charset-checked (non-conforming tokens are rendered as a
// quoted, hex-escaped Go literal, so a newline or ANSI escape cannot forge a log
// line), the platform count is capped, and the whole message is length-capped.
type PlatformMismatchError struct {
	// Wanted is the candidate list, in preference order.
	Wanted []Platform
	// Available is what the image offers (attestation markers excluded).
	Available []Platform
}

// Error renders the mismatch, sanitised and bounded.
func (e *PlatformMismatchError) Error() string {
	msg := fmt.Sprintf("%s: want [%s], image provides [%s]",
		ErrNoPlatformMatch.Error(), renderPlatforms(e.Wanted), renderPlatforms(e.Available))
	if len(msg) > maxErrorLen {
		// Safe to cut on a byte boundary: every token was already sanitised to
		// ASCII (conforming, or a quoted escape), so truncation can neither
		// split a rune nor re-expose a control byte.
		msg = msg[:maxErrorLen] + " (truncated)"
	}
	return msg
}

// Unwrap ties the typed error to the sentinel.
func (e *PlatformMismatchError) Unwrap() error { return ErrNoPlatformMatch }

// renderPlatforms joins a platform list for a message, capped at
// maxRenderedPlatforms with a "(+N more)" tail.
func renderPlatforms(ps []Platform) string {
	if len(ps) == 0 {
		return "none"
	}
	shown := ps
	if len(shown) > maxRenderedPlatforms {
		shown = shown[:maxRenderedPlatforms]
	}
	parts := make([]string, 0, len(shown)+1)
	for _, p := range shown {
		parts = append(parts, p.String())
	}
	if len(ps) > len(shown) {
		parts = append(parts, fmt.Sprintf("(+%d more)", len(ps)-len(shown)))
	}
	return strings.Join(parts, ", ")
}

// sanitizeToken renders one registry-controlled token safely: a token that is
// short and inside the [A-Za-z0-9._-] allowlist passes through verbatim (so
// darwin/arm64/v8 reads naturally); anything else becomes a quoted Go literal,
// which escapes control characters (newline, ANSI ESC) as \n / \x1b and bounds
// what a hostile registry can inject into a log line or a Pod status.
func sanitizeToken(s string) string {
	if len(s) > maxTokenLen {
		return quoteBounded(s, maxTokenLen)
	}
	if !conformingToken(s) {
		return strconv.Quote(s)
	}
	return s
}

// conformingToken reports whether every byte of s is in the safe token charset.
func conformingToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// quoteBounded truncates s to max bytes and renders it as a quoted Go literal.
// strconv.Quote escapes an invalid UTF-8 byte left by the cut as \x.., so a
// mid-rune truncation cannot emit a malformed sequence.
func quoteBounded(s string, max int) string {
	if len(s) > max {
		return strconv.Quote(s[:max]) + "..."
	}
	return strconv.Quote(s)
}
