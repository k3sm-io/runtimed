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
// errors.Is, never by string (GO-STANDARDS §Errors). Its INTENDED consumer is
// k3sm/pkg/provider, which will read it across the k3sm -> runtimed edge to
// render a Pod status; today that repo references neither this sentinel nor
// PlatformMismatchError, so changing their shape is a runtimed-local change,
// not a cross-repo break.
//
// The deliberate divergence from upstream Kubernetes (registered
// divergent-by-design): containerd pulls a mismatched
// single-manifest image and the container dies at exec with an opaque
// exec-format error; k3sm refuses at PULL with a legible error naming the
// platforms the image actually offers.
var ErrNoPlatformMatch = errors.New("no image manifest matches a runnable platform")

// ErrNestedIndex is the decided verdict for an index whose selected child is
// itself an index (index-of-index). k3sm REFUSES it rather than recursing: a
// recursive traversal is an unbounded, registry-controlled fan-out, and no
// registry in the k3sm target set publishes one. It is deliberately NOT wrapped
// around ErrNoPlatformMatch — the platform may well be present, so reporting "no
// match" would misdescribe the failure. Callers that mean "this image cannot run
// here" must test both sentinels, which is what IsTerminalPlatformError is for.
var ErrNestedIndex = errors.New("image index child is itself an index (nested index traversal is refused)")

// IsTerminalPlatformError reports whether err is a PERMANENT k3sm image-platform
// refusal: no manifest matches a runnable platform (ErrNoPlatformMatch) or the
// matching child is itself an index (ErrNestedIndex).
//
// The two sentinels stay distinct so each message describes its own failure, but
// they share one property a consumer must act on: retrying is futile, because
// nothing about the node or the image will change. This predicate is that shared
// verdict, so a caller cannot half-implement it — testing only the documented
// ErrNoPlatformMatch (the natural reading of "this image cannot run here") would
// park a pod in an infinite ImagePullBackOff over an index-of-index.
func IsTerminalPlatformError(err error) bool {
	return errors.Is(err, ErrNoPlatformMatch) || errors.Is(err, ErrNestedIndex)
}

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

// boundTokens returns p with every token capped at maxTokenLen bytes. It is
// applied when a registry-controlled platform is RETAINED (in an error), never
// on the matching path: a token longer than any candidate can never match one,
// so nothing is lost, and the cut is safe because the render boundary
// (sanitizeToken) escapes whatever byte it lands on.
func (p Platform) boundTokens() Platform {
	return Platform{
		OS:           boundToken(p.OS),
		Architecture: boundToken(p.Architecture),
		Variant:      boundToken(p.Variant),
		OSVersion:    boundToken(p.OSVersion),
	}
}

// boundToken caps one token's LENGTH. Charset is not its business — that is the
// render boundary's job (sanitizeToken), which still sees an over-long token as
// over-long because the cut is one byte past the cap.
func boundToken(s string) string {
	if len(s) > maxTokenLen {
		return s[:maxTokenLen+1]
	}
	return s
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
// LIVE CALL SITES (be honest about the green test table): BOTH rungs have one.
// Runtime.resolveBinary threads the backend its pod resolved (pod.backend) on the
// host-process spine, and Runtime.resolveVMContainers threads the vm rung when it
// pulls each container for the image config the guest-side merge needs
// (pkg/runtime/vmcontainers.go). GuestRosetta is still passed FALSE by both, so
// the linux/amd64 candidate row remains test-only; and a linux pull today feeds
// the merge, not a composed guest rootfs (the rootfs builder is a separate
// deliverable), so a green table here is still NOT evidence that vm image
// selection works end to end.
//
// HostRosetta / GuestRosetta are capability INPUTS, not probes: this file stays
// GOOS-agnostic and cgo-free. The probes that answer them SHIPPED with B103
// (sandbox.ProbeHostRosetta / sandbox.ProbeGuestRosetta, advertised as the
// RosettaHostAvailable / RosettaGuestAvailable RuntimeConditions), but the live pull
// call site still passes FALSE on purpose — consuming them waits on B105, the
// Seatbelt x Rosetta spawn proof (an unsigned x86_64 Mach-O is not AMFI-killed the
// way an unsigned arm64 one is, so selecting amd64 payloads would quietly weaken the
// signature policy's kernel backstop). See pkg/runtime/pod.go's pullPolicy. Until
// then a darwin/amd64-only image is refused with a legible error rather than
// silently mis-selected.
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
//   - it carries a non-empty digest (see selectableChild: an absent digest key
//     leaves the zero v1.Hash, which is otherwise selectable);
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

	available, omitted := availablePlatforms(idx)
	return ggcrv1.Descriptor{}, &PlatformMismatchError{Wanted: wanted, Available: available, Omitted: omitted}
}

// selectableChild is the positive allowlist SelectManifest applies to one index
// child. See SelectManifest for the rationale of each clause.
//
// The digest clause closes a first-match-wins shadowing move: an ABSENT digest
// key never invokes v1.Hash.UnmarshalJSON (an absent JSON key is not decoded at
// all), so the child keeps the ZERO v1.Hash — which renders as ":" and is
// otherwise perfectly selectable. A hostile index could then place a digest-less
// darwin/arm64 child AHEAD of the real one and deterministically shadow it. The
// end state was already fail-closed (go-containerregistry refuses the malformed
// reference downstream), but this allowlist is POSITIVE and the OCI spec makes
// digest REQUIRED, so the child is rejected here rather than downstream.
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
	if d.Digest.Algorithm == "" || d.Digest.Hex == "" {
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
// actually offers — the "image provides ..." half of a mismatch error — plus the
// number of further platform-bearing children it deliberately did NOT retain.
// Children with no platform contribute nothing (there is no name to report) and
// the unknown/unknown attestation markers are excluded so the message a human
// reads names only real platforms.
//
// The cap is applied at COLLECTION, not at rendering: maxRenderedPlatforms
// bounds what is PRINTED, but without this the returned error would RETAIN one
// Platform (and its map entry) per index child, over an index bounded only by
// go-containerregistry's 100 MiB manifest limit — hundreds of MB of hostile
// content held alive by one error value. Each retained token is length-bounded
// for the same reason; charset sanitising still happens once, at the render
// boundary (Platform.String), so this is a memory bound and not a second
// sanitiser.
//
// Beyond the cap the children are no longer de-duplicated (de-duplicating them
// needs exactly the unbounded map this cap removes), so the returned count is an
// UPPER BOUND on the platforms not shown, not an exact distinct count.
func availablePlatforms(idx *ggcrv1.IndexManifest) (out []Platform, omitted int) {
	seen := make(map[Platform]struct{}, maxCollectedPlatforms)
	out = make([]Platform, 0, maxCollectedPlatforms)
	for _, d := range idx.Manifests {
		if d.Platform == nil {
			continue
		}
		p := platformFromGGCR(*d.Platform).boundTokens()
		if p.isUnknown() {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		if len(out) == maxCollectedPlatforms {
			omitted++
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, omitted
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
	// maxCollectedPlatforms bounds how many platforms a mismatch error RETAINS
	// (see availablePlatforms). It matches maxRenderedPlatforms because holding
	// more than is ever printed only feeds a hostile index.
	maxCollectedPlatforms = maxRenderedPlatforms
	// maxErrorLen bounds the whole rendered message.
	maxErrorLen = 512
	// maxMediaTypeLen bounds a rendered media type.
	maxMediaTypeLen = 96
	// maxDigestLen bounds a rendered digest (algorithm:hex).
	maxDigestLen = 96
	// maxWrappedErrLen bounds how much of a THIRD-PARTY error message (a
	// go-containerregistry parse/transport error, which formats registry-supplied
	// bytes into itself) k3sm re-renders. It is smaller than maxErrorLen because
	// the quoted rendering can expand up to 4x, so this is the effective ~1 KiB
	// ceiling on one embedded foreign message.
	maxWrappedErrLen = 256
)

// truncatedSuffix marks a message the whole-message cap cut short.
const truncatedSuffix = " (truncated)"

// PlatformMismatchError is the typed carrier for a fail-closed platform
// decision: what the node can run, and what the image actually offers. It
// Unwraps to ErrNoPlatformMatch so errors.Is keeps working, and it is the shape
// k3sm/pkg/provider is INTENDED to read so it can render a Pod status without
// string-matching an error. No such consumer exists yet (grep k3sm: zero
// references), so today this type is exercised only from within runtimed.
//
// Available is REGISTRY-CONTROLLED. Error() is therefore the sanitising choke
// point: every token is charset-checked (non-conforming tokens are rendered as a
// quoted, hex-escaped Go literal, so a newline or ANSI escape cannot forge a log
// line), the platform count is capped, and the whole message is length-capped.
type PlatformMismatchError struct {
	// Wanted is the candidate list, in preference order.
	Wanted []Platform
	// Available is what the image offers (attestation markers excluded), CAPPED
	// at maxCollectedPlatforms entries with every token length-bounded, so one
	// error can never retain a hostile index's whole manifest list.
	Available []Platform
	// Omitted is how many further platform-bearing children the image offered
	// beyond Available. Past the cap the children are no longer de-duplicated,
	// so it is an UPPER BOUND on the platforms not named, not an exact distinct
	// count (see availablePlatforms).
	Omitted int
}

// Error renders the mismatch, sanitised and bounded.
func (e *PlatformMismatchError) Error() string {
	msg := fmt.Sprintf("%s: want [%s], image provides [%s]",
		ErrNoPlatformMatch.Error(), renderPlatforms(e.Wanted, 0), renderPlatforms(e.Available, e.Omitted))
	if len(msg) > maxErrorLen {
		// Safe to cut on a byte boundary: every token was already sanitised to
		// ASCII — conforming ([A-Za-z0-9._-]), or a strconv.QuoteToASCII literal
		// whose non-ASCII runes and invalid bytes are \u/\x escapes — so
		// truncation can neither split a rune nor re-expose a control byte. The
		// cut therefore leaves a string that is still valid UTF-8, which is what
		// keeps the google.rpc.Status carrying it marshalable (proto3 strings
		// reject invalid UTF-8).
		msg = msg[:maxErrorLen] + truncatedSuffix
	}
	return msg
}

// Unwrap ties the typed error to the sentinel.
func (e *PlatformMismatchError) Unwrap() error { return ErrNoPlatformMatch }

// renderPlatforms joins a platform list for a message, capped at
// maxRenderedPlatforms with a "(+N more)" tail. omitted is what the COLLECTION
// cap already dropped (availablePlatforms), so the tail still tells a human how
// much the image offered beyond what is named.
func renderPlatforms(ps []Platform, omitted int) string {
	if len(ps) == 0 && omitted == 0 {
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
	if extra := len(ps) - len(shown) + omitted; extra > 0 {
		parts = append(parts, fmt.Sprintf("(+%d more)", extra))
	}
	return strings.Join(parts, ", ")
}

// sanitizeToken renders one registry-controlled token safely: a token that is
// short and inside the [A-Za-z0-9._-] allowlist passes through verbatim (so
// darwin/arm64/v8 reads naturally); anything else becomes a quoted ASCII Go
// literal, which escapes control characters (newline, ANSI ESC) as \n / \x1b and
// bounds what a hostile registry can inject into a log line or a Pod status.
//
// QuoteToASCII, never Quote: Quote escapes only NON-PRINTABLE runes, so a
// printable non-ASCII token (é, あ) survives it as raw multi-byte UTF-8. That
// would make the whole-message byte cut in PlatformMismatchError.Error able to
// split a rune, and the resulting invalid UTF-8 makes proto.Marshal reject the
// google.rpc.Status the failure travels in — a registry-chosen way to suppress
// the typed failure. ASCII out means every downstream byte boundary is safe.
func sanitizeToken(s string) string {
	if len(s) > maxTokenLen {
		return quoteBounded(s, maxTokenLen)
	}
	if !conformingToken(s) {
		return strconv.QuoteToASCII(s)
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

// boundErr wraps a THIRD-PARTY error so embedding it in a k3sm error message
// cannot echo unbounded registry content. The chain is preserved (Unwrap), so
// errors.Is/As still see the original cause; only the RENDERING is capped and
// escaped to ASCII.
//
// It is needed because go-containerregistry formats registry-supplied bytes into
// its own error strings — v1.Hash's parser prints the offending digest verbatim
// ("unsupported hash: %q"), and transport.Error carries up to 64 KiB of the
// registry's response body — while the manifest those bytes came from is capped
// only by ggcr's 100 MiB limit. Everything this package returns reaches slog,
// the Pod status message and kine, so a foreign message is DATA to be quoted,
// never a message to be adopted.
func boundErr(err error) error { return &boundedError{err: err} }

// boundedError is boundErr's carrier.
type boundedError struct{ err error }

// Error renders the wrapped message capped at maxWrappedErrLen and ASCII-escaped.
func (e *boundedError) Error() string { return quoteBounded(e.err.Error(), maxWrappedErrLen) }

// Unwrap keeps the original cause visible to errors.Is / errors.As.
func (e *boundedError) Unwrap() error { return e.err }

// quoteBounded truncates s to max bytes and renders it as a quoted ASCII Go
// literal. QuoteToASCII escapes every non-ASCII rune as \u.... and any invalid
// UTF-8 byte left by the cut as \x.., so the result is pure ASCII: a mid-rune
// truncation cannot emit a malformed sequence, and no later byte-boundary cut of
// a message built from it can create one either (see sanitizeToken).
func quoteBounded(s string, max int) string {
	if len(s) > max {
		return strconv.QuoteToASCII(s[:max]) + "..."
	}
	return strconv.QuoteToASCII(s)
}
