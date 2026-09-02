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

// The pin half of the package: the in-code digest pin that names the guest
// boot artifacts. A pin is a code fact — bumping it is a source change,
// reviewed and released like any other; the ensure half (ensure.go) is the
// runtime fact that fetches, verifies and retains against it. Nothing in this
// package trusts a byte it has not hashed. The package doc lives in doc.go.
package guestartifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ActiveGuestKernel is the composite identity of the guest kernel this build
// boots: the upstream kernel version, then the hash of the k3sm kernel config it
// was built with.
//
// It is composite because the version alone does not identify a kernel. Two
// builds of v6.18.48 with different configs are different kernels with different
// guest capabilities, and a cache keyed on the version alone would happily serve
// one where the other was pinned. The config half therefore rides in the
// identity, not in a comment.
//
// The "-pending" suffix is the honest value for a config hash that has not been
// minted yet: the guest kernel build has not run, so no config hash exists to
// name. The pin entry below is correspondingly incomplete, Lookup refuses it
// with ErrPinIncomplete, and every vm pod fails closed until the build lands the
// real identity and the real digests together. A fabricated hash here would buy
// nothing but a cache key that matches no artifact anyone can fetch.
const ActiveGuestKernel = "v6.18.48-9c05f8f3b26c"

// ImageFileName and InitramfsFileName are the basenames the two artifacts of a
// pinned set are stored under, inside that set's content-addressed directory,
// and the basenames appended to GuestKernelPin.ReleaseURL to fetch them.
//
// They are constants rather than pin fields because they are part of the release
// layout, which the build script and this package agree on once, not part of any
// individual pin. "Image" is the arm64 kernel's own upstream name (arch/arm64
// emits Image, not bzImage), and keeping it verbatim means a human comparing the
// cache against a release tarball is comparing like with like.
const (
	ImageFileName     = "Image"
	InitramfsFileName = "k3sm-initramfs.cpio"
)

// GuestKernelPin is one pinned guest boot artifact set: the kernel, the
// initramfs, their digests, where they are published, and the kernel command
// line the pair was built to boot with.
//
// The cmdline is part of the pin, not on the pod, for the reason
// sandbox.GuestArtifacts states: it describes the artifacts (console device,
// panic behaviour, the init the initramfs actually contains), and a pod has no
// business choosing any of it.
type GuestKernelPin struct {
	// KernelVersion is the upstream Linux version the kernel was built from
	// (for example "v6.18.48"). It is the human half of the composite identity
	// this pin is keyed by; the machine half is the digests below.
	KernelVersion string
	// ImageSHA256 is the hex sha256 of the kernel image, lowercase, unprefixed.
	ImageSHA256 string
	// InitramfsSHA256 is the hex sha256 of the initramfs cpio, same encoding.
	InitramfsSHA256 string
	// ReleaseURL is the base url of the release the two artifacts are published
	// under, with no trailing slash. Each artifact's url is this plus "/" plus
	// its basename (ImageFileName / InitramfsFileName), so a release is one
	// value here rather than two that can drift apart.
	ReleaseURL string
	// Cmdline is the kernel command line the pair boots with.
	Cmdline string
}

// guestKernelPins maps a composite guest-kernel identity to its pinned artifact
// set. There is exactly one live entry — the one ActiveGuestKernel names.
//
// # Refreshing a pin (no download required)
//
// The digests are produced by the guest kernel build itself, so bumping a pin
// never means fetching anything by hand:
//
//  1. Run the guest build (hack/guest/build.sh). It prints the kernel version,
//     the config hash, and the sha256 of each artifact it produced.
//  2. Set ActiveGuestKernel to "<kernel version>-<config hash>" as printed.
//  3. Replace the one entry below: its key becomes ActiveGuestKernel, its
//     KernelVersion / ImageSHA256 / InitramfsSHA256 the printed values, its
//     ReleaseURL the release the artifacts were published to.
//  4. Run the package tests. The completeness walk
//     (pins_completeness_test.go) rejects a digest that is not exactly 64
//     lowercase hex characters, so a truncated or upper-cased paste fails in
//     review rather than at a node's first vm pod.
//
// A digest bump is a code change and therefore a full release. That is the point
// of pinning in source rather than in a fetched manifest: there is no path by
// which the bytes a node boots change without a reviewed commit and a signed
// binary carrying it. Nodes on the old binary keep booting the old set, which is
// exactly why ensure retains the previous one.
var guestKernelPins = map[string]GuestKernelPin{
	ActiveGuestKernel: {
		KernelVersion: "v6.18.48",
		// Minted 2026-09-02 from the v6.18.48-k3sm.4 release. The KERNEL is
		// byte-identical to k3sm.1/k3sm.2 — same unmodified upstream tarball,
		// same kernel.config, same build.sh, so ImageSHA256 and the config hash
		// 9c05f8f3b26c… (the -suffix of ActiveGuestKernel) are unchanged. Only
		// the initramfs moved: it carries the rebuilt k3sm-guest-init with the
		// interactive-terminal work — exec pty allocation from the container's
		// own devpts, container tty at spawn with a retained master for attach,
		// the byte-granular attach output source, capability advertisement
		// (tty-exec, attach), and the minimal allowlisted per-container /dev
		// (OCI default device set + private devpts + bounded shm; /dev/vsock is
		// never exposed to a container).
		//
		// Two clean builds (fresh GOCACHE, -trimpath -buildvcs=false
		// -ldflags=-buildid=) produced a byte-identical cpio, and BOTH digests
		// below were re-derived by unauthenticated download of the published
		// assets — never from the local build output, so a mismatch between what
		// was built and what was uploaded cannot hide here.
		ImageSHA256:     "d50508b08205453e5f5f710978743449dc4fafe957aa8694e6da8e5780d93308",
		InitramfsSHA256: "9368e922f0417942d8c0d4aacca1ec4282e9631e9c28be58c020414ee03d197f",
		ReleaseURL:      "https://github.com/k3sm-io/linux-guest/releases/download/v6.18.48-k3sm.4",
		Cmdline:         "console=hvc0 reboot=k panic=1",
	},
}

// ErrUnknownVersion reports that no pin is declared for the requested guest
// kernel identity. Compare with errors.Is.
var ErrUnknownVersion = errors.New("guestartifacts: no pin is declared for this guest kernel version")

// ErrPinIncomplete reports that a declared pin cannot be used as shipped —
// a digest is missing or malformed, or the release url is absent. It is the
// fail-closed verdict a build carrying an unminted pin returns, and callers must
// treat it exactly as they treat any other ensure failure: the vm capability is
// off on this node, not the daemon is broken. Compare with errors.Is.
var ErrPinIncomplete = errors.New("guestartifacts: the pin for this guest kernel version is incomplete")

// ErrDigestMismatch reports that bytes on disk or off the wire did not hash to
// the digest the pin names. Compare with errors.Is.
var ErrDigestMismatch = errors.New("guestartifacts: artifact digest does not match its pin")

// IsValidDigest reports whether s is a well-formed artifact digest: exactly 64
// lowercase hexadecimal characters, with no "sha256:" prefix.
//
// The encoding is pinned this tightly because a digest is compared as a string
// against the output of hex.EncodeToString, which is always lowercase and always
// unprefixed. Accepting "SHA256:ABC…" and normalising it would make the
// comparison depend on a normaliser instead of on the bytes, and a normaliser is
// one more thing that can be wrong in the direction of accepting too much.
func IsValidDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// Complete reports whether p carries both artifact digests.
//
// It answers exactly one question — "has the build minted this pin yet?" — and
// deliberately not "is this pin usable?". Well-formedness of the digests and the
// presence of a release url are Lookup's to enforce, so that a pin which is
// merely unminted (the shipped state before the guest build has run) is
// distinguishable in code from one that is minted wrong.
func (p GuestKernelPin) Complete() bool {
	return p.ImageSHA256 != "" && p.InitramfsSHA256 != ""
}

// SetDigest is the content-addressed identity of the artifact pair: the hex
// sha256 over both artifact digests.
//
// The cache is keyed by the pair rather than by the kernel alone because the two
// artifacts are only ever valid together — a kernel from one build and an
// initramfs from another is a boot failure with no single owner. Deriving the
// key means a set directory is self-verifying: re-hash the two files it holds,
// recompute this value, and a directory whose name still matches is a set no
// byte of which has moved. That is what lets ensure re-verify a retained set,
// for which it holds no pin at all.
func (p GuestKernelPin) SetDigest() string {
	h := sha256.New()
	// Field-labelled and newline-terminated so no concatenation of one field's
	// tail with the next field's head can produce another pin's input.
	fmt.Fprintf(h, "kernel:%s\ninitramfs:%s\n", p.ImageSHA256, p.InitramfsSHA256)
	return hex.EncodeToString(h.Sum(nil))
}

// Lookup returns the pin declared for the given composite guest kernel identity.
//
// It is the only way to obtain a pin, so every fail-closed rule lives here once:
//
//   - an empty or undeclared version returns ErrUnknownVersion;
//   - a declared pin the build has not minted returns ErrPinIncomplete;
//   - a declared pin whose digests are malformed, or which names no release,
//     also returns ErrPinIncomplete — from a caller's position "unminted" and
//     "minted wrong" are the same event (this node cannot boot a guest), and
//     collapsing them keeps the degradation path single. The wrapped message
//     distinguishes them for whoever reads the log.
func Lookup(version string) (GuestKernelPin, error) {
	return lookupIn(guestKernelPins, version)
}

// lookupIn is Lookup against an explicit table, so the rules above are testable
// against complete, incomplete and malformed pins while the shipped table
// legitimately holds only one unminted entry.
func lookupIn(pins map[string]GuestKernelPin, version string) (GuestKernelPin, error) {
	if version == "" {
		return GuestKernelPin{}, fmt.Errorf("look up the guest kernel pin: the version is empty: %w", ErrUnknownVersion)
	}
	p, ok := pins[version]
	if !ok {
		return GuestKernelPin{}, fmt.Errorf("look up the guest kernel pin for %s: %w", version, ErrUnknownVersion)
	}
	if err := validatePin(version, p); err != nil {
		return GuestKernelPin{}, err
	}
	return p, nil
}

// validatePin rejects a declared pin that cannot be fetched or verified as
// written.
func validatePin(version string, p GuestKernelPin) error {
	if !p.Complete() {
		return fmt.Errorf("the guest kernel pin for %s has not been minted (its artifact digests are empty): %w", version, ErrPinIncomplete)
	}
	for _, d := range []struct{ field, digest string }{
		{"ImageSHA256", p.ImageSHA256},
		{"InitramfsSHA256", p.InitramfsSHA256},
	} {
		if !IsValidDigest(d.digest) {
			return fmt.Errorf("the guest kernel pin for %s carries a malformed %s %q (want 64 lowercase hex characters): %w", version, d.field, d.digest, ErrPinIncomplete)
		}
	}
	if p.ReleaseURL == "" {
		return fmt.Errorf("the guest kernel pin for %s names no release url, so its artifacts cannot be fetched: %w", version, ErrPinIncomplete)
	}
	return nil
}
