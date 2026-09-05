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

package sandbox

import "context"

// The two Rosetta capability probes — the GOOS/cgo-agnostic contract.
//
// They are two independent capabilities that happen to share a brand name, and
// conflating them is the bug this file exists to prevent:
//
//   - HOST Rosetta (Rosetta 2) translates darwin/amd64 MACH-O payloads for the
//     native host-process (Seatbelt) spine. Probed without cgo: an unforgeable
//     on-disk presence check plus a real translated exec.
//   - GUEST Rosetta (Rosetta for Linux) translates linux/amd64 ELF payloads inside
//     a Virtualization.framework Linux guest. Probed through the Obj-C shim's
//     +[VZLinuxRosettaDirectoryShare availability] class property.
//
// Both are advertised as additive RuntimeConditions and neither is wired into the
// image-pull platform policy: see pkg/runtime/pod.go's pullPolicy, which documents
// why selecting an amd64 payload waits on the Seatbelt x Rosetta spawn proof.
//
// Both probes DEGRADE: they return a state, never an error, so a capability
// absence can never fail daemon startup.

// HostRosettaState is the verdict of the HOST-Rosetta (Rosetta 2, darwin/amd64
// Mach-O) probe. It is 3-valued on purpose: "the translation runtime is not
// installed" and "it is installed but a translated exec did not run" are different
// operator situations, and arch(1) collapses EBADARCH and every other failure into
// one generic non-zero exit — so the distinction has to be made by the probe's
// structure (presence leg vs spawn leg), not by reading a status code.
type HostRosettaState int

const (
	// HostRosettaAbsent — the Rosetta 2 runtime payload is not installed on this
	// host (the presence leg failed). It is the zero value, so an unset state
	// fails closed.
	HostRosettaAbsent HostRosettaState = iota
	// HostRosettaTranslationFailed — the runtime payload IS present but a
	// translated exec did not succeed (non-zero exit, spawn error, or the probe
	// timeout). Fails closed like HostRosettaAbsent, with a distinct Reason.
	HostRosettaTranslationFailed
	// HostRosettaAvailable — the payload is present and a translated exec
	// succeeded. The only state that reports available.
	HostRosettaAvailable
)

// String returns the machine Reason token for s (also its slog value).
func (s HostRosettaState) String() string {
	switch s {
	case HostRosettaAbsent:
		return "NotInstalled"
	case HostRosettaTranslationFailed:
		return "TranslationFailed"
	case HostRosettaAvailable:
		return "Available"
	default:
		return "Unknown"
	}
}

// Available reports whether s is the one genuinely-usable state. Every other
// state — including an out-of-range one — is unavailable (fail closed).
//
// This is the one home of the host fail-closed rule, and it SHIPS: pkg/runtime's
// evalHostRosetta calls it to decide the RuntimeCondition status instead of
// re-deriving the comparison, so the predicate the tests below pin is the same one
// the daemon advertises.
func (s HostRosettaState) Available() bool { return s == HostRosettaAvailable }

// GuestRosettaState is the verdict of the GUEST-Rosetta (Rosetta for Linux,
// linux/amd64 ELF) probe. Its values are pinned to Apple's
// VZLinuxRosettaAvailability enum, plus GuestRosettaQueryFailed for "the probe
// itself could not answer" — the raw enum is preserved rather than collapsed to a
// bool because each state gets its own machine Reason on the RuntimeCondition.
type GuestRosettaState int

const (
	// GuestRosettaQueryFailed — the probe could not answer: an Obj-C exception, an
	// enum value newer than the shim, or a build lane with no Virtualization
	// framework at all. Fails closed.
	GuestRosettaQueryFailed GuestRosettaState = -1
	// GuestRosettaNotSupported — VZLinuxRosettaAvailabilityNotSupported: this host
	// cannot do Rosetta for Linux (also every non-arm64 lane's answer — Rosetta for
	// Linux is Apple-Silicon-only).
	GuestRosettaNotSupported GuestRosettaState = 0
	// GuestRosettaNotInstalled — VZLinuxRosettaAvailabilityNotInstalled: supported,
	// but the payload is not installed. runtimed never installs it: the SDK's
	// install entry points prompt the user, which a GUI-less daemon cannot do.
	GuestRosettaNotInstalled GuestRosettaState = 1
	// GuestRosettaInstalled — VZLinuxRosettaAvailabilityInstalled: supported and
	// installed. The only state that reports available.
	GuestRosettaInstalled GuestRosettaState = 2
)

// String returns the machine Reason token for s (also its slog value).
func (s GuestRosettaState) String() string {
	switch s {
	case GuestRosettaQueryFailed:
		return "QueryFailed"
	case GuestRosettaNotSupported:
		return "NotSupported"
	case GuestRosettaNotInstalled:
		return "NotInstalled"
	case GuestRosettaInstalled:
		return "Available"
	default:
		return "Unknown"
	}
}

// Available reports whether s is the one genuinely-usable state. Every other
// state — including an out-of-range one — is unavailable (fail closed).
//
// Like its host sibling it is the one home of the guest fail-closed rule and it
// SHIPS: pkg/runtime's evalGuestRosetta calls it rather than re-deriving the
// comparison.
func (s GuestRosettaState) Available() bool { return s == GuestRosettaInstalled }

// ProbeHostRosetta reports whether this host can translate darwin/amd64 Mach-O
// payloads (Rosetta 2). It composes two legs with and — an unforgeable presence
// check, then a real translated exec GATED BEHIND it so a non-Rosetta host forks
// nothing — and is described in full at hostRosettaProbe (rosetta_host_darwin.go).
//
// It never returns an error: the daemon must not fail to start because a host
// capability is absent. Off darwin it is HostRosettaAbsent.
//
// ctx bounds the probe; the spawn leg additionally imposes its own short internal
// timeout, so a caller passing a background context still cannot wedge.
func ProbeHostRosetta(ctx context.Context) HostRosettaState {
	return hostRosettaProbe(ctx)
}

// ProbeGuestRosetta reports whether a Virtualization.framework Linux guest on this
// host could translate linux/amd64 ELF payloads (Rosetta for Linux), by reading
// +[VZLinuxRosettaDirectoryShare availability] through the Obj-C shim
// (vm_darwin.m). Off the darwin+cgo lane it is GuestRosettaQueryFailed (vm_other.go).
//
// It takes no context on purpose: the underlying call is a synchronous
// framework-property read with no IO, RPC or blocking step to cancel, so a ctx
// parameter would be decoration. (Its sibling ProbeHostRosetta spawns a process and
// therefore does take one.)
//
// It never returns an error, and it never attempts an INSTALL — the SDK's install
// entry points prompt the user.
func ProbeGuestRosetta() GuestRosettaState {
	return vzRosettaAvailability()
}
