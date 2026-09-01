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

import (
	"context"
	"testing"
	"time"
)

// TestProbeGuestRosettaDoesNotRaise is a value-free smoke test of the real
// guest-Rosetta cgo entry point (mirrors TestVMBackendAvailableFalseWithoutEntitlement):
// it calls +[VZLinuxRosettaDirectoryShare availability] through the Obj-C shim from an
// ad-hoc-signed, zero-entitlement test binary and asserts only that the call RETURNS —
// i.e. it neither raises an uncaught NSException → SIGABRT nor requires an entitlement.
//
// It deliberately asserts NO value. The answer is host- and toolchain-dependent (a
// Rosetta-for-Linux-installed arm64 Mac says Available; the same Mac's amd64 Go
// toolchain hits the shim's arch guard and says NotSupported), so any value assertion
// would flip between machines and lanes. What must hold everywhere is that the state is
// one of the four defined ones and that Available() agrees with the Installed value.
func TestProbeGuestRosettaDoesNotRaise(t *testing.T) {
	// Reaching the line after the call is the actual assertion: the probe is safe.
	got := ProbeGuestRosetta()
	switch got {
	case GuestRosettaQueryFailed, GuestRosettaNotSupported, GuestRosettaNotInstalled, GuestRosettaInstalled:
	default:
		t.Fatalf("ProbeGuestRosetta() = %d, not one of the four defined states", int(got))
	}
	if got.Available() != (got == GuestRosettaInstalled) {
		t.Errorf("state %v: Available() = %v disagrees with the Installed value", got, got.Available())
	}
	if got.String() == "Unknown" {
		t.Errorf("state %v has no Reason token", int(got))
	}
}

// TestProbeHostRosettaDoesNotFail is the value-free smoke test of the real
// host-Rosetta probe: it must return a defined state promptly and without an error
// channel of any kind (the signature has none — a capability absence can never fail
// daemon startup). Like its guest sibling it asserts no value: this repo's dev Macs
// have Rosetta 2 installed while a clean machine does not, so a value assertion would
// be host-dependent.
func TestProbeHostRosettaDoesNotFail(t *testing.T) {
	start := time.Now()
	got := ProbeHostRosetta(context.Background())
	elapsed := time.Since(start)

	switch got {
	case HostRosettaAbsent, HostRosettaTranslationFailed, HostRosettaAvailable:
	default:
		t.Fatalf("ProbeHostRosetta() = %d, not one of the three defined states", int(got))
	}
	if got.Available() != (got == HostRosettaAvailable) {
		t.Errorf("state %v: Available() = %v disagrees with the Available value", got, got.Available())
	}
	if got.String() == "Unknown" {
		t.Errorf("state %v has no Reason token", int(got))
	}
	// The probe is time-boxed precisely because it runs during Runtime construction
	// under a launchd KeepAlive job that respawns on exit, not on a wedge. Allow
	// generous slack over the internal ceiling for a loaded test machine.
	if max := 10 * time.Second; elapsed > max {
		t.Errorf("ProbeHostRosetta took %v, want < %v (it must be time-boxed)", elapsed, max)
	}
}

// TestProbeHostRosettaHonorsCanceledContext asserts a caller's canceled ctx cannot make
// the probe hang or report available: the spawn leg is an exec.CommandContext, so a dead
// ctx kills it and the verdict degrades to TranslationFailed. On a host with no Rosetta
// the presence leg short-circuits first and the answer is Absent — either way it is
// never available, and that is the host-independent invariant worth pinning.
func TestProbeHostRosettaHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := ProbeHostRosetta(ctx); got.Available() {
		t.Errorf("ProbeHostRosetta(canceled ctx) = %v, must never report available", got)
	}
}

// TestRosettaStateTokensAreDistinct pins the machine Reason tokens: they are the strings
// an operator greps for in the daemon log and the values that reach the RuntimeCondition
// Reason, so two states must never share one.
func TestRosettaStateTokensAreDistinct(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		seen := map[string]HostRosettaState{}
		for _, s := range []HostRosettaState{HostRosettaAbsent, HostRosettaTranslationFailed, HostRosettaAvailable} {
			if prev, dup := seen[s.String()]; dup {
				t.Errorf("states %d and %d share the token %q", int(prev), int(s), s.String())
			}
			seen[s.String()] = s
		}
	})
	t.Run("guest", func(t *testing.T) {
		seen := map[string]GuestRosettaState{}
		for _, s := range []GuestRosettaState{GuestRosettaQueryFailed, GuestRosettaNotSupported, GuestRosettaNotInstalled, GuestRosettaInstalled} {
			if prev, dup := seen[s.String()]; dup {
				t.Errorf("states %d and %d share the token %q", int(prev), int(s), s.String())
			}
			seen[s.String()] = s
		}
	})
	t.Run("out-of-range-fails-closed", func(t *testing.T) {
		if HostRosettaState(99).Available() || GuestRosettaState(99).Available() {
			t.Error("an out-of-range state reported available; it must fail closed")
		}
	})
}
