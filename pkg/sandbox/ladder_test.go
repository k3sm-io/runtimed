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
	"errors"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestLadderDropsUIDJailWhenNotRoot is deliverable #4 (ladder half): the uidjail
// rung needs root (it must setuid/chown to a per-pod identity), so the not-root
// ladder must exclude it — leaving only rungs that confine without per-pod root
// (seatbelt, vm). The root ladder keeps uidjail as a pinnable rung.
func TestLadderDropsUIDJailWhenNotRoot(t *testing.T) {
	notRoot := Ladder(false)
	for _, r := range notRoot {
		if r == runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL {
			t.Fatalf("not-root ladder must NOT contain uidjail (needs root): %v", notRoot)
		}
	}
	if len(notRoot) == 0 {
		t.Fatal("not-root ladder must still offer a confining rung")
	}

	var hasUIDJail bool
	for _, r := range Ladder(true) {
		if r == runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL {
			hasUIDJail = true
		}
	}
	if !hasUIDJail {
		t.Error("root ladder should keep uidjail as a pinnable rung")
	}
}

// TestSelectBackendUnspecifiedUsesLadder is the host-process default path (M5.1):
// a pod with no explicit backend — UNSPECIFIED, what the provider stamps for a pod
// without a vm RuntimeClass — walks the host-OS-gated ladder. It degrades to a
// stronger rung, never a weaker one, and never to "unconfined":
//   - Seatbelt available => seatbelt (the default rung).
//   - Seatbelt tripped (missing SPI / canary) + vm available => vm, not unconfined.
//   - Seatbelt tripped + no vm => ErrNoIsolation (refuse to run).
//
// In every case the result is either a confining rung or an error — the selector
// must never return UNSPECIFIED (== unconfined) with a nil error. This is the
// fails-before/passes-after seam for the UNSPECIFIED half: the old SelectBackend
// ignored the request entirely; this asserts the ladder is reached only for an
// UNSPECIFIED request and still degrades up, never down.
func TestSelectBackendUnspecifiedUsesLadder(t *testing.T) {
	cases := []struct {
		name        string
		isRoot      bool
		seatbelt    bool
		vm          bool
		want        runtimev1.SandboxBackend
		wantErr     bool
		notExpected runtimev1.SandboxBackend
	}{
		{
			name:     "seatbelt-available",
			seatbelt: true,
			want:     runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		},
		{
			name:        "missing-spi-not-root-degrades-to-vm",
			isRoot:      false,
			seatbelt:    false,
			vm:          true,
			want:        runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
			notExpected: runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL,
		},
		{
			name:     "missing-spi-no-vm-refuses",
			seatbelt: false,
			vm:       false,
			wantErr:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectBackend(runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED, tc.isRoot, tc.seatbelt, tc.vm)
			if tc.wantErr {
				if !errors.Is(err, ErrNoIsolation) {
					t.Fatalf("want ErrNoIsolation, got rung=%v err=%v", got, err)
				}
				// A refusal must not smuggle a usable-looking rung past the caller.
				if got != runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
					t.Errorf("refusal returned rung %v, want UNSPECIFIED", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("rung = %v, want %v", got, tc.want)
			}
			// The cardinal rule: a non-error selection is never unconfined.
			if got == runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
				t.Error("selected an UNSPECIFIED (unconfined) rung with no error — must never happen")
			}
			if tc.notExpected != runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED && got == tc.notExpected {
				t.Errorf("degraded to the weaker rung %v; must escalate, not weaken", got)
			}
		})
	}
}

// TestSelectBackendVMRequestedUnavailableFailsClosed is the M5.1 safety fix: a pod
// that requested the vm backend (a Linux image / untrusted tenancy) on a host
// where the vm backend is UNAVAILABLE must be refused with ErrBackendUnavailable
// — it must never silently downgrade to Seatbelt (the weaker rung, on which a
// Linux image cannot even exec). The presence of Seatbelt must not rescue a vm
// request. Fails-before: the old SelectBackend ignored the request and returned
// SEATBELT_INPROC. Passes-after: a typed fail-closed error and no usable rung.
func TestSelectBackendVMRequestedUnavailableFailsClosed(t *testing.T) {
	// Seatbelt's availability must not change the verdict for a vm request.
	for _, seatbelt := range []bool{true, false} {
		for _, isRoot := range []bool{true, false} {
			got, err := SelectBackend(runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, isRoot, seatbelt, false /* vm UNavailable */)
			if !errors.Is(err, ErrBackendUnavailable) {
				t.Fatalf("seatbelt=%v isRoot=%v: want ErrBackendUnavailable, got rung=%v err=%v", seatbelt, isRoot, got, err)
			}
			if got == runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC ||
				got == runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC {
				t.Errorf("seatbelt=%v isRoot=%v: vm request DOWNGRADED to seatbelt %v — must fail closed", seatbelt, isRoot, got)
			}
			if got != runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
				t.Errorf("seatbelt=%v isRoot=%v: refusal returned rung %v, want UNSPECIFIED", seatbelt, isRoot, got)
			}
		}
	}
}

// TestSelectBackendVMRequestedAvailable: a vm-requested pod on a vm-capable host
// gets the vm rung — no downgrade, no error — regardless of whether Seatbelt is
// also available (the explicit request wins).
func TestSelectBackendVMRequestedAvailable(t *testing.T) {
	for _, seatbelt := range []bool{true, false} {
		got, err := SelectBackend(runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, false, seatbelt, true /* vm available */)
		if err != nil {
			t.Fatalf("seatbelt=%v: unexpected error: %v", seatbelt, err)
		}
		if got != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
			t.Errorf("seatbelt=%v: rung = %v, want VM", seatbelt, got)
		}
	}
}

// TestSelectBackendExplicitSeatbeltRequiresIt: an explicit Seatbelt pin is honored
// when available and fails closed (ErrBackendUnavailable) when not — only an
// UNSPECIFIED request runs the degrade-capable ladder, so an explicit pin is never
// silently swapped for another rung.
func TestSelectBackendExplicitSeatbeltRequiresIt(t *testing.T) {
	got, err := SelectBackend(runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, false, true, false)
	if err != nil || got != runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC {
		t.Fatalf("seatbelt available: got rung=%v err=%v, want SEATBELT_INPROC", got, err)
	}
	// Seatbelt unavailable but vm available: an explicit seatbelt pin must not be
	// rescued by the vm rung — it fails closed (the ladder degrade is UNSPECIFIED-only).
	got, err = SelectBackend(runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, false, false, true)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("seatbelt unavailable: want ErrBackendUnavailable, got rung=%v err=%v", got, err)
	}
}
