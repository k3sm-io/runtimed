package sandbox

import (
	"errors"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestLadderDropsUIDJailWhenNotRoot is deliverable #4 (ladder half): the uidjail
// rung needs root (it must setuid/chown to a per-pod identity), so the not-root
// ladder MUST exclude it — leaving only rungs that confine without per-pod root
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

// TestSelectBackendFailsClosed is deliverable #4 (selection half): the runtime
// degrades to a STRONGER rung, never a weaker one, and NEVER to "unconfined".
//   - Seatbelt available => seatbelt (the default rung).
//   - Seatbelt tripped (missing SPI / canary) + vm available => vm, NOT unconfined.
//   - Seatbelt tripped + no vm => ErrNoIsolation (refuse to run).
//
// In every case the result is either a confining rung or an error — the selector
// must never return UNSPECIFIED (== unconfined) with a nil error.
func TestSelectBackendFailsClosed(t *testing.T) {
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
			got, err := SelectBackend(tc.isRoot, tc.seatbelt, tc.vm)
			if tc.wantErr {
				if !errors.Is(err, ErrNoIsolation) {
					t.Fatalf("want ErrNoIsolation, got rung=%v err=%v", got, err)
				}
				// A refusal must NOT smuggle a usable-looking rung past the caller.
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
			// The cardinal rule: a non-error selection is NEVER unconfined.
			if got == runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
				t.Error("selected an UNSPECIFIED (unconfined) rung with no error — must never happen")
			}
			if tc.notExpected != runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED && got == tc.notExpected {
				t.Errorf("degraded to the weaker rung %v; must escalate, not weaken", got)
			}
		})
	}
}
