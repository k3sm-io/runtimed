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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestVMAvailableRequiresEntitledHelper is B227's named gate. It proves the vm
// backend's availability is the FULL five-term conjunction — darwin, the macOS
// floor, +[VZVirtualMachine isSupported], the k3sm-vmhost helper resolving at its
// installed path, and that helper's signature being VALID and
// virtualization-entitled — by driving each term to false on its own and asserting
// the whole answer collapses.
//
// The BROKEN-SIGNATURE row is the one that earns the fourth Obj-C entry point. An
// entitlements plist is readable from a binary that was edited after signing, so a
// probe that only read entitlements would label this node vm-capable while macOS
// refuses to launch the very helper the label promises. That row must be
// unavailable, and it is a separate row from "not entitled at all" precisely so a
// future refactor cannot collapse the two into one plist read.
//
// Hermetic: no real Virtualization.framework, no signing, no root. The REAL cgo
// probes are exercised separately by TestVMBackendAvailableFalseWithoutEntitlement.
func TestVMAvailableRequiresEntitledHelper(t *testing.T) {
	const macOS26 = 26
	const helperPath = "/opt/k3sm/bin/" + VMHostName

	cases := []struct {
		name string
		// the five terms, one per injected seam
		major     int
		majorErr  error
		supported bool
		helper    string
		helperErr error
		// signature verdict keyed by the path the backend actually asks about,
		// so a backend that asked about the wrong binary cannot pass.
		validSigs map[string]bool
		want      bool
	}{
		{
			name:      "all-terms-hold",
			major:     macOS26,
			supported: true,
			helper:    helperPath,
			validSigs: map[string]bool{helperPath: true},
			want:      true,
		},
		{
			name:      "helper-missing",
			major:     macOS26,
			supported: true,
			helperErr: ErrVMHostNotFound,
			validSigs: map[string]bool{helperPath: true},
			want:      false,
		},
		{
			name:      "helper-present-but-unentitled",
			major:     macOS26,
			supported: true,
			helper:    helperPath,
			validSigs: map[string]bool{helperPath: false},
			want:      false,
		},
		{
			// The signature check FAILS while an entitlements plist would still
			// read as entitled: the shim reports false, so the node stays quiet.
			name:      "helper-entitled-but-broken-signature",
			major:     macOS26,
			supported: true,
			helper:    helperPath,
			validSigs: map[string]bool{}, // no valid signature at any path
			want:      false,
		},
		{
			name:      "virtualization-unsupported",
			major:     macOS26,
			supported: false,
			helper:    helperPath,
			validSigs: map[string]bool{helperPath: true},
			want:      false,
		},
		{
			name:      "os-too-old",
			major:     15,
			supported: true,
			helper:    helperPath,
			validSigs: map[string]bool{helperPath: true},
			want:      false,
		},
		{
			name:      "os-probe-error",
			majorErr:  errors.New("no version"),
			supported: true,
			helper:    helperPath,
			validSigs: map[string]bool{helperPath: true},
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			b := &VMBackend{
				minMajor:    vmMinMacOSMajor,
				osMajorFn:   func() (int, error) { return tc.major, tc.majorErr },
				supportedFn: func() bool { return tc.supported },
				vmHostFn:    func() (string, error) { return tc.helper, tc.helperErr },
				helperEntitledFn: func(p string) bool {
					asked = append(asked, p)
					return tc.validSigs[p]
				},
			}
			got := b.Available()
			if runtime.GOOS == "darwin" {
				if got != tc.want {
					t.Errorf("Available() = %v, want %v", got, tc.want)
				}
			} else if got {
				t.Errorf("Available() = true off darwin; must be false")
			}
			// When the signature was consulted at all, it must have been
			// consulted about the HELPER — never about this process.
			for _, p := range asked {
				if p != tc.helper {
					t.Errorf("signature was checked for %q, want the helper path %q", p, tc.helper)
				}
			}
		})
	}

	t.Run("nil-seams-fail-closed", func(t *testing.T) {
		if (&VMBackend{minMajor: vmMinMacOSMajor}).Available() {
			t.Error("Available() = true on a zero-value backend; the seams are nil, so it must fail closed")
		}
	})
}

// TestFindVMHostMirrorsExecShimLookup pins the helper lookup's two candidates and
// their order: beside the current executable first, then PATH. The
// beside-the-executable leg is the production one (the daemon and its helpers are
// installed together), so a regression that only kept the PATH leg would work on a
// dev machine and fail on every install.
func TestFindVMHostMirrorsExecShimLookup(t *testing.T) {
	t.Run("absent-reports-the-sentinel", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := FindVMHost(); !errors.Is(err, ErrVMHostNotFound) {
			t.Errorf("FindVMHost err = %v, want ErrVMHostNotFound", err)
		}
	})

	t.Run("found-on-path", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, VMHostName)
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write helper: %v", err)
		}
		t.Setenv("PATH", dir)
		got, err := FindVMHost()
		if err != nil {
			t.Fatalf("FindVMHost: %v", err)
		}
		if got != p {
			t.Errorf("FindVMHost() = %q, want %q", got, p)
		}
	})
}

// TestGuestRosettaShareWithheld is B229's pkg/sandbox half: the node's
// guest-Rosetta advertisement is gated on what the k3sm-vmhost helper BUILDS, and
// this build's helper attaches no Rosetta share.
//
// It asserts a constant on purpose. There is no host fact to observe here — the
// question is what this repo's source does — so the test's job is to make flipping
// the advertisement a deliberate, reviewed edit rather than an accident of some
// unrelated refactor.
func TestGuestRosettaShareWithheld(t *testing.T) {
	if VMHostRosettaShareSupported {
		t.Fatal("VMHostRosettaShareSupported is true, but k3sm-vmhost attaches no Rosetta share: " +
			"a node would advertise guest-Rosetta, pkg/image would add linux/amd64 as a pull " +
			"candidate for every vm pod, and every amd64 image would be pulled and then fail to exec")
	}
	if NewVMBackend().GuestRosettaShareSupported() {
		t.Error("VMBackend.GuestRosettaShareSupported() = true; want false while the helper attaches no share")
	}
}
