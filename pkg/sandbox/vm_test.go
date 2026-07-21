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
	"errors"
	"runtime"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestVMBackendAvailableFalseWithoutEntitlement asserts the vm backend's SAFE
// availability probe returns false on a host WITHOUT the
// com.apple.security.virtualization entitlement (the runtimed test binary is not
// signed with it) and — critically — does NOT crash. Available() must never
// construct or boot a VM: doing so on a non-entitled host raises an uncaught
// NSException → SIGABRT, which would take down the daemon. On darwin+cgo this
// exercises the real +[VZVirtualMachine isSupported] + Security.framework
// entitlement probe (vm_darwin.m); off darwin/cgo it is the false stub
// (vm_other.go). Either way the answer here is false.
func TestVMBackendAvailableFalseWithoutEntitlement(t *testing.T) {
	b := NewVMBackend()
	if b.Name() != VMBackendName {
		t.Errorf("Name() = %q, want %q", b.Name(), VMBackendName)
	}
	// The call itself must not SIGABRT; reaching the assertion proves the probe is
	// safe on a non-entitled host.
	if b.Available() {
		t.Error("vm backend Available() = true on a host without the com.apple.security.virtualization entitlement; want false")
	}
}

// TestVMBackendAvailableComposition checks the Available() gate composition with
// injected probes: it is true only when darwin AND the OS gate AND isSupported AND
// entitled all hold, and false if any is missing. This is the unit-level proof of
// the safe-probe logic independent of the host's real VZ capability (the real cgo
// probe is exercised by TestVMBackendAvailableFalseWithoutEntitlement).
func TestVMBackendAvailableComposition(t *testing.T) {
	const macOS26 = 26
	cases := []struct {
		name      string
		major     int
		majorErr  error
		supported bool
		entitled  bool
		want      bool
	}{
		{name: "supported-and-entitled", major: macOS26, supported: true, entitled: true, want: true},
		{name: "supported-not-entitled", major: macOS26, supported: true, entitled: false, want: false},
		{name: "entitled-not-supported", major: macOS26, supported: false, entitled: true, want: false},
		{name: "os-too-old", major: 15, supported: true, entitled: true, want: false},
		{name: "os-probe-error", majorErr: errors.New("no version"), supported: true, entitled: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &VMBackend{
				minMajor:    vmMinMacOSMajor,
				osMajorFn:   func() (int, error) { return tc.major, tc.majorErr },
				supportedFn: func() bool { return tc.supported },
				entitledFn:  func() bool { return tc.entitled },
			}
			// The composition is only reachable on darwin (Available short-circuits
			// to false off darwin); guard so the test asserts the real composition
			// only where it can run.
			got := b.Available()
			if runtime.GOOS == "darwin" {
				if got != tc.want {
					t.Errorf("Available() = %v, want %v", got, tc.want)
				}
			} else if got {
				t.Errorf("Available() = true off darwin; must be false")
			}
		})
	}
}

// TestVMBackendWrapCommandRefuses asserts the vm backend does NOT implement the
// host-process exec-shim seam: WrapCommand fails closed with ErrVMUsesCreateVM so
// a mis-routed vm pod can never be run through the Seatbelt host-process path.
func TestVMBackendWrapCommandRefuses(t *testing.T) {
	b := NewVMBackend()
	_, _, _, err := b.WrapCommand(context.Background(), "(version 1)(deny default)(import \"system.sb\")", []string{"/bin/true"}, supervisor.LaunchSpec{})
	if !errors.Is(err, ErrVMUsesCreateVM) {
		t.Errorf("WrapCommand err = %v, want ErrVMUsesCreateVM", err)
	}
}

// TestVMBackendCreateVMLabGated asserts CreateVM is the documented lab-gated stub
// (the live boot needs a VZ-capable, entitled Mac). The routing + fail-closed
// dispatch are what M5.1 verifies; the boot is the lab remainder.
func TestVMBackendCreateVMLabGated(t *testing.T) {
	b := NewVMBackend()
	err := b.CreateVM(context.Background(), VMSpec{PodID: "p", Vcpus: 2, MemoryBytes: 1 << 30})
	if !errors.Is(err, ErrVMBootNotImplemented) {
		t.Errorf("CreateVM err = %v, want ErrVMBootNotImplemented", err)
	}
}
