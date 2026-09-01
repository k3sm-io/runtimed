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
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestVMBackendAvailableFalseWithoutEntitlement asserts the vm backend's safe
// availability probe returns false in a test tree — no installed k3sm-vmhost
// helper, and no validly-signed virtualization-entitled binary to find — and,
// critically, does not crash. Available() must never construct or boot a VM: doing
// so on a non-entitled host raises an uncaught NSException → SIGABRT, which would
// take down the daemon. On darwin+cgo this exercises the real
// +[VZVirtualMachine isSupported] and Security.framework probes (vm_darwin.m); off
// darwin/cgo they are the false stubs (vm_other.go). Either way the answer here is
// false. The term-by-term composition is TestVMAvailableRequiresEntitledHelper
// (vmhost_test.go), which supersedes the earlier probe-pair composition table.
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

// TestVMBackendWrapCommandRefuses asserts the vm backend does not implement the
// host-process exec-shim seam: WrapCommand fails closed with ErrVMUsesCreateVM so
// a mis-routed vm pod can never be run through the Seatbelt host-process path.
func TestVMBackendWrapCommandRefuses(t *testing.T) {
	b := NewVMBackend()
	_, _, _, err := b.WrapCommand(context.Background(), "(version 1)(deny default)(import \"system.sb\")", []string{"/bin/true"}, supervisor.LaunchSpec{})
	if !errors.Is(err, ErrVMUsesCreateVM) {
		t.Errorf("WrapCommand err = %v, want ErrVMUsesCreateVM", err)
	}
}

// TestVMBackendCreateVMRejectsAnUnderivedSpec asserts the vm spine refuses a spec
// whose pod paths were not stamped by the runtime's own derivations, before it
// resolves artifacts, writes a file, or spawns anything.
//
// The order is the property. PodDir and AgentSocketPath are handed to a child
// process and used to write and later recursively delete a tree, so a spec that
// reached the spawn with either unset would be acting on a path nothing checked.
// The stamped values come from pkg/runtime's podDir / guestAgentSocket, which
// parse the pod id first; this is the fail-closed backstop behind them.
func TestVMBackendCreateVMRejectsAnUnderivedSpec(t *testing.T) {
	// A locator that would panic if consulted: reaching it means validation ran
	// too late, which is exactly the ordering being asserted.
	b := NewVMBackend(WithGuestArtifacts(func() (GuestArtifacts, error) {
		t.Error("the artifact locator was consulted for a spec that should have been refused first")
		return GuestArtifacts{}, nil
	}))
	err := b.CreateVM(context.Background(), VMSpec{PodID: "p", Vcpus: 2, MemoryBytes: 1 << 30})
	if !errors.Is(err, ErrInvalidVMSpec) {
		t.Errorf("CreateVM err = %v, want ErrInvalidVMSpec", err)
	}
}
