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

	"k3sm.io/runtimed/pkg/supervisor"
)

// VMBackendName identifies the Virtualization.framework micro-VM backend in
// logging/diagnostics; it matches the apis "vm" RuntimeClass handler
// (runtimev1.HandlerVM) the provider maps to SANDBOX_BACKEND_VM.
const VMBackendName = "vm"

// vmMinMacOSMajor is the minimum macOS major version the vm backend targets
// (k3sm targets macOS 26+, where the Virtualization.framework Linux-guest surface
// is well supported). Below it Available reports false.
const vmMinMacOSMajor = 26

// ErrVMBootNotImplemented reports that the vm backend's live guest boot is not
// implemented in this build. The boot path is LAB-GATED: it requires a
// Virtualization.framework-capable Mac signed with the
// com.apple.security.virtualization entitlement, so it cannot run in ordinary CI
// or on a non-entitled host. The runtime surfaces it as the pod failure until the
// lab remainder lands (see the VMBackend type doc). Compare with errors.Is.
var ErrVMBootNotImplemented = errors.New("sandbox: vm backend boot not implemented — lab-gated (requires a Virtualization.framework-capable Mac + the com.apple.security.virtualization entitlement)")

// ErrVMUsesCreateVM reports that the vm backend was asked to WrapCommand — the
// host-process exec-shim seam — which it does not implement. A Linux guest is not
// a confined host process, so the runtime routes a vm pod to CreateVM. It exists
// so VMBackend can totally satisfy the swappable sandbox.Backend interface while
// failing CLOSED if a caller ever mis-routes a vm pod through the host-process
// path. Compare with errors.Is.
var ErrVMUsesCreateVM = errors.New("sandbox: vm backend does not use the host-process exec-shim path; route the pod via CreateVM")

// VMSpec is the sizing + image contract for a pod's Linux guest VM (M5.1). The
// provider stamps Vcpus / MemoryBytes onto the SandboxProfile (vm_vcpus /
// vm_memory_bytes); a zero value means "let the backend choose a default".
type VMSpec struct {
	// PodID is the pod the guest backs (for logging + the guest/helper identity).
	PodID string
	// Vcpus is the guest's virtual CPU count; 0 = backend default.
	Vcpus uint32
	// MemoryBytes is the guest's RAM ceiling in bytes — the VZ memorySize, the VM
	// analog of the host-process memory limit; 0 = backend default.
	MemoryBytes int64
	// RootfsPath is the on-disk pod data volume the OCI-Linux-rootfs→bootable-root
	// builder (lab-gated) turns into the guest root.
	RootfsPath string
}

// VMBackend is the Virtualization.framework micro-VM isolation backend (M5.1) —
// the rung for Linux-image / untrusted-tenancy pods the host-process Seatbelt
// path cannot serve (a Linux ELF cannot exec on macOS, and a Seatbelt profile is
// not a hard tenancy boundary). It implements the swappable sandbox.Backend
// interface so SelectBackend / the supervisor can query it, but the runtime
// routes a vm pod to CreateVM rather than WrapCommand (a guest is not a confined
// host process — WrapCommand fails closed with ErrVMUsesCreateVM).
//
// Availability is a SAFE probe (see Available): +[VZVirtualMachine isSupported]
// AND a static-code-entitlement check for com.apple.security.virtualization, both
// wrapped against Obj-C exceptions in the cgo .m shim (vm_darwin.m). It NEVER
// constructs or boots a VM — instantiating a VZVirtualMachine without the
// entitlement raises an uncaught NSException → SIGABRT, which would take down the
// daemon on a non-entitled host. On such a host Available returns false and
// SelectBackend fails a vm-requested pod CLOSED rather than downgrading it.
//
// Virtualization.framework is a PUBLIC framework, so the vm backend is NOT a
// libsandbox/memorystatus SPI symbol-canary case — internal/spicanary is
// deliberately left unchanged by M5 (acceptance M5.1-a2).
//
// LAB-GATED REMAINDER (needs a VZ-capable, entitled Mac; tracked off CreateVM):
//   - the live guest boot — a VZVirtualMachineConfiguration driven on a per-VM
//     SERIAL dispatch queue (VZ's threading rule), behind an opaque handle, with
//     the VZ-delegate→exit / SIGTERM→ACPI requestStop lifecycle;
//   - the cmd/k3sm-vmhost helper-process lifecycle (VZ-delegate→exit,
//     SIGTERM→requestStop);
//   - the OCI-Linux-rootfs → bootable-root builder (digest-pinned tenant images;
//     no codesign — the guest payload is a Linux rootfs, not arm64 Mach-O);
//   - VM metering (the memory limit → memorySize; working set sourced from a guest
//     agent, NOT proc_pid_rusage, which only sees the vmnet/host task).
//
// Construct it with NewVMBackend. The zero value is not usable.
type VMBackend struct {
	// minMajor is the minimum macOS major version the backend supports.
	minMajor int
	// osMajorFn returns the host macOS major version (injectable for tests).
	osMajorFn func() (int, error)
	// supportedFn reports +[VZVirtualMachine isSupported] (the cgo safe probe on
	// darwin+cgo; a false stub otherwise). Injectable for tests.
	supportedFn func() bool
	// entitledFn reports whether this process carries the
	// com.apple.security.virtualization entitlement (the cgo Security.framework
	// probe on darwin+cgo; a false stub otherwise). Injectable for tests.
	entitledFn func() bool
}

// Ensure VMBackend satisfies the swappable Backend seam.
var _ Backend = (*VMBackend)(nil)

// NewVMBackend constructs the Virtualization.framework vm backend wired to the
// host probes. On darwin+cgo the probes call the Virtualization / Security
// frameworks (vm_darwin.go); on every other build lane they report false
// (vm_other.go), so Available is false and the pure-Go (CGO_ENABLED=0) build lane
// stays unbroken.
func NewVMBackend() *VMBackend {
	return &VMBackend{
		minMajor:    vmMinMacOSMajor,
		osMajorFn:   darwinMajorVersion,
		supportedFn: vzSupported,
		entitledFn:  vzEntitled,
	}
}

// Name returns the backend identifier ("vm").
func (b *VMBackend) Name() string { return VMBackendName }

// Available reports whether the vm backend can run a guest on this host: darwin at
// or above the gated macOS major version, Virtualization.framework reports support
// (+[VZVirtualMachine isSupported]), AND this process carries the
// com.apple.security.virtualization entitlement. It is a SAFE probe — it never
// constructs or boots a VM (see the type doc). A false return makes a vm-requested
// pod fail closed in SelectBackend.
func (b *VMBackend) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if b.osMajorFn == nil || b.supportedFn == nil || b.entitledFn == nil {
		return false
	}
	major, err := b.osMajorFn()
	if err != nil || major < b.minMajor {
		return false
	}
	return b.supportedFn() && b.entitledFn()
}

// WrapCommand always fails with ErrVMUsesCreateVM: a Linux guest is not a confined
// host process, so the vm backend does not implement the host-process exec-shim
// seam. The runtime routes a vm pod to CreateVM; this method exists only so
// VMBackend totally satisfies sandbox.Backend and fails CLOSED on a mis-route.
func (b *VMBackend) WrapCommand(ctx context.Context, profile string, argv []string, cred supervisor.Credential) (string, []string, func() error, error) {
	return "", nil, nil, ErrVMUsesCreateVM
}

// CreateVM boots the pod's Linux guest from spec. In M5.1 it is a documented,
// LAB-GATED STUB returning ErrVMBootNotImplemented: the live boot needs a
// Virtualization.framework-capable Mac signed with com.apple.security.virtualization
// (see the type doc's lab-gated remainder). This is the seam the live boot lands
// behind; on a non-entitled host SelectBackend fails a vm pod closed before
// CreateVM is ever reached.
func (b *VMBackend) CreateVM(ctx context.Context, spec VMSpec) error {
	return ErrVMBootNotImplemented
}
