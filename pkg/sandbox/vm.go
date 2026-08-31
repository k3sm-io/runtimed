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
	"net/netip"
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

// GuestNetworkConfig is the runtimed-LOCAL network contract the vm backend applies
// to a pod's Linux guest (M5.1): the rendered /etc/resolv.conf content plus the
// NAT-attachment advisory fields.
//
// It is an INTENTIONAL decoupling DTO. It mirrors darwin-net's podnet.GuestNetwork
// (the NAT-attachment config) folded together with the rendered resolv.conf from
// darwin-net's pkg/dns.GuestResolvConf — NEITHER of which runtimed may import:
// darwin-net and runtimed are CO-EQUAL LEAVES of the cross-repo DAG (the shared
// contract lives in k3sm.io/apis; neither leaf imports the other). The k3sm
// provider is the named mapper: it owns both darwin-net producers and STAMPS this
// struct as plain data, exactly as it already threads DeniedUnixSocketPaths "as
// data because runtimed cannot import darwin-net" (k3sm/pkg/provider/runtimed.go,
// RuntimedConfig.DeniedUnixSocketPaths).
//
// The zero value networks no guest (no resolver injected, no NAT advisory). In
// M5.1 it IS zero in production — no producer is wired yet; the end-to-end provider
// wiring is the separate k3sm successor.
type GuestNetworkConfig struct {
	// ResolvConf is the rendered /etc/resolv.conf CONTENT the guest provisioner pins
	// into the Linux guest (the pkg/dns.GuestResolvConf output): a `nameserver` line
	// (the cluster DNS VIP), the `search` list, and `options ndots:`. It is the
	// OPERATIVE Linux-guest DNS artifact — the Darwin getaddrinfo DYLD shim that
	// serves a host-process pod is meaningless in a Linux guest (no dyld; glibc/musl
	// NSS instead), so the guest is pointed at the cluster resolver the standard
	// Linux way. Empty means no resolver is injected.
	ResolvConf string
	// PodIP is the pod's cluster identity, allocated from the node podCIDR by
	// darwin-net's IPAM (mirrors podnet.GuestNetwork.PodIP). ADVISORY: an intended
	// value runtimed reconciles from the live attachment — under a NAT attachment the
	// guest's on-the-wire address is macOS-assigned (vmnet DHCP) and may differ.
	PodIP netip.Addr
	// Gateway is the NAT gateway the guest routes through (mirrors
	// podnet.GuestNetwork.Gateway). ADVISORY: macOS-assigned; an intended value
	// runtimed reconciles from the live attachment.
	Gateway netip.Addr
	// NATSubnet is the subnet the guest's interface address sits in behind the
	// VZNATNetworkDeviceAttachment (mirrors podnet.GuestNetwork.NATSubnet). ADVISORY:
	// macOS-assigned; an intended value runtimed reconciles from the live attachment.
	NATSubnet netip.Prefix
	// DNSVIP is the cluster DNS VIP the ResolvConf `nameserver` points at (mirrors
	// podnet.GuestNetwork.DNSVIP) — a cluster fact carried alongside the rendered
	// resolv.conf for reconciliation/diagnostics.
	DNSVIP netip.Addr
}

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
	// Network is the guest's network config (M5.1): the rendered resolv.conf content
	// plus the NAT advisory fields the vm backend applies to the guest. The provider
	// stamps it as data (runtimed cannot import darwin-net — see GuestNetworkConfig);
	// a zero value networks no guest. A NAT-attached guest gets its network via the
	// VZNATNetworkDeviceAttachment, NEVER a host lo0 alias.
	Network GuestNetworkConfig
	// Volumes is the virtiofs share-device plan for the pod's volumes (B106),
	// stamped as data by createVMPod (pkg/runtime), the named mapper from
	// pkg/mount's planner — sandbox imports neither. The zero value plans
	// nothing (safe); see VMVolumePlan.
	Volumes VMVolumePlan
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
// AND the presence of a validly-signed, virtualization-entitled k3sm-vmhost helper,
// both wrapped against Obj-C exceptions in the cgo .m shim (vm_darwin.m). It NEVER
// constructs or boots a VM — instantiating a VZVirtualMachine without the
// entitlement raises an uncaught NSException → SIGABRT, which would take down the
// daemon on a non-entitled host. On such a host Available returns false and
// SelectBackend fails a vm-requested pod CLOSED rather than downgrading it.
//
// THE DAEMON NEVER BOOTS A VM ITSELF. The guest is built and run by the per-pod
// k3sm-vmhost helper (VMHostName), the only k3sm binary carrying
// com.apple.security.virtualization, so this process holds no virtualization
// authority at all.
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
	// vmHostFn locates the k3sm-vmhost helper at its installed path. Defaults to
	// FindVMHost; injectable for tests.
	vmHostFn func() (string, error)
	// helperEntitledFn reports whether the helper at the given path is validly
	// signed AND carries com.apple.security.virtualization (the cgo
	// Security.framework probe on darwin+cgo; a false stub otherwise). Injectable
	// for tests.
	helperEntitledFn func(path string) bool
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
		minMajor:         vmMinMacOSMajor,
		osMajorFn:        darwinMajorVersion,
		supportedFn:      vzSupported,
		vmHostFn:         FindVMHost,
		helperEntitledFn: vzStaticCodeEntitled,
	}
}

// Name returns the backend identifier ("vm").
func (b *VMBackend) Name() string { return VMBackendName }

// Available reports whether the vm backend can run a guest on this host. It is the
// CONJUNCTION of five terms, every one of which must hold (B227):
//
//	darwin
//	  AND macOS major >= vmMinMacOSMajor
//	  AND +[VZVirtualMachine isSupported]
//	  AND the k3sm-vmhost helper resolves at its installed path
//	  AND that helper's static signature is VALID and carries
//	      com.apple.security.virtualization
//
// The last two terms replaced an earlier "this process is entitled" term, and the
// replacement is the architecture rather than a relaxation: the daemon never
// creates a VZVirtualMachine — it spawns the helper, which does — so the daemon
// gating on ITS OWN entitlement asked the wrong binary and would report false on a
// perfectly capable node. The helper's SIGNATURE VALIDITY is checked, not merely
// its entitlements plist, because a plist stays readable on a binary edited after
// signing that macOS will then refuse to launch (see k3sm_vz_static_code_entitled).
//
// It remains a SAFE probe — it never constructs or boots a VM (see the type doc) —
// and it is the ONE probe both consumers read: SelectBackend, which fails a
// vm-requested pod CLOSED when it is false, and pkg/runtime's
// VMBackendAvailable RuntimeCondition, which is what labels the node.
func (b *VMBackend) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if b.osMajorFn == nil || b.supportedFn == nil || b.vmHostFn == nil || b.helperEntitledFn == nil {
		return false
	}
	major, err := b.osMajorFn()
	if err != nil || major < b.minMajor {
		return false
	}
	if !b.supportedFn() {
		return false
	}
	helper, err := b.vmHostFn()
	if err != nil || helper == "" {
		return false
	}
	return b.helperEntitledFn(helper)
}

// GuestRosettaShareSupported reports whether the k3sm-vmhost helper attaches a
// Rosetta directory share to the guests it builds — i.e. whether a linux/amd64 ELF
// could actually execute in one of this node's guests.
//
// It is the SECOND, INDEPENDENT term of the node's guest-Rosetta advertisement
// (B229): Apple's availability probe answers "can this Mac do Rosetta for Linux",
// which is a different question from "does the VM this node builds carry it". The
// answer is the compile-time VMHostRosettaShareSupported; see that constant for why
// the advertisement must be gated on what the helper builds rather than on what the
// framework says the host could do.
func (b *VMBackend) GuestRosettaShareSupported() bool { return VMHostRosettaShareSupported }

// WrapCommand always fails with ErrVMUsesCreateVM: a Linux guest is not a confined
// host process, so the vm backend does not implement the host-process exec-shim
// seam. The runtime routes a vm pod to CreateVM; this method exists only so
// VMBackend totally satisfies sandbox.Backend and fails CLOSED on a mis-route.
func (b *VMBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
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
