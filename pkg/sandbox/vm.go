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
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

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

// ErrVMBootNotImplemented reports that this BUILD LANE cannot boot a guest.
//
// The live boot landed (CreateVM spawns the k3sm-vmhost helper and waits for its
// guest agent), but it is darwin-only by construction: the helper is a macOS
// binary carrying com.apple.security.virtualization and the readiness handshake
// crosses a Virtualization.framework vsock device. On any other lane — the
// pure-Go CGO_ENABLED=0 build, a linux CI runner — CreateVM is a typed refusal
// returning this, rather than code that compiles and then fails at a syscall.
//
// It is retained rather than renamed because it is exactly the same statement it
// always made ("no guest can boot here"); only the reason narrowed, from "not
// written yet" to "not on this lane". Compare with errors.Is.
var ErrVMBootNotImplemented = errors.New("sandbox: the vm backend cannot boot a guest on this build lane (the k3sm-vmhost helper and its Virtualization.framework guest are darwin-only)")

// ErrVMUsesCreateVM reports that the vm backend was asked to WrapCommand — the
// host-process exec-shim seam — which it does not implement. A Linux guest is not
// a confined host process, so the runtime routes a vm pod to CreateVM. It exists
// so VMBackend can totally satisfy the swappable sandbox.Backend interface while
// failing closed if a caller ever mis-routes a vm pod through the host-process
// path. Compare with errors.Is.
var ErrVMUsesCreateVM = errors.New("sandbox: vm backend does not use the host-process exec-shim path; route the pod via CreateVM")

// GuestNetworkConfig is the runtimed-LOCAL network contract the vm backend applies
// to a pod's Linux guest: the guest's DNS configuration — carried both
// structured (Nameservers/Searches/Options) and rendered (ResolvConf) — plus the
// NAT-attachment advisory fields.
//
// It is an INTENTIONAL decoupling DTO. It mirrors darwin-net's podnet.GuestNetwork
// (the NAT-attachment config) folded together with the rendered resolv.conf from
// darwin-net's pkg/dns.GuestResolvConf — neither of which runtimed may import:
// darwin-net and runtimed are CO-equal leaves of the cross-repo DAG (the shared
// contract lives in k3sm.io/apis; neither leaf imports the other). The k3sm
// provider is the named mapper: it owns both darwin-net producers and STAMPS this
// struct as plain data, exactly as it already threads DeniedUnixSocketPaths "as
// data because runtimed cannot import darwin-net" (k3sm/pkg/provider/runtimed.go,
// RuntimedConfig.DeniedUnixSocketPaths).
//
// The DNS configuration is carried TWICE, deliberately. apis guest/v1's
// ResolvConf message carries only the structured form (nameservers/searches/
// options — no rendered-string field), because the guest must render
// /etc/resolv.conf itself to do it musl-safely: Alpine's musl resolver largely
// ignores `options ndots`, so a search list that only works under a host-chosen
// ndots is not portable and the guest has to be free to lay the directives out
// for its own libc. A rendered-string-only carrier would force the host to
// re-parse its own output to fill that message — exactly the round-trip the
// proto shape exists to prevent. So the structured fields are the ones that
// cross into the guest, and ResolvConf is retained as the host-side rendering
// for diagnostics and for any consumer that wants the bytes verbatim. When both
// are set they describe the same configuration; the producer (the k3sm provider)
// is the one authority that fills them, and runtimed never re-derives one from
// the other.
//
// The zero value networks no guest (no resolver injected, no NAT advisory) — the
// inert value a vm pod gets when no Deps.Network implements the pkg/runtime
// GuestNetworker seam.
type GuestNetworkConfig struct {
	// Nameservers are the guest's resolver addresses in query order — the
	// structured form that crosses into the guest as guest/v1 ResolvConf.nameservers
	// (in practice the single cluster DNS VIP). Empty means no resolver is injected.
	Nameservers []string
	// Searches is the guest's resolv.conf search list, in order (guest/v1
	// ResolvConf.searches). It must stand on its own: a musl guest may ignore the
	// Options below, so correctness cannot depend on an ndots value.
	Searches []string
	// Options are the guest's resolver options, e.g. "ndots:5" (guest/v1
	// ResolvConf.options). ADVISORY in effect: a musl guest ignores some of them,
	// which is why Searches carries the load.
	Options []string
	// ResolvConf is the HOST-RENDERED /etc/resolv.conf content (the
	// pkg/dns.GuestResolvConf output): a `nameserver` line (the cluster DNS VIP),
	// the `search` list, and `options ndots:`. It is the same configuration the
	// three structured fields above carry, kept for diagnostics and for a consumer
	// that wants the bytes verbatim — the guest renders from the structured form
	// instead (see the type doc). Empty means nothing was rendered host-side.
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

// VMSpec is the sizing + image contract for a pod's Linux guest VM. The
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
	// Network is the guest's network config: the rendered resolv.conf content
	// plus the NAT advisory fields the vm backend applies to the guest. The provider
	// stamps it as data (runtimed cannot import darwin-net — see GuestNetworkConfig);
	// a zero value networks no guest. A NAT-attached guest gets its network via the
	// VZNATNetworkDeviceAttachment, never a host lo0 alias.
	Network GuestNetworkConfig
	// Hostname is the pod hostname the guest sets and binds into every
	// container's /etc/hostname (guest/v1 GuestSpec.hostname). Empty leaves the
	// guest on the kernel default, which the guest init records as a warning.
	Hostname string
	// FSGroup is the pod's fsGroup, honoured in the guest by idmapped mounts
	// rather than a recursive chown (guest/v1 GuestSpec.fs_group). Zero means
	// unset — the proto has no presence for it, so "unset" and "group 0" are
	// the same wire value, exactly as pkg/runtime already reads run_as_user.
	FSGroup int64
	// Containers are the pod's containers in start order (init containers
	// first), already resolved host-side: merged argv, resolved environment,
	// resolved numeric identity. They cross into the guest as guest/v1
	// GuestContainers.
	//
	// plain DATA on the same decoupling seam as Volumes and Network: sandbox
	// resolves nothing itself. The named mapper is pkg/runtime — it holds the
	// PodBox, the image config and pkg/image.MergeRunSpec, which is where every
	// value below is produced (resolveVMContainers).
	//
	// AN empty list IS still not rejected here. guestinit.Plan is the right
	// refuser — it is PID 1 of a VM that exists to run exactly this pod — and
	// the mapper never produces one for a pod that has containers, so a spec
	// arriving empty says something about the caller rather than about this
	// mapping. It is a field rather than a parameter so the mapper has one
	// place to stamp and the composer one place to read.
	Containers []VMContainer
	// Volumes is the virtiofs share-device plan for the pod's volumes,
	// stamped as data by createVMPod (pkg/runtime), the named mapper from
	// pkg/mount's planner — sandbox imports neither. The zero value plans
	// nothing (safe); see VMVolumePlan.
	Volumes VMVolumePlan
	// PodDir is the pod's on-disk directory (<Root>/pods/<pod_id>): where the
	// machine description (VMSpecFileName), the guest console log
	// (VMConsoleLogName) and the k3sm.spec share root live.
	//
	// It is stamped by createVMPod rather than derived here. pkg/runtime owns
	// every pod-path derivation in this daemon (r.podDir parses the id first),
	// and a second derivation in this package would be a second answer to
	// "where does this pod live" that could disagree with the first — which is
	// the class of bug rootfsPath's byte-equality rule exists to foreclose.
	PodDir string
	// AgentSocketPath is the runtimed-PRIVATE unix socket the helper binds and
	// relays to the guest agent's vsock port. Stamped by createVMPod from
	// pkg/runtime's guestAgentSocket, which is also what the daemon's own
	// GuestDialer reaches — so the socket the helper serves and the socket the
	// Exec/Logs route dials are the same string by construction.
	//
	// It is deliberately not under PodDir: the pod dir is the one tree a pod's
	// own confinement can reach, so an agent socket there would put the pod's
	// control channel inside the pod's reach.
	AgentSocketPath string
	// StopGrace is the pod's termination grace, threaded to the helper's
	// -stop-grace so one budget governs both ends of the shutdown. Zero selects
	// the helper's default; the daemon clamps its own escalation wait to the
	// same resolved value (clampStopGrace) so the two timers cannot race.
	StopGrace time.Duration
}

// VMContainer is one container to run inside the pod's guest, as the host has
// already resolved it. It maps onto guest/v1 GuestContainer field for field.
//
// every Kubernetes indirection is already gone by the time a value lands here:
// the argv is the four-quadrant merge of the pod spec against the image config
// (pkg/image.MergeRunSpec), the environment is fully expanded "KEY=value"
// entries, and the identity is numeric. The guest performs no merge and consults
// no image config of its own, which is what lets it boot with no cluster access.
type VMContainer struct {
	// Name is the container name, unique within the pod. It is the selector
	// Exec / Logs / Stats and the guest's ContainerEvents use.
	Name string
	// Init marks an init container: it runs to completion, in list order,
	// before any main container starts.
	//
	// A native sidecar (an init container with restartPolicy: Always) cannot be
	// expressed — guest/v1 carries this one ordering bit and no other — and the
	// guest init records that ceiling on its own side (guestinit.StartStep).
	Init bool
	// RootfsTag names the virtiofs share carrying this container's read-only
	// rootfs lower layer; the guest composes writability as an overlay. It must
	// name a share in VMSpec.Volumes.Shares — no host path ever crosses.
	RootfsTag string
	// Argv is the merged argument vector, Argv[0] first. It crosses as
	// GuestContainer.command with args empty; see buildGuestSpec for why the
	// merged vector is not re-split.
	Argv []string
	// Env are fully resolved "KEY=value" entries.
	Env []string
	// WorkingDir is the process working directory inside the container rootfs;
	// empty takes the image config's WorkingDir as already merged host-side.
	WorkingDir string
	// TTY and Stdin mirror the pod spec's terminal requests.
	TTY   bool
	Stdin bool
	// UID and GID are the RESOLVED numeric ids the process runs as. A
	// non-numeric image USER is deliberately not resolved host-side (the host
	// does not read a pod-controlled /etc/passwd to decide a privilege
	// question); the guest resolves it at exec time against the container
	// rootfs, so this pair carries the numeric answer only when the host
	// already had one.
	UID int64
	GID int64
	// SupplementalGIDs are the additional groups, including the pod fsGroup.
	SupplementalGIDs []int64
}

// VMBackend is the Virtualization.framework micro-VM isolation backend —
// the rung for Linux-image / untrusted-tenancy pods the host-process Seatbelt
// path cannot serve (a Linux ELF cannot exec on macOS, and a Seatbelt profile is
// not a hard tenancy boundary). It implements the swappable sandbox.Backend
// interface so SelectBackend / the supervisor can query it, but the runtime
// routes a vm pod to CreateVM rather than WrapCommand (a guest is not a confined
// host process — WrapCommand fails closed with ErrVMUsesCreateVM).
//
// Availability is a safe probe (see Available): +[VZVirtualMachine isSupported]
// and the presence of a validly-signed, virtualization-entitled k3sm-vmhost helper,
// both wrapped against Obj-C exceptions in the cgo .m shim (vm_darwin.m). It never
// constructs or boots a VM — instantiating a VZVirtualMachine without the
// entitlement raises an uncaught NSException → SIGABRT, which would take down the
// daemon on a non-entitled host. On such a host Available returns false and
// SelectBackend fails a vm-requested pod closed rather than downgrading it.
//
// the DAEMON never BOOTS A VM itself. The guest is built and run by the per-pod
// k3sm-vmhost helper (VMHostName), the only k3sm binary carrying
// com.apple.security.virtualization, so this process holds no virtualization
// authority at all.
//
// Virtualization.framework is a PUBLIC framework, so the vm backend is not a
// libsandbox/memorystatus SPI symbol-canary case — internal/spicanary is
// deliberately left unchanged by the vm backend's addition.
//
// LAB-GATED remainder (needs a VZ-capable, entitled Mac; tracked off CreateVM):
//   - the live guest boot — a VZVirtualMachineConfiguration driven on a per-VM
//     SERIAL dispatch queue (VZ's threading rule), behind an opaque handle, with
//     the VZ-delegate→exit / SIGTERM→ACPI requestStop lifecycle;
//   - the cmd/k3sm-vmhost helper-process lifecycle (VZ-delegate→exit,
//     SIGTERM→requestStop);
//   - the OCI-Linux-rootfs → bootable-root builder (digest-pinned tenant images;
//     no codesign — the guest payload is a Linux rootfs, not arm64 Mach-O);
//   - VM metering (the memory limit → memorySize; working set sourced from a guest
//     agent, not proc_pid_rusage, which only sees the vmnet/host task).
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
	// signed and carries com.apple.security.virtualization (the cgo
	// Security.framework probe on darwin+cgo; a false stub otherwise). Injectable
	// for tests.
	helperEntitledFn func(path string) bool

	// artifacts resolves this node's pinned guest kernel + initramfs. nil BY
	// DEFAULT, and CreateVM fails closed on nil: the production feeder is its
	// own deliverable, and a backend that guessed a path would boot whatever
	// happened to be on disk under a digest pin it never checked.
	artifacts GuestArtifactLocator
	// stateRoot is the runtime work-dir the orphan-record store lives under
	// (<stateRoot>/vmreap). Empty disables the store — the posture for a
	// backend constructed without one, which is only ever a test double.
	stateRoot string
	// spawner / waiter are pkg/supervisor's spawn and reap seams. The helper is
	// started and reaped through the same primitives every pod process is, so
	// the SETSID group, the signal-mask reset, the combined-output pipe and the
	// single-kqueue-reaper guarantee are inherited rather than re-derived.
	spawner supervisor.Spawner
	waiter  supervisor.ExitWaiter
	// health is the readiness probe: a real guest/v1 Health round trip, never a
	// socket dial. See GuestHealthFunc for why the distinction is load-bearing.
	health GuestHealthFunc
	// signal sends a signal to a process GROUP (supervisor.SignalGroup in
	// production); a field so the whole stop/escalate/reap policy is testable
	// against a recorder.
	signal func(pgid int, sig os.Signal) error
	// procStart / procGroup are the process-table probes the orphan store's
	// exact-instance identity is built from (leader pid + immutable start time).
	procStart func(pid int) (int64, bool)
	procGroup func(pgid int) ([]supervisor.ProcMember, bool)
	// log receives the vm spine's narration; nil means slog.Default (see
	// logger). It is a field rather than a package logger so a node's vm
	// activity rides the daemon's configured handler.
	log *slog.Logger

	// mu guards live only. Every helper call — spawn, health, signal — is made
	// with mu released, so a blocked boot never blocks a concurrent StopVM or a
	// GetRuntimeInfo probe.
	mu sync.Mutex
	// live maps pod id to its running helper. A pod is in it only between a
	// SUCCESSFUL CreateVM and its stop, so membership means "this node holds a
	// booted guest for this pod".
	live map[string]*vmProc
}

// VMBackendOption configures a VMBackend at construction.
//
// Options rather than a config struct because the shipped daemon sets exactly
// one of them today (the state root) while a test sets five, and a struct would
// make every unset field a decision someone has to read past. They are also what
// keeps NewVMBackend's existing zero-argument call sites compiling unchanged.
type VMBackendOption func(*VMBackend)

// WithGuestArtifacts supplies the locator for this node's pinned guest kernel and
// initramfs. Without it CreateVM fails closed with ErrGuestArtifactsUnavailable —
// see GuestArtifactLocator for why the shipped constructor leaves it unset.
func WithGuestArtifacts(locator GuestArtifactLocator) VMBackendOption {
	return func(b *VMBackend) { b.artifacts = locator }
}

// WithStateRoot supplies the runtime work-dir the vm orphan-record store lives
// under. Without it the store is disabled and a helper this daemon spawns cannot
// be swept after a `kill -9`, so the daemon always sets it.
func WithStateRoot(root string) VMBackendOption {
	return func(b *VMBackend) { b.stateRoot = root }
}

// WithLogger supplies the logger the vm spine narrates through.
func WithLogger(log *slog.Logger) VMBackendOption {
	return func(b *VMBackend) { b.log = log }
}

// WithVMProcessSeams replaces the spawn/reap/health/signal/process-table seams.
// It is the TEST seam for the whole boot and teardown state machine: with a fake
// spawner, a fake reaper and a fake agent, readiness, the pre-ready death race,
// the deadline kill and the orphan sweep all run with no VM and no entitlement.
// A nil argument leaves that seam at its production default.
func WithVMProcessSeams(
	spawner supervisor.Spawner,
	waiter supervisor.ExitWaiter,
	health GuestHealthFunc,
	signal func(pgid int, sig os.Signal) error,
	procStart func(pid int) (int64, bool),
	procGroup func(pgid int) ([]supervisor.ProcMember, bool),
) VMBackendOption {
	return func(b *VMBackend) {
		if spawner != nil {
			b.spawner = spawner
		}
		if waiter != nil {
			b.waiter = waiter
		}
		if health != nil {
			b.health = health
		}
		if signal != nil {
			b.signal = signal
		}
		if procStart != nil {
			b.procStart = procStart
		}
		if procGroup != nil {
			b.procGroup = procGroup
		}
	}
}

// WithVMHostLocator replaces the k3sm-vmhost lookup. Test-only: production always
// resolves the helper beside the daemon or on PATH (FindVMHost).
func WithVMHostLocator(fn func() (string, error)) VMBackendOption {
	return func(b *VMBackend) { b.vmHostFn = fn }
}

// logger returns the configured logger, or the process default.
func (b *VMBackend) logger() *slog.Logger {
	if b.log != nil {
		return b.log
	}
	return slog.Default()
}

// Ensure VMBackend satisfies the swappable Backend seam.
var _ Backend = (*VMBackend)(nil)

// NewVMBackend constructs the Virtualization.framework vm backend wired to the
// host probes. On darwin+cgo the probes call the Virtualization / Security
// frameworks (vm_darwin.go); on every other build lane they report false
// (vm_other.go), so Available is false and the pure-Go (CGO_ENABLED=0) build lane
// stays unbroken.
func NewVMBackend(opts ...VMBackendOption) *VMBackend {
	b := &VMBackend{
		minMajor:         vmMinMacOSMajor,
		osMajorFn:        darwinMajorVersion,
		supportedFn:      vzSupported,
		vmHostFn:         FindVMHost,
		helperEntitledFn: vzStaticCodeEntitled,
		spawner:          supervisor.PosixSpawner{},
		waiter:           supervisor.KqueueReaper{},
		health:           dialGuestHealth,
		signal:           supervisor.SignalGroup,
		procStart:        supervisor.ProcStartTimeNano,
		procGroup:        supervisor.ProcGroupMembers,
		live:             make(map[string]*vmProc),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Name returns the backend identifier ("vm").
func (b *VMBackend) Name() string { return VMBackendName }

// Available reports whether the vm backend can run a guest on this host. It is the
// CONJUNCTION of five terms, every one of which must hold:
//
//	darwin
//	  and macOS major >= vmMinMacOSMajor
//	  and +[VZVirtualMachine isSupported]
//	  and the k3sm-vmhost helper resolves at its installed path
//	  and that helper's static signature is valid and carries
//	      com.apple.security.virtualization
//
// The last two terms replaced an earlier "this process is entitled" term, and the
// replacement is the architecture rather than a relaxation: the daemon never
// creates a VZVirtualMachine — it spawns the helper, which does — so the daemon
// gating on ITS own entitlement asked the wrong binary and would report false on a
// perfectly capable node. The helper's SIGNATURE VALIDITY is checked, not merely
// its entitlements plist, because a plist stays readable on a binary edited after
// signing that macOS will then refuse to launch (see k3sm_vz_static_code_entitled).
//
// It remains a safe probe — it never constructs or boots a VM (see the type doc) —
// and it is the one probe both consumers read: SelectBackend, which fails a
// vm-requested pod closed when it is false, and pkg/runtime's
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
// It is the second, independent term of the node's guest-Rosetta advertisement
// Apple's availability probe answers "can this Mac do Rosetta for Linux",
// which is a different question from "does the VM this node builds carry it". The
// answer is the compile-time VMHostRosettaShareSupported; see that constant for why
// the advertisement must be gated on what the helper builds rather than on what the
// framework says the host could do.
func (b *VMBackend) GuestRosettaShareSupported() bool { return VMHostRosettaShareSupported }

// WrapCommand always fails with ErrVMUsesCreateVM: a Linux guest is not a confined
// host process, so the vm backend does not implement the host-process exec-shim
// seam. The runtime routes a vm pod to CreateVM; this method exists only so
// VMBackend totally satisfies sandbox.Backend and fails closed on a mis-route.
func (b *VMBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	return "", nil, nil, ErrVMUsesCreateVM
}
