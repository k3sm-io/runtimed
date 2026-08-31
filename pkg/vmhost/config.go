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

package vmhost

// MachineConfig is the fully-validated, pure-Go description of one pod's virtual
// machine: the value FromSpec produces and realize consumes.
//
// It is deliberately PLAIN DATA — no pointers, no funcs, no maps, no interfaces —
// so a test can build one by hand, compare two with reflect.DeepEqual, and read a
// failure diff without a framework anywhere in the picture. Everything a machine
// needs is here, and nothing that needs a Mac to evaluate is: by the time a
// MachineConfig exists, every check that could reject the pod has already run.
//
// The zero value describes no machine and is rejected by realize; construct one
// with FromSpec.
type MachineConfig struct {
	// PodID is the pod this machine hosts. It is carried for logging and for the
	// deterministic MAC derivation, and is never interpolated into a path.
	PodID string

	// VCPUs and MemoryBytes are the machine's size, already defaulted and clamped
	// into the host's supported range by FromSpec. MemoryBytes is the
	// HYPERVISOR-ENFORCED ceiling for the pod, which is why the vm path needs no
	// host-side memory sampling to enforce a limit.
	VCPUs       uint
	MemoryBytes uint64

	// Boot is the kernel + initramfs + command line.
	Boot BootLoaderConfig

	// Shares are the virtiofs devices, in the order they will be attached. Tags
	// are unique and roots are pairwise non-ancestor (FromSpec's invariant).
	Shares []ShareConfig

	// Network is the single NAT-attached virtio-net device.
	Network NetworkConfig

	// Console is the guest's serial console sink.
	Console ConsoleConfig

	// Vsock is the single virtio-socket device and the port the guest agent
	// listens on.
	Vsock VsockConfig

	// Entropy attaches a virtio-rng device. The guest's crypto — TLS from a
	// workload, anything reading /dev/urandom early — is only as good as its
	// entropy source, and a fresh micro-VM has almost none of its own.
	Entropy bool

	// Balloon attaches a traditional memory-balloon device. It is ATTACHED AND
	// UNUSED on purpose: the device cannot be added to a running machine, so a
	// guest booted without one can never have its memory reclaimed, while a guest
	// booted with one costs nothing until something drives it.
	Balloon bool

	// Rosetta attaches the Rosetta directory share so the guest can register the
	// linux/amd64 binfmt_misc interpreter. It is FALSE in this build and FromSpec
	// refuses a spec that asks for it — see RosettaShareSupported.
	Rosetta bool
}

// BootLoaderConfig is the Linux boot loader: a pinned kernel, its initramfs, and
// the kernel command line. Both paths are absolute, lexically clean, and were
// present when FromSpec ran.
type BootLoaderConfig struct {
	// KernelPath is the uncompressed-or-gzipped kernel image (vmlinuz).
	KernelPath string
	// InitramfsPath is the initial RAM disk carrying k3sm-guest-init as PID 1.
	InitramfsPath string
	// Cmdline is the kernel command line, carried verbatim from the spec.
	Cmdline string
}

// ShareConfig is one virtiofs device: the host directory Root exported under the
// guest-visible mount Tag.
//
// ReadOnly is the ENFORCEMENT POINT for a share's writability, and it is enforced
// HERE, at the VZ device, rather than by any guest-side mount option: the guest
// runs the tenant's code as root, so a `mount -o ro` inside it is
// attacker-controlled. A guest-side read-only flag mirrors this one; it can never
// substitute for it.
type ShareConfig struct {
	// Tag is the guest-visible mount tag. Host paths never cross the boundary —
	// the tag is the only name the guest learns.
	Tag string
	// Root is the host directory the device exports.
	Root string
	// ReadOnly exports the directory without write access at the device.
	ReadOnly bool
}

// NetworkConfig is the machine's single NAT-attached virtio-net device.
//
// NAT ONLY, never bridged: a bridged attachment needs com.apple.vm.networking,
// which is a RESTRICTED entitlement Apple grants by request, and a pod does not
// need a LAN-visible address — the cluster reaches it through the node.
type NetworkConfig struct {
	// MACAddress is the guest NIC's hardware address in canonical lowercase
	// colon-separated form. It is deterministic in the pod id (see DeriveMAC), so
	// the guest's DHCP lease survives a VM restart of the same pod.
	MACAddress string
}

// ConsoleConfig is the guest's serial console sink: a size-capped file in the pod
// directory, deleted with the pod.
//
// The cap is not tidiness. The console carries whatever the guest kernel and the
// workload's PID 1 write to it, at a rate the host does not control, onto the same
// volume the node's images and datastore live on. An uncapped console makes a
// chatty or hostile guest a node-wide disk-exhaustion vector.
type ConsoleConfig struct {
	// LogPath is the host file the console is written to; empty discards it.
	LogPath string
	// MaxBytes caps the file; 0 means DefaultConsoleMaxBytes.
	MaxBytes int64
}

// VsockConfig is the machine's single virtio-socket device and the guest port the
// agent listens on.
type VsockConfig struct {
	// AgentPort is the vsock port the guest agent serves and the host dials. It
	// MUST equal GuestSpec.agent_port — the two specs are written by the same
	// host and a disagreement makes the guest unreachable.
	AgentPort uint32
}
