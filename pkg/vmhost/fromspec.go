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

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
	"k3sm.io/runtimed/pkg/mount"

	guestv1 "k3sm.io/apis/guest/v1"
)

// ErrInvalidSpec reports a VMHostSpec this helper refuses to build a machine
// from. Every rejection in this file wraps it, so a caller can tell a bad spec
// apart from a framework failure with errors.Is.
var ErrInvalidSpec = errors.New("vmhost: invalid VMHostSpec")

// RosettaShareSupported reports whether this helper attaches a Rosetta directory
// share to the guests it builds. It is false, and FromSpec refuses a spec that
// asks for one rather than silently building a guest that cannot honour it.
//
// This is the helper's own copy of the fact that
// pkg/sandbox.VMHostRosettaShareSupported advertises to the cluster. The two must
// agree — a node that advertises guest-Rosetta while the helper drops it on the
// floor would have every linux/amd64 image pulled and then fail to exec — and
// pkg/sandbox cannot import this package (that would drag the Virtualization-
// linking module into the daemon), so the agreement is pinned by
// TestRosettaShareCapabilityIsSingleValued instead of by an import.
const RosettaShareSupported = false

// maxShareTagBytes is Virtualization.framework's limit on a virtiofs device tag.
// A longer tag is rejected by VZ at device construction, which would surface as an
// opaque framework error at boot; rejecting it here names the tag instead.
const maxShareTagBytes = 36

// DefaultConsoleMaxBytes caps a guest's console log. It is generous for a boot
// narrative plus a workload's early stderr and small enough that a screaming guest
// cannot fill the node's disk (see ConsoleConfig).
const DefaultConsoleMaxBytes int64 = 8 << 20

// specShareDirName is the pod-dir subdirectory the k3sm.spec share exports. It
// coincides with the tag (guestinit.SpecShareTag) exactly as pkg/mount's proj and
// vols dirs coincide with theirs: the tag is the guest-visible contract, the
// directory name the host-disk one, and keeping them equal makes the layout
// readable on both sides.
const specShareDirName = guestinit.SpecShareTag

// Options are the bounds and seams FromSpec resolves a spec against. They are
// INJECTED rather than read from the host inside FromSpec, which is what keeps the
// translator pure: the vcpu/memory clamp, the artifact existence check and the
// console sink are all decided by values the caller supplies, so the whole of
// FromSpec is table-testable on a machine that could never boot a VM.
//
// DefaultOptions fills them from the host at the process edge.
type Options struct {
	// PodDir is the pod's on-disk directory. The k3sm.spec share is rooted at
	// PodDir/k3sm.spec; nothing else is derived from it.
	PodDir string

	// ConsoleLogPath is the host file the guest console is written to; empty
	// discards the console. ConsoleMaxBytes caps it (0 = DefaultConsoleMaxBytes).
	ConsoleLogPath  string
	ConsoleMaxBytes int64

	// MinVCPUs / MaxVCPUs bound the guest's CPU count, and DefaultVCPUs is used
	// when the spec asks for 0. The bounds come from
	// VZVirtualMachineConfiguration's own advertised range on the host.
	MinVCPUs     uint
	MaxVCPUs     uint
	DefaultVCPUs uint

	// MinMemoryBytes / MaxMemoryBytes bound the guest's RAM and
	// DefaultMemoryBytes is used when the spec asks for 0. Same provenance as the
	// vcpu bounds.
	MinMemoryBytes     uint64
	MaxMemoryBytes     uint64
	DefaultMemoryBytes uint64

	// Stat is the filesystem seam the kernel/initramfs existence check goes
	// through; nil means os.Stat. A test injects a table of paths so the
	// artifact-verification rows need no files on disk.
	Stat func(name string) (fs.FileInfo, error)
}

// clamp resolves one dimension: a zero request takes the default, and the result
// is pinned into [min,max]. Clamping rather than rejecting is deliberate for the
// upper bound — a pod asking for more vCPUs than this Mac has is a scheduling
// mismatch the node should still run, degraded, rather than a pod that can never
// start on any node in the cluster.
func clampUint(req, def, minimum, maximum uint) uint {
	if req == 0 {
		req = def
	}
	if req < minimum {
		req = minimum
	}
	if maximum > 0 && req > maximum {
		req = maximum
	}
	return req
}

func clampUint64(req, def, minimum, maximum uint64) uint64 {
	if req == 0 {
		req = def
	}
	if req < minimum {
		req = minimum
	}
	if maximum > 0 && req > maximum {
		req = maximum
	}
	return req
}

// FromSpec validates spec against opts and translates it into the pure-Go machine
// description realize builds a VM from.
//
// IT CARRIES all the VALIDATION. Nothing downstream re-checks anything, which is
// the point: a check split between here and a darwin-only translator is a check
// that half the test suite cannot reach. A spec this function accepts is one the
// helper is willing to boot.
//
// The invariants it enforces, and why each is here rather than trusted from the
// producer:
//
//   - The rootfs and projected-credential shares are forced READ-only regardless
//     of what the spec says. The producer already marks them read-only, but "the
//     guest must not be able to write its own lower layer or a mounted Secret" is
//     a property of the vm boundary, not of one producer's correctness, and the
//     device flag is the only place it is actually enforced.
//   - Share roots are PAIRWISE non-ancestor. Two devices where one root contains
//     the other let a guest reach a read-only tree through its writable parent,
//     which quietly undoes the previous rule.
//   - The k3sm.spec share is APPENDED here. pkg/guestinit mounts
//     guestinit.SpecShareTag as its first act and cannot boot without it, and
//     pkg/mount's ComputeSharePlan emits only rootfs/proj/vols/pvc — so nothing
//     else in the tree produces it and a guest built from a plan alone would die
//     with an opaque "cannot find its spec".
//   - Kernel and initramfs must be absolute, CLEAN and present. VZ's own error
//     for a missing kernel arrives as a framework failure at boot; naming the path
//     here is the difference between a legible pod event and a crash report.
func FromSpec(spec *guestv1.VMHostSpec, opts Options) (MachineConfig, error) {
	if spec == nil {
		return MachineConfig{}, fmt.Errorf("%w: nil spec", ErrInvalidSpec)
	}
	podID := spec.GetPodId()
	if err := validPodID(podID); err != nil {
		return MachineConfig{}, err
	}
	if opts.PodDir == "" {
		return MachineConfig{}, fmt.Errorf("%w: no pod directory was supplied, so the %s share has no root", ErrInvalidSpec, guestinit.SpecShareTag)
	}
	if !filepath.IsAbs(opts.PodDir) || filepath.Clean(opts.PodDir) != opts.PodDir {
		return MachineConfig{}, fmt.Errorf("%w: pod directory %q is not an absolute, clean path", ErrInvalidSpec, opts.PodDir)
	}

	statFn := opts.Stat
	if statFn == nil {
		statFn = os.Stat
	}
	boot := BootLoaderConfig{
		KernelPath:    spec.GetKernelPath(),
		InitramfsPath: spec.GetInitramfsPath(),
		Cmdline:       spec.GetCmdline(),
	}
	if err := validArtifact(statFn, "kernel_path", boot.KernelPath); err != nil {
		return MachineConfig{}, err
	}
	if err := validArtifact(statFn, "initramfs_path", boot.InitramfsPath); err != nil {
		return MachineConfig{}, err
	}
	if err := validCmdline(boot.Cmdline); err != nil {
		return MachineConfig{}, err
	}
	cmdline, err := withPodIDParam(boot.Cmdline, podID)
	if err != nil {
		return MachineConfig{}, err
	}
	boot.Cmdline = cmdline

	if spec.GetRosetta() && !RosettaShareSupported {
		return MachineConfig{}, fmt.Errorf(
			"%w: the spec requests a Rosetta directory share, which this helper does not attach; "+
				"refusing rather than booting a guest that cannot execute the linux/amd64 payloads the share was requested for",
			ErrInvalidSpec)
	}

	port := spec.GetAgentVsockPort()
	if port == 0 {
		return MachineConfig{}, fmt.Errorf("%w: agent_vsock_port is 0; the host would have no way to reach the guest agent", ErrInvalidSpec)
	}

	mac, err := resolveMAC(spec.GetMacAddress(), podID)
	if err != nil {
		return MachineConfig{}, err
	}

	shares, err := resolveShares(spec.GetShares(), opts.PodDir)
	if err != nil {
		return MachineConfig{}, err
	}

	consoleMax := opts.ConsoleMaxBytes
	if consoleMax <= 0 {
		consoleMax = DefaultConsoleMaxBytes
	}

	return MachineConfig{
		PodID:       podID,
		VCPUs:       clampUint(uint(spec.GetVcpus()), opts.DefaultVCPUs, opts.MinVCPUs, opts.MaxVCPUs),
		MemoryBytes: clampUint64(memoryRequest(spec.GetMemoryBytes()), opts.DefaultMemoryBytes, opts.MinMemoryBytes, opts.MaxMemoryBytes),
		Boot:        boot,
		Shares:      shares,
		Network:     NetworkConfig{MACAddress: mac},
		Console:     ConsoleConfig{LogPath: opts.ConsoleLogPath, MaxBytes: consoleMax},
		Vsock:       VsockConfig{AgentPort: port},
		Entropy:     true,
		Balloon:     true,
		Rosetta:     false,
	}, nil
}

// memoryRequest converts the spec's SIGNED memory_bytes to the unsigned size a
// machine takes. A negative value is treated as 0 — "unset, take the default" —
// rather than wrapping to an enormous unsigned number, which the clamp would then
// silently pin to the host maximum.
func memoryRequest(v int64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

// validPodID rejects a pod id this helper will not carry.
//
// The id reaches a log line and the MAC derivation, never a path — the pod
// directory arrives separately, already derived by the daemon that validated it —
// so this is a legibility and injection check rather than a containment one: a
// single clean path component, no separators, no control characters.
func validPodID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: pod_id is empty", ErrInvalidSpec)
	}
	if len(id) > 253 {
		return fmt.Errorf("%w: pod_id is %d bytes, over the 253-byte bound", ErrInvalidSpec, len(id))
	}
	if id != filepath.Clean(id) || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return fmt.Errorf("%w: pod_id %q is not a single clean path component", ErrInvalidSpec, id)
	}
	for _, r := range id {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("%w: pod_id %q carries a non-printable-ASCII character", ErrInvalidSpec, id)
		}
	}
	return nil
}

// validArtifact rejects a guest artifact path that is not absolute, not clean, or
// not an existing regular file. The DIRECTORY case is called out separately
// because a path pointing at a directory is the shape a half-finished artifact
// install leaves behind, and VZ's own message for it is unhelpful.
func validArtifact(statFn func(string) (fs.FileInfo, error), field, path string) error {
	if path == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidSpec, field)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s %q is not absolute", ErrInvalidSpec, field, path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%w: %s %q is not lexically clean", ErrInvalidSpec, field, path)
	}
	fi, err := statFn(path)
	if err != nil {
		return fmt.Errorf("%w: %s %q: %w", ErrInvalidSpec, field, path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %s %q is a directory, not a file", ErrInvalidSpec, field, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s %q is not a regular file (mode %v)", ErrInvalidSpec, field, path, fi.Mode())
	}
	return nil
}

// validCmdline rejects a kernel command line carrying a NUL or a newline. Both
// truncate or split the line inside the framework rather than being reported, so a
// guest would boot with silently different arguments from the ones the spec named.
func validCmdline(cmdline string) error {
	if strings.ContainsAny(cmdline, "\x00\n\r") {
		return fmt.Errorf("%w: cmdline carries a NUL or newline, which would silently truncate the kernel command line", ErrInvalidSpec)
	}
	return nil
}

// resolveMAC returns the canonical MAC for the guest NIC: the spec's, if it names
// one, else the deterministic derivation from the pod id.
//
// A spec-supplied address must be a UNICAST, LOCALLY ADMINISTERED 6-byte address —
// the same shape DeriveMAC produces. A multicast address is not a legal source
// address at all, and a globally-unique one claims an OUI k3sm does not own, which
// is how a guest ends up colliding with real hardware on the operator's LAN.
func resolveMAC(specMAC, podID string) (string, error) {
	if specMAC == "" {
		return DeriveMAC(podID), nil
	}
	hw, err := net.ParseMAC(specMAC)
	if err != nil {
		return "", fmt.Errorf("%w: mac_address %q: %w", ErrInvalidSpec, specMAC, err)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("%w: mac_address %q is %d bytes; an ethernet address is 6", ErrInvalidSpec, specMAC, len(hw))
	}
	if hw[0]&0x01 != 0 {
		return "", fmt.Errorf("%w: mac_address %q is a multicast address, which cannot be a NIC's own address", ErrInvalidSpec, specMAC)
	}
	if hw[0]&0x02 == 0 {
		return "", fmt.Errorf("%w: mac_address %q is not locally administered; k3sm owns no OUI, so a globally-unique address risks colliding with real hardware", ErrInvalidSpec, specMAC)
	}
	return hw.String(), nil
}

// forcedReadOnlyTags are the share tags whose read-only flag is not the producer's
// to choose. See FromSpec's doc for why the enforcement lives here.
var forcedReadOnlyTags = map[string]string{
	mount.ShareTagRootfs:   "the guest composes writability as an overlay; a writable lower layer would let a pod mutate the image tree the node shares between pods",
	mount.ShareTagProj:     "projected credentials (configMap / secret / projected / downwardAPI) are read-only in Kubernetes, and this device is the only place that is enforced for a guest",
	guestinit.SpecShareTag: "the boot spec is the host's instruction to the guest; a guest that could rewrite it could re-describe itself",
}

// resolveShares validates the spec's virtiofs devices, forces the read-only tags,
// and appends the k3sm.spec share the guest init requires.
func resolveShares(specShares []*guestv1.VMShare, podDir string) ([]ShareConfig, error) {
	out := make([]ShareConfig, 0, len(specShares)+1)
	seen := make(map[string]struct{}, len(specShares)+1)

	for i, s := range specShares {
		if s == nil {
			return nil, fmt.Errorf("%w: shares[%d] is nil", ErrInvalidSpec, i)
		}
		tag := s.GetTag()
		if err := validShareTag(tag); err != nil {
			return nil, err
		}
		if _, dup := seen[tag]; dup {
			return nil, fmt.Errorf("%w: share tag %q is used twice; a guest mounts by tag, so the second device would be unreachable", ErrInvalidSpec, tag)
		}
		seen[tag] = struct{}{}

		root := s.GetHostPath()
		if err := validShareRoot(tag, root); err != nil {
			return nil, err
		}
		readOnly := s.GetReadOnly()
		if _, forced := forcedReadOnlyTags[tag]; forced {
			readOnly = true
		}
		out = append(out, ShareConfig{Tag: tag, Root: root, ReadOnly: readOnly})
	}

	// The spec share: the guest init's very first mount, produced by nobody else.
	if _, dup := seen[guestinit.SpecShareTag]; dup {
		return nil, fmt.Errorf("%w: the spec already declares a %q share; that device is appended by the VM host and must not be supplied", ErrInvalidSpec, guestinit.SpecShareTag)
	}
	out = append(out, ShareConfig{
		Tag:      guestinit.SpecShareTag,
		Root:     filepath.Join(podDir, specShareDirName),
		ReadOnly: true,
	})

	if err := shareRootsDisjoint(out); err != nil {
		return nil, err
	}
	return out, nil
}

// validShareTag rejects a tag VZ would refuse or a guest could not address: empty,
// over the framework's byte limit, or carrying anything outside printable ASCII
// (the tag crosses into a mount(2) source string in the guest).
func validShareTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("%w: a share has an empty tag", ErrInvalidSpec)
	}
	if len(tag) > maxShareTagBytes {
		return fmt.Errorf("%w: share tag %q is %d bytes, over Virtualization.framework's %d-byte limit", ErrInvalidSpec, tag, len(tag), maxShareTagBytes)
	}
	for _, r := range tag {
		if r <= 0x20 || r > 0x7e {
			return fmt.Errorf("%w: share tag %q carries a character outside printable ASCII", ErrInvalidSpec, tag)
		}
	}
	if strings.ContainsAny(tag, `/\`) {
		return fmt.Errorf("%w: share tag %q carries a path separator; a tag is a device name, not a path", ErrInvalidSpec, tag)
	}
	return nil
}

// validShareRoot rejects a share root that is not an absolute, lexically clean
// path, or that is the filesystem root itself (which would export the whole Mac
// into a tenant's guest).
func validShareRoot(tag, root string) error {
	if root == "" {
		return fmt.Errorf("%w: share %q has an empty host_path", ErrInvalidSpec, tag)
	}
	if !filepath.IsAbs(root) {
		return fmt.Errorf("%w: share %q host_path %q is not absolute", ErrInvalidSpec, tag, root)
	}
	if filepath.Clean(root) != root {
		return fmt.Errorf("%w: share %q host_path %q is not lexically clean", ErrInvalidSpec, tag, root)
	}
	if root == string(filepath.Separator) {
		return fmt.Errorf("%w: share %q would export the filesystem root into the guest", ErrInvalidSpec, tag)
	}
	return nil
}

// shareRootsDisjoint enforces the pairwise non-ancestor invariant across the whole
// device set, including the appended spec share.
//
// Ancestry, not equality, is the property that matters: two devices are only
// independent if neither's tree contains the other's. Where one contains the
// other, the guest reaches the inner tree through the outer device — under the
// OUTER device's read-only flag — so a writable pooled share that happened to
// contain the read-only rootfs would hand the pod write access to its own image
// layer while both devices still looked correctly flagged.
func shareRootsDisjoint(shares []ShareConfig) error {
	for i := range shares {
		for j := range shares {
			if i == j {
				continue
			}
			if isAtOrUnder(shares[j].Root, shares[i].Root) {
				return fmt.Errorf(
					"%w: share %q (%s) is at or under share %q (%s); the guest would reach the inner tree through the outer device, under the outer device's read-only flag",
					ErrInvalidSpec, shares[j].Tag, shares[j].Root, shares[i].Tag, shares[i].Root)
			}
		}
	}
	return nil
}

// isAtOrUnder reports whether path is ancestor itself or lies beneath it. Both
// arguments are already absolute and clean (validShareRoot), so this is a pure
// lexical test — no symlink resolution, which is deliberate: the answer must not
// depend on filesystem state a racing process could change between the check and
// the device construction.
func isAtOrUnder(path, ancestor string) bool {
	if path == ancestor {
		return true
	}
	return strings.HasPrefix(path, ancestor+string(filepath.Separator))
}

// withPodIDParam ensures the kernel command line carries the pod id the guest must
// assert its own identity against.
//
// the guest has no other way to learn it. guest.proto requires the agent to reject
// a pod_id that is not the pod it booted, but guest/v1's GuestSpec carries no
// pod_id field — only VMHostSpec does, and that message never crosses into the
// guest. So the id rides the command line under guestagent.PodIDCmdlineKey (see
// that constant for the full reasoning and the apis residual).
//
// APPEND, DON'T demand. A cmdline that already names the right pod is left alone;
// one that names none has the parameter appended; one that names a different pod
// is refused. Appending rather than requiring means the daemon that composes the
// cmdline needs to know nothing about this convention, while a disagreement — the
// only case that could make a guest answer for the wrong pod — is a loud rejection.
func withPodIDParam(cmdline, podID string) (string, error) {
	existing, err := guestagent.PodIDFromCmdline(cmdline)
	switch {
	case err == nil && existing == podID:
		return cmdline, nil
	case err == nil:
		return "", fmt.Errorf(
			"%w: cmdline sets %s=%q but the spec's pod_id is %q; the guest would assert the wrong identity",
			ErrInvalidSpec, guestagent.PodIDCmdlineKey, existing, podID)
	case errors.Is(err, guestagent.ErrPodIDAbsent):
		param := guestagent.PodIDCmdlineKey + "=" + podID
		if cmdline == "" {
			return param, nil
		}
		return cmdline + " " + param, nil
	default:
		return "", fmt.Errorf("%w: cmdline %s: %w", ErrInvalidSpec, guestagent.PodIDCmdlineKey, err)
	}
}
