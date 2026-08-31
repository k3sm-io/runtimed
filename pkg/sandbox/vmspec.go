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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"k3sm.io/runtimed/pkg/guestinit"

	guestv1 "k3sm.io/apis/guest/v1"
)

// THE SPEC IS BUILT AGAINST guestv1 DIRECTLY, NEVER THROUGH pkg/vmhost.
//
// pkg/vmhost is where FromSpec lives, and it would be the obvious place to reuse.
// It is unreachable from here on purpose: that package imports Code-Hex/vz, so an
// import would drag Virtualization.framework into the daemon's address space and
// dissolve the entitlement split into a packaging convention
// (pkg/vmhost.TestVZIsNotReachableFromTheDaemon fails the build that tries it).
//
// The two ends therefore meet at guest/v1 and nowhere else, which is exactly what
// that contract is versioned for: this file EMITS a VMHostSpec, the helper's
// ReadSpec PARSES one with unknown fields rejected, and a disagreement between
// them is a loud refusal at boot rather than a silently dropped field. Nothing
// here re-implements FromSpec's validation, and nothing here should: the helper
// re-validates everything it is handed, because the file crosses a process
// boundary and a producer's correctness is not an input the consumer may assume.

// VMSpecFileName is the basename of the per-pod machine description CreateVM
// writes into the pod dir and the k3sm-vmhost helper is pointed at with -spec.
//
// It lives in the POD DIR — not the daemon's private run tree — because the
// helper derives its own PodDir from the spec file's directory (see
// cmd/k3sm-vmhost's defaultOptions), so the two cannot disagree about which pod
// they are serving. The file describes the machine, never a credential: it names
// share ROOTS, and the shares' contents are the pod's own already.
const VMSpecFileName = "vmhost.spec.json"

// VMConsoleLogName is the basename of the pod's guest console log, written by the
// helper under the pod dir. Every boot failure names it, because on a guest that
// never reached its agent the console is the ONLY narrative there is: the host
// sees a helper that exited and nothing about why the kernel stopped.
const VMConsoleLogName = "console.log"

// VMAgentVsockPort is the vsock port a pod's guest agent listens on and the
// helper dials.
//
// It is a CONSTANT rather than an allocation because a vsock port space is
// per-machine: every pod gets its own VM, so every pod's agent can use the same
// number without collision, and a per-pod allocation would add a value the host
// and the guest must agree on for no isolation gained. 1024 matches the apis
// guest/v1 golden fixtures (testdata/vmhost.spec.json, testdata/guest-spec.json).
//
// SINGLE-HOME OBLIGATION: it fills VMHostSpec.agent_vsock_port here, and the
// guest half of the same pair is GuestSpec.agent_port, which guest.proto requires
// to be EQUAL. Whatever writes the GuestSpec must read this constant.
const VMAgentVsockPort uint32 = 1024

// VMHostDefaultStopGrace and VMHostMaxStopGrace MIRROR pkg/vmhost's
// DefaultStopGrace and MaxStopGrace.
//
// They are duplicated for the reason VMHostRosettaShareSupported is: pkg/sandbox
// cannot import pkg/vmhost without dragging the Virtualization-linking module
// into the daemon. The values are load-bearing on THIS side because the daemon
// must know the budget the helper will actually honour: the helper clamps the
// grace it is given, so a daemon that escalated on the UNCLAMPED number would
// SIGKILL a helper still inside its own graceful stop — the two-timers bug the
// -stop-grace flag exists to remove. Computing the clamp host-side is what makes
// the daemon's wait provably >= the helper's.
//
// The pairing is pinned by a TEST that may import both
// (pkg/vmhost.TestStopGraceBoundsAreSingleValued), exactly as the Rosetta
// constant's is.
const (
	VMHostDefaultStopGrace = 20 * time.Second
	VMHostMaxStopGrace     = 30 * time.Second
)

// GuestArtifacts are the pinned Linux guest boot artifacts a vm pod boots from:
// the kernel, the initramfs carrying the guest init, and the kernel command line
// they were built to be started with.
//
// The cmdline rides WITH the artifacts, not with the pod, because it is a
// property of the pair — console device, panic behaviour, the init the initramfs
// actually contains — and a pod has no business choosing any of it. The pod's own
// contribution is its id, which the helper appends as k3sm.pod_id (FromSpec's
// withPodIDParam); nothing else pod-specific belongs on the kernel command line.
type GuestArtifacts struct {
	// KernelPath is the host path of the guest kernel image.
	KernelPath string
	// InitramfsPath is the host path of the initramfs carrying the guest init.
	InitramfsPath string
	// Cmdline is the kernel command line the pair boots with.
	Cmdline string
}

// GuestArtifactLocator resolves the pinned guest boot artifacts for this node.
//
// It is a SEAM, not a path pair on VMSpec, because artifact provisioning is a
// NODE fact with its own lifecycle — fetch, digest-verify against the in-code
// pin, cache — and none of that is a per-pod decision. Making it a function also
// keeps CreateVM honest about the failure: a node whose artifacts are absent
// fails every vm pod with one legible reason instead of silently booting whatever
// happens to be on disk.
//
// It is DELIBERATELY UNSET in the shipped constructor. The production feeder is
// its own deliverable (the EnsureGuestArtifacts slice); until it lands, CreateVM
// fails closed with ErrGuestArtifactsUnavailable rather than guessing a path.
type GuestArtifactLocator func() (GuestArtifacts, error)

// ErrGuestArtifactsUnavailable reports that the pinned guest kernel/initramfs
// could not be resolved, so no vm pod can boot on this node. Compare with
// errors.Is.
var ErrGuestArtifactsUnavailable = errors.New("sandbox: the pinned guest boot artifacts (kernel + initramfs) are unavailable")

// ErrInvalidVMSpec reports a VMSpec CreateVM refuses to build a machine from.
// Every rejection in the vm spine wraps it, so a caller can tell a malformed
// request apart from a boot failure with errors.Is.
var ErrInvalidVMSpec = errors.New("sandbox: invalid VMSpec")

// validateVMSpec rejects a VMSpec the vm spine will not act on.
//
// It checks the three PATHS the spine writes to or hands a child process, and
// nothing else: sizing is the helper's to clamp and the share plan is the
// helper's to re-validate. The pod dir and the agent socket are stamped by
// pkg/runtime's own derivations (podDir / guestAgentSocket, both of which parse
// the pod id first), so this is the fail-closed backstop behind those — a
// defence-in-depth check, not the primary one, which is why it is lexical and
// touches no disk.
func validateVMSpec(spec VMSpec) error {
	if spec.PodID == "" {
		return fmt.Errorf("%w: pod_id is empty", ErrInvalidVMSpec)
	}
	for _, p := range []struct{ field, path string }{
		{"PodDir", spec.PodDir},
		{"AgentSocketPath", spec.AgentSocketPath},
	} {
		if p.path == "" {
			return fmt.Errorf("%w: %s is empty for pod %s", ErrInvalidVMSpec, p.field, spec.PodID)
		}
		if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path {
			return fmt.Errorf("%w: %s %q is not an absolute, clean path", ErrInvalidVMSpec, p.field, p.path)
		}
	}
	return nil
}

// buildVMHostSpec renders the machine description for one pod.
//
// FIELDS DELIBERATELY LEFT ZERO, each for its own reason:
//
//   - mac_address — empty means "derive it deterministically from pod_id"
//     (vmhost.DeriveMAC), which is what keeps a guest's DHCP lease stable across
//     a VM restart of the same pod. A host-chosen address would be a second
//     authority for a value that already has one.
//   - rosetta — this node's helper attaches no Rosetta share
//     (VMHostRosettaShareSupported), and FromSpec REFUSES a spec that asks for
//     one, so requesting it would fail every amd64 pod at boot rather than
//     silently. The flag is sourced from the constant so the day the helper
//     attaches the share, this follows it.
//
// The k3sm.spec share is NOT emitted: FromSpec appends it and rejects a spec that
// supplies it, because its root is derived from the helper's own PodDir.
func buildVMHostSpec(spec VMSpec, art GuestArtifacts) *guestv1.VMHostSpec {
	hs := &guestv1.VMHostSpec{
		PodId:          spec.PodID,
		Vcpus:          spec.Vcpus,
		MemoryBytes:    spec.MemoryBytes,
		KernelPath:     art.KernelPath,
		InitramfsPath:  art.InitramfsPath,
		Cmdline:        art.Cmdline,
		Rosetta:        VMHostRosettaShareSupported,
		AgentVsockPort: VMAgentVsockPort,
	}
	for _, s := range spec.Volumes.Shares {
		// Writable is inverted into read_only at exactly one place — here — so
		// the fail-closed zero value of VMShare.Writable stays fail-closed on the
		// wire. The helper then FORCES read-only on the tags where it is not the
		// producer's to choose (vmhost.forcedReadOnlyTags).
		hs.Shares = append(hs.Shares, &guestv1.VMShare{
			Tag:      s.Tag,
			HostPath: s.Root,
			ReadOnly: !s.Writable,
		})
	}
	return hs
}

// marshalVMHostSpec encodes hs as the proto-JSON the helper's ReadSpec decodes.
//
// UseProtoNames is off — the wire form is lowerCamel, matching the apis goldens
// (guest/v1/testdata/vmhost.spec.json), which are the schema's only executable
// statement. Multiline is on because this file is read by a human on every boot
// failure, and a one-line blob is the difference between a diagnosable pod and a
// grep.
func marshalVMHostSpec(hs *guestv1.VMHostSpec) ([]byte, error) {
	out, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(hs)
	if err != nil {
		return nil, fmt.Errorf("encode the vm host spec for pod %s: %w", hs.GetPodId(), err)
	}
	return append(out, '\n'), nil
}

// writeVMHostSpec writes the machine description into the pod dir and returns its
// path, creating the k3sm.spec share root alongside it.
//
// THE SHARE ROOT IS CREATED HERE because FromSpec appends that share
// unconditionally and VZ refuses a shared directory that does not exist, so a
// missing dir would fail the boot with a framework error naming a path the pod
// spec never mentioned. It is created EMPTY: the GuestSpec that belongs inside it
// is written by the guest-provisioning slice, not by this one, and a guest that
// finds an empty share fails in its own init with its own reason.
//
// The write is atomic (temp + rename) for the ordinary reason: the helper reads
// this file as its first act, and a half-written spec would be a parse error
// blamed on the contract instead of on the crash that truncated it.
func writeVMHostSpec(podDir string, hs *guestv1.VMHostSpec) (string, error) {
	data, err := marshalVMHostSpec(hs)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(podDir, guestinit.SpecShareTag), 0o700); err != nil {
		return "", fmt.Errorf("create the %s share root for pod %s: %w", guestinit.SpecShareTag, hs.GetPodId(), err)
	}
	final := filepath.Join(podDir, VMSpecFileName)
	tmp := final + ".tmp"
	// 0600: the spec names every share root the guest is given, which is a map of
	// this pod's credential mounts even though it carries none of their contents.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", fmt.Errorf("write the vm host spec for pod %s: %w", hs.GetPodId(), err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", fmt.Errorf("commit the vm host spec for pod %s: %w", hs.GetPodId(), err)
	}
	return final, nil
}

// clampStopGrace resolves the grace budget the helper will actually honour,
// applying the SAME rule NewLifecycle applies on the other side of the process
// boundary (0 takes the default, anything above the ceiling is clamped).
//
// The daemon computes it so its own SIGTERM->SIGKILL escalation can be made
// provably >= the helper's budget. Duplicating the arithmetic is the cost of the
// import boundary; the constants it reads are pinned to the helper's by
// pkg/vmhost.TestStopGraceBoundsAreSingleValued.
func clampStopGrace(d time.Duration) time.Duration {
	if d <= 0 {
		return VMHostDefaultStopGrace
	}
	if d > VMHostMaxStopGrace {
		return VMHostMaxStopGrace
	}
	return d
}
