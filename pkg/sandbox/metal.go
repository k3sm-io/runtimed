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

import "strings"

// metalUserClientClasses is the ENTIRE Metal/GPU delta a confined pod needs over
// the default-deny profile: the two IOKit USER-CLIENT classes a Metal device open
// requires. It is lab-derived, not designed — the M8.0 S1 spike ran a full MLX
// generation and a COLD Metal-kernel JIT compile under the generated profile on an
// M1 Ultra / macOS 26.5.2 rig and reduced the allow-set to exactly these two names
// by ablation (k3sm hack/spike/m8 findings-s1.md).
//
// Three properties of that measurement are load-bearing here, because each one
// forecloses a rule a reader would otherwise expect to find:
//
//   - The filter binds the USER CLIENT, not the accelerator IOService. The
//     designed-first candidate — a single
//     (iokit-registry-entry-class-prefix "AGXAcceleratorG") prefix rule — MATCHES
//     nothing: on that rig the IOService is AGXAcceleratorG13X but the object MLX
//     opens is AGXDeviceUserClient, so the prefix was derived from the wrong axis.
//     Do not reinstate it.
//   - Both names are FAMILY-independent. Neither carries a G13X/G14/G16 suffix, so
//     two exact class names cover every Apple-silicon family by construction. The
//     per-chip-family data table the plan carried as a fallback is therefore not
//     merely unnecessary, it is UNEXPRESSIBLE on this filter axis (a table of
//     AGXAcceleratorG13X-style IOService names can never match an iokit-open
//     filter). Do not encode one.
//   - Exact classes beat a shorter prefix. (iokit-registry-entry-class-prefix "AGX")
//     also passes, but admits every future AGX* user client sight-unseen; the two
//     exact names are tighter and cost nothing, since neither varies by family.
//
// Everything else that was proposed was measured UNNECESSARY and is deliberately
// absent: no (allow mach-lookup (global-name "com.apple.MTLCompilerService")) — the
// Metal front-end compiles in-process on macOS 26 and a cold JIT succeeds without
// it; no (allow iokit-get-properties); no /private/var/db/CVMS read; and NO
// shader-cache write allow at all. That last one matters most: the confined pod can
// neither list nor write DARWIN_USER_CACHE_DIR/com.apple.metal{,fe} and generation
// plus cold JIT still succeed, so the profile's core invariant — no file-write*
// outside the pod's own data volume — stays intact and there is no cross-pod
// shader-cache channel to disclose.
//
// The one residual, recorded rather than hidden: only M1-family hardware (G13X) was
// available to the spike, so "family-independent" rests on the names' form plus
// Apple's own practice, not on an M3/M4 measurement. What makes that safe is the
// fail-closed control this rule set deliberately does not carry — see
// SandboxGPUSupported: the SBPL rules are a STATIC ceiling containing no family
// information whatsoever, and the functional Metal probe is the sole gate on
// whether the node advertises GPU at all. On a family where these two names are
// wrong, the probe fails and no GPU pod is ever scheduled here.
//
// A drifted class name has no linker-symbol canary to catch it (SBPL strings are
// data, not symbols), so the tripwires are the golden fixture below and the
// lab-cadence GPU smoke (acceptance M8.2-a4).
var metalUserClientClasses = []string{
	"AGXDeviceUserClient",
	"IOSurfaceRootUserClient",
}

// metalStanza is the exact text Generate emits for a pod with allow_gpu set. It is
// a single const-shaped rendering (built once at init from metalUserClientClasses)
// so the golden fixture pins the same bytes the generator emits, and so a reader
// auditing "what does allow_gpu actually grant" reads one artifact.
var metalStanza = buildMetalStanza()

// buildMetalStanza renders the Metal allow-set in the profile's house style: a
// comment naming the grant and its provenance, then one (allow iokit-open …) rule
// carrying every user-client class filter.
func buildMetalStanza() string {
	var b strings.Builder
	b.WriteString(";; gpu: Metal device access (allow_gpu) — the two exact IOKit\n")
	b.WriteString(";; user-client classes a Metal device open requires. Family-independent\n")
	b.WriteString(";; and lab-derived by ablation; no mach-lookup, no iokit-get-properties,\n")
	b.WriteString(";; no CVMS read, and NO shader-cache write are needed or granted.\n")
	b.WriteString("(allow iokit-open\n")
	for i, class := range metalUserClientClasses {
		b.WriteString("  (iokit-registry-entry-class \"" + class + "\")")
		if i == len(metalUserClientClasses)-1 {
			b.WriteString(")")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// The metalReason tokens a probe reports on MetalStatus.Reason. They are MACHINE
// tokens — an operator greps them and a future consumer may branch on them — so
// each distinct outcome gets its own and none is reused across two meanings.
const (
	// MetalReasonOK — the compile+dispatch round trip completed and the results
	// were correct.
	MetalReasonOK = "OK"
	// MetalReasonNoDevice — MTLCreateSystemDefaultDevice returned nil: this host
	// exposes no Metal device to the daemon at all.
	MetalReasonNoDevice = "NoDevice"
	// MetalReasonParavirtual — a device was opened but it identifies as the VZ
	// paravirtual GPU, so the host is a virtual machine and must never advertise a
	// GPU to the scheduler.
	MetalReasonParavirtual = "Paravirtual"
	// MetalReasonCompileFailed — the probe kernel did not compile (newLibrary /
	// pipeline construction failed).
	MetalReasonCompileFailed = "CompileFailed"
	// MetalReasonDispatchFailed — the compute command buffer did not complete.
	MetalReasonDispatchFailed = "DispatchFailed"
	// MetalReasonWrongResult — the dispatch completed but produced values the probe
	// did not ask for: the device answered, incorrectly. Distinct from
	// DispatchFailed on purpose, because it is the one outcome that would otherwise
	// look like success.
	MetalReasonWrongResult = "WrongResult"
	// MetalReasonUnsupportedBuild — this build cannot ask: the Metal shim is
	// compiled only into the darwin+cgo lane, so a CGO_ENABLED=0 or non-darwin
	// build reports absence of an ANSWER, not absence of a GPU.
	MetalReasonUnsupportedBuild = "UnsupportedBuild"
)

// MetalStatus is one functional Metal probe's verdict about this host's GPU: not
// "is there a device pointer", but "did a Metal library compile, a compute
// pipeline build, and a dispatch return the values it was asked to compute".
//
// The distinction is the whole point of the type. MTLCreateSystemDefaultDevice
// returns a non-nil paravirtual device inside a VZ guest (including a GitHub-hosted
// macOS runner), so a nil-check would make every VM node advertise a GPU it cannot
// give a pod — and the node-level extended resource derived from these facts would
// then attract MLX workloads onto hosts that cannot run them. Functional plus the
// explicit Paravirtual discrimination is what keeps that from happening.
//
// The zero value is the fail-closed one: not functional, no device, no ceiling.
type MetalStatus struct {
	// Functional reports that the compile+dispatch round trip completed and
	// produced the expected values.
	Functional bool
	// Paravirtual reports that the device identifies as a VZ paravirtual GPU.
	// It is carried separately from Functional because the two answer different
	// questions ("did the GPU work" vs "is this a real GPU"), and a VZ guest can
	// answer yes to the first while still being a host no MLX pod may land on.
	Paravirtual bool
	// DeviceName is the MTLDevice's name, verbatim, for logs and diagnostics.
	DeviceName string
	// RecommendedMaxWorkingSetBytes is the device's recommendedMaxWorkingSetSize —
	// the allocation ceiling Metal advises for it, and the number a model-admission
	// check sizes against. 0 when the device could not be opened.
	RecommendedMaxWorkingSetBytes uint64
	// Reason is a MACHINE token naming the probe outcome (see the metalReason
	// constants). It is never empty: a successful probe reports its own token, so
	// an operator asking "why is this node not GPU-labelled" always has an answer.
	Reason string
}

// Available reports the one availability verdict derived from a probe: the GPU
// worked and it is a real GPU. It is the single home of that rule — SandboxGPUSupported
// and DeriveGPUFacts both call it rather than re-deriving the conjunction, so the
// paravirtual discrimination cannot be honoured in one place and forgotten in the
// other (the same one-home discipline HostRosettaState.Available() enforces).
func (m MetalStatus) Available() bool { return m.Functional && !m.Paravirtual }

// SandboxGPUSupported reports GPUFacts.sandbox_gpu_supported: whether this daemon,
// as configured, can grant a pod GPU access at all. It is the fail-closed
// advertisement control (the fail-closed family gate) and it is scoped to the selected
// backend on purpose — the same machine supports GPU pods under the Seatbelt rung
// and not under the vm rung, so it is not a hardware property.
//
// Two independent conditions, both required:
//
//   - backend must be the host-process Seatbelt rung and Available(). It is the
//     only rung whose profile carries metalStanza; a vm pod's Linux guest has no
//     Metal device to open, so vm reports false rather than a grant that cannot
//     take effect. An unavailable backend reports false because a pod cannot run
//     on it at all.
//   - metal.Available() must be true — the functional compile+dispatch probe passed
//     and the device is not the VZ paravirtual one, not a device nil-check. This is where the family residual documented on
//     metalUserClientClasses is discharged: a host whose user-client classes differ
//     from the two encoded above cannot complete the probe under this profile, so
//     it never advertises GPU.
//
// A nil backend reports false (fail closed).
func SandboxGPUSupported(backend Backend, metal MetalStatus) bool {
	if backend == nil || !backend.Available() {
		return false
	}
	if backend.Name() != ExecShimBackendName {
		return false
	}
	return metal.Available()
}
