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

// HostFacts are the GPU-relevant facts read from the host itself rather than from
// a Metal device: the chip identity, the unified-memory size, and the configured
// iogpu wired-memory limit. On Apple silicon the system memory IS the GPU's memory,
// which is why a host fact belongs in a GPU report at all.
type HostFacts struct {
	// ChipBrand is the marketing chip name exactly as the host reports it
	// ("Apple M1 Ultra"), carried VERBATIM. It is the raw fact and is NOT a valid
	// Kubernetes label value; the node-label slug is the advertising consumer's
	// derivation, not this layer's.
	ChipBrand string
	// ChipFamily is the coarser generation ("M1"), derived from ChipBrand for
	// scheduling that wants a generation rather than an exact model.
	ChipFamily string
	// MemBytes is total physical (unified) memory in bytes.
	MemBytes uint64
	// IOGPUWiredLimitBytes is the configured iogpu wired-memory limit in bytes.
	//
	// 0 is a MODELLED SENTINEL: "no explicit limit is configured, the kernel
	// default applies". It does NOT mean unbounded and it does NOT mean unknown.
	// The host reports the sysctl as 0 precisely when no override is set, so the
	// sentinel is the host's own answer rather than a substitute for a missing one
	// — and a read that FAILS also lands on 0, which is the fail-closed direction:
	// a consumer sizing a model against "the kernel default" is conservative, while
	// a consumer told a large limit that does not exist is not.
	IOGPUWiredLimitBytes uint64
}

// GPUProbeResult is one complete GPU observation: the functional Metal verdict plus
// the host facts. It is the value the probe SEAM returns, so a test can supply an
// entire observation without a GPU, a VM, or cgo.
type GPUProbeResult struct {
	// Metal is the functional probe's verdict (see MetalStatus).
	Metal MetalStatus
	// Host is what the host itself reports (see HostFacts).
	Host HostFacts
}

// GPUFacts is what the daemon REPORTS about this host's GPU — the facts the node
// advertisement is derived from. It is plain data, not a proto message, for the
// same reason the Rosetta conditions are: the value is computed once at daemon
// construction and read by a concurrent RPC handler, and handing every caller the
// same proto pointer invites a cross-RPC mutation. The RPC layer stamps a fresh
// message from these values.
type GPUFacts struct {
	// MetalAvailable reports a usable Metal device: the functional probe passed AND
	// the device is not paravirtual.
	MetalAvailable bool
	// ChipBrand / ChipFamily / MemBytes / IOGPUWiredLimitBytes /
	// RecommendedMaxWorkingSetBytes are the NODE-FACING facts. They are populated
	// only when MetalAvailable; see DeriveGPUFacts for why they are cleared rather
	// than reported alongside a false.
	ChipBrand                     string
	ChipFamily                    string
	MemBytes                      uint64
	IOGPUWiredLimitBytes          uint64
	RecommendedMaxWorkingSetBytes uint64
	// SandboxGPUSupported reports whether the CURRENTLY-SELECTED backend can grant
	// a pod GPU access at all (see SandboxGPUSupported). It is scoped to the
	// backend, never a hardware property.
	SandboxGPUSupported bool
	// Reason is the probe's machine token (MetalReason*). It is NOT part of the
	// reported wire message — it exists so the daemon can log, once, why a node is
	// or is not GPU-capable, which is the question an operator actually asks.
	Reason string
}

// DeriveGPUFacts turns one probe observation plus the daemon's selected backend
// into the facts the daemon reports. It is pure, so the whole advertisement
// decision is unit-testable over a fake probe seam with no GPU present.
//
// The availability verdict is FUNCTIONAL AND NON-PARAVIRTUAL (MetalStatus.Available):
// a VZ guest hands back a non-nil device that can even complete a compute dispatch,
// so a node inside a VM would otherwise advertise a GPU that no pod can use.
//
// When the verdict is false EVERY node-facing field is CLEARED. That is the
// deliberate choice over reporting "metal_available=false, chip=Apple M4 Max, 64
// GiB": those numbers exist to size GPU workloads, so a consumer that reads one
// while ignoring the false — the classic partial-read bug — must find a zero, not a
// plausible number. The reported facts are consistent by construction: either the
// host has a usable GPU and every figure describes it, or it does not and there are
// no figures to misread. Reason survives to say which.
func DeriveGPUFacts(p GPUProbeResult, backend Backend) GPUFacts {
	facts := GPUFacts{Reason: p.Metal.Reason}
	if !p.Metal.Available() {
		return facts
	}
	facts.MetalAvailable = true
	facts.ChipBrand = p.Host.ChipBrand
	facts.ChipFamily = p.Host.ChipFamily
	facts.MemBytes = p.Host.MemBytes
	facts.IOGPUWiredLimitBytes = p.Host.IOGPUWiredLimitBytes
	facts.RecommendedMaxWorkingSetBytes = p.Metal.RecommendedMaxWorkingSetBytes
	facts.SandboxGPUSupported = SandboxGPUSupported(backend, p.Metal)
	return facts
}

// ProbeGPU is the production GPU probe seam: the functional Metal probe plus the
// host sysctl reads. It is called EAGERLY, EXACTLY ONCE, at daemon construction —
// never per pod — so the GPU driver is touched once per daemon lifetime.
//
// It takes no context because neither leg has anything to cancel: the sysctl reads
// are immediate and the Metal legs are local driver calls (see probeMetal).
func ProbeGPU() GPUProbeResult {
	return GPUProbeResult{Metal: probeMetal(), Host: probeHostFacts()}
}

// chipFamily derives the generation slug ("M1") from a marketing chip brand
// ("Apple M1 Ultra"). It returns "" when no family token is recognizable, which is
// the honest answer for a chip this code has never seen — an invented family would
// become a node label that schedules work onto the wrong hardware.
//
// The recognizer is deliberately narrow: a token that is "M" followed by digits and
// nothing else. "Apple M4 Max" yields "M4"; "Apple M2" yields "M2"; an Intel
// "Intel(R) Core(TM) i9-9880H CPU" yields "" (no such token), which is correct — an
// Intel Mac has no Apple-silicon GPU family.
func chipFamily(brand string) string {
	for _, field := range strings.Fields(brand) {
		if len(field) < 2 || field[0] != 'M' {
			continue
		}
		digits := true
		for _, r := range field[1:] {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		if digits {
			return field
		}
	}
	return ""
}
