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

package runtime

import (
	"log/slog"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The GPU facts (M8.2-d4) are evaluated EAGERLY, EXACTLY ONCE, in New and stored
// immutably on the Runtime — the same discipline as the Rosetta conditions
// (rosetta.go), for the same two reasons: GetRuntimeInfo is a CONCURRENT gRPC
// handler, so a lazily-populated field would be shared mutable state needing a lock
// forever after; and the probe compiles and dispatches a Metal kernel, which is a
// GPU driver round trip that must happen once per daemon lifetime, never per RPC
// and never per pod.
//
// The facts are held as sandbox.GPUFacts (plain data), not as a *runtimev1.GPUFacts:
// a proto message is a mutable pointer, and handing the same pointer to every
// concurrent caller invites a cross-RPC mutation. Each RPC stamps a fresh message.

// gpuFactsProto renders the immutable facts as a fresh proto message for one RPC.
//
// It is total — it always returns a message, never nil — and that is a wire-contract
// decision, not a convenience. The apis contract distinguishes an ABSENT gpu field
// ("this daemon does not report GPU facts at all", an older daemon) from a PRESENT
// one carrying metal_available=false ("known to be absent"). A daemon that can
// probe must therefore always report, or a host with no GPU would be indistinguish-
// able from a daemon too old to know — and the consumer is required to treat those
// two differently.
//
// Reason is deliberately NOT carried onto the wire: the message is a facts report,
// and the probe's own diagnosis belongs in the daemon's log (logGPUProbe), where the
// operator asking "why is my node not GPU-labelled" is actually looking.
func gpuFactsProto(f sandbox.GPUFacts) *runtimev1.GPUFacts {
	return &runtimev1.GPUFacts{
		MetalAvailable:                f.MetalAvailable,
		ChipBrand:                     f.ChipBrand,
		ChipFamily:                    f.ChipFamily,
		MemBytes:                      f.MemBytes,
		IogpuWiredLimitBytes:          f.IOGPUWiredLimitBytes,
		RecommendedMaxWorkingSetBytes: f.RecommendedMaxWorkingSetBytes,
		SandboxGpuSupported:           f.SandboxGPUSupported,
	}
}

// logGPUProbe emits the ONE construction-time log line for the GPU probe. Like the
// Rosetta probes it logs at Info for BOTH outcomes — an absent GPU is normal, not a
// fault — and it carries the Reason token the wire message does not, because this
// line is the only place the "why" survives.
func logGPUProbe(log *slog.Logger, f sandbox.GPUFacts, deviceName string) {
	log.Info("gpu capability probe",
		"metalAvailable", f.MetalAvailable,
		"sandboxGPUSupported", f.SandboxGPUSupported,
		"reason", f.Reason,
		"device", deviceName,
		"chip", f.ChipBrand,
		"recommendedMaxWorkingSetBytes", f.RecommendedMaxWorkingSetBytes)
}
