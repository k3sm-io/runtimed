//go:build darwin

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

import "golang.org/x/sys/unix"

// The sysctl names the host GPU facts are read from. They are PUBLIC sysctls read
// through golang.org/x/sys/unix (no cgo), so unlike libsandbox they need no symbol
// canary — a renamed sysctl surfaces as a read error, which degrades one fact
// rather than failing the build.
const (
	// sysctlChipBrand is the marketing chip name ("Apple M1 Ultra"). It is the CPU
	// brand string because on Apple silicon the SoC name IS the GPU's identity.
	sysctlChipBrand = "machdep.cpu.brand_string"
	// sysctlMemSize is total physical memory in bytes — the unified-memory pool the
	// GPU shares.
	sysctlMemSize = "hw.memsize"
	// sysctlIOGPUWiredLimit is the configured iogpu wired-memory limit in MEGABYTES
	// (the units are the sysctl's, not a choice here). 0 means no override.
	sysctlIOGPUWiredLimit = "iogpu.wired_limit_mb"
)

// probeHostFacts reads the host GPU facts from sysctl.
//
// Every read DEGRADES rather than fails: a sysctl this kernel does not have leaves
// its field at the zero value. That is the right posture because these facts are
// reported alongside an availability verdict the caller has already decided from
// the functional Metal probe — a missing chip string must not be able to flip a
// working GPU to unavailable, and a fact that is absent is reported as absent.
func probeHostFacts() HostFacts {
	var f HostFacts
	if brand, err := unix.Sysctl(sysctlChipBrand); err == nil {
		f.ChipBrand = brand
		f.ChipFamily = chipFamily(brand)
	}
	if mem, err := unix.SysctlUint64(sysctlMemSize); err == nil {
		f.MemBytes = mem
	}
	// The sysctl is in MB; convert at the boundary so every consumer of HostFacts
	// sees bytes, which is what the reported fact is defined in.
	if mb, err := unix.SysctlUint32(sysctlIOGPUWiredLimit); err == nil {
		f.IOGPUWiredLimitBytes = uint64(mb) * 1024 * 1024
	}
	return f
}
