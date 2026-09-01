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

import "testing"

// realGPU is a probe observation from a healthy GPU host: the functional probe
// passed on a non-paravirtual device, and the host reported its chip facts.
func realGPU() GPUProbeResult {
	return GPUProbeResult{
		Metal: MetalStatus{
			Functional:                    true,
			DeviceName:                    "Apple M1 Ultra",
			RecommendedMaxWorkingSetBytes: 55662788608,
			Reason:                        MetalReasonOK,
		},
		Host: HostFacts{
			ChipBrand:            "Apple M1 Ultra",
			ChipFamily:           "M1",
			MemBytes:             68719476736,
			IOGPUWiredLimitBytes: 0,
		},
	}
}

// TestDeriveGPUFacts is acceptance M8.2-a3: the whole advertisement decision,
// proven over a FAKE probe seam on a machine that need not have a GPU at all.
func TestDeriveGPUFacts(t *testing.T) {
	seatbelt := stubBackend{ExecShimBackendName, true}

	t.Run("healthy host reports every fact", func(t *testing.T) {
		got := DeriveGPUFacts(realGPU(), seatbelt)
		if !got.MetalAvailable {
			t.Fatal("metal_available false on a functional non-paravirtual device")
		}
		if !got.SandboxGPUSupported {
			t.Fatal("sandbox_gpu_supported false on the Seatbelt rung with a functional probe")
		}
		if got.ChipBrand != "Apple M1 Ultra" || got.ChipFamily != "M1" {
			t.Fatalf("chip facts = %q/%q, want the host's verbatim values", got.ChipBrand, got.ChipFamily)
		}
		if got.MemBytes != 68719476736 {
			t.Fatalf("mem_bytes = %d, want the host figure", got.MemBytes)
		}
	})

	// The VZ discrimination, both halves. A paravirtual device can COMPLETE a
	// dispatch, so "functional" alone must not be enough — a VM node advertising a
	// GPU would attract MLX workloads onto a host that cannot run them.
	t.Run("VZ paravirtual clears the node-facing fields", func(t *testing.T) {
		p := realGPU()
		p.Metal.Paravirtual = true
		p.Metal.DeviceName = "Apple Paravirtual device"
		p.Metal.Reason = MetalReasonParavirtual

		got := DeriveGPUFacts(p, seatbelt)
		assertClearedFacts(t, got)
		if got.Reason != MetalReasonParavirtual {
			t.Fatalf("Reason = %q, want the probe's own token", got.Reason)
		}
	})

	t.Run("failed functional probe clears the node-facing fields", func(t *testing.T) {
		for _, reason := range []string{
			MetalReasonNoDevice,
			MetalReasonCompileFailed,
			MetalReasonDispatchFailed,
			MetalReasonWrongResult,
			MetalReasonUnsupportedBuild,
		} {
			t.Run(reason, func(t *testing.T) {
				p := realGPU()
				p.Metal.Functional = false
				p.Metal.Reason = reason
				assertClearedFacts(t, DeriveGPUFacts(p, seatbelt))
			})
		}
	})

	// The 0-sentinel is a REPORTED fact ("no override configured; the kernel default
	// applies"), not a missing one: it must survive a healthy probe unchanged, and a
	// configured limit must pass through in bytes.
	t.Run("iogpu wired limit", func(t *testing.T) {
		zero := DeriveGPUFacts(realGPU(), seatbelt)
		if zero.IOGPUWiredLimitBytes != 0 {
			t.Fatalf("iogpu_wired_limit_bytes = %d, want the 0 sentinel preserved", zero.IOGPUWiredLimitBytes)
		}
		p := realGPU()
		p.Host.IOGPUWiredLimitBytes = 48 * 1024 * 1024 * 1024
		if got := DeriveGPUFacts(p, seatbelt).IOGPUWiredLimitBytes; got != 48*1024*1024*1024 {
			t.Fatalf("iogpu_wired_limit_bytes = %d, want the configured limit passed through", got)
		}
	})

	t.Run("recommended working set passes through from the device", func(t *testing.T) {
		if got := DeriveGPUFacts(realGPU(), seatbelt).RecommendedMaxWorkingSetBytes; got != 55662788608 {
			t.Fatalf("recommended_max_working_set_bytes = %d, want the MTLDevice figure", got)
		}
	})

	// sandbox_gpu_supported is scoped to the selected backend: same host, same
	// probe, different answer under the vm rung — because a Linux guest has no
	// Metal device to open, so the grant could not take effect there.
	t.Run("sandbox_gpu_supported is backend-scoped", func(t *testing.T) {
		vm := DeriveGPUFacts(realGPU(), stubBackend{VMBackendName, true})
		if !vm.MetalAvailable {
			t.Fatal("the host's metal_available must not depend on the backend")
		}
		if vm.SandboxGPUSupported {
			t.Fatal("sandbox_gpu_supported true under the vm rung")
		}
		down := DeriveGPUFacts(realGPU(), stubBackend{ExecShimBackendName, false})
		if down.SandboxGPUSupported {
			t.Fatal("sandbox_gpu_supported true with the selected backend unavailable")
		}
	})
}

// assertClearedFacts asserts the fail-closed shape: metal_available false and every
// node-facing figure zeroed, so a consumer that reads a number while ignoring the
// verdict finds nothing usable rather than a plausible lie.
func assertClearedFacts(t *testing.T, got GPUFacts) {
	t.Helper()
	if got.MetalAvailable {
		t.Fatal("metal_available true")
	}
	if got.SandboxGPUSupported {
		t.Fatal("sandbox_gpu_supported true with no usable Metal device")
	}
	if got.ChipBrand != "" || got.ChipFamily != "" {
		t.Fatalf("chip facts not cleared: %q/%q", got.ChipBrand, got.ChipFamily)
	}
	if got.MemBytes != 0 || got.IOGPUWiredLimitBytes != 0 || got.RecommendedMaxWorkingSetBytes != 0 {
		t.Fatalf("numeric facts not cleared: mem=%d wired=%d ws=%d",
			got.MemBytes, got.IOGPUWiredLimitBytes, got.RecommendedMaxWorkingSetBytes)
	}
	if got.Reason == "" {
		t.Fatal("Reason empty: an unavailable GPU must still say why")
	}
}

// TestChipFamily pins the family derivation, including the case that must yield
// nothing: an invented family would become a node label that schedules work onto
// the wrong hardware.
func TestChipFamily(t *testing.T) {
	cases := []struct{ brand, want string }{
		{"Apple M1 Ultra", "M1"},
		{"Apple M2", "M2"},
		{"Apple M4 Max", "M4"},
		{"Apple M10 Pro", "M10"},
		{"Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz", ""},
		{"", ""},
		{"Apple Max", ""},
	}
	for _, tc := range cases {
		t.Run(tc.brand, func(t *testing.T) {
			if got := chipFamily(tc.brand); got != tc.want {
				t.Fatalf("chipFamily(%q) = %q, want %q", tc.brand, got, tc.want)
			}
		})
	}
}
