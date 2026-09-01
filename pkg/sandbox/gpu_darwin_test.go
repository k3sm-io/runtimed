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

import (
	"strings"
	"testing"
)

// TestProbeGPULiveShape runs the real probe on whatever darwin host the tests are
// on. It deliberately asserts only host-independent properties — the probe returns,
// it names a reason, and its fields are mutually consistent — because the verdict
// itself is hardware-dependent (a GPU Mac, a VZ guest, and a CGO_ENABLED=0 build
// legitimately give three different answers, and a test that demanded one of them
// would be a test of the test host).
//
// What it does buy: the cgo shim actually links and executes, and it does so
// without raising into the daemon's process — the one property no fake-seam test
// can cover.
func TestProbeGPULiveShape(t *testing.T) {
	got := ProbeGPU()

	if got.Metal.Reason == "" {
		t.Fatal("the probe returned no reason token")
	}
	if got.Metal.Functional && got.Metal.Reason != MetalReasonOK {
		t.Fatalf("functional probe reported reason %q, want %q", got.Metal.Reason, MetalReasonOK)
	}
	if got.Metal.Paravirtual && got.Metal.Available() {
		t.Fatal("a paravirtual device was reported available")
	}
	if got.Metal.Functional && got.Metal.RecommendedMaxWorkingSetBytes == 0 {
		t.Fatal("a functional Metal device reported a zero working-set ceiling")
	}
	// The host facts come from public sysctls, so they are readable on every darwin
	// host regardless of the GPU verdict.
	if got.Host.MemBytes == 0 {
		t.Fatal("hw.memsize read as 0 on a darwin host")
	}
	if got.Host.ChipBrand == "" {
		t.Fatal("machdep.cpu.brand_string read as empty on a darwin host")
	}
	if strings.HasPrefix(got.Host.ChipBrand, "Apple ") && got.Host.ChipFamily == "" {
		t.Fatalf("no chip family derived from an Apple brand string %q", got.Host.ChipBrand)
	}
	t.Logf("live probe: reason=%s functional=%v paravirtual=%v device=%q chip=%q family=%q mem=%d wired=%d ws=%d",
		got.Metal.Reason, got.Metal.Functional, got.Metal.Paravirtual, got.Metal.DeviceName,
		got.Host.ChipBrand, got.Host.ChipFamily, got.Host.MemBytes,
		got.Host.IOGPUWiredLimitBytes, got.Metal.RecommendedMaxWorkingSetBytes)
}
