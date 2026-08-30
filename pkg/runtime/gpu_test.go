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
	"context"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// seatbeltBackend is an available backend that reports the REAL Seatbelt rung's
// name, because sandbox_gpu_supported is scoped to the selected backend by NAME:
// the generic fakeBackend ("fake") is correctly not GPU-capable, so a test that
// wants the capable case must say which rung it is standing in.
type seatbeltBackend struct{ available bool }

func (b seatbeltBackend) Available() bool { return b.available }
func (b seatbeltBackend) Name() string    { return sandbox.ExecShimBackendName }
func (b seatbeltBackend) WrapCommand(_ context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	return "/fake/shim", argv, func() error { return nil }, nil
}

// gpuHost is a probe observation from a healthy GPU host.
func gpuHost() sandbox.GPUProbeResult {
	return sandbox.GPUProbeResult{
		Metal: sandbox.MetalStatus{
			Functional:                    true,
			DeviceName:                    "Apple M1 Ultra",
			RecommendedMaxWorkingSetBytes: 55662788608,
			Reason:                        sandbox.MetalReasonOK,
		},
		Host: sandbox.HostFacts{
			ChipBrand:  "Apple M1 Ultra",
			ChipFamily: "M1",
			MemBytes:   68719476736,
		},
	}
}

// TestGetRuntimeInfoGPUFacts is acceptance M8.2-a3 at the RPC boundary: the facts a
// consumer actually receives, driven end to end by the fake probe seam. The
// derivation itself is pinned in pkg/sandbox; what this adds is that the daemon
// probes once, holds the result immutably, and stamps it onto every response.
func TestGetRuntimeInfoGPUFacts(t *testing.T) {
	t.Run("healthy GPU host advertises the facts", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{
			Backend:  seatbeltBackend{available: true},
			GPUProbe: gpuHost,
		})
		gpu := runtimeInfoGPU(t, rt)
		if !gpu.GetMetalAvailable() || !gpu.GetSandboxGpuSupported() {
			t.Fatalf("metal_available=%v sandbox_gpu_supported=%v, want both true", gpu.GetMetalAvailable(), gpu.GetSandboxGpuSupported())
		}
		if gpu.GetChipBrand() != "Apple M1 Ultra" || gpu.GetChipFamily() != "M1" {
			t.Fatalf("chip facts = %q/%q", gpu.GetChipBrand(), gpu.GetChipFamily())
		}
		if gpu.GetRecommendedMaxWorkingSetBytes() != 55662788608 {
			t.Fatalf("recommended_max_working_set_bytes = %d", gpu.GetRecommendedMaxWorkingSetBytes())
		}
		if gpu.GetIogpuWiredLimitBytes() != 0 {
			t.Fatalf("iogpu_wired_limit_bytes = %d, want the 0 sentinel", gpu.GetIogpuWiredLimitBytes())
		}
	})

	// The case this whole seam exists for: inside a VZ guest (a GitHub-hosted macOS
	// runner included) MTLCreateSystemDefaultDevice is non-nil, so a nil-check would
	// advertise a GPU here. The node must report none, with every figure cleared.
	t.Run("VZ paravirtual host advertises nothing", func(t *testing.T) {
		probe := gpuHost()
		probe.Metal.Paravirtual = true
		probe.Metal.DeviceName = "Apple Paravirtual device"
		probe.Metal.Reason = sandbox.MetalReasonParavirtual

		rt := newTestRuntime(t, Deps{
			Backend:  seatbeltBackend{available: true},
			GPUProbe: func() sandbox.GPUProbeResult { return probe },
		})
		gpu := runtimeInfoGPU(t, rt)
		if gpu.GetMetalAvailable() || gpu.GetSandboxGpuSupported() {
			t.Fatal("a VZ paravirtual host advertised a GPU")
		}
		if gpu.GetChipBrand() != "" || gpu.GetMemBytes() != 0 || gpu.GetRecommendedMaxWorkingSetBytes() != 0 {
			t.Fatalf("node-facing fields not cleared: %v", gpu)
		}
	})

	// sandbox_gpu_supported is a property of the SELECTED backend, so the same
	// hardware answers differently under a rung whose profile cannot carry the
	// Metal allow-set — while metal_available, a host fact, does not move.
	t.Run("non-Seatbelt backend still reports the host but grants nothing", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{
			Backend:  fakeBackend{available: true},
			GPUProbe: gpuHost,
		})
		gpu := runtimeInfoGPU(t, rt)
		if !gpu.GetMetalAvailable() {
			t.Fatal("metal_available changed with the backend; it is a host fact")
		}
		if gpu.GetSandboxGpuSupported() {
			t.Fatal("sandbox_gpu_supported true on a backend that cannot express the Metal allow-set")
		}
	})

	// A daemon that CAN probe always reports the message, so an absent gpu keeps its
	// distinct meaning on the wire ("this daemon does not report GPU facts").
	t.Run("no-GPU host still reports a present message", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		info, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if info.GetGpu() == nil {
			t.Fatal("GetRuntimeInfo omitted the gpu message; absent means \"daemon cannot report\", not \"no GPU\"")
		}
		if info.GetGpu().GetMetalAvailable() {
			t.Fatal("metal_available true with no usable device")
		}
	})

	// Probed EXACTLY ONCE at construction: the probe is a GPU driver round trip, so
	// a per-RPC probe would put a compile+dispatch on the handshake path.
	t.Run("probed once at construction, not per RPC", func(t *testing.T) {
		var mu sync.Mutex
		calls := 0
		rt := newTestRuntime(t, Deps{
			Backend: seatbeltBackend{available: true},
			GPUProbe: func() sandbox.GPUProbeResult {
				mu.Lock()
				calls++
				mu.Unlock()
				return gpuHost()
			},
		})
		for i := 0; i < 3; i++ {
			runtimeInfoGPU(t, rt)
		}
		mu.Lock()
		defer mu.Unlock()
		if calls != 1 {
			t.Fatalf("GPU probe ran %d times, want exactly 1", calls)
		}
	})

	// Each response carries its OWN message: the daemon holds plain data and stamps
	// a fresh proto, so one caller mutating its copy cannot corrupt another's.
	t.Run("each response gets a fresh message", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{
			Backend:  seatbeltBackend{available: true},
			GPUProbe: gpuHost,
		})
		first := runtimeInfoGPU(t, rt)
		first.ChipBrand = "mutated by a caller"
		if second := runtimeInfoGPU(t, rt); second.GetChipBrand() != "Apple M1 Ultra" {
			t.Fatalf("a caller's mutation leaked into the next response: %q", second.GetChipBrand())
		}
	})
}

// runtimeInfoGPU calls GetRuntimeInfo and returns its gpu message.
func runtimeInfoGPU(t *testing.T, rt *Runtime) *runtimev1.GPUFacts {
	t.Helper()
	info, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeInfo: %v", err)
	}
	gpu := info.GetGpu()
	if gpu == nil {
		t.Fatal("GetRuntimeInfo returned no gpu facts")
	}
	return gpu
}
