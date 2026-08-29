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
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestListPodStatsMapsFootprint is the M2.8 ListPodStats proof: a pod's
// ri_phys_footprint working set maps onto PodStats.containers[].memory.working_set_bytes
// (the typed wire form of the M2.5 sampler); empty pod_id returns every pod,
// INCLUDING one with no memory limit (the limit selects OOM enforcement, not
// metering — a `kubectl top` that omitted unlimited pods would lie by omission).
func TestListPodStatsMapsFootprint(t *testing.T) {
	w := newBlockingWaiter()
	ff := runtimeFakeFootprinter{bytes: 4 << 20} // 4 MiB per container PID
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal // no real signals

	// Two OOM-enforced pods (one via the typed field, one via the legacy annotation,
	// to prove both feed the limit gate) + one unlimited pod, which is metered too.
	typed := hostBinBox(rt, "pod-a")
	typed.MemoryLimitBytes = 100 << 20 // no breach
	annotated := hostBinBox(rt, "pod-b")
	annotated.Annotations = map[string]string{memoryLimitAnnotation: "104857600"}
	mustCreatePod(t, rt, typed)
	mustCreatePod(t, rt, annotated)
	mustCreatePod(t, rt, hostBinBox(rt, "pod-unlimited"))

	// empty pod_id returns EVERY pod, each with the per-container working set.
	// (Container working set is sampled at request time from the Footprinter, so it
	// is populated immediately.)
	var resp *runtimev1.ListPodStatsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ = rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{})
		if len(resp.GetPodStats()) == 3 && allHaveContainerWorkingSet(resp.GetPodStats()) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(resp.GetPodStats()) != 3 {
		t.Fatalf("ListPodStats(all) = %d pods, want 3 (every pod is metered)", len(resp.GetPodStats()))
	}

	byID := map[string]*runtimev1.PodStats{}
	for _, ps := range resp.GetPodStats() {
		byID[ps.GetPodId()] = ps
	}
	if byID["pod-unlimited"] == nil {
		t.Error("a pod without a memory limit must still be metered — the limit gates OOM, not metering")
	}
	for _, id := range []string{"pod-a", "pod-b", "pod-unlimited"} {
		ps := byID[id]
		if ps == nil {
			t.Fatalf("metered pod %s missing from ListPodStats", id)
		}
		if ps.GetNamespace() != "default" || ps.GetName() != "p" {
			t.Errorf("%s pod reference = %s/%s, want default/p", id, ps.GetNamespace(), ps.GetName())
		}
		if len(ps.GetContainers()) != 1 {
			t.Fatalf("%s containers = %d, want 1", id, len(ps.GetContainers()))
		}
		c0 := ps.GetContainers()[0]
		if c0.GetName() != "main" {
			t.Errorf("%s container name = %q, want main", id, c0.GetName())
		}
		if got := c0.GetMemory().GetWorkingSetBytes(); got != 4<<20 {
			t.Errorf("%s container working_set_bytes = %d, want %d (ri_phys_footprint)", id, got, 4<<20)
		}
	}

	// pod_id set returns just that pod.
	one, _ := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "pod-a"})
	if len(one.GetPodStats()) != 1 || one.GetPodStats()[0].GetPodId() != "pod-a" {
		t.Fatalf("ListPodStats(pod-a) = %+v, want exactly pod-a", one.GetPodStats())
	}

	// An unknown pod_id yields an empty list (gone), not an error.
	if r, _ := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "ghost"}); len(r.GetPodStats()) != 0 {
		t.Errorf("ListPodStats(unknown) = %d pods, want 0", len(r.GetPodStats()))
	}

	w.release(1001)
	w.release(1002)
	w.release(1003)
}

// allHaveContainerWorkingSet reports whether every PodStats has a sole container
// carrying a non-zero working set (the request-time Footprinter sample).
func allHaveContainerWorkingSet(stats []*runtimev1.PodStats) bool {
	for _, ps := range stats {
		if len(ps.GetContainers()) == 0 || ps.GetContainers()[0].GetMemory().GetWorkingSetBytes() == 0 {
			return false
		}
	}
	return true
}

// fakeRUsager is the richer supervisor.RUsager seam (memory AND cumulative CPU
// from one sample), so the joint stats path is exercised with no syscall. cpu is
// keyed by pid so a "restart" (a different pid) can be simulated.
type fakeRUsager struct {
	bytes uint64
	cpu   map[int]uint64
}

func (f fakeRUsager) Footprint(int) (uint64, error) { return f.bytes, nil }

func (f fakeRUsager) RUsage(pid int) (supervisor.RUsage, error) {
	return supervisor.RUsage{PhysFootprintBytes: f.bytes, CPUTimeNanos: f.cpu[pid]}, nil
}

// TestListPodStatsCarriesCPUJointlyWithMemory is the B14 producer proof: a sampled
// pod's ContainerStats and PodStats carry CPU **and** memory together, sourced from
// the one rusage_info_v2 sample, and the CPU value is a monotone cumulative counter.
//
// The joint part is the point. metrics-server has no memory-only path: its resource
// decoder drops a whole pod when any container's CumulativeCPUUsed or MemoryUsage is
// zero (pkg/scraper/client/resource/decode.go), so a memory-only PodStats produces an
// EMPTY `kubectl top` plus scrape-error noise — strictly worse than serving nothing.
// A field-presence check would not catch that; this asserts the pair.
func TestListPodStatsCarriesCPUJointlyWithMemory(t *testing.T) {
	w := newBlockingWaiter()
	fr := fakeRUsager{bytes: 4 << 20, cpu: map[int]uint64{1001: 7_000_000_000}}
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: fr})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal

	mustCreatePod(t, rt, hostBinBox(rt, "pod-cpu"))

	var ps *runtimev1.PodStats
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "pod-cpu"})
		if len(resp.GetPodStats()) == 1 && resp.GetPodStats()[0].GetMemory().GetWorkingSetBytes() > 0 {
			ps = resp.GetPodStats()[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ps == nil {
		t.Fatal("pod-cpu never appeared in ListPodStats with a working set")
	}

	// Pod level: BOTH samples present.
	if got := ps.GetMemory().GetWorkingSetBytes(); got == 0 {
		t.Error("pod memory working_set_bytes = 0, want the sampler's footprint")
	}
	if got := ps.GetCpu().GetUsageCoreNanoSeconds(); got != 7_000_000_000 {
		t.Errorf("pod cpu usage_core_nano_seconds = %d, want 7000000000", got)
	}

	// Container level: BOTH samples present, from the same rusage read.
	if len(ps.GetContainers()) != 1 {
		t.Fatalf("containers = %d, want 1", len(ps.GetContainers()))
	}
	c0 := ps.GetContainers()[0]
	if got := c0.GetMemory().GetWorkingSetBytes(); got != 4<<20 {
		t.Errorf("container working_set_bytes = %d, want %d", got, 4<<20)
	}
	if got := c0.GetCpu().GetUsageCoreNanoSeconds(); got != 7_000_000_000 {
		t.Errorf("container cpu usage_core_nano_seconds = %d, want 7000000000", got)
	}

	w.release(1001)
}

// TestListPodStatsWithoutRUsagerLeavesCPUUnset pins the fail-quiet half of the
// contract: a Footprinter that cannot report CPU (a memory-only injection) leaves
// every CPU field ABSENT rather than reporting a zero. Absent is what lets the k3sm
// provider withhold the pod from /metrics/resource; a zero would look like an idle
// pod and be published as an incomplete sample.
func TestListPodStatsWithoutRUsagerLeavesCPUUnset(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: runtimeFakeFootprinter{bytes: 4 << 20}})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal

	mustCreatePod(t, rt, hostBinBox(rt, "pod-nocpu"))

	var ps *runtimev1.PodStats
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "pod-nocpu"})
		if len(resp.GetPodStats()) == 1 && resp.GetPodStats()[0].GetMemory().GetWorkingSetBytes() > 0 {
			ps = resp.GetPodStats()[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ps == nil {
		t.Fatal("pod-nocpu never appeared in ListPodStats with a working set")
	}
	if ps.GetCpu() != nil {
		t.Errorf("pod cpu = %+v, want nil (a CPU-blind sampler reports no CPU, not zero)", ps.GetCpu())
	}
	if len(ps.GetContainers()) != 1 {
		t.Fatalf("containers = %d, want 1", len(ps.GetContainers()))
	}
	if c := ps.GetContainers()[0].GetCpu(); c != nil {
		t.Errorf("container cpu = %+v, want nil", c)
	}

	w.release(1001)
}
