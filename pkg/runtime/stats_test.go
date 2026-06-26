package runtime

import (
	"context"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestListPodStatsMapsFootprint is the M2.8 ListPodStats proof: a metered pod's
// ri_phys_footprint working set maps onto PodStats.containers[].memory.working_set_bytes
// (the typed wire form of the M2.5 sampler); empty pod_id returns all metered pods;
// a pod with no memory sampler (unmetered) is omitted.
func TestListPodStatsMapsFootprint(t *testing.T) {
	w := newBlockingWaiter()
	ff := runtimeFakeFootprinter{bytes: 4 << 20} // 4 MiB per container PID
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal // no real signals

	// Two metered pods (one via the typed field, one via the legacy annotation, to
	// prove both feed the sampler gate) + one unmetered pod (no limit → no sampler).
	typed := hostBinBox("pod-a")
	typed.MemoryLimitBytes = 100 << 20 // no breach
	annotated := hostBinBox("pod-b")
	annotated.Annotations = map[string]string{memoryLimitAnnotation: "104857600"}
	mustCreatePod(t, rt, typed)
	mustCreatePod(t, rt, annotated)
	mustCreatePod(t, rt, hostBinBox("pod-unmetered"))

	// empty pod_id returns all METERED pods, each with the per-container working set;
	// the unmetered pod is omitted. (Container working set is sampled at request time
	// from the Footprinter, so it is populated immediately.)
	var resp *runtimev1.ListPodStatsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ = rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{})
		if len(resp.GetPodStats()) == 2 && allHaveContainerWorkingSet(resp.GetPodStats()) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(resp.GetPodStats()) != 2 {
		t.Fatalf("ListPodStats(all) = %d pods, want 2 (metered only)", len(resp.GetPodStats()))
	}

	byID := map[string]*runtimev1.PodStats{}
	for _, ps := range resp.GetPodStats() {
		byID[ps.GetPodId()] = ps
	}
	if byID["pod-unmetered"] != nil {
		t.Error("an unmetered pod (no memory limit → no sampler) must be omitted from ListPodStats")
	}
	for _, id := range []string{"pod-a", "pod-b"} {
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

	// An unmetered or unknown pod_id yields an empty list (omitted / gone), not an error.
	if r, _ := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "pod-unmetered"}); len(r.GetPodStats()) != 0 {
		t.Errorf("ListPodStats(unmetered) = %d pods, want 0", len(r.GetPodStats()))
	}
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
