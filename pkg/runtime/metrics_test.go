package runtime

import (
	"context"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// runtimeFakeFootprinter reports a fixed footprint for any pid (the supervisor
// Footprinter seam), so the sampler's OOM/metering paths are exercised with no
// real proc_pid_rusage.
type runtimeFakeFootprinter struct{ bytes uint64 }

func (f runtimeFakeFootprinter) Footprint(int) (uint64, error) { return f.bytes, nil }

// TestCreatePodOOMKilled is the runtime-level M2.5 OOM proof: a pod whose sampled
// footprint exceeds its memory limit is SIGKILLed and its ContainerStatus reports
// OOMKilled. The sampler mechanics (sample/breach-once/stop) are proven in
// supervisor.TestMemorySampler*.
func TestCreatePodOOMKilled(t *testing.T) {
	w := newBlockingWaiter()
	w.code, w.sig = 137, 9                       // a SIGKILLed container reports signal 9
	ff := runtimeFakeFootprinter{bytes: 8 << 20} // 8 MiB, over the limit
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 5 * time.Millisecond

	// The SIGKILL from the OOM path releases the (fake) waiter so the container
	// actually exits, driving the reaper → OOMKilled-reason path.
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal

	box := hostBinBox("pod-oom")
	box.Annotations = map[string]string{memoryLimitAnnotation: "1048576"} // 1 MiB limit
	mustCreatePod(t, rt, box)

	reason := waitTerminatedReason(t, rt, "pod-oom", 3*time.Second)
	if reason != "OOMKilled" {
		t.Fatalf("terminated reason = %q, want OOMKilled", reason)
	}
	if !rec.sawKill() {
		t.Error("OOM breach did not SIGKILL the pod")
	}
}

// TestCreatePodNoLimitNoOOM confirms a pod with no memory limit runs no sampler
// and is never OOMKilled even with a huge footprint (metering is limit-driven in
// M2; existing no-limit pods are unaffected).
func TestCreatePodNoLimitNoOOM(t *testing.T) {
	w := newBlockingWaiter()
	ff := runtimeFakeFootprinter{bytes: 64 << 20}
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rec := &recordingSignalGroup{}
	rt.signalGroup = rec.signal

	mustCreatePod(t, rt, hostBinBox("pod-nolimit")) // no memory-limit annotation

	// Give a would-be sampler time to (not) fire.
	time.Sleep(50 * time.Millisecond)
	if rec.sawKill() {
		t.Error("a pod without a memory limit must not be OOMKilled")
	}
	if _, ok := rt.PodMetrics("pod-nolimit"); ok {
		t.Error("a pod without a memory limit has no sampler, so PodMetrics is ok=false")
	}
	w.release(1001)
}

// TestPodMetricsSurfacesFootprint is the runtime-level M2.5 Summary-API proof: a
// metered pod's latest ri_phys_footprint is surfaced via PodMetrics (the kubectl
// top source the provider wires to the kubelet Summary endpoint in Wave 3).
func TestPodMetricsSurfacesFootprint(t *testing.T) {
	w := newBlockingWaiter()
	ff := runtimeFakeFootprinter{bytes: 4 << 20} // 4 MiB
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal // no real signals

	box := hostBinBox("pod-top")
	box.Annotations = map[string]string{memoryLimitAnnotation: "104857600"} // 100 MiB, no breach
	mustCreatePod(t, rt, box)

	deadline := time.Now().Add(2 * time.Second)
	var m PodMetrics
	var ok bool
	for time.Now().Before(deadline) {
		if m, ok = rt.PodMetrics("pod-top"); ok && m.WorkingSetBytes > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ok || m.WorkingSetBytes != 4<<20 {
		t.Fatalf("PodMetrics = %+v ok=%v, want WorkingSetBytes=%d", m, ok, 4<<20)
	}
	if m.PodID != "pod-top" {
		t.Errorf("PodMetrics PodID = %q, want pod-top", m.PodID)
	}
	if _, ok := rt.PodMetrics("nope"); ok {
		t.Error("PodMetrics(unknown) should report ok=false")
	}

	w.release(1001)
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-top"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
}

// waitTerminatedReason polls GetPodStatus until the (sole) container terminates,
// returning its reason, or fails on timeout.
func waitTerminatedReason(t *testing.T, rt *Runtime, podID string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
		cs := gs.GetStatus().GetContainerStatuses()
		if len(cs) == 1 {
			if term := cs[0].GetState().GetTerminated(); term != nil {
				return term.GetReason()
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("container in pod %s did not terminate within %s", podID, timeout)
	return ""
}
