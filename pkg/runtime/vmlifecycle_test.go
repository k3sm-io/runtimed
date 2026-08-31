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
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// THE VM POD'S HOST-SIDE LIFECYCLE, with the boot faked at the backend seam.
//
// pkg/sandbox owns the boot state machine and tests it there; what is asserted
// here is the RUNTIME's half — that a booted guest becomes a registered Running
// pod, that DeletePod tears down the helper instead of iterating containerProcs a
// vm pod does not have, that shutdown stops helpers a host pod would survive, and
// that a helper dying under a live pod is noticed rather than leaving it Running
// forever.

// vmPodBox builds a minimal vm-routed PodBox with a termination grace, which the
// spine must thread to the helper as its stop budget.
//
// It takes the runtime for the same reason hostBinBox does: data_volume_path is
// accepted only when it is byte-equal to one of this pod's own derived spellings
// (B142), and the runtime under test is rooted at a t.TempDir().
func vmPodBox(rt *Runtime, podID string, graceSeconds int64) *runtimev1.PodBox {
	dataVol := filepath.Join(rt.cache.PodsRoot(), podID)
	if id, err := image.ParsePodID(podID); err == nil {
		dataVol = rt.cache.PodDir(id)
	}
	return &runtimev1.PodBox{
		PodId:     podID,
		Namespace: "default",
		Name:      "p",
		SandboxProfile: &runtimev1.SandboxProfile{
			Backend:        runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
			DataVolumePath: dataVol,
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			{Name: "main", Image: "docker.io/library/alpine:3"},
		},
		TerminationGracePeriodSeconds: graceSeconds,
	}
}

// bootedVMRuntime returns a runtime whose vm backend boots successfully, plus
// that backend and a created, Running vm pod.
func bootedVMRuntime(t *testing.T, podID string, graceSeconds int64) (*Runtime, *fakeVMBackend, *runtimev1.PodBox) {
	t.Helper()
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{VMBackend: vmb})
	box := vmPodBox(rt, podID, graceSeconds)
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	if resp.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Fatalf("phase = %v, want RUNNING — a booted guest is a running pod", resp.GetStatus().GetPhase())
	}
	return rt, vmb, box
}

// TestCreateVMPodAssemblesARunningPod asserts a successful boot produces a
// registered vm pod with the vm-shaped supervision, and that the spec the backend
// received carries the paths and the grace only the runtime can derive.
func TestCreateVMPodAssemblesARunningPod(t *testing.T) {
	rt, vmb, box := bootedVMRuntime(t, "pod-vm-1", 12)

	n, spec := vmb.created()
	if n != 1 {
		t.Fatalf("CreateVM called %d times, want 1", n)
	}
	wantPodDir, err := rt.podDir(box.GetPodId())
	if err != nil {
		t.Fatalf("podDir: %v", err)
	}
	if spec.PodDir != wantPodDir {
		t.Errorf("VMSpec.PodDir = %q, want the runtime's own derivation %q", spec.PodDir, wantPodDir)
	}
	wantSock, err := guestAgentSocket(rt.cfg.Root, box.GetPodId())
	if err != nil {
		t.Fatalf("guestAgentSocket: %v", err)
	}
	if spec.AgentSocketPath != wantSock {
		// The helper binds this and the daemon's Exec/Logs route dials it; two
		// derivations that could disagree is exactly what stamping prevents.
		t.Errorf("VMSpec.AgentSocketPath = %q, want %q (the same string GuestDialer reaches)", spec.AgentSocketPath, wantSock)
	}
	if spec.StopGrace != 12*time.Second {
		t.Errorf("VMSpec.StopGrace = %s, want 12s — the pod's grace must reach the helper, or the daemon and the helper run two independent timers", spec.StopGrace)
	}

	t.Run("the pod is registered and reads as a vm pod", func(t *testing.T) {
		p, ok := rt.lookupPod(box.GetPodId())
		if !ok {
			t.Fatal("the pod is not registered")
		}
		if !p.isVM() {
			t.Error("the assembled pod does not report the vm backend, so every vm route (Exec, GetLogs, stats, teardown) would take the host-process branch")
		}
	})

	t.Run("no host memory sampler is armed", func(t *testing.T) {
		// A vm pod's ceiling is the hypervisor's memorySize and its OOM truth is
		// the guest cgroup's; a host sample would meter the vmhost helper (B107).
		p, _ := rt.lookupPod(box.GetPodId())
		p.mu.Lock()
		sampler, cancel := p.memSampler, p.memCancel
		p.mu.Unlock()
		if sampler != nil || cancel != nil {
			t.Error("a vm pod was armed with the host memory sampler")
		}
	})

	t.Run("the pod dir exists for the helper to be pointed into", func(t *testing.T) {
		if _, err := rt.podDir(box.GetPodId()); err != nil {
			t.Fatalf("podDir: %v", err)
		}
	})
}

// TestDeleteVMPodStopsTheHelper is the TEARDOWN gate. Without the vm branch,
// DeletePod's two-phase container teardown iterates a container list a vm pod
// does not have — it would silently do nothing and leave the helper running with
// a live machine for a pod the cluster has deleted.
func TestDeleteVMPodStopsTheHelper(t *testing.T) {
	rt, vmb, box := bootedVMRuntime(t, "pod-vm-2", 9)

	resp, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: box.GetPodId()})
	if err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if resp == nil {
		t.Fatal("DeletePod returned no response")
	}
	stops := vmb.stops()
	if len(stops) != 1 || stops[0].podID != box.GetPodId() {
		t.Fatalf("StopVM calls = %v, want exactly one for %s", stops, box.GetPodId())
	}
	if stops[0].grace != 9*time.Second {
		t.Errorf("StopVM grace = %s, want the pod's own 9s (the ONE budget both ends share)", stops[0].grace)
	}
	if _, ok := rt.lookupPod(box.GetPodId()); ok {
		t.Error("the pod is still registered after DeletePod")
	}

	t.Run("a second delete is idempotent and stops nothing more", func(t *testing.T) {
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: box.GetPodId()}); err != nil {
			t.Fatalf("second DeletePod: %v", err)
		}
		if got := len(vmb.stops()); got != 1 {
			t.Errorf("StopVM called %d times across two deletes, want 1", got)
		}
	})

	t.Run("an expected teardown is not reported as a crash", func(t *testing.T) {
		// StopVM closes the helper's exit edge, exactly as a real stop does. The
		// exit watch must lose that race to the supervision cancel, or every vm
		// pod deletion would publish a spurious Failed status on its way out.
		//
		// The pod is already deregistered, so the observable is that nothing
		// panicked and the watch returned; a Failed publish for a deleted pod is
		// unobservable by design. What this pins is that the ordering in
		// DeletePod (stop, THEN cancel) has not been reversed.
		time.Sleep(50 * time.Millisecond)
	})
}

// TestCloseStopsVMHelpersButNotHostPods pins the two OPPOSITE shutdown contracts
// in one place, because they are easy to conflate and the conflation is silent
// either way: a host pod's processes must SURVIVE `launchctl kickstart -k`, and a
// vm pod's helper must NOT ("no VM outlives the binary that booted it").
func TestCloseStopsVMHelpersButNotHostPods(t *testing.T) {
	vmb := &fakeVMBackend{available: true, bootOK: true}
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{VMBackend: vmb, Spawner: sp, Waiter: w})

	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: vmPodBox(rt, "pod-vm-3", 5)}); err != nil {
		t.Fatalf("CreatePod (vm): %v", err)
	}
	hostBox := hostBinBox(rt, "pod-host-1")
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBox}); err != nil {
		t.Fatalf("CreatePod (host): %v", err)
	}
	sp.mu.Lock()
	spawnedBefore := len(sp.specs)
	sp.mu.Unlock()

	_ = rt.Close()

	if got := vmb.stopAlls(); got != 1 {
		t.Errorf("StopAllVMs called %d times on Close, want 1; a helper left running holds a machine nothing on the node can reach", got)
	}
	sp.mu.Lock()
	spawnedAfter := len(sp.specs)
	sp.mu.Unlock()
	if spawnedAfter != spawnedBefore {
		t.Errorf("Close spawned host processes (%d -> %d); host pods survive a daemon restart by design", spawnedBefore, spawnedAfter)
	}
	if _, ok := rt.lookupPod("pod-host-1"); !ok {
		t.Error("Close forgot a host pod; the registry must stay intact because those pods are still running")
	}
}

// TestCloseStopsVMHelpersWithNoRegisteredPods asserts the shutdown sweep runs even
// when the pod registry is empty. The registry and the backend's handle map are
// different records, and a helper whose CreatePod failed to register is exactly
// the one worth catching.
func TestCloseStopsVMHelpersWithNoRegisteredPods(t *testing.T) {
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{VMBackend: vmb})
	if err := rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := vmb.stopAlls(); got != 1 {
		t.Errorf("StopAllVMs called %d times with no registered pods, want 1", got)
	}
}

// TestStartupSweepReapsOrphanVMs asserts the vm orphan sweep runs exactly once,
// before pods are served, on the same hook the host-process reap uses.
func TestStartupSweepReapsOrphanVMs(t *testing.T) {
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{VMBackend: vmb})

	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	if got := vmb.reaps(); got != 1 {
		t.Fatalf("ReapOrphanVMs called %d times, want 1", got)
	}
	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatalf("second ReapOrphanedPods: %v", err)
	}
	if got := vmb.reaps(); got != 1 {
		t.Errorf("ReapOrphanVMs called %d times across two calls, want 1 (the sweep is exactly-once per Runtime)", got)
	}
}

// TestVMHelperExitFailsTheRunningPod is the POST-READY EXIT WATCH gate.
//
// Everything that reports a vm pod's health flows through the guest agent, and
// the agent is reached through the helper — so when the hypervisor dies or the
// guest panics, a pod with no exit watch simply stops being updated and sits at
// Running forever, with the scheduler believing it healthy.
func TestVMHelperExitFailsTheRunningPod(t *testing.T) {
	rt, vmb, box := bootedVMRuntime(t, "pod-vm-4", 5)

	vmb.killHelper(box.GetPodId())

	deadline := time.Now().Add(3 * time.Second)
	var phase runtimev1.PodPhase
	for time.Now().Before(deadline) {
		resp, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: box.GetPodId()})
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		phase = resp.GetStatus().GetPhase()
		if phase == runtimev1.PodPhase_POD_PHASE_FAILED {
			if got := resp.GetStatus().GetReason(); got != "VMHostExited" {
				t.Errorf("reason = %q, want VMHostExited", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the pod stayed at %v after its helper exited; a dead machine must not leave a pod Running", phase)
}

// TestRestartContainerRefusesAVMPod asserts the vm fork is at the TOP of
// RestartContainer, before any containerProc is touched.
//
// A vm pod's containers are guest processes, so every line of the host path
// operates on state it does not have. Restarting one inside a running guest needs
// a guest/v1 verb that does not exist, so the honest answer is a typed
// Unimplemented — never a silent no-op that would report a bumped restart_count
// for a container nothing restarted.
func TestRestartContainerRefusesAVMPod(t *testing.T) {
	rt, _, box := bootedVMRuntime(t, "pod-vm-5", 5)

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
		PodId: box.GetPodId(), Container: "main",
	})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if resp.GetStatus() != nil {
		t.Error("a refused restart returned a container status; a caller could read that as a completed restart")
	}
	if got := codes.Code(resp.GetError().GetCode()); got != codes.Unimplemented {
		t.Errorf("code = %v, want %v", got, codes.Unimplemented)
	}
	if resp.GetError().GetMessage() == "" {
		t.Error("the refusal carries no message")
	}
	_ = status.New(codes.Unimplemented, "")
}

// TestVMTeardownCancelsSupervisionBeforeStopping pins the ordering that keeps a
// DELIBERATE teardown from being reported as a crash.
//
// FOUND BY THE LIVE SMOKE, NOT BY REVIEW. A helper's exit is observed by two
// watchers — the stop's own GracefulStop and watchVMHelperExit, whose whole job
// is to fail a pod whose machine died under it — and cancelling supervision
// AFTER the stop left which one won to chance. On the rig the watcher won
// routinely: an ordinary DeletePod logged "the vm host helper exited while its
// pod was running; the guest is gone" and published a Failed status for a pod the
// operator had just asked to delete. A provider consuming that event sees a
// crash where there was none.
//
// The assertion is on the ORDER, not on the outcome, and deliberately so: an
// outcome test ("the pod was not published Failed") passes on a racy
// implementation most of the time, which is the worst possible test for a race.
// Contexts are monotonic, so "supCtx is already cancelled when the backend is
// asked to stop" is a property that either holds on every run or never does.
func TestVMTeardownCancelsSupervisionBeforeStopping(t *testing.T) {
	t.Run("DeletePod", func(t *testing.T) {
		vmb := &fakeVMBackend{available: true, bootOK: true}
		rt := newTestRuntime(t, Deps{VMBackend: vmb})
		box := vmPodBox(rt, "pod-vm-order-1", 5)

		var cancelledAtStop bool
		var stops int
		vmb.stopHook = func(podID string) {
			stops++
			p, ok := rt.lookupPod(podID)
			if !ok {
				// DeletePod deregisters before tearing down, so resolve the pod
				// the way the teardown itself holds it.
				cancelledAtStop = deletedPodSupCancelled(t, rt, podID)
				return
			}
			cancelledAtStop = p.supCtx.Err() != nil
		}
		if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box}); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		p, _ := rt.lookupPod(box.GetPodId())
		vmb.stopHook = func(string) {
			stops++
			cancelledAtStop = p.supCtx.Err() != nil
		}
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: box.GetPodId()}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if stops != 1 {
			t.Fatalf("stop hook ran %d times, want 1", stops)
		}
		if !cancelledAtStop {
			t.Error("the pod's supervision context was still live when the helper was asked to stop; " +
				"watchVMHelperExit then races that exit and can publish a Failed status for a deliberately deleted pod")
		}
	})

	t.Run("Close", func(t *testing.T) {
		// Same property on the shutdown path, where the cost is worse: every vm
		// pod on the node would be published Failed on the way out.
		vmb := &fakeVMBackend{available: true, bootOK: true}
		rt := newTestRuntime(t, Deps{VMBackend: vmb})
		box := vmPodBox(rt, "pod-vm-order-2", 5)
		if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box}); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		p, _ := rt.lookupPod(box.GetPodId())
		var cancelledAtStop, ran bool
		vmb.stopHook = func(string) {
			ran = true
			cancelledAtStop = p.supCtx.Err() != nil
		}
		_ = rt.Close()
		if !ran {
			t.Fatal("StopAllVMs never reached the live helper")
		}
		if !cancelledAtStop {
			t.Error("Close asked the helpers to stop while pod supervision was still live; " +
				"every vm pod would be published Failed during an ordinary daemon shutdown")
		}
	})
}

// deletedPodSupCancelled is the fallback for a pod already removed from the
// registry: there is nothing left to inspect, so the ordering cannot be observed
// and the caller must not read a false negative as a pass.
func deletedPodSupCancelled(t *testing.T, _ *Runtime, podID string) bool {
	t.Helper()
	t.Fatalf("pod %s was already deregistered when the stop hook ran, so the ordering could not be observed", podID)
	return false
}
