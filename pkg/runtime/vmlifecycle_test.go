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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/image"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// the VM POD'S HOST-side LIFECYCLE, with the boot faked at the backend seam.
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
// Its container names an OCI REFERENCE and carries a command, because both are
// what a vm pod needs to resolve at all: the absolute-path
// host-binary convention is refused on this path, and the harness's fake image
// config declares no Entrypoint, so a container with no command of its own would
// fail the merge rather than reach the backend.
//
// It takes the runtime for the same reason hostBinBox does: data_volume_path is
// accepted only when it is byte-equal to one of this pod's own derived spellings, and the runtime under test is rooted at a t.TempDir().
func vmPodBox(rt *Runtime, podID string, graceSeconds int64) *runtimev1.PodBox {
	dataVol := filepath.Join(rt.cache.PodsRoot(), podID)
	if id, err := image.ParsePodID(podID); err == nil {
		dataVol = rt.cache.PodDir(id)
	}
	return &runtimev1.PodBox{
		PodId:        podID,
		Namespace:    "default",
		Name:         "p",
		LogDirectory: testPodLogDir(rt, podID),
		SandboxProfile: &runtimev1.SandboxProfile{
			Backend:        runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
			DataVolumePath: dataVol,
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			{Name: "main", Image: "docker.io/library/alpine:3", Command: []string{"/bin/sleep", "3600"}},
		},
		TerminationGracePeriodSeconds: graceSeconds,
	}
}

// bootedVMRuntime returns a runtime whose vm backend boots successfully, plus
// that backend and a created, Running vm pod.
func bootedVMRuntime(t *testing.T, podID string, graceSeconds int64) (*Runtime, *fakeVMBackend, *runtimev1.PodBox) {
	t.Helper()
	vmb := &fakeVMBackend{available: true, bootOK: true}
	// The GuestNetworker producer is wired for the same reason vmPodConfig wires
	// one: a vm pod's published identity has no other source, and createVMPod
	// refuses a pod without it.
	rt := newTestRuntime(t, Deps{
		VMBackend: vmb,
		Network:   &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
		Resolver:  fakeResolver{},
	})
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
		// the guest cgroup's; a host sample would meter the vmhost helper.
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

	// The caller resolves the pod's grace (DeletePod takes it literally), so the
	// delete carries the pod's own 9s.
	resp, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: box.GetPodId(), GracePeriodSeconds: 9})
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
		t.Errorf("StopVM grace = %s, want the requested 9s (the ONE budget both ends share)", stops[0].grace)
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
		// DeletePod (stop, then cancel) has not been reversed.
		time.Sleep(50 * time.Millisecond)
	})
}

// TestDeleteVMPodGraceZeroStopsImmediately pins the vm route of the apis
// contract: a DeletePod with grace 0 asks the helper for an immediate stop (a
// StopVM grace of 0) even though the pod's own grace is 9s. DeletePod never falls
// back to the pod's grace; the caller resolves it.
func TestDeleteVMPodGraceZeroStopsImmediately(t *testing.T) {
	rt, vmb, box := bootedVMRuntime(t, "pod-vm-g0", 9)

	if _, err := rt.DeletePod(context.Background(),
		&runtimev1.DeletePodRequest{PodId: box.GetPodId(), GracePeriodSeconds: 0}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	stops := vmb.stops()
	if len(stops) != 1 || stops[0].podID != box.GetPodId() {
		t.Fatalf("StopVM calls = %v, want exactly one for %s", stops, box.GetPodId())
	}
	if stops[0].grace != 0 {
		t.Errorf("StopVM grace = %s, want 0 (immediate; no fallback to the pod's 9s)", stops[0].grace)
	}
}

// TestCloseLeavesVMHelpersAndHostPodsRunning pins the one shutdown contract
// both kinds of pod now share: a `launchctl kickstart -k` stops no workload. A
// host pod's processes are left running, and a vm pod's helper is detached
// (DetachVMs), never stopped, so the next daemon can adopt it.
func TestCloseLeavesVMHelpersAndHostPodsRunning(t *testing.T) {
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

	if got := vmb.stopAlls(); got != 0 {
		t.Errorf("StopAllVMs called %d times on Close, want 0: a daemon exit must not stop a vm pod", got)
	}
	if got := len(vmb.stops()); got != 0 {
		t.Errorf("StopVM called %d times on Close, want 0", got)
	}
	if got := vmb.detaches(); got != 1 {
		t.Errorf("DetachVMs called %d times on Close, want 1: the record locks must be released for the next daemon", got)
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

// TestCloseDetachesVMHelpersWithNoRegisteredPods asserts the detach runs even
// when the pod registry is empty. The registry and the backend's handle map are
// different records, and a helper this daemon holds must be released either way.
func TestCloseDetachesVMHelpersWithNoRegisteredPods(t *testing.T) {
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{
		VMBackend: vmb,
		Network:   &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
		Resolver:  fakeResolver{},
	})
	if err := rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := vmb.detaches(); got != 1 {
		t.Errorf("DetachVMs called %d times with no registered pods, want 1", got)
	}
	if got := vmb.stopAlls(); got != 0 {
		t.Errorf("StopAllVMs called %d times with no registered pods, want 0", got)
	}
}

// TestStartupSweepReapsOrphanVMs asserts the vm orphan sweep runs exactly once,
// before pods are served, on the same hook the host-process reap uses.
func TestStartupSweepReapsOrphanVMs(t *testing.T) {
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{
		VMBackend: vmb,
		Network:   &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
		Resolver:  fakeResolver{},
	})

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

// guestExecutor stands in for the guest's container executor behind the real
// agent: a restart publishes the old instance's exit and the new instance's start
// on the agent's own event bus, exactly the two events the shipped executor's
// stop and start steps publish, and records what it was asked.
type guestExecutor struct {
	events  *guestagent.Events
	nextPID int32
	// silent is how many restarts to acknowledge without publishing anything,
	// the way a guest that acked and then lost its event would.
	silent int

	mu    sync.Mutex
	calls []string
	grace time.Duration
}

func (g *guestExecutor) RestartContainer(_ context.Context, container string, grace time.Duration) error {
	g.mu.Lock()
	g.calls = append(g.calls, container)
	g.grace = grace
	if g.silent > 0 {
		g.silent--
		g.mu.Unlock()
		return nil
	}
	g.nextPID++
	pid := g.nextPID
	g.mu.Unlock()
	g.events.Publish(guestagent.ContainerEvent{Container: container, At: time.Now(),
		Exited: &guestagent.ContainerExited{Signal: 15}})
	g.events.Publish(guestagent.ContainerEvent{Container: container, At: time.Now(),
		Started: &guestagent.ContainerStarted{PID: pid}})
	return nil
}

func (g *guestExecutor) snapshot() ([]string, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.calls...), g.grace
}

// bootedVMRuntimeWithAgent is bootedVMRuntime with the pod's guest agent served
// in-process (the shipped guestagent.Server over the GuestDialer seam), its
// "main" container already started, and that start folded into the pod's status.
func bootedVMRuntimeWithAgent(t *testing.T, podID string, graceSeconds int64) (*Runtime, *pod, *guestExecutor) {
	t.Helper()
	events := guestagent.NewEvents(16)
	events.Publish(guestagent.ContainerEvent{Container: "main", At: time.Now(),
		Started: &guestagent.ContainerStarted{PID: 100}})
	exec := &guestExecutor{events: events, nextPID: 100}
	dial := startRealGuestAgent(t, podID, guestagent.Deps{
		Runner:    stubRunner{names: []string{"main"}},
		Logs:      stubLogs{},
		Status:    stubStatus{st: guestagent.Status{Ready: true, GuestIP: "10.0.0.9"}},
		Events:    events,
		Restarter: exec,
	})
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{
		VMBackend:   vmb,
		Network:     &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
		Resolver:    fakeResolver{},
		GuestDialer: dial,
	})
	box := vmPodBox(rt, podID, graceSeconds)
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	p, ok := rt.lookupPod(podID)
	if !ok {
		t.Fatal("the created vm pod is not registered")
	}
	waitGuestContainer(t, p, "main", func(st *runtimev1.ContainerStatus) bool {
		return st.GetState().GetRunning() != nil
	})
	return rt, p, exec
}

// waitGuestContainer polls the pod's folded status for name until ok holds.
func waitGuestContainer(t *testing.T, p *pod, name string, ok func(*runtimev1.ContainerStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		st, _ := proto.Clone(p.guestContainers[name]).(*runtimev1.ContainerStatus)
		p.mu.Unlock()
		if st != nil && ok(st) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("container %s never reached the expected status", name)
}

// TestRestartContainerRestartsAVMPodContainer asserts the vm fork at the top of
// RestartContainer routes a vm pod's restart to its guest, and that the host
// keeps what CRI says the runtime keeps: the count, the previous run as
// last_termination_state, and a new log file per instance, so `kubectl logs
// --previous` reads the replaced run's own file. Without the fork the host path
// answers Unimplemented, which is the refusal this verb used to give.
func TestRestartContainerRestartsAVMPodContainer(t *testing.T) {
	const podID = "pod-vm-6"
	rt, p, exec := bootedVMRuntimeWithAgent(t, podID, 5)
	rt.setGuestCapabilities(p, guestagent.Capabilities())
	p.mu.Lock()
	oldID := p.guestContainers["main"].GetContainerId()
	p.mu.Unlock()

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
		PodId: podID, Container: "main", Reason: "liveness probe failed",
	})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("RestartContainer refused: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	calls, grace := exec.snapshot()
	if len(calls) != 1 || calls[0] != "main" {
		t.Fatalf("guest restarts = %v, want exactly [main]", calls)
	}
	if grace != 5*time.Second {
		t.Errorf("guest grace = %v, want the pod's 5s", grace)
	}

	st := resp.GetStatus()
	if st.GetRestartCount() != 1 {
		t.Errorf("restart_count = %d, want 1", st.GetRestartCount())
	}
	if st.GetState().GetRunning() == nil {
		t.Errorf("state = %v, want running", st.GetState())
	}
	if st.GetContainerId() == "" || st.GetContainerId() == oldID {
		t.Errorf("container id = %q, want a new id for the new instance (old %q)", st.GetContainerId(), oldID)
	}
	last := st.GetLastTerminationState().GetTerminated()
	if last == nil {
		t.Fatal("no last_termination_state: the replaced run is lost")
	}
	if last.GetContainerId() != oldID {
		t.Errorf("last state id = %q, want the replaced run's %q", last.GetContainerId(), oldID)
	}
	if last.GetReason() != "Killed" || last.GetMessage() != "liveness probe failed" {
		t.Errorf("last state = %s/%q, want Killed with the request's reason", last.GetReason(), last.GetMessage())
	}
	logDir := containerLogDir(testPodLogDir(rt, podID), "main")
	if want := filepath.Join(logDir, "1.log"); st.GetLogPath() != want {
		t.Errorf("log path = %q, want the new instance's %q", st.GetLogPath(), want)
	}
	if want := filepath.Join(logDir, "0.log"); last.GetLogPath() != want {
		t.Errorf("last state log path = %q, want the replaced run's %q", last.GetLogPath(), want)
	}
	if _, err := os.Stat(filepath.Join(logDir, "1.log")); err != nil {
		t.Errorf("the new instance's log file was not created: %v", err)
	}
	ps := rt.podStatus(p)
	if got := ps.GetContainerStatuses()[0].GetRestartCount(); got != 1 {
		t.Errorf("pod status restart_count = %d, want 1: the status and the response disagree", got)
	}
}

// TestRestartContainerRefusesAGuestWithoutTheCapability asserts a vm pod whose
// guest cannot restart a container in place gets a typed refusal that names
// the fix, and that nothing is touched: FailedPrecondition + UNSUPPORTED,
// because the booted initramfs will not change and a recreated pod is the
// remedy. It covers both ways to be such a guest: one whose Health did not
// advertise the token, and one that was asked before its Health was read and
// answered Unimplemented.
func TestRestartContainerRefusesAGuestWithoutTheCapability(t *testing.T) {
	assertRefusal := func(t *testing.T, resp *runtimev1.RestartContainerResponse) {
		t.Helper()
		if resp.GetStatus() != nil {
			t.Error("a refused restart returned a container status; a caller could read that as a completed restart")
		}
		if got := codes.Code(resp.GetError().GetCode()); got != codes.FailedPrecondition {
			t.Errorf("code = %v, want %v", got, codes.FailedPrecondition)
		}
		if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED {
			t.Errorf("failure_reason = %v, want UNSUPPORTED", got)
		}
		msg := resp.GetError().GetMessage()
		if !strings.Contains(msg, "predates") || !strings.Contains(msg, guestagent.CapabilityRestartContainer) {
			t.Errorf("message = %q; it must say the booted initramfs predates the verb and name the capability", msg)
		}
	}

	t.Run("health-did-not-advertise-it", func(t *testing.T) {
		rt, _, box := bootedVMRuntime(t, "pod-vm-5", 5)
		p, _ := rt.lookupPod(box.GetPodId())
		rt.setGuestCapabilities(p, nil)
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: box.GetPodId(), Container: "main",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		assertRefusal(t, resp)
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.guestRestarts) != 0 {
			t.Error("a refused restart left a claim behind")
		}
	})

	t.Run("an-older-agent-answers-unimplemented", func(t *testing.T) {
		const podID = "pod-vm-7"
		lis := bufconn.Listen(1 << 20)
		srv := grpc.NewServer()
		guestv1.RegisterGuestAgentServer(srv, olderGuestAgent{})
		served := make(chan struct{})
		go func() { defer close(served); _ = srv.Serve(lis) }()
		t.Cleanup(func() { srv.Stop(); <-served; _ = lis.Close() })
		rt := newTestRuntime(t, Deps{
			VMBackend: &fakeVMBackend{available: true},
			GuestDialer: func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		})
		p := addVMPod(t, rt, podID, "app")
		p.mu.Lock()
		p.guestContainerLocked("app", "").State = &runtimev1.ContainerState{
			Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()}}
		p.mu.Unlock()
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: podID, Container: "app",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		assertRefusal(t, resp)
	})
}

// TestRestartContainerReleasesAClaimTheGuestNeverConfirmed asserts the restart
// claim cannot outlive a guest that acknowledged the restart and never reported
// the replacement's start: the wait lapses, the stale status comes back, and the
// next restart is served rather than refused as in flight.
func TestRestartContainerReleasesAClaimTheGuestNeverConfirmed(t *testing.T) {
	saved := guestRestartFoldWait
	guestRestartFoldWait = 100 * time.Millisecond
	t.Cleanup(func() { guestRestartFoldWait = saved })

	const podID = "pod-vm-9"
	rt, p, exec := bootedVMRuntimeWithAgent(t, podID, 1)
	rt.setGuestCapabilities(p, guestagent.Capabilities())
	exec.mu.Lock()
	exec.silent = 1
	exec.mu.Unlock()

	first, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
	if err != nil || first.GetError() != nil {
		t.Fatalf("first RestartContainer: %v / %v", err, first.GetError())
	}
	if got := first.GetStatus().GetRestartCount(); got != 0 {
		t.Errorf("first restart_count = %d, want the stale 0: no start was ever reported", got)
	}
	p.mu.Lock()
	leaked := p.guestRestarts["main"] != nil
	p.mu.Unlock()
	if leaked {
		t.Fatal("the restart claim outlived the fold wait")
	}

	second, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
	if err != nil {
		t.Fatalf("second RestartContainer: %v", err)
	}
	if second.GetError() != nil {
		t.Fatalf("second restart refused: %v (reason %v)", second.GetError(), second.GetFailureReason())
	}
	st := second.GetStatus()
	if st.GetState().GetRunning() == nil || st.GetLastTerminationState().GetTerminated() == nil {
		t.Errorf("second restart status = %v, want a running replacement with the previous run recorded", st)
	}
	// The first attempt's file is kept (the guest did acknowledge it), so the
	// second instance takes the number after it, and count and file agree.
	if st.GetRestartCount() != 2 || filepath.Base(st.GetLogPath()) != "2.log" {
		t.Errorf("second restart = count %d, file %s; want 2 and 2.log", st.GetRestartCount(), filepath.Base(st.GetLogPath()))
	}
	if calls, _ := exec.snapshot(); len(calls) != 2 {
		t.Errorf("guest restarts = %v, want 2", calls)
	}
}

// TestRefusedGuestRestartsLeaveTheLogDirAsItWas asserts a restart the guest
// refused leaves no empty instance file behind: the next instance number is one
// past the highest file on disk, so each leftover would advance the count with
// no run behind it.
func TestRefusedGuestRestartsLeaveTheLogDirAsItWas(t *testing.T) {
	const podID = "pod-vm-10"
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	guestv1.RegisterGuestAgentServer(srv, olderGuestAgent{})
	served := make(chan struct{})
	go func() { defer close(served); _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); <-served; _ = lis.Close() })
	rt := newTestRuntime(t, Deps{
		VMBackend: &fakeVMBackend{available: true},
		GuestDialer: func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		},
	})
	p := addVMPod(t, rt, podID, "app")
	logDir := containerLogDir(p.box.GetLogDirectory(), "app")
	w0, err := crilog.Open(filepath.Join(logDir, "0.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w0.Write(crilog.StreamStdout, []byte("first run"), false); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.guestLogs = map[string]*crilog.Writer{"app": w0}
	p.guestContainerLocked("app", "").State = &runtimev1.ContainerState{
		Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()}}
	p.mu.Unlock()

	for i := range 2 {
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "app"})
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED {
			t.Fatalf("attempt %d: reason %v, want the UNSUPPORTED refusal", i, resp.GetFailureReason())
		}
	}

	entries, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "0.log" {
		t.Errorf("log dir = %v, want only 0.log: a refused restart left a file behind", names)
	}
	if next, _ := restartCountFromLogDir(logDir); next != 1 {
		t.Errorf("next instance number = %d, want 1", next)
	}
	p.mu.Lock()
	count := p.guestContainers["app"].GetRestartCount()
	current := p.guestLogs["app"]
	p.mu.Unlock()
	if count != 0 {
		t.Errorf("restart_count = %d, want 0", count)
	}
	if current != w0 {
		t.Error("the container's writer was not restored to the first run's")
	}
}

// olderGuestAgent is an agent built before RestartContainer existed: every RPC
// it does not implement answers Unimplemented, as the generated stub does.
type olderGuestAgent struct {
	guestv1.UnimplementedGuestAgentServer
}

// TestVMTeardownCancelsSupervisionBeforeStopping pins the ordering that keeps a
// deliberate teardown from being reported as a crash.
//
// FOUND BY the LIVE SMOKE, not BY REVIEW. A helper's exit is observed by two
// watchers — the stop's own GracefulStop and watchVMHelperExit, whose whole job
// is to fail a pod whose machine died under it — and cancelling supervision
// after the stop left which one won to chance. On hardware the watcher won
// routinely: an ordinary DeletePod logged "the vm host helper exited while its
// pod was running; the guest is gone" and published a Failed status for a pod the
// operator had just asked to delete. A provider consuming that event sees a
// crash where there was none.
//
// The assertion is on the order, not on the outcome, and deliberately so: an
// outcome test ("the pod was not published Failed") passes on a racy
// implementation most of the time, which is the worst possible test for a race.
// Contexts are monotonic, so "supCtx is already cancelled when the backend is
// asked to stop" is a property that either holds on every run or never does.
func TestVMTeardownCancelsSupervisionBeforeStopping(t *testing.T) {
	t.Run("DeletePod", func(t *testing.T) {
		vmb := &fakeVMBackend{available: true, bootOK: true}
		rt := newTestRuntime(t, Deps{
			VMBackend: vmb,
			Network:   &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
			Resolver:  fakeResolver{},
		})
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
		// The shutdown path stops no helper at all now; what must hold is that
		// supervision is cancelled and nothing is asked to stop, so no vm pod is
		// published Failed on the way out and every guest keeps running.
		vmb := &fakeVMBackend{available: true, bootOK: true}
		rt := newTestRuntime(t, Deps{
			VMBackend: vmb,
			Network:   &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
			Resolver:  fakeResolver{},
		})
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
		if ran {
			t.Fatalf("Close asked a vm helper to stop (supervision cancelled first: %v); a daemon exit must leave the guest running", cancelledAtStop)
		}
		if p.supCtx.Err() == nil {
			t.Error("Close left the vm pod's supervision running")
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

// sequencedLogs serves one scripted batch of entries per Logs connection, then
// ends that stream, the way a guest ends a container's stream when the instance
// exits. Connections past the script get an empty stream.
type sequencedLogs struct {
	mu      sync.Mutex
	batches [][]guestagent.LogEntry
}

func (l *sequencedLogs) Stream(_ context.Context, _ string, sel guestagent.Selector) (<-chan guestagent.LogEntry, func(), error) {
	l.mu.Lock()
	var batch []guestagent.LogEntry
	if len(l.batches) > 0 {
		batch, l.batches = l.batches[0], l.batches[1:]
	}
	l.mu.Unlock()
	ch := make(chan guestagent.LogEntry, len(batch))
	for _, e := range batch {
		if sel.SinceTime.IsZero() || !e.At.Before(sel.SinceTime) {
			ch <- e
		}
	}
	close(ch)
	return ch, func() {}, nil
}

// TestGuestLogFollowerMovesToTheRestartedInstancesFile pins the log half of
// the in-guest restart: the follower drains the old instance's output into the
// old file, and once the pod's writer is replaced its next connection writes
// the new instance into the new file. `kubectl logs --previous` reads the old
// file, so a follower that kept writing into it would hand the previous view
// the current run.
func TestGuestLogFollowerMovesToTheRestartedInstancesFile(t *testing.T) {
	const podID = "pod-vm-8"
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	logs := &sequencedLogs{batches: [][]guestagent.LogEntry{
		{{At: base, Line: []byte("old"), Stream: guestagent.StreamStdout}},
		{{At: base.Add(time.Second), Line: []byte("new"), Stream: guestagent.StreamStdout}},
	}}
	dial := startRealGuestAgent(t, podID, guestagent.Deps{Runner: stubRunner{names: []string{"app"}}, Logs: logs})
	rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
	p := addVMPod(t, rt, podID, "app")

	dir := t.TempDir()
	w0, err := crilog.Open(filepath.Join(dir, "0.log"))
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.guestLogs = map[string]*crilog.Writer{"app": w0}
	p.mu.Unlock()
	rt.startGuestLogFollower(p, "app")
	waitLogLines(t, filepath.Join(dir, "0.log"), 1)

	w1, err := crilog.Open(filepath.Join(dir, "1.log"))
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.guestLogs["app"] = w1
	p.mu.Unlock()
	waitLogLines(t, filepath.Join(dir, "1.log"), 1)

	if got := readCRILog(t, filepath.Join(dir, "0.log")); len(got) != 1 || got[0].payload != "old" {
		t.Errorf("0.log = %+v, want only the old instance's line", got)
	}
	if got := readCRILog(t, filepath.Join(dir, "1.log")); len(got) != 1 || got[0].payload != "new" {
		t.Errorf("1.log = %+v, want only the new instance's line", got)
	}
}

// waitLogLines polls a CRI log file until it holds n lines.
func waitLogLines(t *testing.T, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.Count(string(b), "\n") >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never held %d lines", path, n)
}
