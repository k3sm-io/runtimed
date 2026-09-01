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
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- fakes ----------------------------------------------------------------

// guestStatsAgent is a real guest/v1 GuestAgent server answering the two verbs
// the METERING fork rides on — Stats and ContainerEvents — over the same
// bufconn+gRPC round trip startFakeGuestAgent gives the exec/logs routes. There
// is no VM, no vmhost and no vsock anywhere in this file: only the SOCKET is
// replaced.
//
// bootedPod is the single pod this guest "booted": a request naming any other
// pod is rejected, as guest.proto requires.
type guestStatsAgent struct {
	guestv1.UnimplementedGuestAgentServer

	bootedPod string
	// sample is the StatsResponse handed back; statsErr (when set) is returned
	// instead, so an agent that is reachable but failing is distinguishable from
	// one that cannot be dialled at all.
	sample   *guestv1.StatsResponse
	statsErr error
	// events is the ContainerEvents script; the stream ends after the last one.
	events []*guestv1.ContainerEvent

	mu        sync.Mutex
	statsReqs []*guestv1.StatsRequest
	eventReqs []*guestv1.ContainerEventsRequest
}

func (a *guestStatsAgent) Stats(_ context.Context, req *guestv1.StatsRequest) (*guestv1.StatsResponse, error) {
	a.mu.Lock()
	a.statsReqs = append(a.statsReqs, req)
	a.mu.Unlock()
	if req.GetPodId() != a.bootedPod {
		return nil, status.Errorf(codes.InvalidArgument,
			"stats: pod_id %q is not the pod this guest booted (%q)", req.GetPodId(), a.bootedPod)
	}
	if a.statsErr != nil {
		return nil, a.statsErr
	}
	return a.sample, nil
}

func (a *guestStatsAgent) ContainerEvents(req *guestv1.ContainerEventsRequest, gs guestv1.GuestAgent_ContainerEventsServer) error {
	a.mu.Lock()
	a.eventReqs = append(a.eventReqs, req)
	a.mu.Unlock()
	if req.GetPodId() != a.bootedPod {
		return status.Errorf(codes.InvalidArgument,
			"events: pod_id %q is not the pod this guest booted (%q)", req.GetPodId(), a.bootedPod)
	}
	for _, ev := range a.events {
		if err := gs.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

func (a *guestStatsAgent) statsRequests() []*guestv1.StatsRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*guestv1.StatsRequest(nil), a.statsReqs...)
}

func (a *guestStatsAgent) eventRequests() []*guestv1.ContainerEventsRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*guestv1.ContainerEventsRequest(nil), a.eventReqs...)
}

// --- helpers --------------------------------------------------------------

// podCondition returns the named condition from st, or nil.
func podCondition(st *runtimev1.PodStatus, typ string) *runtimev1.PodCondition {
	for _, c := range st.GetConditions() {
		if c.GetType() == typ {
			return c
		}
	}
	return nil
}

// statsByPodID indexes a ListPodStats response.
func statsByPodID(resp *runtimev1.ListPodStatsResponse) map[string]*runtimev1.PodStats {
	out := map[string]*runtimev1.PodStats{}
	for _, ps := range resp.GetPodStats() {
		out[ps.GetPodId()] = ps
	}
	return out
}

// containerStatusByName indexes a pod status's main container statuses.
func containerStatusByName(st *runtimev1.PodStatus) map[string]*runtimev1.ContainerStatus {
	out := map[string]*runtimev1.ContainerStatus{}
	for _, cs := range st.GetContainerStatuses() {
		out[cs.GetName()] = cs
	}
	return out
}

// --- the B107 gate --------------------------------------------------------

// TestVMPodStatsFromGuestAgentNotRusage is the B107 gate: the vm-pod METERING
// and KILL-reason fork, asserted in four parts.
//
// It lives in pkg/runtime, not pkg/supervisor, because that is where the fork
// actually is: pkg/supervisor owns the proc_pid_rusage sampler mechanism and has
// no notion of a backend, while the decision "which kernel produced this pod's
// numbers" is taken by pkg/runtime's ListPodStats/podStats over the pod's
// RESOLVED backend. The BACKLOG-named test name is kept.
//
//  1. source FORK — a vm pod's working set and CPU come from the guest agent's
//     cgroup2 Stats verb, ON demand at ListPodStats, and the host rusage seam is
//     never consulted for it.
//  2. NO TICKER — arming a vm pod registers NO host memory sampler at all (the
//     negative assertion, with a live host pod as the positive control proving
//     the arming machinery is running in this very test).
//  3. UNREACHABLE — an agent that cannot be dialled omits that pod from the
//     stats response and says so in a pod condition; it never reports zeros.
//  4. KILL-reason FORK — the host sampler's over-limit path can never mark a vm
//     pod OOMKilled, and an agent ContainerEvents exited{oom} can.
func TestVMPodStatsFromGuestAgentNotRusage(t *testing.T) {
	t.Run("1-source-fork-guest-cgroup2-not-host-rusage", func(t *testing.T) {
		agent := &guestStatsAgent{
			bootedPod: "pod-vm",
			sample: &guestv1.StatsResponse{
				Timestamp: timestamppb.New(time.Unix(1_700_000_000, 0)),
				Containers: []*guestv1.GuestContainerStats{
					{Container: "app", CpuUsageUsec: 1_500, MemoryWorkingSetBytes: 7 << 20},
					{Container: "side", CpuUsageUsec: 2_500, MemoryWorkingSetBytes: 3 << 20},
					// A container this pod never declared: guest-controlled data,
					// dropped at the boundary.
					{Container: "ghost", CpuUsageUsec: 9, MemoryWorkingSetBytes: 1 << 30},
				},
			},
		}
		dial, dialed := startFakeGuestAgent(t, agent)
		fp := &countingFootprinter{bytes: 99 << 20}
		rt := newTestRuntime(t, Deps{GuestDialer: dial, Footprinter: fp})
		vm := addVMPod(t, rt, "pod-vm", "app", "side")

		resp, err := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "pod-vm"})
		if err != nil {
			t.Fatalf("ListPodStats: %v", err)
		}
		ps := statsByPodID(resp)["pod-vm"]
		if ps == nil {
			t.Fatalf("vm pod missing from ListPodStats: %+v", resp.GetPodStats())
		}

		// The host rusage seam is the wrong kernel for a vm pod: it would meter the
		// vmhost helper, not the workload. It must not have been touched at all.
		if n := int(fp.samples.Load()); n != 0 {
			t.Errorf("proc_pid_rusage seam consulted %d times for a vm pod, want 0 (rusage is not guest truth)", n)
		}
		// …and the agent's Stats verb must have been asked, on demand, for this pod.
		reqs := agent.statsRequests()
		if len(reqs) != 1 {
			t.Fatalf("guest Stats calls = %d, want exactly 1 (on demand at ListPodStats)", len(reqs))
		}
		if reqs[0].GetPodId() != "pod-vm" {
			t.Errorf("guest Stats pod_id = %q, want pod-vm", reqs[0].GetPodId())
		}
		if got := dialed(); len(got) != 1 {
			t.Errorf("guest-agent dials = %v, want exactly one", got)
		}

		byName := map[string]*runtimev1.ContainerStats{}
		for _, cs := range ps.GetContainers() {
			byName[cs.GetName()] = cs
		}
		if _, ok := byName["ghost"]; ok {
			t.Error("a container the pod never declared was accepted from the guest")
		}
		if len(ps.GetContainers()) != 2 {
			t.Fatalf("containers = %d (%v), want 2 (the declared set)", len(ps.GetContainers()), byName)
		}
		if got := byName["app"].GetMemory().GetWorkingSetBytes(); got != 7<<20 {
			t.Errorf("app working_set_bytes = %d, want %d (guest cgroup2 memory.current - inactive_file)", got, 7<<20)
		}
		if got := byName["app"].GetCpu().GetUsageCoreNanoSeconds(); got != 1_500_000 {
			t.Errorf("app usage_core_nano_seconds = %d, want 1500000 (cgroup2 usage_usec x 1000)", got)
		}
		if got := byName["side"].GetMemory().GetWorkingSetBytes(); got != 3<<20 {
			t.Errorf("side working_set_bytes = %d, want %d", got, 3<<20)
		}
		if got := ps.GetMemory().GetWorkingSetBytes(); got != 10<<20 {
			t.Errorf("pod working_set_bytes = %d, want %d (sum of the guest samples)", got, 10<<20)
		}
		if got := ps.GetCpu().GetUsageCoreNanoSeconds(); got != 4_000_000 {
			t.Errorf("pod usage_core_nano_seconds = %d, want 4000000", got)
		}
		// A reachable agent flips the condition true, so `kubectl describe` can tell
		// "metered" from "never asked".
		cond := podCondition(rt.podStatus(vm), GuestStatsConditionType)
		if cond.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_TRUE {
			t.Errorf("%s = %v, want True after a successful sample", GuestStatsConditionType, cond.GetStatus())
		}
	})

	t.Run("2-no-host-memory-sampler-is-registered-for-a-vm-pod", func(t *testing.T) {
		agent := &guestStatsAgent{bootedPod: "pod-vm", sample: &guestv1.StatsResponse{}}
		dial, _ := startFakeGuestAgent(t, agent)
		fp := &countingFootprinter{bytes: 4 << 20}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{GuestDialer: dial, Footprinter: fp, Waiter: w})
		rt.cfg.SampleInterval = 5 * time.Millisecond // ~200 Hz: a tick is immediate
		rt.signalGroup = (&recordingSignalGroup{}).signal

		// positive CONTROL: a host-process pod on the same runtime, armed by the
		// same call. Without it "no ticks were observed" could just mean the test
		// never waited long enough for any sampler to run.
		mustCreatePod(t, rt, hostBinBox(rt, "pod-host"))
		vm := addVMPod(t, rt, "pod-vm", "app")
		rt.armMemorySampler(vm) // exactly what CreatePod does after registration

		waitFor(t, 2*time.Second, "the host-process pod's sampler to tick (without it the negative assertion below is vacuous)",
			func() bool { return fp.samples.Load() > 0 })

		// The sampler REGISTRY is (pod.memSampler, pod.memCancel) — the pair every
		// stopper reads (DeletePod, cancelPodSupervision). A vm pod must hold
		// neither: nothing to tick, nothing to cancel, no 1 Hz vsock wakeup.
		rt.mu.Lock()
		host := rt.pods["pod-host"]
		rt.mu.Unlock()
		if host == nil {
			t.Fatal("the host-process pod is not registered")
		}
		host.mu.Lock()
		hostSampler := host.memSampler
		host.mu.Unlock()
		if hostSampler == nil {
			t.Fatal("the host-process pod registered no sampler: the registry assertion below would be vacuous")
		}
		vm.mu.Lock()
		vmSampler, vmCancel := vm.memSampler, vm.memCancel
		vm.mu.Unlock()
		if vmSampler != nil {
			t.Error("a vm pod registered a host memory sampler: the vm path has no OOM race to poll for (VZ memorySize is the ceiling)")
		}
		if vmCancel != nil {
			t.Error("a vm pod registered a sampler cancel, so something was started to cancel")
		}
		// Registry sweep: no vm-backed pod anywhere in the table holds a sampler.
		rt.mu.Lock()
		pods := make([]*pod, 0, len(rt.pods))
		for _, p := range rt.pods {
			pods = append(pods, p)
		}
		rt.mu.Unlock()
		for _, p := range pods {
			if !p.isVM() {
				continue
			}
			p.mu.Lock()
			s := p.memSampler
			p.mu.Unlock()
			if s != nil {
				t.Errorf("vm pod %s holds a host memory sampler", p.box.GetPodId())
			}
		}
		// PodMetrics is the host sampler's read side; for a vm pod it must report
		// "no host sample", and the vm pod must still be metered anyway (via the
		// agent) — the two facts together are the whole point of the fork.
		if _, ok := rt.PodMetrics("pod-vm"); ok {
			t.Error("PodMetrics reported a host rusage sample for a vm pod")
		}
		w.release(1001)
	})

	t.Run("3-unreachable-agent-omits-stats-and-conditions-the-pod", func(t *testing.T) {
		dialErr := errors.New("dial agent.sock: no such file or directory")
		fp := &countingFootprinter{bytes: 4 << 20}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{
			GuestDialer: func(context.Context, string) (net.Conn, error) { return nil, dialErr },
			Footprinter: fp,
			Waiter:      w,
		})
		rt.cfg.SampleInterval = 5 * time.Millisecond
		rt.signalGroup = (&recordingSignalGroup{}).signal
		mustCreatePod(t, rt, hostBinBox(rt, "pod-host"))
		vm := addVMPod(t, rt, "pod-vm", "app")

		var byID map[string]*runtimev1.PodStats
		waitFor(t, 2*time.Second, "the host-process pod to appear in ListPodStats", func() bool {
			resp, _ := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{})
			byID = statsByPodID(resp)
			return byID["pod-host"] != nil
		})
		if ps, ok := byID["pod-vm"]; ok {
			t.Errorf("an unreachable guest agent produced a stats entry %+v; stats must be OMITTED, never zeros-as-data", ps)
		}

		st := rt.podStatus(vm)
		cond := podCondition(st, GuestStatsConditionType)
		if cond == nil {
			t.Fatalf("no %s condition on a vm pod whose agent is unreachable (conditions: %+v)", GuestStatsConditionType, st.GetConditions())
		}
		if cond.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_FALSE {
			t.Errorf("%s = %v, want False", GuestStatsConditionType, cond.GetStatus())
		}
		if cond.GetReason() != guestStatsReasonUnreachable {
			t.Errorf("%s reason = %q, want %q", GuestStatsConditionType, cond.GetReason(), guestStatsReasonUnreachable)
		}
		if cond.GetMessage() == "" {
			t.Errorf("%s carries no message: an operator cannot tell why the pod has no figures", GuestStatsConditionType)
		}
		if !cond.GetLastTransitionTime().IsValid() {
			t.Errorf("%s carries no last_transition_time", GuestStatsConditionType)
		}
		w.release(1001)
	})

	t.Run("4-kill-reason-fork", func(t *testing.T) {
		t.Run("host-sampler-over-limit-never-oomkills-a-vm-pod", func(t *testing.T) {
			agent := &guestStatsAgent{bootedPod: "pod-vm", sample: &guestv1.StatsResponse{}}
			dial, _ := startFakeGuestAgent(t, agent)
			sig := &recordingSignalGroup{}
			rt := newTestRuntime(t, Deps{GuestDialer: dial, Footprinter: &countingFootprinter{}})
			rt.signalGroup = sig.signal
			vm := addVMPod(t, rt, "pod-vm", "app")

			// The host sampler's breach callback, invoked directly with a footprint
			// far over any limit — the exact call a 1 Hz over-limit run would make.
			rt.oomKill(vm, 64<<30)

			vm.mu.Lock()
			oom := vm.oomKilled
			vm.mu.Unlock()
			if oom {
				t.Error("the host rusage sampler marked a vm pod OOMKilled; only the guest cgroup can observe a guest OOM")
			}
			if s := sig.sentSignals(); len(s) != 0 {
				t.Errorf("host OOM path signalled %v for a vm pod; there is no host process group to kill", s)
			}
			for _, cs := range rt.podStatus(vm).GetContainerStatuses() {
				if r := cs.GetState().GetTerminated().GetReason(); r == "OOMKilled" {
					t.Errorf("container %s reports OOMKilled from the host sampler", cs.GetName())
				}
			}
		})

		t.Run("agent-oom-event-marks-the-vm-pod-oomkilled", func(t *testing.T) {
			at := timestamppb.New(time.Unix(1_700_000_100, 0))
			agent := &guestStatsAgent{
				bootedPod: "pod-vm",
				events: []*guestv1.ContainerEvent{
					{Container: "app", Timestamp: at, Started: &guestv1.ContainerStarted{Pid: 7}},
					// Undeclared: guest-controlled data, dropped at the boundary.
					{Container: "ghost", Timestamp: at, Exited: &guestv1.ContainerExited{ExitCode: 137, Signal: 9, OomKilled: true}},
					{Container: "app", Timestamp: at, Exited: &guestv1.ContainerExited{ExitCode: 137, Signal: 9, OomKilled: true}},
				},
			}
			dial, _ := startFakeGuestAgent(t, agent)
			rt := newTestRuntime(t, Deps{GuestDialer: dial, Footprinter: &countingFootprinter{}})
			vm := addVMPod(t, rt, "pod-vm", "app")

			if err := rt.watchGuestContainerEvents(context.Background(), vm); err != nil {
				t.Fatalf("watchGuestContainerEvents: %v", err)
			}
			if reqs := agent.eventRequests(); len(reqs) != 1 || reqs[0].GetPodId() != "pod-vm" {
				t.Fatalf("ContainerEvents subscriptions = %+v, want exactly one for pod-vm", reqs)
			}

			vm.mu.Lock()
			oom := vm.oomKilled
			vm.mu.Unlock()
			if !oom {
				t.Error("a guest ContainerEvents exited{oom_killed} did not mark the pod OOMKilled")
			}
			st := rt.podStatus(vm)
			byName := containerStatusByName(st)
			if _, ok := byName["ghost"]; ok {
				t.Error("a container the pod never declared was accepted from the guest event stream")
			}
			app := byName["app"]
			if app == nil {
				t.Fatalf("no container status for app (statuses: %+v)", st.GetContainerStatuses())
			}
			term := app.GetState().GetTerminated()
			if term == nil {
				t.Fatalf("app is not terminated: %+v", app.GetState())
			}
			if term.GetReason() != "OOMKilled" {
				t.Errorf("app termination reason = %q, want OOMKilled", term.GetReason())
			}
			if term.GetExitCode() != 137 || term.GetSignal() != 9 {
				t.Errorf("app termination = exit %d signal %d, want 137/9", term.GetExitCode(), term.GetSignal())
			}
		})
	})
}
