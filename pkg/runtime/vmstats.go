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
	"math"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// guestStatsTimeout bounds ONE on-demand guest-agent Stats call.
//
// A stats scrape must not be hostage to a wedged guest: without a deadline a
// single unresponsive agent would hold ListPodStats — and therefore the node's
// whole `kubectl top` / Summary answer — for as long as it stayed silent. Two
// seconds is far above a vsock round trip that reads four cgroup2 files, and the
// call is additionally bounded by the caller's own context, so an aggressive
// client deadline still wins.
const guestStatsTimeout = 2 * time.Second

// GuestStatsConditionType is the pod-condition type reporting whether a vm pod's
// guest agent answered the last on-demand Stats call.
//
// It is a QUALIFIED name because it is not one of the four condition types the
// upstream kubelet owns (Initialized / Ready / ContainersReady / PodScheduled);
// qualifying it is the form upstream defines for a non-standard pod condition,
// and it makes a future upstream type of the same short name impossible to
// collide with. It exists so that "this pod has no figures" is a STATED fact an
// operator can read in `kubectl describe pod` — the alternative to omission is
// reporting zeros, and a zero working set is indistinguishable from an idle
// workload, which is a lie the metering surface must not tell.
const GuestStatsConditionType = "k3sm.io/guest-stats-available"

// The reasons GuestStatsConditionType carries. They are distinct because the
// operator actions differ: unreachable means the agent/VM is gone (look at the
// pod's lifecycle), unreadable means the agent answered but could read no
// cgroup2 sample (look inside the guest).
const (
	guestStatsReasonReachable   = "GuestAgentReachable"
	guestStatsReasonNoSamples   = "GuestStatsUnreadable"
	guestStatsReasonUnreachable = "GuestAgentUnreachable"
)

// guestStatsRecord is the outcome of a vm pod's LAST on-demand guest-agent Stats
// call. Guarded by pod.mu.
type guestStatsRecord struct {
	// observed is false until the first Stats attempt. A pod nothing has asked
	// about yet therefore carries NO condition at all, rather than a fabricated
	// "Unknown" that would read as a probe result when nothing was probed.
	observed  bool
	available bool
	reason    string
	message   string
	// lastProbe is when the last attempt was made; lastTransition is when
	// available last CHANGED (the corev1 condition semantics: a transition time
	// that moved on every probe would make "since when" unreadable).
	lastProbe      time.Time
	lastTransition time.Time
}

// vmPodStats builds a vm pod's PodStats from the guest agent's cgroup2 sample,
// pulled ON DEMAND, or nil when there is nothing honest to report.
//
// ON DEMAND, NOT ON A TICK. The host runs no sampling loop against a guest (see
// armMemorySampler's vm refusal): the 1 Hz host sampler exists solely to win the
// OOM race on the host spine, and the vm path has no such race — the VZ
// memorySize IS the hypervisor-enforced ceiling and an OOM arrives as a
// ContainerEvent. Sampling a guest on a tick would buy nothing and cost N idle
// vsock wakeups per second for data a consumer reads every 15-60 s.
//
// UNTRUSTED DATA. Everything in the response is guest-controlled (guest.proto
// §TRUST). Three narrowings are applied here, at the boundary:
//   - only containers THIS POD DECLARED are accepted, in the DECLARED order, so
//     a guest can neither inject a container the pod never had nor decide the
//     order the host reports;
//   - the sample is HOST-stamped, not guest-stamped: a metrics consumer derives
//     a CPU rate from (counter, timestamp) pairs, so a guest-chosen timestamp is
//     a guest-chosen rate;
//   - the microsecond→nanosecond conversion is overflow-checked; a counter that
//     cannot be converted is reported as absent, never as a wrapped value.
func (r *Runtime) vmPodStats(ctx context.Context, p *pod) *runtimev1.PodStats {
	podID := p.box.GetPodId()
	resp, err := r.guestStats(ctx, podID)
	if err != nil {
		// OMITTED, never zeros. The pod says why in its condition instead.
		r.recordGuestStats(p, false, guestStatsReasonUnreachable, boundGuestMessage(err.Error()))
		r.log.Debug("vm pod stats unavailable", "pod", podID, "err", err)
		return nil
	}

	ts := timestamppb.New(time.Now())
	containers := vmContainerStats(p.box, resp, ts)
	if len(containers) == 0 {
		r.recordGuestStats(p, false, guestStatsReasonNoSamples,
			"the guest agent returned no readable cgroup2 sample for any declared container")
		return nil
	}
	r.recordGuestStats(p, true, guestStatsReasonReachable, "")

	ps := &runtimev1.PodStats{
		PodId:      podID,
		Namespace:  p.box.GetNamespace(),
		Name:       p.box.GetName(),
		Timestamp:  ts,
		Containers: containers,
	}
	var totalWS, totalCPU uint64
	cpuComplete := true
	for _, cs := range containers {
		totalWS += cs.GetMemory().GetWorkingSetBytes()
		cpu := cs.GetCpu()
		if cpu == nil {
			cpuComplete = false
			continue
		}
		totalCPU += cpu.GetUsageCoreNanoSeconds()
	}
	ps.Memory = &runtimev1.MemoryStats{Timestamp: ts, WorkingSetBytes: totalWS}
	// The pod-level counter is published only when EVERY reported container
	// contributed one — the same completeness rule the host path applies, for the
	// same reason: a partial sum is not a pod total, and being a counter it would
	// fall when the missing container reappeared.
	if cpuComplete {
		ps.Cpu = &runtimev1.CPUStats{Timestamp: ts, UsageCoreNanoSeconds: totalCPU}
	}
	return ps
}

// guestStats performs one bounded, on-demand Stats RPC against podID's guest
// agent over the injected transport seam.
//
// One connection per call, closed here — the same posture the exec/logs routes
// take (see dialGuest): a stats scrape is periodic, not hot, and a per-call conn
// means no reconnect state machine and no way for one pod's dead socket to hold
// resources against another's.
func (r *Runtime) guestStats(ctx context.Context, podID string) (*guestv1.StatsResponse, error) {
	conn, err := r.dialGuest(podID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	cctx, cancel := context.WithTimeout(ctx, guestStatsTimeout)
	defer cancel()

	resp, err := guestv1.NewGuestAgentClient(conn).Stats(cctx, &guestv1.StatsRequest{PodId: podID})
	if err != nil {
		return nil, guestStreamError("stats", podID, err)
	}
	return resp, nil
}

// vmContainerStats maps the guest's per-container cgroup2 samples onto the
// runtime/v1 ContainerStats shape, in the pod's DECLARED container order.
//
// The declared list drives the walk (not the response), which is what makes an
// undeclared name unrepresentable rather than merely rejected, and bounds the
// output at the pod's own container count. A declared container the guest did
// not report is OMITTED — absence is the only honest encoding of "unknown",
// exactly as guest.proto says of the response itself.
func vmContainerStats(box *runtimev1.PodBox, resp *guestv1.StatsResponse, ts *timestamppb.Timestamp) []*runtimev1.ContainerStats {
	samples := make(map[string]*guestv1.GuestContainerStats, len(resp.GetContainers()))
	for _, gcs := range resp.GetContainers() {
		if _, dup := samples[gcs.GetContainer()]; dup {
			continue // first sample wins; a guest cannot restate a container
		}
		samples[gcs.GetContainer()] = gcs
	}

	declared := declaredContainers(box)
	out := make([]*runtimev1.ContainerStats, 0, len(declared))
	for _, name := range declared {
		gcs := samples[name]
		if gcs == nil {
			continue
		}
		cs := &runtimev1.ContainerStats{
			Name:      name,
			Timestamp: ts,
			Memory: &runtimev1.MemoryStats{
				Timestamp: ts,
				// cgroup2 memory.current - memory.stat inactive_file, as the
				// kubelet defines a working set (guest.proto). It is a DIFFERENT
				// kernel's figure from the host path's ri_phys_footprint; the
				// provenance is why guest/v1 keeps its own message type.
				WorkingSetBytes: gcs.GetMemoryWorkingSetBytes(),
			},
		}
		if nanos, ok := usecToNanos(gcs.GetCpuUsageUsec()); ok {
			cs.Cpu = &runtimev1.CPUStats{Timestamp: ts, UsageCoreNanoSeconds: nanos}
		}
		out = append(out, cs)
	}
	return out
}

// usecToNanos converts a cgroup2 cpu.stat usage_usec counter to the nanoseconds
// the kubelet Summary API reports, reporting ok=false rather than a wrapped
// value when the guest-supplied counter cannot be scaled without overflow.
func usecToNanos(usec uint64) (uint64, bool) {
	if usec > math.MaxUint64/1000 {
		return 0, false
	}
	return usec * 1000, true
}

// declaredContainers returns the pod's declared container names, inits first —
// the host-side authority on what a vm pod contains. A vm pod's containers are
// guest processes with no host containerProc, so the PodBox is the only place
// this can be resolved (the same reason vmContainerName resolves against it).
func declaredContainers(box *runtimev1.PodBox) []string {
	out := make([]string, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	for _, c := range box.GetInitContainers() {
		out = append(out, c.GetName())
	}
	for _, c := range box.GetContainers() {
		out = append(out, c.GetName())
	}
	return out
}

// recordGuestStats records the outcome of one guest-agent Stats attempt on p,
// moving the condition's transition time only when availability actually
// CHANGED (corev1 condition semantics).
func (r *Runtime) recordGuestStats(p *pod, available bool, reason, message string) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	prev := p.guestStats
	p.guestStats = guestStatsRecord{
		observed:       true,
		available:      available,
		reason:         reason,
		message:        message,
		lastProbe:      now,
		lastTransition: prev.lastTransition,
	}
	if !prev.observed || prev.available != available {
		p.guestStats.lastTransition = now
	}
}

// guestStatsConditionLocked renders p's guest-stats availability as a pod
// condition, or nil when no Stats call has been made yet. The caller holds p.mu.
func guestStatsConditionLocked(p *pod) *runtimev1.PodCondition {
	rec := p.guestStats
	if !rec.observed {
		return nil
	}
	st := runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
	if rec.available {
		st = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
	}
	return &runtimev1.PodCondition{
		Type:               GuestStatsConditionType,
		Status:             st,
		LastProbeTime:      timestamppb.New(rec.lastProbe),
		LastTransitionTime: timestamppb.New(rec.lastTransition),
		Reason:             rec.reason,
		Message:            rec.message,
	}
}
