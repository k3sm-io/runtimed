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

	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/supervisor"
)

// ListPodStats returns point-in-time resource-usage snapshots for pods on the
// node — the typed wire form of the M2.5 memory sampler, behind `kubectl top` /
// the kubelet Summary API. It replaces the runtimed-internal-only PodMetrics path
// with the apis:M2.2 PodStats/ContainerStats/MemoryStats contract the k3sm
// provider serves.
//
// pod_id empty returns every metered pod (the Summary shape); pod_id set returns
// just that pod. EVERY running pod is metered — the memory limit selects OOM
// enforcement, not metering (see armMemorySampler) — so a HOST-PROCESS pod is
// omitted only when its sampler was never armed, matching PodMetrics' ok==false,
// and a VM pod only when its guest agent had no readable sample to give
// (vmPodStats, which also states the reason as a pod condition). An unknown
// pod_id yields an empty list (not an error): a stats query races pod teardown,
// so "gone" is an empty snapshot, not a failure.
//
// A vm pod's sample is an on-demand RPC, so this walk performs one bounded
// guest round trip per vm pod, sequentially. That is affordable because it is
// bounded twice — by guestStatsTimeout per pod and by the caller's own ctx
// overall — and because a node runs few vm pods; it is also the whole reason
// there is no 1 Hz guest ticker (see vmPodStats).
func (r *Runtime) ListPodStats(ctx context.Context, req *runtimev1.ListPodStatsRequest) (*runtimev1.ListPodStatsResponse, error) {
	ids := r.statsTargets(req.GetPodId())
	out := make([]*runtimev1.PodStats, 0, len(ids))
	for _, id := range ids {
		if st := r.podStats(ctx, id); st != nil {
			out = append(out, st)
		}
	}
	return &runtimev1.ListPodStatsResponse{PodStats: out}, nil
}

// statsTargets returns the pod ids ListPodStats should sample: the single id when
// set (and present), else every known pod. Snapshotted under r.mu so the per-pod
// sampling below takes no runtime-wide lock.
func (r *Runtime) statsTargets(podID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if podID != "" {
		if _, ok := r.pods[podID]; ok {
			return []string{podID}
		}
		return nil
	}
	ids := make([]string, 0, len(r.pods))
	for id := range r.pods {
		ids = append(ids, id)
	}
	return ids
}

// podStats builds the wire PodStats for podID, or nil when the pod is unknown or
// has no sample to report.
//
// THE SOURCE FORK (B107). Which KERNEL produced a pod's figures is decided here,
// once, by the pod's RESOLVED backend: a vm pod's working set and CPU come from
// the guest's own cgroup2 hierarchy over the agent's Stats verb (vmPodStats),
// and a host-process pod's come from Darwin proc_pid_rusage (hostPodStats). The
// two are never mixed and neither is ever a fallback for the other — a host
// rusage figure for a vm pod would meter the vmhost helper process, not the
// workload, and would be off by the whole guest.
func (r *Runtime) podStats(ctx context.Context, podID string) *runtimev1.PodStats {
	r.mu.Lock()
	p := r.pods[podID]
	r.mu.Unlock()
	if p == nil {
		return nil
	}
	if p.isVM() {
		return r.vmPodStats(ctx, p)
	}
	return r.hostPodStats(ctx, p)
}

// hostPodStats builds the wire PodStats for a HOST-PROCESS pod, or nil when it
// has no sampler (the PodMetrics ok==false gate). It takes a ctx it does not use
// — every source in this fork is reached through the same seam, and a signature
// that differed by branch would invite the caller to decide per branch whether a
// deadline applies; proc_pid_rusage simply has nothing to cancel.
//
// The pod-level working set is the sampler's latest summed ri_phys_footprint
// (PodMetrics — the same value OOMKilled is judged against); per-container working
// sets and CPU are sampled from the proc_pid_rusage seam at request time (the
// sampler tracks only the pod-wide memory sum, and each host-process container is
// a single process, so a per-PID rusage IS the container's sample).
//
// CPU: ri_user_time + ri_system_time come out of the SAME rusage_info_v2 struct as
// the footprint, so a container's CPU and memory are one kernel sample, not two —
// which matters because the /metrics/resource consumer publishes a pod only when it
// has BOTH. The value is cumulative and carried across restarts by the pod's
// cpuAccumulator so it never goes backwards. It is USAGE accounting only: k3sm
// enforces no CFS millicore quota (best-effort QoS — see docs/resources.md), so
// this says what a pod consumed, never what it was entitled to.
//
// A Footprinter that is not also a supervisor.RUsager (a memory-only test fake)
// leaves every CPU field nil; the k3sm provider then withholds the pod from
// /metrics/resource entirely rather than publishing a memory-only sample the
// consumer would drop anyway.
//
// Only LIVE containers are reported. A terminated container has no process to
// sample, so it could only contribute a zero working set — and a zero working set
// is not "idle", it is a missing sample that makes the consumer drop the whole pod.
func (r *Runtime) hostPodStats(_ context.Context, p *pod) *runtimev1.PodStats {
	podID := p.box.GetPodId()
	// PodMetrics gates inclusion (ok==false for an unknown/unsampled pod) and
	// supplies the pod-level working set sourced from the sampler.
	m, ok := r.PodMetrics(podID)
	if !ok {
		return nil
	}

	// Snapshot each live container's name + current pid under p.mu; sample rusage
	// OUTSIDE the lock (the sampler syscalls).
	type ctr struct {
		name string
		pid  int
	}
	p.mu.Lock()
	ns, name := p.box.GetNamespace(), p.box.GetName()
	live := liveContainersLocked(p)
	ctrs := make([]ctr, 0, len(live))
	for _, cp := range live {
		ctrs = append(ctrs, ctr{name: cp.name, pid: cp.proc.PID()})
	}
	p.mu.Unlock()

	// The richer rusage seam is optional (see supervisor.RUsager): production wires
	// PhysFootprinter, which reads memory and CPU in one call.
	ru, withCPU := r.footprinter.(supervisor.RUsager)

	ts := timestamppb.New(m.Timestamp)
	containers := make([]*runtimev1.ContainerStats, 0, len(ctrs))
	// podCPUComplete tracks whether every LIVE container yielded a CPU sample; the
	// VALUE reported is the accumulator's sum over EVERY container it has seen (see
	// cpuAccumulator.sum), so a container that has since exited keeps contributing.
	podCPUComplete := len(ctrs) > 0
	for _, c := range ctrs {
		var ws uint64
		if c.pid > 0 {
			if withCPU {
				if s, err := ru.RUsage(c.pid); err == nil {
					ws = s.PhysFootprintBytes
					p.cpuAcc.observe(c.name, c.pid, s.CPUTimeNanos)
				}
			} else if fp, err := r.footprinter.Footprint(c.pid); err == nil {
				ws = fp
			}
		}
		cs := &runtimev1.ContainerStats{
			Name:      c.name,
			Timestamp: ts,
			Memory:    &runtimev1.MemoryStats{Timestamp: ts, WorkingSetBytes: ws},
		}
		// Read the accumulated total rather than this call's raw sample: it is the
		// restart-carrying, monotone figure, and it survives a sample that failed.
		if cum, seen := p.cpuAcc.total(c.name); seen {
			cs.Cpu = &runtimev1.CPUStats{Timestamp: ts, UsageCoreNanoSeconds: cum}
		} else {
			podCPUComplete = false
		}
		containers = append(containers, cs)
	}

	ps := &runtimev1.PodStats{
		PodId:      podID,
		Namespace:  ns,
		Name:       name,
		Timestamp:  ts,
		Memory:     &runtimev1.MemoryStats{Timestamp: ts, WorkingSetBytes: m.WorkingSetBytes},
		Containers: containers,
	}
	// The pod-level counter is reported only when EVERY live container contributed
	// — a partial sum is not a pod total, and publishing one would understate the
	// pod and (being a counter) could fall when the missing container reappears.
	if podTotal, seen := p.cpuAcc.sum(); podCPUComplete && seen {
		ps.Cpu = &runtimev1.CPUStats{Timestamp: ts, UsageCoreNanoSeconds: podTotal}
	}
	return ps
}
