package runtime

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ListPodStats returns point-in-time resource-usage snapshots for pods on the
// node — the typed wire form of the M2.5 memory sampler, behind `kubectl top` /
// the kubelet Summary API. It replaces the runtimed-internal-only PodMetrics path
// with the apis:M2.2 PodStats/ContainerStats/MemoryStats contract the k3sm
// provider serves.
//
// pod_id empty returns every metered pod (the Summary shape); pod_id set returns
// just that pod. A pod with NO memory sampler is OMITTED: only pods with a memory
// limit are metered in M2 (the sampler is limit-driven), matching PodMetrics'
// ok==false — broadening metering to all pods awaits the same posture decision as
// PodMetrics. An unknown pod_id yields an empty list (not an error): a stats query
// races pod teardown, so "gone" is an empty snapshot, not a failure.
func (r *Runtime) ListPodStats(_ context.Context, req *runtimev1.ListPodStatsRequest) (*runtimev1.ListPodStatsResponse, error) {
	ids := r.statsTargets(req.GetPodId())
	out := make([]*runtimev1.PodStats, 0, len(ids))
	for _, id := range ids {
		if st := r.podStats(id); st != nil {
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
// not metered (no M2.5 memory sampler → omitted, the PodMetrics ok==false gate).
//
// The pod-level working set is the sampler's latest summed ri_phys_footprint
// (PodMetrics — the same value OOMKilled is judged against); per-container working
// sets are sampled from the same proc_pid_rusage Footprinter seam at request time
// (the M2 sampler tracks only the pod sum, and each M2 container is a single
// process, so a per-PID footprint is the container's working set). CPU is left
// unset: k3sm has no CPU accounting (best-effort QoS only — see docs/resources.md).
func (r *Runtime) podStats(podID string) *runtimev1.PodStats {
	// PodMetrics gates inclusion (ok==false for an unknown/unmetered pod) and
	// supplies the pod-level working set sourced from the sampler.
	m, ok := r.PodMetrics(podID)
	if !ok {
		return nil
	}

	r.mu.Lock()
	p := r.pods[podID]
	r.mu.Unlock()
	if p == nil {
		return nil
	}

	// Snapshot each container's name + current pid under p.mu; sample footprints
	// OUTSIDE the lock (the Footprinter may syscall).
	type ctr struct {
		name string
		pid  int
	}
	p.mu.Lock()
	ns, name := p.box.GetNamespace(), p.box.GetName()
	ctrs := make([]ctr, 0, len(p.containers))
	for _, cp := range p.containers {
		ctrs = append(ctrs, ctr{name: cp.name, pid: cp.proc.PID()})
	}
	p.mu.Unlock()

	ts := timestamppb.New(m.Timestamp)
	containers := make([]*runtimev1.ContainerStats, 0, len(ctrs))
	for _, c := range ctrs {
		var ws uint64
		if c.pid > 0 {
			if fp, err := r.footprinter.Footprint(c.pid); err == nil {
				ws = fp
			}
		}
		containers = append(containers, &runtimev1.ContainerStats{
			Name:      c.name,
			Timestamp: ts,
			Memory:    &runtimev1.MemoryStats{Timestamp: ts, WorkingSetBytes: ws},
		})
	}

	return &runtimev1.PodStats{
		PodId:      podID,
		Namespace:  ns,
		Name:       name,
		Timestamp:  ts,
		Memory:     &runtimev1.MemoryStats{Timestamp: ts, WorkingSetBytes: m.WorkingSetBytes},
		Containers: containers,
	}
}
