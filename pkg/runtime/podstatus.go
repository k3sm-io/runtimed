package runtime

import (
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// podStatus renders a PodStatus snapshot for p (safe to call without holding
// Runtime.mu; it takes p.mu).
func (r *Runtime) podStatus(p *pod) *runtimev1.PodStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	st := &runtimev1.PodStatus{
		PodId:     p.box.GetPodId(),
		Phase:     p.phase,
		Reason:    p.reason,
		Message:   p.message,
		PodIp:     p.podIP,
		StartTime: nowProto(),
	}
	if p.podIP != "" {
		st.PodIps = []string{p.podIP}
	}
	for _, cp := range p.containers {
		// Clone the per-container status so callers can't mutate pod state. The
		// volume_mount + user mirrors (M2.2/M2.3) are carried through losslessly.
		cs := &runtimev1.ContainerStatus{
			Name:         cp.state.GetName(),
			Image:        cp.state.GetImage(),
			State:        cp.state.GetState(),
			Ready:        cp.state.GetState().GetRunning() != nil,
			VolumeMounts: cp.state.GetVolumeMounts(),
			User:         cp.state.GetUser(),
		}
		st.ContainerStatuses = append(st.ContainerStatuses, cs)
	}
	return st
}

// publish renders the event and fans it out to WatchPodStatus subscribers. Called
// OUTSIDE any pod/runtime lock.
func (r *Runtime) publish(t runtimev1.PodStatusEventType, st *runtimev1.PodStatus) {
	r.broker.publish(&runtimev1.PodStatusEvent{Type: t, Status: st})
}

// snapshotStatuses returns the current status of podID (or all pods if empty).
func (r *Runtime) snapshotStatuses(podID string) []*runtimev1.PodStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if podID != "" {
		if p, ok := r.pods[podID]; ok {
			return []*runtimev1.PodStatus{r.podStatusLocked(p)}
		}
		return nil
	}
	out := make([]*runtimev1.PodStatus, 0, len(r.pods))
	for _, p := range r.pods {
		out = append(out, r.podStatusLocked(p))
	}
	return out
}

// podStatusLocked is podStatus for callers already holding Runtime.mu (it still
// takes the finer-grained p.mu, which never nests the other way).
func (r *Runtime) podStatusLocked(p *pod) *runtimev1.PodStatus {
	return r.podStatus(p)
}
