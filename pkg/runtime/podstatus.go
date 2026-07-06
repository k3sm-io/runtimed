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
	// Long-lived containers split by declaration list: an init-declared container
	// (today only native sidecars are tracked long-lived from the init list)
	// reports under init_container_statuses, mains under container_statuses.
	for _, cp := range p.containers {
		if cp.initDeclared {
			st.InitContainerStatuses = append(st.InitContainerStatuses, containerStatusOf(cp))
		} else {
			st.ContainerStatuses = append(st.ContainerStatuses, containerStatusOf(cp))
		}
	}
	return st
}

// containerStatusOf clones a container's status so callers can't mutate pod state.
// The restart_count + last_termination_state (M2.2) and volume_mount + user
// mirrors (M2.2/M2.3) are carried through losslessly. The caller holds pod.mu.
func containerStatusOf(cp *containerProc) *runtimev1.ContainerStatus {
	st := &runtimev1.ContainerStatus{
		Name:                 cp.state.GetName(),
		Image:                cp.state.GetImage(),
		State:                cp.state.GetState(),
		Ready:                cp.state.GetState().GetRunning() != nil,
		RestartCount:         cp.state.GetRestartCount(),
		LastTerminationState: cp.state.GetLastTerminationState(),
		VolumeMounts:         cp.state.GetVolumeMounts(),
		User:                 cp.state.GetUser(),
	}
	if cp.sidecar() {
		// A native sidecar reports started while running (spawn-equals-started:
		// startup-probe gating is deliberately out of scope per the apis
		// restart_policy contract); an exited/mid-restart sidecar reads
		// started=false until its replacement runs.
		st.Started = st.Ready
		st.StartedSet = true
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
