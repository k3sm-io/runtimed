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

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// RestartContainer restarts a single container of a running pod IN PLACE: it
// terminates the container's process group within the grace window, then re-spawns
// it FROM THE SAME SPEC through the same machinery createPod uses — the pod's
// already-generated SBPL profile, the M2.3 uid/gid drop via the exec-shim backend,
// and the same mounts — so the replacement runs in exactly the same confinement
// domain. The restart_count is incremented and the prior run is recorded in
// last_termination_state. A failed liveness probe or a CrashLoopBackOff re-exec
// drives this (the provider's probe/backoff runner invokes it); it is NOT a
// pod-level restart — other containers are untouched.
//
// A re-exec is also how a pod LEAVES a terminal phase: the swap below feeds
// recomputePhaseLocked, which de-escalates the pod back to Running (B26), and
// re-arms the memory sampler if that terminal transition had cancelled it.
//
// Unknown pod / container return a structured NOT_FOUND (RestartContainerResponse
// carries a google.rpc.Status, matching CreatePod/UpdatePod) rather than a
// transport error.
func (r *Runtime) RestartContainer(ctx context.Context, req *runtimev1.RestartContainerRequest) (*runtimev1.RestartContainerResponse, error) {
	r.mu.Lock()
	p, ok := r.pods[req.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return restartFailure(codes.NotFound, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"pod %s not found", req.GetPodId()), nil
	}
	oldCP := r.findContainer(p, req.GetContainer())
	if oldCP == nil {
		return restartFailure(codes.NotFound, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"container %s not found in pod %s", req.GetContainer(), req.GetPodId()), nil
	}

	// Snapshot the old process + spec, and flag the container as restarting so the
	// kqueue reaper's watchContainerExit does NOT conclude the pod terminal (which
	// would flip the phase and cancel the memory sampler) while we re-spawn.
	p.mu.Lock()
	oldProc := oldCP.proc
	oldRestartCount := oldCP.state.GetRestartCount()
	oldStarted := oldCP.state.GetState().GetRunning().GetStartedAt()
	spec := oldCP.spec
	initDeclared := oldCP.initDeclared
	oldCP.restarting = true
	p.mu.Unlock()

	// Terminate the old process group within the grace window (SIGTERM → grace →
	// SIGKILL, the M2.4 escalation), then wait for the kqueue reaper to collect it
	// BEFORE re-spawning so the replacement does not race the old for the pod
	// IP/ports. SIGKILL is uncatchable, so the wait is bounded; ctx bounds it too.
	grace := graceDuration(req.GetGracePeriodSeconds(), p)
	var oldCode, oldSig int
	if oldPID := oldProc.PID(); oldPID > 0 {
		if _, err := supervisor.GracefulStop(ctx, oldPID, grace, oldProc.Done(), termSignal, killSignal, r.signalGroup); err != nil {
			r.log.Warn("restart: graceful stop", "pod", req.GetPodId(), "container", oldCP.name, "pid", oldPID, "err", err)
		}
		select {
		case <-oldProc.Done():
		case <-ctx.Done():
			r.clearRestarting(p, oldCP)
			return restartFailure(codes.Canceled, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
				"restart %s/%s: %v", req.GetPodId(), oldCP.name, ctx.Err()), nil
		}
		oldCode, oldSig, _ = oldProc.Wait(ctx) // already reaped: returns recorded status
	}

	// Re-spawn from the same spec, in the same LIFECYCLE CLASS: initDeclared is
	// threaded through so an init-declared native sidecar stays a sidecar across a
	// provider-driven restart (this RPC is the ONLY sidecar restart path — the
	// provider owns the restart decision/backoff; runtimed performs no exit-driven
	// restarts). The flag never alters confinement — the SBPL profile is
	// pod-scoped (p.profile) and the rootfs resolution (r.rootfsPath) is
	// pod-scoped, identical for init and main containers — but it derives
	// sidecar(): dropping it would silently re-classify the restarted sidecar as a
	// MAIN, so its next exit would wrongly conclude the pod (mains-only phase
	// accounting) and it would miss the reverse-order teardown. The supervision
	// (reaper + watchContainerExit) must outlive THIS RPC, so detach the spawn
	// context from the RPC's cancellation (the pull/sign/wrap during a restart are
	// fast/cache-backed).
	newCP, reason, err := r.startContainer(context.WithoutCancel(ctx), p, r.rootfsPath(p.box), spec, initDeclared)
	if err != nil {
		r.clearRestarting(p, oldCP)
		r.log.Error("restart: re-spawn failed", "pod", req.GetPodId(), "container", oldCP.name, "err", err)
		return restartFailure(codes.Internal, reason, "restart %s/%s: %v", req.GetPodId(), oldCP.name, err), nil
	}

	// Swap the new container in for the old (the old is now reaped + detached),
	// carrying the incremented restart_count and the prior run's termination state.
	//
	// ATOMICITY INVARIANT (B26): the count bump, the last_termination_state, the
	// container swap, the phase recompute and the status snapshot all happen
	// under ONE hold of p.mu. No observer — GetPodStatus, WatchPodStatus, or this
	// response — can ever see a bumped restart_count next to the PREVIOUS run's
	// terminated state; the count and the state advance together. The k3sm
	// provider's terminationKey restart idempotency rests entirely on that, so
	// never split this block.
	p.mu.Lock()
	wasTerminal := p.phase == runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	newCP.state.RestartCount = oldRestartCount + 1
	newCP.state.LastTerminationState = lastTerminationState(oldCP, oldCode, oldSig, oldStarted, req.GetReason())
	for i, cp := range p.containers {
		if cp == oldCP {
			p.containers[i] = newCP
			break
		}
	}
	r.recomputePhaseLocked(p)
	// A re-exec de-escalates the pod out of a terminal phase (recomputePhaseLocked
	// is a pure function of the container states, never a latch).
	deEscalated := wasTerminal && p.phase == runtimev1.PodPhase_POD_PHASE_RUNNING
	status := containerStatusOf(newCP)
	p.mu.Unlock()

	if deEscalated {
		// The pod had reached Succeeded, so watchContainerExit's truly-terminal
		// transition already cancelled the memory sampler. The replacement main is
		// Running again, so re-arm it: a resurrected container must not run
		// without the OOM enforcement its memory limit promises. (Sidecars stopped
		// by that same transition CANNOT be resurrected — the documented residual
		// in watchContainerExit's invariant comment.)
		r.armMemorySampler(p)
	}

	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
	return &runtimev1.RestartContainerResponse{Status: status}, nil
}

// clearRestarting resets the restarting flag on a failed restart so the container
// resumes normal phase accounting (its old process is gone, so the pod will
// reflect the failure on the next reap/status).
func (r *Runtime) clearRestarting(p *pod, cp *containerProc) {
	p.mu.Lock()
	cp.restarting = false
	p.mu.Unlock()
}

// lastTerminationState builds the ContainerStatus.last_termination_state for the
// run being replaced: it prefers a terminated state the reaper already recorded
// (the container exited on its own before the restart), else synthesizes one from
// the reaped exit code/signal with the restart reason. The caller holds pod.mu.
func lastTerminationState(oldCP *containerProc, code, sig int, startedAt *timestamppb.Timestamp, reqReason string) *runtimev1.ContainerState {
	if t := oldCP.state.GetState().GetTerminated(); t != nil {
		return &runtimev1.ContainerState{Terminated: t}
	}
	reason := "Completed"
	if code != 0 || sig != 0 {
		reason = "Killed" // terminated by RestartContainer (e.g. a liveness restart)
	}
	return &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
		ExitCode:   int32(code),
		Signal:     int32(sig),
		Reason:     reason,
		Message:    reqReason,
		StartedAt:  startedAt,
		FinishedAt: nowProto(),
	}}
}

// restartFailure builds a RestartContainerResponse carrying a structured failure.
func restartFailure(code codes.Code, reason runtimev1.FailureReason, format string, args ...any) *runtimev1.RestartContainerResponse {
	return &runtimev1.RestartContainerResponse{
		Error:         rpcStatus(code, format, args...),
		FailureReason: reason,
	}
}
