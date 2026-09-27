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

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// StopContainer kills ONE container of a running pod and leaves it Terminated:
// the CRI StopContainer(container_id, timeout) the kubelet's killContainer
// issues, for example when a postStart hook fails. It is the terminate half of
// RestartContainer with no re-spawn — the shared eligibility chain
// (refuseIneligible) and the shared kill sequence (terminateContainer, SIGTERM →
// grace → SIGKILL on the container's own process group, or an immediate SIGKILL
// at grace 0). Whether the container ever runs again is the provider's
// restartPolicy decision, made through RestartContainer; runtimed performs no
// exit-driven restarts.
//
// The verb, not the kqueue reaper, concludes the container. It claims it with
// the per-container `stopped` latch before the kill (the `restarting`
// precedent), waits for the exit and the log drain, then writes the terminated
// state through terminatedStateLocked — the same derivation the reaper uses —
// recomputes the phase, claims any truly-terminal teardown, publishes ONE
// MODIFIED, and returns that status. watchContainerExit sees the latch and
// neither writes nor publishes, so every observer sees one FinishedAt and one
// event for the death. restart_count, the log file and its numbering are
// unchanged, and no last_termination_state is recorded: nothing replaced the
// run.
//
// Refusals are structured responses, never transport errors: unknown pod or
// container → NOT_FOUND; vm pod → UNSUPPORTED with an embedded
// codes.Unimplemented (guest/v1 has no per-container stop); a pod being
// deleted → FailedPrecondition; a container that
// never started, or one a restart or another stop is already acting on →
// FailedPrecondition + NOT_UPDATABLE. A container that has already exited is
// stopped: the verb returns its recorded terminated state and signals nothing.
// A DeletePod that begins while the stop is in flight owns the pod's terminal
// event: the verb then returns the exit it observed and records, tears down and
// publishes nothing.
func (r *Runtime) StopContainer(ctx context.Context, req *runtimev1.StopContainerRequest) (*runtimev1.StopContainerResponse, error) {
	p, cp, refused := r.refuseIneligible("stop", req.GetPodId(), req.GetContainer())
	if refused != nil {
		return stopFailure(refused.code, refused.reason, "%s", refused.msg), nil
	}

	// Claim the container, in the same hold that reads its state, so the
	// reaper's latch check and this claim cannot interleave: an exit the reaper
	// already recorded is returned as-is, and an exit it has not recorded yet
	// is this verb's to record.
	p.mu.Lock()
	if cp.state.GetState().GetTerminated() != nil {
		status := containerStatusOf(cp)
		p.mu.Unlock()
		return &runtimev1.StopContainerResponse{Status: status}, nil
	}
	if inFlight := verbInFlightLocked(cp); inFlight != "" {
		p.mu.Unlock()
		refused := r.refuseInFlight("stop", req.GetPodId(), cp.name, inFlight)
		return stopFailure(refused.code, refused.reason, "%s", refused.msg), nil
	}
	cp.stopped = true
	p.mu.Unlock()

	grace := graceDuration(req.GetGracePeriodSeconds(), p)
	exit, reaped, err := r.terminateContainer(ctx, p, cp, grace)
	if err != nil || !reaped {
		// Release the claim so the reaper records the exit whenever it comes.
		// The release is safe only while the process is still alive: once Done
		// has closed the reaper may already have seen the latch and returned, so
		// a kill that completed after all is concluded here instead.
		if r.releaseStopClaim(p, cp) {
			if err == nil {
				return stopFailure(codes.Internal, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
					"stop %s/%s: the container has no process to signal", req.GetPodId(), cp.name), nil
			}
			return stopFailure(codes.Canceled, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
				"stop %s/%s: %v", req.GetPodId(), cp.name, err), nil
		}
		code, sig, werr := cp.proc.Wait(context.WithoutCancel(ctx))
		exit = containerExit{code: code, sig: sig, err: werr}
	}
	if !r.awaitLogsDrained(cp.proc) {
		r.log.Warn("stopped container's log tail still running; its last output may be missing from the terminated status's log file",
			"pod", req.GetPodId(), "container", cp.name, "grace", r.drainGraceDuration())
	}

	p.mu.Lock()
	if p.stopping {
		// DeletePod began while this stop was in flight. It has removed the pod,
		// owns its teardown, and publishes its DELETED; a terminal write, a
		// teardown claim or a MODIFIED from here would describe a deleted pod,
		// after the event that ended its stream. The container did stop, so the
		// exit this verb observed is returned without being recorded.
		status := containerStatusOf(cp)
		status.State = &runtimev1.ContainerState{Terminated: terminatedLocked(p, cp, exit.code, exit.sig, exit.err)}
		status.Ready = false
		p.mu.Unlock()
		r.log.Debug("stop concluded while its pod was being deleted; the delete owns the terminal event",
			"pod", req.GetPodId(), "container", cp.name)
		return &runtimev1.StopContainerResponse{Status: status}, nil
	}
	terminatedStateLocked(p, cp, exit.code, exit.sig, exit.err)
	r.recomputePhaseLocked(p)
	// Killing the last live main can conclude the pod; the teardown that claim
	// carries (the memory sampler, the native sidecars) is the same one the
	// reaper would have claimed for this exit.
	td := claimTerminalTeardownLocked(p)
	status := containerStatusOf(cp)
	p.mu.Unlock()

	// Detached: a teardown that stops root-owned process groups must not be
	// truncated by this RPC returning.
	r.runTerminalTeardown(context.WithoutCancel(ctx), p, td)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
	return &runtimev1.StopContainerResponse{Status: status}, nil
}

// releaseStopClaim drops a container's stopped latch after a stop that did not
// complete, reporting whether it did. It refuses when the process has in fact
// exited (Done closed): the reaper checks the latch only after the exit, so it
// may already have returned without recording anything, and clearing the latch
// then would leave the exit recorded by nobody.
func (r *Runtime) releaseStopClaim(p *pod, cp *containerProc) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if procDone(cp.proc) {
		return false
	}
	cp.stopped = false
	return true
}

// stopFailure builds a StopContainerResponse carrying a structured failure.
func stopFailure(code codes.Code, reason runtimev1.FailureReason, format string, args ...any) *runtimev1.StopContainerResponse {
	return &runtimev1.StopContainerResponse{
		Error:         rpcStatus(code, format, args...),
		FailureReason: reason,
	}
}
