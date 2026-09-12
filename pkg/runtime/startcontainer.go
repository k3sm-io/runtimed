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

// StartContainer starts a container that is WAITING because a previous start
// attempt failed before its process was spawned — an image that could not be
// resolved, pulled, platform-matched, credentialed, signature-gated, or turned
// into a run spec (the partial-start contract, see startSequence). It re-runs
// image resolution and the spawn for that one container.
//
// # Why this is not RestartContainer
//
// RestartContainer's contract is to replace a container that RAN: it terminates
// the old process within the grace window, increments restart_count and records
// the prior run in last_termination_state. None of that describes a container
// that never started, and a retry loop driven through it would report a growing
// restart count for a pod whose container has restarted zero times — which
// upstream reads as a CrashLoopBackOff signal and a Job counts against its
// backoff limit. So this verb NEVER touches restart_count and NEVER writes a
// last_termination_state, and RestartContainer refuses a never-started container
// outright rather than silently doing the wrong thing.
//
// # The init sequence
//
// A successful start of an INIT container resumes the sequence it was blocking:
// the remaining init containers run in order and then the mains start, through
// the same startSequence createPod uses. Those containers' states arrive on
// WatchPodStatus / GetPodStatus, never in this response, which carries the named
// container only.
//
// Unknown pod / container return a structured NOT_FOUND, and a container that
// already has a process (running or terminated) is refused with
// FailedPrecondition + NOT_UPDATABLE — matching RestartContainer's shape, so a
// caller reads one taxonomy across both verbs. A pod that is being deleted is
// refused with FailedPrecondition + NOT_FOUND: it is not going to exist.
//
// # The trust assumption: the caller owns the backoff
//
// This verb applies NO per-call rate floor, and that is a deliberate omission
// rather than an oversight. Its only caller is the in-process Darwin provider,
// which owns the retry decision for a waiting container — it holds the
// ImagePullBackOff clock the kubelet's vocabulary describes, and a second,
// independent floor inside runtimed would silently stretch that schedule and
// make the two disagree about when the next attempt is due. CRI has no such
// floor either (RunPodSandbox/CreateContainer are unthrottled), so adding one
// here would also be a divergence from the contract this daemon mirrors.
//
// The cost of the assumption is bounded by the single-flight claim below rather
// than by trust: a caller that hammers the verb gets one in-flight start per
// container and an immediate FailedPrecondition for the rest, so the work is
// capped even when the schedule is not. What is NOT bounded is pull traffic from
// a caller that retries in a tight loop, which is the reason this paragraph
// exists — if runtimed ever gains an untrusted caller for this verb, the floor
// has to arrive with it.
func (r *Runtime) StartContainer(ctx context.Context, req *runtimev1.StartContainerRequest) (*runtimev1.StartContainerResponse, error) {
	r.mu.Lock()
	p, ok := r.pods[req.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return startFailure(codes.NotFound, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"pod %s not found", req.GetPodId()), nil
	}
	// The vm fork, at the top and before any .proc touch — the same one
	// RestartContainer takes, for the same reason: a vm pod's containers are
	// guest processes with no host containerProc, so nothing below applies to
	// one. A guest container that failed to start is the guest agent's to
	// re-attempt, and guest/v1 defines no per-container start verb, so the
	// honest answer is a typed unimplemented rather than a NotFound that would
	// read as "no such container".
	if p.isVM() {
		return startFailure(codes.Unimplemented, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			"start %s/%s: a vm pod's containers run inside its guest, and guest/v1 defines no per-container start; recreate the pod",
			req.GetPodId(), req.GetContainer()), nil
	}

	cp := r.findContainer(p, req.GetContainer())
	if cp == nil {
		return startFailure(codes.NotFound, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"container %s not found in pod %s", req.GetContainer(), req.GetPodId()), nil
	}
	// Claim the start under p.mu: the two refusals and the claim are one atomic
	// decision, so a second caller cannot pass the "has no process" check while
	// the first is mid-spawn (see containerProc.starting).
	p.mu.Lock()
	switch {
	case p.stopping:
		p.mu.Unlock()
		return startFailure(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"start %s/%s: pod is being deleted", req.GetPodId(), req.GetContainer()), nil
	case cp.proc != nil:
		p.mu.Unlock()
		return startFailure(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			"start %s/%s: container has already started; use RestartContainer",
			req.GetPodId(), req.GetContainer()), nil
	case cp.starting:
		p.mu.Unlock()
		return startFailure(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			"start %s/%s: a start is already in flight", req.GetPodId(), req.GetContainer()), nil
	}
	cp.starting = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		cp.starting = false
		p.mu.Unlock()
	}()

	rootfs, err := r.rootfsPath(p.box)
	if err != nil {
		return startFailure(codes.InvalidArgument, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			"start %s: %v", req.GetPodId(), err), nil
	}

	// The spawn and its supervision must outlive this unary RPC (the request ctx
	// is cancelled the moment the handler returns), so they run under the
	// pod-lifetime context — the same one createPod's sequence uses.
	newCP, reason, err := r.startContainer(p.supCtx, p, rootfs, cp.spec, cp.initDeclared)
	if err != nil {
		r.log.Warn("start container failed; it stays waiting",
			"pod", req.GetPodId(), "container", cp.name, "reason", reason.String(), "err", err)
		p.mu.Lock()
		// Re-type the SAME entry: the container is still waiting, now for this
		// attempt's reason. The provider renders the kubelet waiting reason from
		// it, so a stale cause here would have the operator chasing the previous
		// failure.
		cp.state.State = &runtimev1.ContainerState{
			Waiting: &runtimev1.ContainerStateWaiting{
				Message:       boundedFailureMessage(err),
				FailureReason: reason,
			},
		}
		status := containerStatusOf(cp)
		p.mu.Unlock()
		r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
		return &runtimev1.StartContainerResponse{
			Status:        status,
			Error:         rpcStatus(failureCode(err), "start %s/%s: %v", req.GetPodId(), cp.name, err),
			FailureReason: reason,
		}, nil
	}

	p.mu.Lock()
	// Carried, never bumped: this path is defined by what it does NOT change.
	// Both values are the waiting entry's own (zero and nil), and copying them
	// explicitly is what makes a future edit that starts writing a restart count
	// here visibly wrong.
	newCP.state.RestartCount = cp.state.GetRestartCount()
	newCP.state.LastTerminationState = cp.state.GetLastTerminationState()
	// The SECOND stopping check, and the one that matters: the first ran before a
	// pull that can take seconds, and DeletePod snapshots the containers it will
	// signal at its own entry. A spawn that installs after that snapshot is
	// signalled by nobody and its reap record is removed by the same call, so it
	// would outlive the pod as a root-owned group. installing is refused and the
	// group this call just created is SIGKILLed synchronously.
	if p.stopping {
		p.mu.Unlock()
		r.killUntrackedSpawn(p.supCtx, p, newCP, "the pod is being deleted")
		return startFailure(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"start %s/%s: pod is being deleted", req.GetPodId(), cp.name), nil
	}
	if err := setContainerLocked(p, newCP); err != nil {
		p.mu.Unlock()
		r.killUntrackedSpawn(p.supCtx, p, newCP, err.Error())
		return startFailure(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			"start %s/%s: %v", req.GetPodId(), cp.name, err), nil
	}
	if waitingContainersLocked(p) == 0 && p.phase == runtimev1.PodPhase_POD_PHASE_PENDING {
		// Nothing waits any more, so the pod leaves Pending. recomputePhaseLocked
		// is not used here: it is the MAINS-only terminal accounting, and this
		// pod may still be mid-init-sequence with no main started at all.
		p.phase = runtimev1.PodPhase_POD_PHASE_RUNNING
	}
	// The response's snapshot is taken NOW, before any init resume: it reports
	// the named container's status as of its start, which is what the caller
	// asked about. Whatever the resumed sequence does to the other containers
	// arrives on the status stream.
	status := containerStatusOf(newCP)
	p.mu.Unlock()
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))

	if newCP.initDeclared {
		r.resumeInitSequence(p, rootfs, newCP)
	}
	return &runtimev1.StartContainerResponse{Status: status}, nil
}

// resumeInitSequence completes the init step cp just started and then runs the
// rest of the pod's start sequence — the remaining init containers, then the
// mains — through the same startSequence createPod uses.
//
// It runs SYNCHRONOUSLY inside the RPC, exactly as CreatePod runs the sequence
// inside its own: a plain init container is waited to completion before the next
// step, and a caller that asked to start an init container is asking for the
// sequence it blocks.
//
// A failure during the resume cannot fail anything — the pod already exists.
// A pod-class failure (an init container that runs and exits non-zero, a spawn
// that fails) is logged and leaves the still-unreached containers Waiting with
// PodInitializing, which is the truthful state: the sequence stopped again. The
// caller re-attempts through this verb.
func (r *Runtime) resumeInitSequence(p *pod, rootfs string, cp *containerProc) {
	idx := initContainerIndex(p.box, cp.name)
	if idx < 0 {
		// Declared in the init list at spawn time but absent from the box now:
		// nothing coherent to resume from, and guessing an index would run the
		// sequence from the wrong place.
		r.log.Warn("started init container is not in the pod's init list; not resuming the sequence",
			"pod", p.box.GetPodId(), "container", cp.name)
		return
	}
	if reason, err := r.finishInitStep(p.supCtx, p, cp); err != nil {
		r.log.Error("resumed init step failed; the pod's remaining containers keep waiting",
			"pod", p.box.GetPodId(), "container", cp.name, "reason", reason.String(), "err", err)
		return
	}
	if reason, err := r.startSequence(p.supCtx, p, rootfs, idx+1); err != nil {
		r.log.Error("resumed start sequence failed; the pod's remaining containers keep waiting",
			"pod", p.box.GetPodId(), "reason", reason.String(), "err", err)
		return
	}
	p.mu.Lock()
	if waitingContainersLocked(p) == 0 && p.phase == runtimev1.PodPhase_POD_PHASE_PENDING {
		p.phase = runtimev1.PodPhase_POD_PHASE_RUNNING
	}
	p.mu.Unlock()
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
}

// initContainerIndex returns the position of the named container in the box's
// init list, or -1.
func initContainerIndex(box *runtimev1.PodBox, name string) int {
	for i, c := range box.GetInitContainers() {
		if c.GetName() == name {
			return i
		}
	}
	return -1
}

// startFailure builds a StartContainerResponse carrying a structured failure.
func startFailure(code codes.Code, reason runtimev1.FailureReason, format string, args ...any) *runtimev1.StartContainerResponse {
	return &runtimev1.StartContainerResponse{
		Error:         rpcStatus(code, format, args...),
		FailureReason: reason,
	}
}
