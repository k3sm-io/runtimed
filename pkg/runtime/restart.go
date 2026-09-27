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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// RestartContainer restarts a single container of a running pod IN place: it
// terminates the container's process group within the grace window, then re-spawns
// it from the same SPEC through the same machinery createPod uses — the pod's
// already-generated SBPL profile, the uid/gid drop via the exec-shim backend,
// and the same mounts — so the replacement runs in exactly the same confinement
// domain. The restart_count is incremented and the prior run is recorded in
// last_termination_state. A failed liveness probe or a CrashLoopBackOff re-exec
// drives this (the provider's probe/backoff runner invokes it); it is not a
// pod-level restart — other containers are untouched.
//
// A re-exec is also how a pod leaves a terminal phase: the swap below feeds
// recomputePhaseLocked, which de-escalates the pod back to Running, and
// re-arms the memory sampler if that terminal transition had cancelled it.
//
// RestartContainer is the shared terminate (terminateContainer, the one kill
// sequence StopContainer also uses) followed by a re-spawn; StopContainer is the
// terminate alone. Both verbs refuse through the same eligibility chain
// (refuseIneligible), so unknown pod / container return a structured NOT_FOUND
// (RestartContainerResponse carries a google.rpc.Status, matching
// CreatePod/UpdatePod) rather than a transport error, and a vm pod answers
// UNSUPPORTED with an embedded codes.Unimplemented. A pod that is being deleted
// is refused up front with FailedPrecondition + NOT_FOUND; one whose delete
// begins during the re-spawn refuses the replacement with the same answer and
// SIGKILLs the group it had already spawned — the answer StartContainer gives,
// through the same installer, because a group installed after DeletePod's
// snapshot is one nothing would ever signal.
func (r *Runtime) RestartContainer(ctx context.Context, req *runtimev1.RestartContainerRequest) (*runtimev1.RestartContainerResponse, error) {
	// The shared eligibility chain (refuseIneligible): unknown pod, vm pod
	// (UNSUPPORTED), a pod being deleted, unknown container, and a
	// container that never started are all refused here, before the old process
	// is touched — stopping it and then failing the re-spawn would turn a
	// running container into a dead one.
	p, oldCP, refused := r.refuseIneligible("restart", req.GetPodId(), req.GetContainer())
	if refused != nil {
		return restartFailure(refused.code, refused.reason, "%s", refused.msg), nil
	}

	// Snapshot the old process + spec, and flag the container as restarting so the
	// kqueue reaper's watchContainerExit does not conclude the pod terminal (which
	// would flip the phase and cancel the memory sampler) while we re-spawn.
	p.mu.Lock()
	// The shared claim discipline (verbInFlightLocked): a stop that has claimed
	// this container and not yet recorded its exit is concluding it, and a
	// re-spawn now would install a replacement the stop then reports dead.
	if verbInFlightLocked(oldCP) == "stop" {
		p.mu.Unlock()
		refused := r.refuseInFlight("restart", req.GetPodId(), oldCP.name, "stop")
		return restartFailure(refused.code, refused.reason, "%s", refused.msg), nil
	}
	oldProc := oldCP.proc
	oldRestartCount := oldCP.state.GetRestartCount()
	oldStarted := oldCP.state.GetState().GetRunning().GetStartedAt()
	spec := oldCP.spec
	initDeclared := oldCP.initDeclared
	oldCP.restarting = true
	p.mu.Unlock()

	// Terminate the old process group within the grace window (SIGTERM → grace →
	// SIGKILL escalation), then wait for the kqueue reaper to collect it
	// before re-spawning so the replacement does not race the old for the pod
	// IP/ports. SIGKILL is uncatchable, so the wait is bounded; ctx bounds it too.
	grace := graceDuration(req.GetGracePeriodSeconds(), p)
	oldExit, reaped, err := r.terminateContainer(ctx, p, oldCP, grace)
	if err != nil {
		r.clearRestarting(ctx, p, oldCP)
		return restartFailure(codes.Canceled, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			"restart %s/%s: %v", req.GetPodId(), oldCP.name, err), nil
	}
	if reaped {
		// The replacement tails the SAME capture files from the persisted
		// offset, so the old instance's final drain must finish first or both
		// tails read the same bytes. It follows the reap promptly (a file tail
		// has no inherited-pipe EOF to wait for); the bound is the backstop.
		if !r.awaitLogsDrained(oldProc) {
			r.log.Warn("old instance's log tail still running at restart; its last output may be lost or duplicated",
				"pod", req.GetPodId(), "container", oldCP.name, "grace", r.drainGraceDuration())
		}
	}

	// Re-spawn from the same spec, in the same LIFECYCLE CLASS: initDeclared is
	// threaded through so an init-declared native sidecar stays a sidecar across a
	// provider-driven restart (this RPC is the only sidecar restart path — the
	// provider owns the restart decision/backoff; runtimed performs no exit-driven
	// restarts). The flag never alters confinement — the SBPL profile is
	// pod-scoped (p.profile) and the rootfs resolution (r.rootfsPath) is
	// pod-scoped, identical for init and main containers — but it derives
	// sidecar(): dropping it would silently re-classify the restarted sidecar as a
	// main, so its next exit would wrongly conclude the pod (mains-only phase
	// accounting) and it would miss the reverse-order teardown. The supervision
	// (reaper + watchContainerExit) must outlive this RPC, so detach the spawn
	// context from the RPC's cancellation (the pull/sign/wrap during a restart are
	// fast/cache-backed).
	restartRootfs, err := r.rootfsPath(p.box)
	if err != nil {
		return restartFailure(codes.InvalidArgument, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX, "restart %s: %v", req.GetPodId(), err), nil
	}
	// The replacement is started AS restart_count oldRestartCount+1, which is
	// also the floor on its log file's instance number — so the new instance
	// writes <n+1>.log and the run being replaced keeps its own file for
	// `kubectl logs --previous` to read.
	newCP, reason, err := r.startContainer(context.WithoutCancel(ctx), p, restartRootfs, spec, initDeclared, oldRestartCount+1)
	if err != nil {
		r.clearRestarting(ctx, p, oldCP)
		r.log.Error("restart: re-spawn failed", "pod", req.GetPodId(), "container", oldCP.name, "err", err)
		return restartFailure(codes.Internal, reason, "restart %s/%s: %v", req.GetPodId(), oldCP.name, err), nil
	}

	// Swap the new container in for the old (the old is now reaped + detached),
	// carrying the incremented restart_count and the prior run's termination state.
	//
	// ATOMICITY INVARIANT: the count bump, the last_termination_state, the
	// container swap, the phase recompute and the status snapshot all happen
	// under one hold of p.mu. No observer — GetPodStatus, WatchPodStatus, or this
	// response — can ever see a bumped restart_count next to the previous run's
	// terminated state; the count and the state advance together. The k3sm
	// provider's terminationKey restart idempotency rests entirely on that, so
	// never split this block.
	p.mu.Lock()
	// Both terminal phases count: a Succeeded OR Failed pod has already had its
	// memory sampler cancelled by the truly-terminal teardown (trulyTerminalLocked),
	// so a re-exec out of EITHER must re-arm it. Failed is the CrashLoopBackOff
	// case and thus the common one — omitting it would leave every re-execed
	// crash-looping pod permanently unenforced.
	wasTerminal := p.phase == runtimev1.PodPhase_POD_PHASE_SUCCEEDED ||
		p.phase == runtimev1.PodPhase_POD_PHASE_FAILED
	// Written on the not-yet-installed entry, which no observer can reach, so a
	// refused install below discards them with it.
	// startContainer already stamped this instance's number (it names the log
	// file too, and the two must not disagree); assert the agreement rather
	// than overwrite it, since a divergence would mean the file a client reads
	// for --previous is not the one last_termination_state names.
	if newCP.state.GetRestartCount() != oldRestartCount+1 {
		r.log.Warn("the container log dir carried a higher instance number than the restart count",
			"pod", req.GetPodId(), "container", oldCP.name,
			"restart_count", newCP.state.GetRestartCount(), "expected", oldRestartCount+1)
	}
	newCP.state.LastTerminationState = lastTerminationState(p, oldCP, oldExit, oldStarted, req.GetReason())
	// THE SWAP, through the installer StartContainer and the start sequence use
	// (installContainerLocked) rather than an open-coded write into p.containers.
	// This verb used to walk the slice itself and so honoured neither of the
	// installer's preconditions: a restart racing DeletePod installed a
	// root-owned process group into a pod whose teardown had already snapshotted
	// what it would signal and removed its reap records, leaving a group nothing
	// tracks, stops or collects — the very leak StartContainer's second stopping
	// check exists to close.
	//
	// oldCP is passed as the replaced entry because this function terminated it
	// and waited for its exit above, which is exactly the precondition the
	// exemption states. It is needed and not merely tidy: the terminated state is
	// recorded by the reaper goroutine, so oldCP can still read live to
	// containerLiveLocked at this instant and an unexempted install would refuse
	// an ordinary restart whenever it won that race.
	if err := installContainerLocked(p, newCP, oldCP); err != nil {
		p.mu.Unlock()
		// The replacement is spawned but untracked, so it is torn down here — the
		// obligation every caller of the installer carries. Detached from ctx for
		// the reason the re-spawn was: the pod-lifetime context is cancelled by
		// the very teardown that made this install unwelcome.
		r.killUntrackedSpawn(context.WithoutCancel(ctx), p, newCP, err.Error())
		// Only now drop the restarting flag: the old process is gone and no
		// replacement took its place, so the pod must resume ordinary phase
		// accounting for a container that is simply dead.
		r.clearRestarting(ctx, p, oldCP)
		r.log.Warn("restart: the replacement could not be installed",
			"pod", req.GetPodId(), "container", oldCP.name, "err", err)
		return restartFailure(codes.FailedPrecondition, installFailureReason(err),
			"restart %s/%s: %v", req.GetPodId(), oldCP.name, err), nil
	}
	r.recomputePhaseLocked(p)
	// A re-exec de-escalates the pod out of a terminal phase (recomputePhaseLocked
	// is a pure function of the container states, never a latch).
	deEscalated := wasTerminal && p.phase == runtimev1.PodPhase_POD_PHASE_RUNNING
	// If it did not de-escalate, this swap just spawned a process into a pod that
	// is still terminal, and it is this function's job to notice. Two ways in:
	// restarting a SIDECAR held trulyTerminalLocked false via oldCP.restarting and
	// the swap drops that flag (the mid-restart guard must be a DEFERRAL, never a
	// permanent skip); or the pod was already torn down and the provider re-execed
	// a sidecar into it anyway. In both, p.sidecarTeardown is a latch recording
	// that SOME earlier transition claimed the teardown — it cannot have covered a
	// process spawned after it — so a terminal pod re-claims its LIVE sidecars
	// outright. stopSidecars skips already-reaped procs, so the re-claim can only
	// stop something genuinely still running.
	td := claimTerminalTeardownLocked(p)
	if trulyTerminalLocked(p) {
		td.sidecars = liveSidecarsLocked(p)
	}
	status := containerStatusOf(newCP)
	p.mu.Unlock()

	// Release the REPLACED instance's log file handle. It is not released at the
	// container's exit — a forked grandchild can outlive its parent holding the
	// pipe, and closing the writer under it would fail its writes and, by the
	// write-failure policy, hand it an EPIPE — so the restart, which has already
	// terminated and reaped that process group, is where the handle goes. The
	// FILE stays: `kubectl logs --previous` reads it, and only the node deletes it.
	r.releaseReplacedContainerLog(oldCP)

	if deEscalated {
		// The pod had reached Succeeded or Failed, so the truly-terminal transition
		// already cancelled the memory sampler. The replacement main is Running
		// again, so re-arm it: a resurrected container must not run without the OOM
		// enforcement its memory limit promises. (Sidecars stopped by that same
		// transition cannot be resurrected — the documented residual in
		// trulyTerminalLocked.)
		r.armMemorySampler(p)
	}
	// Detached for the same reason as the re-spawn above: a teardown that stops
	// root-owned process groups must not be truncated by this RPC returning.
	r.runTerminalTeardown(context.WithoutCancel(ctx), p, td)

	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
	return &runtimev1.RestartContainerResponse{Status: status}, nil
}

// releaseReplacedContainerLog closes a replaced instance's log writer once its
// pumps have drained, bounded by the same grace the terminated-status path uses.
//
// It runs in its own goroutine because the bound is a wait: a grandchild holding
// the pipe keeps LogsDrained open, and a restart must not block on one. Without
// the release each restart of a crash-looping container would leak a descriptor
// for the life of the pod, which is precisely the container that restarts most.
func (r *Runtime) releaseReplacedContainerLog(oldCP *containerProc) {
	if oldCP == nil || oldCP.logw == nil {
		return
	}
	go func() {
		if oldCP.proc != nil {
			timer := time.NewTimer(r.drainGraceDuration())
			defer timer.Stop()
			select {
			case <-oldCP.proc.LogsDrained():
			case <-timer.C:
			}
		}
		if err := oldCP.logw.Close(); err != nil {
			r.log.Warn("close the replaced container log", "container", oldCP.name, "path", oldCP.logw.Path(), "err", err)
		}
	}()
}

// clearRestarting resets the restarting flag on a failed restart so the container
// resumes normal phase accounting (its old process is gone, so the pod will
// reflect the failure on the next reap/status).
//
// Dropping the flag can release a teardown that trulyTerminalLocked deferred
// while the restart was in flight (the pod concluded meanwhile), and no reap will
// re-evaluate it — this container's exit was already recorded. So the predicate is
// re-checked here too; without it a failed restart is the second way the
// mid-restart guard could turn a deferral into a permanent skip.
func (r *Runtime) clearRestarting(ctx context.Context, p *pod, cp *containerProc) {
	p.mu.Lock()
	cp.restarting = false
	r.recomputePhaseLocked(p)
	td := claimTerminalTeardownLocked(p)
	p.mu.Unlock()
	// Detached: one of the two callers is the ctx-cancelled path, and a teardown
	// that stops root-owned processes must not be truncated by the RPC's fate.
	r.runTerminalTeardown(context.WithoutCancel(ctx), p, td)
}

// lastTerminationState builds the ContainerStatus.last_termination_state for the
// run being replaced: it prefers a terminated state the reaper already recorded
// (the container exited on its own before the restart), else synthesizes one from
// the reaped exit with the restart reason. The caller holds pod.mu.
//
// An exit whose status could not be read (supervisor.ErrExitUnknown: a
// re-attached instance, not this daemon's child) is derived by terminatedLocked,
// the reaper's own derivation, so it reads ExitStatusUnknown / exitCodeUnknown
// whichever of the reaper's write and this read comes first. Synthesizing from
// the zero code the waiter returns with that error would report a live instance
// the restart killed as Completed / 0 — a success nobody observed.
func lastTerminationState(p *pod, oldCP *containerProc, exit containerExit, startedAt *timestamppb.Timestamp, reqReason string) *runtimev1.ContainerState {
	if t := oldCP.state.GetState().GetTerminated(); t != nil {
		return &runtimev1.ContainerState{Terminated: t}
	}
	if errors.Is(exit.err, supervisor.ErrExitUnknown) {
		return &runtimev1.ContainerState{Terminated: terminatedLocked(p, oldCP, exit.code, exit.sig, exit.err)}
	}
	code, sig := exit.code, exit.sig
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
		// The REPLACED instance's log file, which is what `kubectl logs
		// --previous` resolves through. runtimed does not delete it — the node
		// prunes instances — so the path stays readable until it does.
		LogPath: oldCP.state.GetLogPath(),
		// The PREDECESSOR's id: this state describes the run being replaced, so
		// it carries oldCP's identity — never the replacement's.
		ContainerId: oldCP.state.GetContainerId(),
	}}
}

// restartFailure builds a RestartContainerResponse carrying a structured failure.
func restartFailure(code codes.Code, reason runtimev1.FailureReason, format string, args ...any) *runtimev1.RestartContainerResponse {
	return &runtimev1.RestartContainerResponse{
		Error:         rpcStatus(code, format, args...),
		FailureReason: reason,
	}
}
