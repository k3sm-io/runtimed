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
	"fmt"
	"time"

	"google.golang.org/grpc/codes"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The two per-container kill verbs, RestartContainer and StopContainer, share
// one eligibility chain (refuseIneligible) and one terminate sequence
// (terminateContainer). RestartContainer is the terminate plus a re-spawn;
// StopContainer is the terminate alone. Keeping both halves single-sourced is
// what stops the two verbs from answering one ineligible pod two ways, or
// killing one container two ways.

// verbRefusal is a structured refusal from refuseIneligible: the gRPC code and
// the typed failure reason both verbs report, and the message. Each verb wraps
// it in its own response type.
type verbRefusal struct {
	code   codes.Code
	reason runtimev1.FailureReason
	msg    string
}

// refuseIneligible resolves the pod and container a per-container kill verb
// names, or explains why the verb cannot act on them. verb ("restart", "stop")
// only names the refusal. Every refusal is decided BEFORE any process is
// touched, which is the point: stopping a process and then discovering the verb
// cannot finish would turn a running container into a dead one.
//
// The chain, in order:
//
//   - unknown pod: NotFound + NOT_FOUND.
//   - vm pod: codes.Unimplemented + UNSUPPORTED. A vm pod's containers are guest
//     processes with no host containerProc, so every step after this one
//     (findContainer, the process-group GracefulStop, a re-spawn) operates on
//     state a vm pod does not have. Killing or restarting one container inside a
//     running guest needs a guest-agent verb guest/v1 does not define, so the
//     honest answer is a typed "the backend does not implement this" rather than
//     a silent no-op. The provider reads Unimplemented and does not retry.
//   - pod being deleted (p.stopping): FailedPrecondition + NOT_FOUND, the answer
//     the installer gives a spawn that lands during a delete — the pod is not
//     going to exist, so no retry helps. DeletePod's teardown owns every process
//     group of a stopping pod.
//   - unknown container: NotFound + NOT_FOUND.
//   - a container that never started: FailedPrecondition + NOT_UPDATABLE. It is
//     Waiting because its start failed before the spawn (the partial-start
//     contract), so it has no process to terminate and no run to record, and
//     supervisor.Process does not nil-guard the proc every later step
//     dereferences. runtimed is the node's in-process runtime, so that panic
//     would be node-scoped; refuse instead, and name the verb that does apply.
func (r *Runtime) refuseIneligible(verb, podID, name string) (*pod, *containerProc, *verbRefusal) {
	r.mu.Lock()
	p, ok := r.pods[podID]
	r.mu.Unlock()
	if !ok {
		return nil, nil, refusal(codes.NotFound, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"pod %s not found", podID)
	}
	if p.isVM() {
		return nil, nil, refusal(codes.Unimplemented, runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED,
			"%s %s/%s: a vm pod's containers run inside its guest, and guest/v1 defines no per-container %s; recreate the pod",
			verb, podID, name, verb)
	}
	p.mu.Lock()
	stopping := p.stopping
	p.mu.Unlock()
	if stopping {
		return nil, nil, refusal(codes.FailedPrecondition, installFailureReason(errPodStopping),
			"%s %s/%s: %v", verb, podID, name, errPodStopping)
	}
	cp := r.findContainer(p, name)
	if cp == nil {
		return nil, nil, refusal(codes.NotFound, runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			"container %s not found in pod %s", name, podID)
	}
	if cp.proc == nil {
		return nil, nil, refusal(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			"%s %s/%s: container has not started; use StartContainer", verb, podID, name)
	}
	return p, cp, nil
}

// verbInFlightLocked names the kill verb already acting on cp, or "" when
// none is: "restart" while RestartContainer holds its `restarting` claim, and
// "stop" while StopContainer holds its `stopped` claim and has not yet
// recorded the exit. It is the one claim discipline both verbs consult before
// taking their own claim, in the same p.mu hold that takes it, so a stop and a
// restart can never act on one container at once: a restart would re-spawn a
// container the stop is concluding (the stop then records a terminated state
// over a live replacement), and a stop would kill the replacement a restart is
// installing. A `stopped` latch whose exit is recorded is a concluded stop, not
// an in-flight one; restarting that container is how it runs again. Caller
// holds p.mu.
func verbInFlightLocked(cp *containerProc) string {
	switch {
	case cp.restarting:
		return "restart"
	case cp.stopped && cp.state.GetState().GetTerminated() == nil:
		return "stop"
	}
	return ""
}

// refuseInFlight builds the refusal a kill verb returns when another kill verb
// (inFlight, from verbInFlightLocked) is already acting on the container, and
// logs it once here, at the boundary that decides it: FailedPrecondition +
// NOT_UPDATABLE, because the container will be updatable again once the other
// verb concludes, so the caller's retry is the right response.
func (r *Runtime) refuseInFlight(verb, podID, name, inFlight string) *verbRefusal {
	r.log.Warn("refused a container kill verb: another is in flight",
		"pod", podID, "container", name, "verb", verb, "in_flight", inFlight)
	return refusal(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
		"%s %s/%s: a %s of the container is in flight", verb, podID, name, inFlight)
}

// procDone reports, without blocking, whether proc's exit has been reaped.
func procDone(proc *supervisor.Process) bool {
	select {
	case <-proc.Done():
		return true
	default:
		return false
	}
}

// refusal builds a verbRefusal with a formatted message.
func refusal(code codes.Code, reason runtimev1.FailureReason, format string, args ...any) *verbRefusal {
	return &verbRefusal{code: code, reason: reason, msg: fmt.Sprintf(format, args...)}
}

// containerExit is what the kqueue reaper recorded for a terminated container.
type containerExit struct {
	code, sig int
	err       error
}

// terminateContainer stops ONE container's own process group within grace
// (supervisor.GracefulStop: SIGTERM → grace → SIGKILL, or an immediate SIGKILL
// at grace 0) and waits for the kqueue reaper to collect it, returning the
// recorded exit. SIGKILL is uncatchable, so the wait is bounded; ctx bounds it
// too, and a cancelled ctx is the only error.
//
// reaped reports that there was a process to wait for (a pid was assigned);
// the caller's post-exit steps (the log-drain wait) apply only then.
//
// The ctx arm re-checks Done non-blockingly before it is honoured: when the
// kill has completed and ctx is cancelled at the same instant, select picks
// either ready arm at random, and reporting Canceled for a container that is in
// fact dead would leave the caller's latch set, or cleared, for the wrong
// reason. The recorded status is read with a detached ctx for the same reason:
// Wait itself selects between ctx and the already-closed Done.
func (r *Runtime) terminateContainer(ctx context.Context, p *pod, cp *containerProc, grace time.Duration) (exit containerExit, reaped bool, err error) {
	proc := cp.proc
	pid := proc.PID()
	if pid <= 0 {
		return containerExit{}, false, nil
	}
	if _, _, err := supervisor.GracefulStop(ctx, pid, grace, proc.Done(),
		termSignal, killSignal, r.signalGroup, r.exitObservationGrace()); err != nil {
		r.log.Warn("terminate container: graceful stop", "pod", p.box.GetPodId(), "container", cp.name, "pid", pid, "err", err)
	}
	select {
	case <-proc.Done():
	case <-ctx.Done():
		select {
		case <-proc.Done():
		default:
			return containerExit{}, false, ctx.Err()
		}
	}
	code, sig, werr := proc.Wait(context.WithoutCancel(ctx)) // already reaped: returns recorded status
	return containerExit{code: code, sig: sig, err: werr}, true, nil
}

// awaitLogsDrained waits, bounded by the drain grace and independent of any
// RPC ctx, for a terminated instance's log pumps to flush its final output
// into the container's log file, reporting whether they did. Both kill verbs
// run it after terminateContainer: RestartContainer because the replacement
// tails the same capture files, StopContainer because the terminated state it
// publishes is what tells the node the log tail is final. A forked grandchild
// holding the pipe keeps LogsDrained open, so the bound is load-bearing.
func (r *Runtime) awaitLogsDrained(proc *supervisor.Process) bool {
	drain := time.NewTimer(r.drainGraceDuration())
	defer drain.Stop()
	select {
	case <-proc.LogsDrained():
		return true
	case <-drain.C:
		return false
	}
}
