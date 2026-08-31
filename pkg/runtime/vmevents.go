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
	"fmt"
	"io"
	"time"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// watchGuestContainerEvents subscribes to a vm pod's guest-agent ContainerEvents
// stream and folds every event into that pod's container statuses until the
// stream ends or ctx is cancelled.
//
// THE KILL-REASON FORK (B107). This is the ONLY source of OOMKilled for a vm
// pod. The kill happens in the guest kernel's cgroup, which the host cannot
// observe at all: the host's proc_pid_rusage sampler can see the vmhost helper's
// footprint and nothing inside the guest, so a host-derived OOMKilled for a vm
// pod would be a guess dressed as a kernel fact — and upstream treats OOMKilled
// as the pod's own fault (it restarts it and counts it against a Job's backoff).
// oomKill therefore refuses vm pods outright (see pod.go) and this stream is
// what fills the gap.
//
// It is the vm pod's own supervision goroutine, started by the vm-pod ASSEMBLY
// (createVMPod, once M11.2-d2's live boot lands — CreateVM is a lab-gated stub
// today, so no assembled vm pod exists in production yet) and rooted at the
// pod-lifetime supCtx like every other per-pod goroutine. A stream error is
// returned, not retried here: the caller owns the pod's lifecycle and is the
// only thing that knows whether a dead agent means "restart the watch" or "the
// VM is gone".
func (r *Runtime) watchGuestContainerEvents(ctx context.Context, p *pod) error {
	podID := p.box.GetPodId()
	conn, err := r.dialGuest(podID)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	stream, err := guestv1.NewGuestAgentClient(conn).
		ContainerEvents(ctx, &guestv1.ContainerEventsRequest{PodId: podID})
	if err != nil {
		return guestStreamError("events", podID, err)
	}
	for {
		ev, rerr := stream.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil // the guest closed the stream
			}
			return guestStreamError("events", podID, rerr)
		}
		r.applyGuestContainerEvent(p, ev)
	}
}

// applyGuestContainerEvent folds one guest-agent container event into p's
// guest-container statuses.
//
// UNTRUSTED DATA. The event names a container, and the name is resolved against
// what THIS POD DECLARED — an undeclared name is dropped, not created — so the
// status map a guest can grow is bounded by the pod's own container count and a
// guest cannot invent a container the cluster never scheduled. The event's own
// timestamp is ignored in favour of a host stamp for the same reason vmPodStats
// host-stamps its sample: a guest-chosen time on a host status is a guest-chosen
// ordering. The exit code and signal ARE taken verbatim — the guest legitimately
// owns them (it ran the process), exactly as the exec route relays an exit code.
func (r *Runtime) applyGuestContainerEvent(p *pod, ev *guestv1.ContainerEvent) {
	name := ev.GetContainer()
	spec := declaredContainerSpec(p.box, name)
	if spec == nil {
		r.log.Warn("dropping a guest container event for an undeclared container",
			"pod", p.box.GetPodId(), "container", boundGuestMessage(name))
		return
	}
	started, exited := ev.GetStarted(), ev.GetExited()
	if (started == nil) == (exited == nil) {
		// The union requires exactly one arm; neither (or an unknown future arm)
		// is not an event this build can fold.
		return
	}
	at := nowProto()

	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.guestContainerLocked(name, spec.GetImage())
	if started != nil {
		st.State = &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: at}}
		st.Ready = true
		return
	}
	st.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
		ExitCode:   exited.GetExitCode(),
		Signal:     exited.GetSignal(),
		FinishedAt: at,
		Reason:     guestTerminationReason(exited),
	}}
	st.Ready = false
	if exited.GetOomKilled() {
		// The pod-level latch, set from the ONE source that can observe a guest
		// cgroup OOM. It mirrors the host spine's p.oomKilled, which only the host
		// sampler sets — and which oomKill refuses to set for a vm pod.
		p.oomKilled = true
	}
}

// guestTerminationReason maps a guest exit onto the same reason strings the
// host-process path emits (watchContainerExit), so a consumer reads one
// vocabulary regardless of which kernel ran the container.
func guestTerminationReason(exited *guestv1.ContainerExited) string {
	switch {
	case exited.GetOomKilled():
		return "OOMKilled"
	case exited.GetExitCode() == 0 && exited.GetSignal() == 0:
		return "Completed"
	default:
		return "Error"
	}
}

// guestContainerLocked returns name's guest container status on p, creating it
// on first sight and recording the declaration order so the status list is
// stable across reads. The caller holds p.mu.
func (p *pod) guestContainerLocked(name, image string) *runtimev1.ContainerStatus {
	if p.guestContainers == nil {
		p.guestContainers = map[string]*runtimev1.ContainerStatus{}
	}
	if st, ok := p.guestContainers[name]; ok {
		return st
	}
	st := &runtimev1.ContainerStatus{Name: name, Image: image}
	p.guestContainers[name] = st
	p.guestContainerOrder = append(p.guestContainerOrder, name)
	return st
}

// declaredContainerSpec returns the pod's declaration of name, or nil when the
// pod declares no such container. Unlike vmContainerName it does NOT treat an
// empty name as "the sole container": a verb's selector may be elided by an
// operator, but an EVENT that does not say which container it is about is
// malformed, and resolving it to a guess would attribute a guest's exit — an
// OOMKilled, at that — to a container that may not have exited at all.
func declaredContainerSpec(box *runtimev1.PodBox, name string) *runtimev1.Container {
	if name == "" {
		return nil
	}
	for _, c := range box.GetInitContainers() {
		if c.GetName() == name {
			return c
		}
	}
	for _, c := range box.GetContainers() {
		if c.GetName() == name {
			return c
		}
	}
	return nil
}

// watchVMPodEvents keeps a vm pod's guest-container statuses fed for the pod's
// whole life, restarting the subscription when the stream ends.
//
// THE RETRY IS THIS FUNCTION'S JOB, not watchGuestContainerEvents'. That function
// deliberately returns a stream error rather than retrying, because only the
// caller knows whether a dead agent means "resubscribe" or "the VM is gone" — and
// here the answer is knowable: the helper's exit watch owns "the VM is gone", so
// anything this loop sees while the helper is alive is a stream that should be
// re-established. Without the retry, one transient agent hiccup would silence a
// pod's container statuses — including its ONLY source of OOMKilled — for the
// rest of its life, with nothing to indicate it had stopped listening.
//
// The delay between attempts is what keeps a guest whose agent is permanently
// wedged from spinning the daemon at the speed of a failed dial.
func (r *Runtime) watchVMPodEvents(ctx context.Context, p *pod) {
	podID := p.box.GetPodId()
	for {
		if err := r.watchGuestContainerEvents(ctx, p); err != nil {
			if ctx.Err() != nil {
				return // the pod is being torn down; not a failure
			}
			r.log.Warn("the guest container-event stream ended; resubscribing",
				"pod", podID, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(guestEventResubscribeDelay):
		}
	}
}

// guestEventResubscribeDelay paces the container-event resubscription. It is
// short enough that a transient agent restart costs at most one interval of
// missed events, and long enough that a permanently wedged guest costs one dial
// per second rather than a busy loop.
const guestEventResubscribeDelay = time.Second

// watchVMHelperExit fails a vm pod when its host helper dies after readiness.
//
// WITHOUT IT A POD WEDGES AT RUNNING. Everything that reports a vm pod's health
// flows through the guest agent, and the agent is reached through the helper — so
// when the hypervisor dies, the guest panics, or the helper is killed, the pod's
// containers simply stop being updated and the pod sits Running forever with no
// host-side event. The kubelet analog is a container runtime noticing its own
// child exited; here the child IS the machine.
//
// It reports the pod FAILED with the helper's retained output, which is the same
// evidence a pre-ready failure would have carried — read while the handle is
// still registered, because StopVM drops it. A clean daemon shutdown does not
// come through here: Close cancels supCtx first, and the ctx arm wins.
func (r *Runtime) watchVMHelperExit(ctx context.Context, p *pod) {
	podID := p.box.GetPodId()
	done, ok := r.vmBackend.VMDone(podID)
	if !ok {
		// No live helper is registered for a pod that just booted one: the only
		// way here is a concurrent teardown, which owns the pod's fate.
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-done:
	}
	// Re-check the teardown edge: a DeletePod stops the helper and cancels
	// supCtx, and the two are observed in an arbitrary order, so an expected
	// stop can arrive here as an exit. Reporting that as a crash would make
	// every vm pod deletion look like a failure.
	if ctx.Err() != nil {
		return
	}
	output := r.vmBackend.VMHelperOutput(podID)
	r.log.Error("the vm host helper exited while its pod was running; the guest is gone",
		"pod", podID, "helper_output", output)
	r.failVMPod(p, "VMHostExited",
		fmt.Sprintf("the vm host helper for pod %s exited unexpectedly, so its guest is gone; helper output: %s", podID, output))
}

// failVMPod transitions a running vm pod to Failed and publishes the change.
//
// Every guest container still believed to be Running is terminated with the same
// reason, because a pod whose machine is gone cannot have a running container in
// it — and a status that left them Running would be read by the provider as a
// healthy pod behind a failed one, which is exactly the wedge this path exists to
// prevent. The publish happens OUTSIDE p.mu (the re-entrancy rule).
func (r *Runtime) failVMPod(p *pod, reason, message string) {
	at := nowProto()
	p.mu.Lock()
	if p.phase == runtimev1.PodPhase_POD_PHASE_FAILED || p.phase == runtimev1.PodPhase_POD_PHASE_SUCCEEDED {
		p.mu.Unlock()
		return // already terminal; do not overwrite the first, more specific reason
	}
	p.phase = runtimev1.PodPhase_POD_PHASE_FAILED
	p.reason = reason
	p.message = message
	for _, name := range p.guestContainerOrder {
		st := p.guestContainers[name]
		if st == nil || st.GetState().GetRunning() == nil {
			continue
		}
		st.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
			// Exit code 255 is the "terminated for a reason the runtime could
			// not observe" convention the host-process path uses for a
			// container whose status was never collected: the guest is gone, so
			// no real code exists and inventing 0 would read as success.
			ExitCode:   255,
			FinishedAt: at,
			Reason:     reason,
			Message:    message,
		}}
		st.Ready = false
	}
	p.mu.Unlock()
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
}
