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
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/supervisor"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// CreatePod materializes and starts a PodBox. It is idempotent on pod id: a
// second call for a live pod returns the current status as a no-op. On failure it
// returns a structured google.rpc.Status plus a typed FailureReason; the RPC
// itself returns (response, nil) so the typed failure crosses the wire.
func (r *Runtime) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	box := req.GetPod()
	if reason, err := r.validatePodBox(box); err != nil {
		return createFailure(reason, err), nil
	}

	r.mu.Lock()
	if existing, ok := r.pods[box.GetPodId()]; ok {
		r.mu.Unlock()
		return &runtimev1.CreatePodResponse{Status: r.podStatus(existing)}, nil
	}
	r.mu.Unlock()

	p, reason, err := r.createPod(ctx, box)
	if err != nil {
		r.log.Error("create pod failed", "pod", box.GetPodId(), "reason", reason.String(), "err", err)
		_ = r.removePodDir(box.GetPodId())
		return createFailure(reason, err), nil
	}

	r.mu.Lock()
	r.pods[box.GetPodId()] = p
	r.mu.Unlock()

	// Arm the M2.5 memory sampler only NOW, after registration: armMemorySampler
	// refuses to arm a pod absent from r.pods (its anti-stranding guard, B26), so
	// arming inside createPod would leave every limited pod unenforced.
	r.armMemorySampler(p)

	st := r.podStatus(p)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_ADDED, st)
	return &runtimev1.CreatePodResponse{Status: st}, nil
}

// DeletePod gracefully stops the pod's containers and forgets it. Each container
// process group gets the M2.4 SIGTERM → grace timer (raced against the kqueue
// reaper) → SIGKILL escalation; grace 0 is an immediate SIGKILL. The teardown is
// TWO-PHASE (M10.2): the MAIN containers are stopped first (concurrently, as
// before), then any native sidecars in REVERSE start order with whatever REMAINS
// of the one pod-level grace budget (see resolveGrace / stopSidecars).
// Idempotent: deleting an unknown pod succeeds.
func (r *Runtime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	r.mu.Lock()
	p, ok := r.pods[req.GetPodId()]
	if ok {
		delete(r.pods, req.GetPodId())
	}
	r.mu.Unlock()
	if !ok {
		return &runtimev1.DeletePodResponse{}, nil // idempotent
	}

	// Stop the memory sampler (M2.5): the pod is going away. The read takes p.mu —
	// memCancel is REPLACED at arbitrary runtime by armMemorySampler (a
	// RestartContainer re-exec re-arms it), so an unsynchronized read here is a
	// data race that can cancel a stale sampler and strand the live one on a
	// deleted pod (B26). armMemorySampler's own guard closes the other side: the
	// r.pods delete above already happened, so a concurrent arm is refused, and
	// p.cancel below tears down any sampler that slipped through (it is rooted at
	// p.supCtx).
	p.mu.Lock()
	memCancel := p.memCancel
	p.mu.Unlock()
	if memCancel != nil {
		memCancel()
	}

	grace := resolveGrace(req, p)

	// THE VM ROUTE. A vm pod has no containerProc to signal — its containers are
	// guest processes — so the two-phase mains/sidecars teardown below has
	// nothing to iterate and would silently do nothing, leaving the helper (and
	// its live machine) running for a pod the cluster has deleted. The whole
	// teardown for one is: stop the helper, which runs the graceful sequence
	// INSIDE the guest (agent Stop -> wait the budget -> halt the machine) and
	// then dies.
	//
	// ONE GRACE BUDGET. The helper was given this pod's grace at spawn
	// (-stop-grace) and the backend's escalation wait is never shorter than what
	// the helper will honour, so the daemon cannot SIGKILL a helper that is still
	// asking its guest to stop — the two-independently-clocked-timers power cut.
	if p.isVM() {
		// SUPERVISION IS CANCELLED FIRST, and the order is the opposite of the
		// host-process path's for a reason the live smoke found the hard way.
		//
		// The helper's exit is observed by TWO watchers: StopVM's own
		// GracefulStop, and watchVMHelperExit, which exists to fail a pod whose
		// machine died under it. They race, and cancelling afterwards lost that
		// race often enough to be the normal case — a plain `DeletePod` logged
		// "the vm host helper exited while its pod was running; the guest is
		// gone" and published a Failed status for a pod the operator had just
		// asked to delete. Contexts are monotonic, so cancelling BEFORE the stop
		// makes the watch's ctx check true by the time any exit can arrive: an
		// expected teardown can no longer be misread as a crash, deterministically
		// rather than by winning a race.
		//
		// Nothing is lost by stopping the event fold early: the pod is going
		// away, and its status is replaced with SUCCEEDED below.
		if p.cancel != nil {
			p.cancel()
		}
		if err := r.vmBackend.StopVM(ctx, req.GetPodId(), grace); err != nil {
			// Log and continue, exactly as the host path treats a failed stop: a
			// pod that will not die must never wedge its own deletion, and the
			// helper's record is kept for the next startup sweep.
			r.log.Warn("stop the vm host helper", "pod", req.GetPodId(), "err", err)
		}
		st := r.podStatus(p)
		st.Phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
		r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED, st)
		// No network Teardown: the vm route allocated no lo0 alias (a NAT-attached
		// guest is reached over its VZ attachment), and calling it would ask the
		// IPAM to release something it never handed out.
		if err := r.removePodDir(req.GetPodId()); err != nil {
			r.log.Warn("remove pod dir", "pod", req.GetPodId(), "err", err)
		}
		return &runtimev1.DeletePodResponse{}, nil
	}

	// The ONE pod-level grace budget (M10.2): anchor its deadline BEFORE the
	// mains are stopped so the sidecars that follow get only the REMAINDER.
	deadline := time.Now().Add(grace)

	p.mu.Lock()
	mains := make([]*supervisor.Process, 0, len(p.containers))
	for _, cp := range p.containers {
		if cp.sidecar() {
			continue
		}
		mains = append(mains, cp.proc)
	}
	sidecars := sidecarsLocked(p)
	// Claim the sidecar teardown for THIS delete: the main exits phase 1 induces
	// would otherwise conclude the pod in watchContainerExit and trigger the
	// voluntary-completion teardown concurrently with phase 2 (a double stop).
	p.sidecarTeardown = true
	p.mu.Unlock()

	// Phase 1: graceful-stop each MAIN container's process group concurrently: the
	// per-PID grace timers start together, so a multi-container pod shares one
	// effective grace window. GracefulStop only OBSERVES proc.Done (the kqueue
	// reaper stays the sole reaper) — an early voluntary exit skips the SIGKILL.
	var wg sync.WaitGroup
	for _, proc := range mains {
		pid := proc.PID()
		if pid <= 0 {
			continue
		}
		wg.Add(1)
		go func(proc *supervisor.Process, pid int) {
			defer wg.Done()
			escalated, observed, err := supervisor.GracefulStop(ctx, pid, grace, proc.Done(),
				termSignal, killSignal, r.signalGroup, r.exitObservationGrace())
			if err != nil {
				r.log.Warn("graceful stop pod group", "pod", req.GetPodId(), "pid", pid, "err", err)
			}
			// Diagnostic: escalated=true means the grace timer fired (SIGTERM did NOT
			// cause an exit → SIGKILL); escalated=false means the process exited within
			// grace (SIGTERM honored). Localizes a slow delete to runtimed vs the caller.
			r.log.Info("pod container graceful-stop outcome",
				"pod", req.GetPodId(), "pid", pid, "grace", grace.String(), "escalated", escalated)
			// observed=false means the reaper did not report the exit within the
			// observation bound, so the p.cancel below CAN still preempt it and the
			// container's terminated status may read "context canceled" for a group
			// the daemon SIGKILLed. The cancel is never dropped for it (a pod whose
			// process refuses to die must not wedge teardown), so this line is the
			// only record that the status which follows is not trustworthy.
			if !observed {
				r.log.Warn("pod container exit not observed before teardown deadline",
					"pod", req.GetPodId(), "pid", pid, "bound", r.exitObservationGrace().String())
			}
		}(proc, pid)
	}
	wg.Wait()

	// Phase 2 (M10.2): stop the native sidecars in REVERSE start order with the
	// budget's remainder — mains first, then their support processes, mirroring
	// the kubelet's KEP-753 termination order. A remainder <= 0 (the mains ran
	// the budget out) is the immediate-SIGKILL path — which now includes the case
	// where a main's post-SIGKILL exit-observation wait ran past the budget: the
	// grace window is the workload's promise, and a main that had to be killed
	// and then waited for has already spent it.
	r.stopSidecars(ctx, req.GetPodId(), sidecars, deadline)

	// End the pod-lifetime supervision context AFTER the graceful stop: the reapers
	// have collected the real exits — GracefulStop now WAITS for each observation
	// (bounded by exitObservationGrace) rather than merely racing it, so canceling
	// here only unblocks any watchContainerExit drain-wait still in flight instead
	// of preempting a reaper mid-kill. It must NOT precede GracefulStop, or a
	// grace>0 container would be seen as exited and never SIGKILLed. Fired here it
	// mirrors p.memCancel: pod teardown, no leak. On the bound's expiry (logged
	// above) the cancel still fires: teardown must never hang on a process that
	// refuses to die.
	if p.cancel != nil {
		p.cancel()
	}

	st := r.podStatus(p)
	st.Phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED, st)
	// Release the pod's networking (with real IPAM behind the seam, its /32 lo0
	// alias — skipping this leaks one address of the 253/node pool per pod
	// churn). Best-effort log-and-continue: a teardown error never blocks the
	// delete (the startup reconcile sweeps any stragglers).
	if err := r.network.Teardown(req.GetPodId()); err != nil {
		r.log.Warn("network teardown", "pod", req.GetPodId(), "err", err)
	}
	if err := r.removePodDir(req.GetPodId()); err != nil {
		r.log.Warn("remove pod dir", "pod", req.GetPodId(), "err", err)
	}
	// Drop the pod's reap records: its groups were just SIGKILL-escalated above,
	// so the durable records (stored outside the pod dir, so removePodDir does
	// not touch them) have served their purpose.
	r.removePodReapRecords(req.GetPodId())
	return &runtimev1.DeletePodResponse{}, nil
}

// resolveGrace computes the SIGTERM→SIGKILL window for a DeletePod: the request's
// grace_period_seconds if non-zero, else the pod's
// PodBox.termination_grace_period_seconds. A resolved value of 0 means IMMEDIATE
// kill (no SIGTERM) — the apis contract. runtimed honors the value literally; the
// Kubernetes 30s default for an UNSET grace is applied provider-side, since proto3
// cannot distinguish "unset" from an explicit 0 at this boundary (and mapping 0→30s
// would make an explicit immediate-kill unreachable).
//
// The resolved value is ONE pod-level budget shared by the whole teardown
// (M10.2): the MAIN containers are stopped first, concurrently, against the full
// budget; then the native sidecars are stopped in REVERSE start order with
// whatever REMAINS of it (elapsed time subtracted; a remainder <= 0 is the
// immediate-SIGKILL path). Sidecars never extend the pod's grace. The same rule
// governs voluntary completion (watchContainerExit), where the mains exited on
// their own and the sidecars start with the whole budget.
func resolveGrace(req *runtimev1.DeletePodRequest, p *pod) time.Duration {
	return graceDuration(req.GetGracePeriodSeconds(), p)
}

// graceDuration resolves the SIGTERM→SIGKILL window for a stop: secs if non-zero,
// else the pod's PodBox.termination_grace_period_seconds; a resolved 0 means an
// IMMEDIATE kill (no SIGTERM). Shared by DeletePod (resolveGrace) and
// RestartContainer, both of which honor an explicit per-request grace and
// otherwise fall back to the pod's configured grace.
func graceDuration(secs int64, p *pod) time.Duration {
	if secs == 0 {
		secs = p.box.GetTerminationGracePeriodSeconds()
	}
	if secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// UpdatePod applies an in-place spec change. M1 supports labels/annotations only;
// any other field change is NOT_UPDATABLE (requires recreate).
func (r *Runtime) UpdatePod(_ context.Context, req *runtimev1.UpdatePodRequest) (*runtimev1.UpdatePodResponse, error) {
	box := req.GetPod()
	if box.GetPodId() == "" {
		return &runtimev1.UpdatePodResponse{
			Error:         rpcStatus(codes.InvalidArgument, "pod_id is required"),
			FailureReason: runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
		}, nil
	}
	r.mu.Lock()
	p, ok := r.pods[box.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return &runtimev1.UpdatePodResponse{
			Error:         rpcStatus(codes.NotFound, "pod %s not found", box.GetPodId()),
			FailureReason: runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
		}, nil
	}

	if reason, err := updatableOnly(p.box, box); err != nil {
		return &runtimev1.UpdatePodResponse{
			Error:         rpcStatus(codes.FailedPrecondition, "%s", err.Error()),
			FailureReason: reason,
		}, nil
	}

	p.mu.Lock()
	p.box.Labels = box.GetLabels()
	p.box.Annotations = box.GetAnnotations()
	p.mu.Unlock()

	st := r.podStatus(p)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, st)
	return &runtimev1.UpdatePodResponse{Status: st}, nil
}

// GetPodStatus returns a single point-in-time PodStatus.
func (r *Runtime) GetPodStatus(_ context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	r.mu.Lock()
	p, ok := r.pods[req.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return &runtimev1.GetPodStatusResponse{
			Error: rpcStatus(codes.NotFound, "pod %s not found", req.GetPodId()),
		}, nil
	}
	return &runtimev1.GetPodStatusResponse{Status: r.podStatus(p)}, nil
}

// WatchPodStatus streams PodStatus snapshots: the current state immediately, then
// every transition. pod_id empty watches all pods on the node.
func (r *Runtime) WatchPodStatus(req *runtimev1.WatchPodStatusRequest, stream grpc.ServerStreamingServer[runtimev1.PodStatusEvent]) error {
	ctx := stream.Context()
	ch, cancel := r.broker.subscribe(req.GetPodId())
	defer cancel()

	// Emit current snapshot(s) immediately on subscribe.
	for _, st := range r.snapshotStatuses(req.GetPodId()) {
		if err := stream.Send(&runtimev1.PodStatusEvent{
			Type:   runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_ADDED,
			Status: st,
		}); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// GetLogs streams a container's combined output under the full GetLogsRequest
// option set, in the order the kubelet applies them:
//
//  1. tail_lines selects positionally from the end of the buffer;
//  2. since_time then drops entries older than the cutoff (so tail+since compose
//     to FEWER than tail lines, never to "the newest N recent ones");
//  3. timestamps renders the RFC3339 prefix and limit_bytes caps the result
//     (logEmitter, logs.go).
//
// follow keeps the stream open and delivers lines as the supervisor's pump writes
// them, applying the same since/presentation options, until the container exits
// (a clean end — `kubectl logs -f` returns) or the client goes away. The follower
// is registered BEFORE the buffer snapshot so no line is lost in between; the
// cost of that ordering is that a line written in the gap can be delivered twice,
// which is the same trade Attach makes and the right way round (a duplicate line
// is recoverable, a dropped one is not).
//
// previous is REFUSED. runtimed keeps one in-memory buffer per LIVE container and
// a restart replaces it, so the previous instance's output does not exist to
// serve; answering from the running instance would hand `kubectl logs -p` the
// wrong output labelled as the crashed run's, which is worse than an error.
func (r *Runtime) GetLogs(req *runtimev1.GetLogsRequest, stream grpc.ServerStreamingServer[runtimev1.LogEntry]) error {
	r.mu.Lock()
	p, ok := r.pods[req.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "pod %s not found", req.GetPodId())
	}
	// Route dispatch (M11.2-d6): a vm pod's output lives in the guest, which
	// holds it — there is no host log buffer to serve from (see getLogsGuest).
	if p.isVM() {
		return r.getLogsGuest(req, stream, p)
	}

	cp := r.findContainer(p, req.GetContainer())
	if cp == nil {
		return status.Errorf(codes.NotFound, "container %s not found in pod %s", req.GetContainer(), req.GetPodId())
	}
	if req.GetPrevious() {
		return status.Errorf(codes.Unimplemented,
			"logs of the previous instance of %s/%s are not retained: runtimed buffers only the live container",
			req.GetPodId(), req.GetContainer())
	}

	var since time.Time
	if ts := req.GetSinceTime(); ts.IsValid() {
		since = ts.AsTime()
	}
	// Register the follower before snapshotting (see the doc comment's ordering
	// note); a non-follow request never subscribes.
	var live <-chan logLine
	if req.GetFollow() {
		ch, cancel := cp.logs.subscribe()
		defer cancel()
		live = ch
	}

	em := newLogEmitter(stream, req)
	send := func(ent logLine) error {
		if ent.at.Before(since) {
			return nil
		}
		return em.send(ent)
	}
	for _, ent := range cp.logs.snapshotEntries(int(req.GetTailLines())) {
		if err := send(ent); err != nil {
			if errors.Is(err, errLogLimitReached) {
				return nil
			}
			return err
		}
	}
	if !req.GetFollow() {
		return nil
	}

	ctx := stream.Context()
	// A nil Done channel (a container with no process, which only a test builds)
	// blocks forever, leaving ctx as the sole exit — the right degradation.
	var exited <-chan struct{}
	if cp.proc != nil {
		exited = cp.proc.Done()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ent := <-live:
			if err := send(ent); err != nil {
				if errors.Is(err, errLogLimitReached) {
					return nil
				}
				return err
			}
		case <-exited:
			// Flush whatever the pump had already handed the buffer before the
			// exit was observed, then end the stream cleanly. A line still in
			// flight inside the pump goroutine can still be missed — the same
			// unavoidable race Attach has — but everything already written is
			// delivered rather than cut off.
			for {
				select {
				case ent := <-live:
					if err := send(ent); err != nil {
						if errors.Is(err, errLogLimitReached) {
							return nil
						}
						return err
					}
				default:
					return nil
				}
			}
		}
	}
}

// Exec, Attach, and PortForward (the bidi streaming RPCs) are implemented in
// exec.go: Exec re-enters the pod's confinement via the exec-shim; Attach
// follows a running container's output; PortForward proxies to the pod's lo0 IP.

// The RuntimeCondition Types GetRuntimeInfo advertises.
//
// These string VALUES are a CROSS-REPO WIRE CONTRACT carried as DATA. The proto's
// Conditions field is `repeated` and Type is a free string, so adding a capability
// needs NO proto change (the B1 precedent) — but that also means nothing but these
// constants binds producer to consumer. k3sm's provider IMPORTS them, so a rename on
// either side becomes a COMPILE error instead of a node label that is silently,
// permanently absent. Never change a value; only ever add.
//
// The node labels k3sm derives from them (for orientation only — the mapping is
// k3sm's, not runtimed's): VMBackendAvailable drives k3sm.io/virtualization, and the
// two Rosetta conditions drive the k3sm.io/rosetta{,-linux} pair, the guest one
// composed as VMBackendAvailable AND RosettaGuestAvailable.
const (
	// ConditionSandboxBackend reports the health of the confinement backend that
	// runs host-process pods. It is the one condition mirrored into the response's
	// Healthy field: a false SandboxBackend means pods would run unconfined, which
	// runtimed refuses.
	ConditionSandboxBackend = "SandboxBackend"
	// ConditionVMBackendAvailable reports whether this host can run the vm
	// RuntimeClass (Virtualization.framework isSupported AND the
	// com.apple.security.virtualization entitlement — the SAFE probe that never
	// boots a VM).
	ConditionVMBackendAvailable = "VMBackendAvailable"
	// ConditionRosettaHostAvailable reports whether this host can translate
	// darwin/amd64 MACH-O payloads via Rosetta 2 (the NATIVE host-process spine's
	// capability). B103.
	ConditionRosettaHostAvailable = "RosettaHostAvailable"
	// ConditionRosettaGuestAvailable reports whether a Linux GUEST on this host
	// could translate linux/amd64 ELF payloads via Rosetta for Linux (the vm
	// backend's capability). B103.
	ConditionRosettaGuestAvailable = "RosettaGuestAvailable"
)

// GetRuntimeInfo reports the daemon version + health for the M2 handshake.
func (r *Runtime) GetRuntimeInfo(_ context.Context, _ *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	healthy := r.backend.Available()
	cond := runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
	reason := "Available"
	msg := fmt.Sprintf("sandbox backend %q available", r.backend.Name())
	if !healthy {
		cond = runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
		reason = "Unavailable"
		msg = fmt.Sprintf("sandbox backend %q unavailable (pods would run unconfined; refusing)", r.backend.Name())
	}
	// VMBackendAvailable advertises whether this host can run the vm RuntimeClass
	// (Virtualization.framework isSupported + the com.apple.security.virtualization
	// entitlement — the SAFE probe on r.vmBackend, which never boots a VM). k3sm
	// reads it at node bring-up to label the node truthfully (k3sm.io/virtualization),
	// so a VZ-incapable node is not silently offered as vm-schedulable. Carried as
	// an additive RuntimeCondition Type — no proto change (B1).
	vmCond := runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
	vmReason := "Unavailable"
	vmMsg := "vm backend unavailable (Virtualization.framework unsupported or process unentitled); vm-RuntimeClass pods fail closed"
	if r.vmBackend != nil && r.vmBackend.Available() {
		vmCond = runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
		vmReason = "Available"
		vmMsg = fmt.Sprintf("vm backend %q available", r.vmBackend.Name())
	}
	return &runtimev1.GetRuntimeInfoResponse{
		RuntimeName:    RuntimeName,
		RuntimeVersion: r.cfg.RuntimeVersion,
		ApiVersion:     apiVersion,
		Healthy:        healthy,
		Conditions: []*runtimev1.RuntimeCondition{
			{
				Type:    ConditionSandboxBackend,
				Status:  cond,
				Reason:  reason,
				Message: msg,
			},
			{
				Type:    ConditionVMBackendAvailable,
				Status:  vmCond,
				Reason:  vmReason,
				Message: vmMsg,
			},
			// The two Rosetta capability conditions are ADDITIVE — they are appended
			// to, never a replacement for, the two above (B103). Their values were
			// computed once in New and are immutable, so this handler only stamps them
			// into fresh proto messages; a probe that reported UNAVAILABLE is a
			// capability absence, NOT a handshake failure, so err stays nil.
			r.rosettaHost.condition(ConditionRosettaHostAvailable),
			r.rosettaGuest.condition(ConditionRosettaGuestAvailable),
		},
		// GPU facts (M8.2-d4), stamped fresh from the immutable observation New
		// made. ALWAYS present on a daemon that can probe: the apis contract reads
		// an absent gpu as "this daemon does not report GPU facts", which is a
		// different fact from a host with no usable GPU, and collapsing the two
		// would advertise a GPU resource on nodes that have none.
		Gpu: gpuFactsProto(r.gpuFacts),
	}, nil
}

// findContainer returns the named container's proc, or the sole container if name
// is empty, or nil.
func (r *Runtime) findContainer(p *pod, name string) *containerProc {
	p.mu.Lock()
	defer p.mu.Unlock()
	if name == "" && len(p.containers) == 1 {
		return p.containers[0]
	}
	for _, cp := range p.containers {
		if cp.name == name {
			return cp
		}
	}
	return nil
}

// createFailure builds a CreatePodResponse carrying a structured failure.
func createFailure(reason runtimev1.FailureReason, err error) *runtimev1.CreatePodResponse {
	code := codes.Internal
	if errors.Is(err, errInvalidPodBox) {
		code = codes.InvalidArgument
	}
	return &runtimev1.CreatePodResponse{
		Error:         rpcStatus(code, "%s", err.Error()),
		FailureReason: reason,
	}
}

// rpcStatus builds a google.rpc.Status with a gRPC code and formatted message.
func rpcStatus(code codes.Code, format string, args ...any) *rpcstatus.Status {
	return &rpcstatus.Status{
		Code:    int32(code),
		Message: fmt.Sprintf(format, args...),
	}
}
