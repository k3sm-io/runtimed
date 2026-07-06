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

	"k3sm.io/runtimed/pkg/sandbox"
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
	if reason, err := validatePodBox(box); err != nil {
		return createFailure(reason, err), nil
	}

	r.mu.Lock()
	if existing, ok := r.pods[box.GetPodId()]; ok {
		r.mu.Unlock()
		return &runtimev1.CreatePodResponse{Status: r.podStatus(existing)}, nil
	}
	r.mu.Unlock()

	// No producer is wired in M5.1, so the guest network config is zero-valued here
	// (it is inert on the host-process spine and zero on the vm route). The k3sm
	// provider populates it in the separate successor; runtimed cannot import
	// darwin-net, so it arrives as data (sandbox.GuestNetworkConfig).
	p, reason, err := r.createPod(ctx, box, sandbox.GuestNetworkConfig{})
	if err != nil {
		r.log.Error("create pod failed", "pod", box.GetPodId(), "reason", reason.String(), "err", err)
		_ = r.removePodDir(box.GetPodId())
		return createFailure(reason, err), nil
	}

	r.mu.Lock()
	r.pods[box.GetPodId()] = p
	r.mu.Unlock()

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

	// Stop the memory sampler (M2.5): the pod is going away.
	if p.memCancel != nil {
		p.memCancel()
	}

	grace := resolveGrace(req, p)
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
			if _, err := supervisor.GracefulStop(ctx, pid, grace, proc.Done(), termSignal, killSignal, r.signalGroup); err != nil {
				r.log.Warn("graceful stop pod group", "pod", req.GetPodId(), "pid", pid, "err", err)
			}
		}(proc, pid)
	}
	wg.Wait()

	// Phase 2 (M10.2): stop the native sidecars in REVERSE start order with the
	// budget's remainder — mains first, then their support processes, mirroring
	// the kubelet's KEP-753 termination order. A remainder <= 0 (the mains ran
	// the budget out) is the immediate-SIGKILL path.
	r.stopSidecars(ctx, req.GetPodId(), sidecars, deadline)

	// End the pod-lifetime supervision context AFTER the graceful stop: the reapers
	// have collected the real exits (GracefulStop observed proc.Done), so canceling
	// now only unblocks any watchContainerExit drain-wait still in flight — it must
	// NOT precede GracefulStop, or a grace>0 container would be seen as exited and
	// never SIGKILLed. Fired here it mirrors p.memCancel: pod teardown, no leak.
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

// GetLogs streams a container's buffered combined output. follow keeps the
// stream open for new lines; M1 serves the current buffer (tail honored) and,
// when follow is set, blocks until the context ends.
func (r *Runtime) GetLogs(req *runtimev1.GetLogsRequest, stream grpc.ServerStreamingServer[runtimev1.LogEntry]) error {
	r.mu.Lock()
	p, ok := r.pods[req.GetPodId()]
	r.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "pod %s not found", req.GetPodId())
	}

	cp := r.findContainer(p, req.GetContainer())
	if cp == nil {
		return status.Errorf(codes.NotFound, "container %s not found in pod %s", req.GetContainer(), req.GetPodId())
	}

	for _, line := range cp.logs.snapshot(int(req.GetTailLines())) {
		if err := stream.Send(&runtimev1.LogEntry{
			Line:   line,
			Stream: runtimev1.LogStream_LOG_STREAM_STDOUT,
		}); err != nil {
			return err
		}
	}
	if req.GetFollow() {
		<-stream.Context().Done()
	}
	return nil
}

// Exec, Attach, and PortForward (the bidi streaming RPCs) are implemented in
// exec.go: Exec re-enters the pod's confinement via the exec-shim; Attach
// follows a running container's output; PortForward proxies to the pod's lo0 IP.

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
	return &runtimev1.GetRuntimeInfoResponse{
		RuntimeName:    RuntimeName,
		RuntimeVersion: r.cfg.RuntimeVersion,
		ApiVersion:     apiVersion,
		Healthy:        healthy,
		Conditions: []*runtimev1.RuntimeCondition{{
			Type:    "SandboxBackend",
			Status:  cond,
			Reason:  reason,
			Message: msg,
		}},
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
