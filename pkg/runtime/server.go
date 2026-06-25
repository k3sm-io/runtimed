package runtime

import (
	"context"
	"errors"
	"fmt"

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
	if reason, err := validatePodBox(box); err != nil {
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

	st := r.podStatus(p)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_ADDED, st)
	return &runtimev1.CreatePodResponse{Status: st}, nil
}

// DeletePod kills the pod's process group and forgets it. Idempotent: deleting an
// unknown pod succeeds.
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

	p.mu.Lock()
	procs := make([]*supervisor.Process, 0, len(p.containers))
	for _, cp := range p.containers {
		procs = append(procs, cp.proc)
	}
	p.mu.Unlock()

	// Signal each container's process group (SIGKILL for grace 0). The kqueue
	// reaper observes the exits.
	for _, proc := range procs {
		if pid := proc.PID(); pid > 0 {
			if err := supervisor.SignalGroup(pid, killSignal); err != nil {
				r.log.Warn("signal pod group", "pod", req.GetPodId(), "pid", pid, "err", err)
			}
		}
	}

	st := r.podStatus(p)
	st.Phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED, st)
	if err := r.removePodDir(req.GetPodId()); err != nil {
		r.log.Warn("remove pod dir", "pod", req.GetPodId(), "err", err)
	}
	return &runtimev1.DeletePodResponse{}, nil
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

// Exec runs a command in a container. M2 work; returns Unimplemented in M1.
func (r *Runtime) Exec(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	return status.Error(codes.Unimplemented, "Exec is implemented in M2")
}

// Attach attaches to a container's streams. M2 work; returns Unimplemented in M1.
func (r *Runtime) Attach(grpc.BidiStreamingServer[runtimev1.AttachRequest, runtimev1.AttachResponse]) error {
	return status.Error(codes.Unimplemented, "Attach is implemented in M2")
}

// PortForward forwards a local stream to a pod port. M2 work; Unimplemented in M1.
func (r *Runtime) PortForward(grpc.BidiStreamingServer[runtimev1.PortForwardRequest, runtimev1.PortForwardResponse]) error {
	return status.Error(codes.Unimplemented, "PortForward is implemented in M2")
}

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

// killSignal is SIGKILL via the supervisor's signal type (set in server_signal.go
// so the os.Signal value is platform-correct).
//
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
