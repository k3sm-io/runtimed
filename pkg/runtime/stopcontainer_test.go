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
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestStopContainerTerminatesWithoutRespawn is the B171 runtimed gate: the
// CRI StopContainer shape. A stop kills ONE container's process group within
// the grace window and leaves it Terminated — no re-spawn, no restart_count
// bump, the same log file — publishing exactly one MODIFIED for the exit, with
// the one FinishedAt every observer sees. The refusals share RestartContainer's
// guard chain, so every ineligible pod or container is answered before any
// process is touched.
//
// Red on main: Runtime embeds UnimplementedRuntimeServer, so StopContainer
// resolved to the generated stub and every case failed with a transport
// Unimplemented.
func TestStopContainerTerminatesWithoutRespawn(t *testing.T) {
	t.Run("grace-0-kills-and-stays-terminated", func(t *testing.T) {
		stopKills(t, 0)
	})
	t.Run("grace-escalates-term-then-kill", func(t *testing.T) {
		stopKills(t, 1)
	})

	refusals := []struct {
		name       string
		setup      func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func())
		wantCode   codes.Code
		wantReason runtimev1.FailureReason
		wantText   string
	}{
		{
			name: "adopted",
			setup: func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func()) {
				waiter := unknownExitWaiter{newBlockingWaiter()}
				groups := fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}}
				rt := newTestRuntime(t, Deps{
					ProcGroup:     groups.inspect,
					ProcStartTime: func(int) (int64, bool) { return 5000, true },
					AdoptedWaiter: waiter,
				})
				seedPodProcRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: 100, StartUnixNano: 5000})
				if _, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p1")); err != nil {
					t.Fatalf("AttachPod: %v", err)
				}
				return rt, &runtimev1.StopContainerRequest{PodId: "p1", Container: "main"}, func() { waiter.release(100) }
			},
			wantCode:   codes.FailedPrecondition,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			wantText:   errAdoptedPod.Error(),
		},
		{
			name: "vm",
			setup: func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func()) {
				rt, _, box := bootedVMRuntime(t, "pod-vm-stop", 5)
				return rt, &runtimev1.StopContainerRequest{PodId: box.GetPodId(), Container: "main"}, func() {}
			},
			wantCode:   codes.Unimplemented,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED,
			wantText:   "guest/v1 defines no per-container stop",
		},
		{
			name: "pod-stopping",
			setup: func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func()) {
				rt, w := stopRuntime(t, "pod-sd")
				p := rt.pods["pod-sd"]
				p.mu.Lock()
				p.stopping = true
				p.mu.Unlock()
				return rt, &runtimev1.StopContainerRequest{PodId: "pod-sd", Container: "main"}, func() { w.release(1001) }
			},
			wantCode:   codes.FailedPrecondition,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			wantText:   errPodStopping.Error(),
		},
		{
			name: "unknown-pod",
			setup: func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func()) {
				rt, w := stopRuntime(t, "pod-up")
				return rt, &runtimev1.StopContainerRequest{PodId: "nope", Container: "main"}, func() { w.release(1001) }
			},
			wantCode:   codes.NotFound,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			wantText:   "pod nope not found",
		},
		{
			name: "unknown-container",
			setup: func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func()) {
				rt, w := stopRuntime(t, "pod-uc")
				return rt, &runtimev1.StopContainerRequest{PodId: "pod-uc", Container: "ghost"}, func() { w.release(1001) }
			},
			wantCode:   codes.NotFound,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			wantText:   "container ghost not found",
		},
		{
			name: "never-started",
			setup: func(t *testing.T) (*Runtime, *runtimev1.StopContainerRequest, func()) {
				rt, w := stopRuntime(t, "pod-ns")
				p := rt.pods["pod-ns"]
				p.mu.Lock()
				p.containers = append(p.containers, rt.waitingContainerProc("pod-ns",
					&runtimev1.Container{Name: "late", Image: "/bin/sleep"}, false,
					runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "ErrImagePull", "pull failed"))
				p.mu.Unlock()
				return rt, &runtimev1.StopContainerRequest{PodId: "pod-ns", Container: "late"}, func() { w.release(1001) }
			},
			wantCode:   codes.FailedPrecondition,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			wantText:   "container has not started",
		},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			rt, req, cleanup := tc.setup(t)
			defer cleanup()
			resp, err := rt.StopContainer(context.Background(), req)
			if err != nil {
				t.Fatalf("StopContainer transport error = %v; a refusal is a structured response, never a transport error", err)
			}
			if resp.GetStatus() != nil {
				t.Errorf("a refused stop returned a container status %v; a caller could read that as a completed stop", resp.GetStatus())
			}
			if got := codes.Code(resp.GetError().GetCode()); got != tc.wantCode {
				t.Errorf("code = %v, want %v (error %v)", got, tc.wantCode, resp.GetError())
			}
			if resp.GetFailureReason() != tc.wantReason {
				t.Errorf("failure_reason = %v, want %v", resp.GetFailureReason(), tc.wantReason)
			}
			if !strings.Contains(resp.GetError().GetMessage(), tc.wantText) {
				t.Errorf("message = %q, want it to contain %q", resp.GetError().GetMessage(), tc.wantText)
			}
		})
	}
}

// stopRuntime builds a runtime holding one running host-binary pod whose
// container (pid 1001) blocks until released.
func stopRuntime(t *testing.T, podID string) (*Runtime, *blockingWaiter) {
	t.Helper()
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, podID))
	return rt, w
}

// stopKills drives one successful stop at the given per-request grace and
// asserts the whole terminal contract.
func stopKills(t *testing.T, graceSeconds int64) {
	t.Helper()
	const podID = "pod-stop"
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	// The fake reaper reports what a SIGKILLed child reports.
	w.code, w.sig = 137, 9
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})
	rel := releaseOnce(w)
	// Only SIGKILL releases the waiter: a grace > 0 stop must first send a
	// SIGTERM the fake process ignores, then escalate.
	rec := &recordingSignalGroup{onKill: rel}
	rt.signalGroup = rec.signal
	mustCreatePod(t, rt, hostBinBox(rt, podID))

	before := containerSnapshot(t, rt, podID)
	sp.mu.Lock()
	spawnsBefore := len(sp.specs)
	sp.mu.Unlock()

	events, cancel := rt.broker.subscribe(podID)
	defer cancel()

	// A concurrent observer for the whole stop, including the log-drain window:
	// every terminated state it sees must carry the one FinishedAt the response
	// reports.
	var (
		obsMu    sync.Mutex
		observed []*runtimev1.ContainerStateTerminated
	)
	stopObs := make(chan struct{})
	obsDone := make(chan struct{})
	go func() {
		defer close(obsDone)
		for {
			gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
			for _, cs := range gs.GetStatus().GetContainerStatuses() {
				if term := cs.GetState().GetTerminated(); term != nil {
					obsMu.Lock()
					observed = append(observed, term)
					obsMu.Unlock()
				}
			}
			select {
			case <-stopObs:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	resp, err := rt.StopContainer(context.Background(), &runtimev1.StopContainerRequest{
		PodId: podID, Container: "main", GracePeriodSeconds: graceSeconds, Reason: "FailedPostStartHook",
	})
	if err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("StopContainer failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}

	// Let the kqueue-reaper stand-in's watchContainerExit run to completion:
	// a second publish or state write from it would land in this window.
	time.Sleep(300 * time.Millisecond)
	close(stopObs)
	<-obsDone

	term := resp.GetStatus().GetState().GetTerminated()
	if term == nil {
		t.Fatalf("response state = %v, want Terminated", resp.GetStatus().GetState())
	}
	if term.GetExitCode() != 137 || term.GetSignal() != 9 {
		t.Errorf("terminated = (code %d, sig %d), want the reaped (137, 9)", term.GetExitCode(), term.GetSignal())
	}
	if resp.GetStatus().GetRestartCount() != 0 {
		t.Errorf("restart_count = %d, want 0: a stop is not a restart", resp.GetStatus().GetRestartCount())
	}
	if resp.GetStatus().GetLastTerminationState() != nil {
		t.Errorf("last_termination_state = %v, want none: a stop replaces no run", resp.GetStatus().GetLastTerminationState())
	}
	if got := resp.GetStatus().GetLogPath(); got == "" || got != before.GetLogPath() || term.GetLogPath() != got {
		t.Errorf("log_path = %q (terminated %q), want the running instance's %q", got, term.GetLogPath(), before.GetLogPath())
	}
	if term.GetContainerId() != before.GetContainerId() {
		t.Errorf("terminated container_id = %q, want the stopped instance's %q", term.GetContainerId(), before.GetContainerId())
	}

	sp.mu.Lock()
	spawnsAfter := len(sp.specs)
	sp.mu.Unlock()
	if spawnsAfter != spawnsBefore {
		t.Errorf("spawns = %d after the stop, want %d: StopContainer must never re-spawn", spawnsAfter, spawnsBefore)
	}

	var wantSigs []string
	if graceSeconds > 0 {
		wantSigs = []string{termSignal.String(), killSignal.String()}
	} else {
		wantSigs = []string{killSignal.String()}
	}
	var gotSigs []string
	for _, s := range rec.signals() {
		gotSigs = append(gotSigs, s.String())
	}
	if strings.Join(gotSigs, ",") != strings.Join(wantSigs, ",") {
		t.Errorf("signals = %v, want %v", gotSigs, wantSigs)
	}

	// Exactly ONE publish for the exit, and it carries the response's state.
	var published []*runtimev1.PodStatusEvent
	for drained := false; !drained; {
		select {
		case ev := <-events:
			published = append(published, ev)
		default:
			drained = true
		}
	}
	if len(published) != 1 {
		t.Fatalf("publishes = %d, want exactly 1 for the stop (the reaper's own publish must be suppressed)", len(published))
	}
	pubCS := published[0].GetStatus().GetContainerStatuses()
	if len(pubCS) != 1 || !proto.Equal(pubCS[0].GetState().GetTerminated(), term) {
		t.Errorf("published state = %v, want the response's %v", pubCS, term)
	}

	obsMu.Lock()
	defer obsMu.Unlock()
	for _, o := range observed {
		if !proto.Equal(o.GetFinishedAt(), term.GetFinishedAt()) {
			t.Fatalf("a concurrent GetPodStatus saw FinishedAt %v, the response reports %v: two writers stamped the exit",
				o.GetFinishedAt().AsTime(), term.GetFinishedAt().AsTime())
		}
	}

	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if ph := gs.GetStatus().GetPhase(); ph != runtimev1.PodPhase_POD_PHASE_FAILED {
		t.Errorf("phase = %v, want FAILED: the only main was killed", ph)
	}
	after := gs.GetStatus().GetContainerStatuses()[0]
	if !proto.Equal(after.GetState().GetTerminated(), term) {
		t.Errorf("GetPodStatus terminated = %v, want the response's %v", after.GetState().GetTerminated(), term)
	}
}

// containerSnapshot returns the pod's only container status.
func containerSnapshot(t *testing.T, rt *Runtime, podID string) *runtimev1.ContainerStatus {
	t.Helper()
	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	cs := gs.GetStatus().GetContainerStatuses()
	if len(cs) != 1 {
		t.Fatalf("container statuses = %v, want 1", cs)
	}
	return cs[0]
}

// stopResult carries one StopContainer return across a goroutine.
type stopResult struct {
	resp *runtimev1.StopContainerResponse
	err  error
}

// goStop runs StopContainer on podID's "main" in a goroutine.
func goStop(ctx context.Context, rt *Runtime, podID string) <-chan stopResult {
	done := make(chan stopResult, 1)
	go func() {
		resp, err := rt.StopContainer(ctx, &runtimev1.StopContainerRequest{PodId: podID, Container: "main"})
		done <- stopResult{resp, err}
	}()
	return done
}

// awaitParkedKill waits until a kill verb has sent its SIGKILL and outlived the
// exit-observation bound, so it is parked on the container's exit itself.
func awaitParkedKill(t *testing.T, rt *Runtime, rec *recordingSignalGroup) {
	t.Helper()
	waitFor(t, 5*time.Second, "the kill verb's SIGKILL", rec.sawKill)
	time.Sleep(3 * rt.exitObservationGrace())
}

// drainEvents returns every event already buffered on a broker subscription.
func drainEvents(events <-chan *runtimev1.PodStatusEvent) []*runtimev1.PodStatusEvent {
	var out []*runtimev1.PodStatusEvent
	for {
		select {
		case ev := <-events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// TestStopContainerConcurrentWithDeletePod pins the stop-then-delete ordering.
// A DeletePod that begins while a StopContainer is in flight removes the pod
// and publishes its DELETED; the stop, concluding afterwards, must neither
// record a state nor publish a MODIFIED for the deleted pod, and must still
// return the exit it observed. And a delete that finds a claimed container
// whose process has already exited must not run a second stop sequence
// against its pid.
func TestStopContainerConcurrentWithDeletePod(t *testing.T) {
	t.Run("delete-owns-the-terminal-event", func(t *testing.T) {
		const podID = "pod-stop-del"
		rt, w := stopRuntime(t, podID)
		// No signal releases the fake process, so the stop parks on the exit.
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal
		events, cancel := rt.broker.subscribe(podID)
		defer cancel()

		done := goStop(context.Background(), rt, podID)
		awaitParkedKill(t, rt, rec)
		select {
		case res := <-done:
			t.Fatalf("the stop returned before its container exited: %v", res.resp)
		default:
		}

		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		// The container exits only now, after the delete published DELETED, so
		// any terminal publish from the stop would follow it.
		w.release(1001)
		var res stopResult
		select {
		case res = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the stop did not return after its container exited")
		}
		if res.err != nil {
			t.Fatalf("StopContainer transport error: %v", res.err)
		}
		if res.resp.GetError() != nil {
			t.Fatalf("StopContainer failed: %v; the container did stop", res.resp.GetError())
		}
		if res.resp.GetStatus().GetState().GetTerminated() == nil {
			t.Errorf("response state = %v, want the Terminated exit the stop observed", res.resp.GetStatus().GetState())
		}

		// Let the reaper stand-in run out: a late publish would land here.
		time.Sleep(300 * time.Millisecond)
		evs := drainEvents(events)
		if len(evs) == 0 {
			t.Fatal("no events: want the delete's DELETED")
		}
		for i, ev := range evs {
			if ev.GetType() == runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED {
				t.Errorf("event %d of %d is MODIFIED: the stop published for a pod the delete had removed", i+1, len(evs))
			}
		}
		if last := evs[len(evs)-1].GetType(); last != runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED {
			t.Errorf("last event = %v, want DELETED", last)
		}
	})

	t.Run("delete-skips-a-concluding-stop", func(t *testing.T) {
		const podID = "pod-stop-conc"
		rt, w := stopRuntime(t, podID)
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal
		p := rt.pods[podID]
		p.mu.Lock()
		cp := p.containers[0]
		// A stop's claim over a process that has exited but whose conclusion
		// (the log drain, the terminal write) has not run yet.
		cp.stopped = true
		p.mu.Unlock()
		w.release(1001)
		waitFor(t, 5*time.Second, "the claimed container's exit", func() bool { return procDone(cp.proc) })

		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if sent := rec.sentSignals(); len(sent) != 0 {
			t.Errorf("DeletePod sent %v to a stopped container's exited group, want nothing", sent)
		}
	})
}

// TestStopContainerConcurrentWithRestartContainer pins the mutual refusal of the
// two kill verbs: while one holds its claim on a container, the other is refused
// with FailedPrecondition + NOT_UPDATABLE naming the in-flight verb, signals
// nothing, and spawns nothing.
func TestStopContainerConcurrentWithRestartContainer(t *testing.T) {
	setup := func(t *testing.T, podID string) (*Runtime, *blockingWaiter, *fakeSpawner, *recordingSignalGroup) {
		t.Helper()
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal
		mustCreatePod(t, rt, hostBinBox(rt, podID))
		return rt, w, sp, rec
	}
	spawns := func(sp *fakeSpawner) int {
		sp.mu.Lock()
		defer sp.mu.Unlock()
		return len(sp.specs)
	}

	t.Run("stop-in-flight-refuses-restart", func(t *testing.T) {
		const podID = "pod-stop-rs"
		rt, w, sp, rec := setup(t, podID)
		done := goStop(context.Background(), rt, podID)
		awaitParkedKill(t, rt, rec)
		spawnsBefore, sigsBefore := spawns(sp), len(rec.signals())

		// Bounded: a restart that took its own claim would park on the same exit.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := rt.RestartContainer(ctx, &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatalf("RestartContainer transport error: %v", err)
		}
		if got := codes.Code(resp.GetError().GetCode()); got != codes.FailedPrecondition {
			t.Errorf("code = %v, want FailedPrecondition (error %v)", got, resp.GetError())
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("failure_reason = %v, want NOT_UPDATABLE", resp.GetFailureReason())
		}
		if msg := resp.GetError().GetMessage(); !strings.Contains(msg, "a stop of the container is in flight") {
			t.Errorf("message = %q, want it to name the in-flight stop", msg)
		}
		if got := spawns(sp); got != spawnsBefore {
			t.Errorf("spawns = %d, want %d: a refused restart must spawn nothing", got, spawnsBefore)
		}
		if got := len(rec.signals()); got != sigsBefore {
			t.Errorf("signals = %d, want %d: a refused restart must signal nothing", got, sigsBefore)
		}

		w.release(1001)
		select {
		case res := <-done:
			if res.err != nil || res.resp.GetError() != nil {
				t.Fatalf("the in-flight stop failed: %v %v", res.err, res.resp.GetError())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the in-flight stop did not return")
		}
	})

	t.Run("restart-in-flight-refuses-stop", func(t *testing.T) {
		const podID = "pod-rs-stop"
		rt, w, sp, rec := setup(t, podID)
		restartDone := make(chan *runtimev1.RestartContainerResponse, 1)
		go func() {
			resp, _ := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
			restartDone <- resp
		}()
		awaitParkedKill(t, rt, rec)
		spawnsBefore, sigsBefore := spawns(sp), len(rec.signals())

		// Bounded: a stop that took its own claim would park on the same exit.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := rt.StopContainer(ctx, &runtimev1.StopContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatalf("StopContainer transport error: %v", err)
		}
		if got := codes.Code(resp.GetError().GetCode()); got != codes.FailedPrecondition {
			t.Errorf("code = %v, want FailedPrecondition (error %v)", got, resp.GetError())
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("failure_reason = %v, want NOT_UPDATABLE", resp.GetFailureReason())
		}
		if msg := resp.GetError().GetMessage(); !strings.Contains(msg, "a restart of the container is in flight") {
			t.Errorf("message = %q, want it to name the in-flight restart", msg)
		}
		if got := len(rec.signals()); got != sigsBefore {
			t.Errorf("signals = %d, want %d: a refused stop must signal nothing", got, sigsBefore)
		}
		if got := spawns(sp); got != spawnsBefore {
			t.Errorf("spawns = %d, want %d", got, spawnsBefore)
		}

		w.release(1001)
		select {
		case resp := <-restartDone:
			if resp.GetError() != nil {
				t.Fatalf("the in-flight restart failed: %v", resp.GetError())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the in-flight restart did not return")
		}
	})
}

// TestStopContainerCancelledAsProcessExits pins the cancellation race: the
// stop's ctx is cancelled at the instant its container dies. The container did
// stop, so the verb reports the exit, not Canceled; the exit is recorded and
// published exactly once; and a later stop returns that recorded status without
// signalling. The race is a random select between two ready arms, so it is
// driven repeatedly.
func TestStopContainerCancelledAsProcessExits(t *testing.T) {
	for i := range 16 {
		podID := "pod-stop-cx"
		w := newBlockingWaiter()
		w.code, w.sig = 137, 9
		rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: w})
		// Long enough that the stop's exit-observation wait always sees the
		// exit, so both of terminateContainer's arms are ready together.
		rt.exitObsGrace = 2 * time.Second
		mustCreatePod(t, rt, hostBinBox(rt, podID))
		ctx, cancelCtx := context.WithCancel(context.Background())
		rel := releaseOnce(w)
		rec := &recordingSignalGroup{onKill: func(pid int) {
			cancelCtx()
			rel(pid)
		}}
		rt.signalGroup = rec.signal
		events, cancel := rt.broker.subscribe(podID)

		resp, err := rt.StopContainer(ctx, &runtimev1.StopContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatalf("iteration %d: StopContainer transport error: %v", i, err)
		}
		if resp.GetError() != nil {
			t.Fatalf("iteration %d: StopContainer failed: %v; the container died, so the stop completed", i, resp.GetError())
		}
		term := resp.GetStatus().GetState().GetTerminated()
		if term == nil || term.GetExitCode() != 137 || term.GetSignal() != 9 {
			t.Fatalf("iteration %d: terminated = %v, want the reaped (137, 9)", i, term)
		}

		time.Sleep(150 * time.Millisecond)
		if evs := drainEvents(events); len(evs) != 1 {
			t.Fatalf("iteration %d: publishes = %d, want exactly 1 for the exit", i, len(evs))
		}
		cancel()

		sigs := len(rec.signals())
		again, err := rt.StopContainer(context.Background(), &runtimev1.StopContainerRequest{PodId: podID, Container: "main"})
		if err != nil || again.GetError() != nil {
			t.Fatalf("iteration %d: second StopContainer: %v %v", i, err, again.GetError())
		}
		if !proto.Equal(again.GetStatus().GetState().GetTerminated(), term) {
			t.Fatalf("iteration %d: second stop returned %v, want the recorded %v", i, again.GetStatus().GetState().GetTerminated(), term)
		}
		if got := len(rec.signals()); got != sigs {
			t.Fatalf("iteration %d: the second stop sent %d signals, want none", i, got-sigs)
		}
	}
}
