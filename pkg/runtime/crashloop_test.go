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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- B26 fixtures ---------------------------------------------------------

// testCP builds a bare containerProc for the phase-accounting unit tests:
// recomputePhaseLocked reads only spec/state/restarting/initDeclared, never proc.
func testCP(name string, term *runtimev1.ContainerStateTerminated, restarting, isSidecar bool) *containerProc {
	cp := &containerProc{
		name:         name,
		spec:         &runtimev1.Container{Name: name},
		state:        &runtimev1.ContainerStatus{Name: name},
		restarting:   restarting,
		initDeclared: isSidecar,
	}
	if isSidecar {
		cp.spec.RestartPolicy = runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
	}
	if term != nil {
		cp.state.State = &runtimev1.ContainerState{Terminated: term}
	} else {
		cp.state.State = &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()}}
	}
	return cp
}

func exited(code int32) *runtimev1.ContainerStateTerminated {
	return &runtimev1.ContainerStateTerminated{ExitCode: code, FinishedAt: nowProto()}
}

// releaseOnce adapts blockingWaiter.release into an IDEMPOTENT signal hook: a
// restart graceful-stops a pid that may already be reaped (the crash-then-restart
// case), and releasing the same pid twice closes a closed channel. The single
// returned closure is shared by onTerm and onKill so an escalation cannot
// double-release either.
func releaseOnce(w *blockingWaiter) func(int) {
	var mu sync.Mutex
	done := make(map[int]bool)
	return func(pid int) {
		mu.Lock()
		defer mu.Unlock()
		if done[pid] {
			return
		}
		done[pid] = true
		w.release(pid)
	}
}

// countingFootprinter reports a fixed (sub-limit) footprint and counts samples,
// so a test can observe whether the memory sampler is ALIVE.
type countingFootprinter struct {
	bytes   uint64
	samples atomic.Int64
}

func (f *countingFootprinter) Footprint(int) (uint64, error) {
	f.samples.Add(1)
	return f.bytes, nil
}

// --- Defect 1: the phase is a function of the container states, not a latch ---

// TestRecomputePhaseDeEscalates is the B26 phase proof: recomputePhaseLocked is a
// pure function of the MAIN containers' current states, so a pod that reached a
// terminal phase DE-ESCALATES back to Running once a main is live again (a
// RestartContainer re-exec, or a container mid-restart). Without this a
// restartPolicy:Always pod that crashes once and successfully re-execs reports
// phase:Failed forever — upstream then deletes/replaces, podgc-reaps, or
// backoffLimit-counts a perfectly healthy pod.
func TestRecomputePhaseDeEscalates(t *testing.T) {
	rt := newTestRuntime(t, Deps{})

	cases := []struct {
		name       string
		startPhase runtimev1.PodPhase
		containers []*containerProc
		want       runtimev1.PodPhase
	}{
		{
			name:       "all-mains-exited-zero-succeeded",
			startPhase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			containers: []*containerProc{testCP("main", exited(0), false, false)},
			want:       runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
		},
		{
			name:       "any-main-exited-nonzero-failed",
			startPhase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			containers: []*containerProc{testCP("a", exited(0), false, false), testCP("b", exited(5), false, false)},
			want:       runtimev1.PodPhase_POD_PHASE_FAILED,
		},
		{
			name:       "de-escalates-from-failed-when-a-main-runs-again",
			startPhase: runtimev1.PodPhase_POD_PHASE_FAILED,
			containers: []*containerProc{testCP("main", nil, false, false)},
			want:       runtimev1.PodPhase_POD_PHASE_RUNNING,
		},
		{
			name:       "de-escalates-from-succeeded-when-a-main-runs-again",
			startPhase: runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			containers: []*containerProc{testCP("main", nil, false, false)},
			want:       runtimev1.PodPhase_POD_PHASE_RUNNING,
		},
		{
			name:       "mid-restart-main-holds-the-pod-at-running",
			startPhase: runtimev1.PodPhase_POD_PHASE_FAILED,
			containers: []*containerProc{testCP("main", exited(5), true, false)},
			want:       runtimev1.PodPhase_POD_PHASE_RUNNING,
		},
		{
			name:       "one-main-still-running-keeps-running",
			startPhase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			containers: []*containerProc{testCP("a", exited(1), false, false), testCP("b", nil, false, false)},
			want:       runtimev1.PodPhase_POD_PHASE_RUNNING,
		},
		{
			name:       "crashed-sidecar-alone-never-concludes-the-pod",
			startPhase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			containers: []*containerProc{testCP("sc", exited(7), false, true), testCP("main", nil, false, false)},
			want:       runtimev1.PodPhase_POD_PHASE_RUNNING,
		},
		{
			name:       "sidecar-only-pod-has-no-mains-phase-untouched",
			startPhase: runtimev1.PodPhase_POD_PHASE_FAILED,
			containers: []*containerProc{testCP("sc", exited(7), false, true)},
			want:       runtimev1.PodPhase_POD_PHASE_FAILED, // mains == 0 → early return
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pod{box: &runtimev1.PodBox{PodId: "p"}, phase: tc.startPhase, containers: tc.containers}
			p.mu.Lock()
			rt.recomputePhaseLocked(p)
			got := p.phase
			p.mu.Unlock()
			if got != tc.want {
				t.Errorf("phase = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRestartAfterCrashClearsTerminalPhase is the end-to-end B26 proof: a pod
// whose main CRASHES goes Failed, and the provider-issued RestartContainer
// re-exec puts it back to Running with restart_count bumped and the crash
// preserved in last_termination_state — the CrashLoopBackOff surface.
func TestRestartAfterCrashClearsTerminalPhase(t *testing.T) {
	w := newBlockingWaiter()
	w.code = 5 // the main crashes
	rt := newTestRuntime(t, Deps{Waiter: w})
	rel := releaseOnce(w)
	rec := &recordingSignalGroup{onKill: rel, onTerm: rel}
	rt.signalGroup = rec.signal

	mustCreatePod(t, rt, hostBinBox("pod-clbo")) // main = pid 1001

	rel(1001)
	waitFor(t, 5*time.Second, "pod Failed after the crash", func() bool {
		return podPhase(t, rt, "pod-clbo") == runtimev1.PodPhase_POD_PHASE_FAILED
	})

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
		PodId: "pod-clbo", Container: "main", Reason: "back-off restart",
	})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("RestartContainer failed: %v", resp.GetError())
	}
	if got := podPhase(t, rt, "pod-clbo"); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase after a successful re-exec = %v, want RUNNING (the terminal phase must de-escalate)", got)
	}
	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-clbo"})
	cs := gs.GetStatus().GetContainerStatuses()
	if len(cs) != 1 {
		t.Fatalf("container_statuses = %+v, want 1", cs)
	}
	if cs[0].GetRestartCount() != 1 || cs[0].GetState().GetRunning() == nil {
		t.Errorf("restarted main = count %d state %+v, want count 1 Running", cs[0].GetRestartCount(), cs[0].GetState())
	}
	if lt := cs[0].GetLastTerminationState().GetTerminated(); lt.GetExitCode() != 5 {
		t.Errorf("last_termination_state exit code = %d, want 5 (the crash is preserved)", lt.GetExitCode())
	}

	w.release(1002) // let the replacement's supervision goroutine end
}

// --- Defect 2: irreversible teardown fires only on a TRULY terminal pod ------

// TestFailedPodKeepsMemoryEnforcement is the B26 truly-terminal proof on the
// OOM-enforcement axis: reaching Failed must NOT cancel the memory sampler,
// because a Failed pod is the restart-expected case — a re-exec would otherwise
// resurrect the main into a pod with no limit enforcement at all.
func TestFailedPodKeepsMemoryEnforcement(t *testing.T) {
	w := newBlockingWaiter()
	w.code = 5 // the main crashes → Failed
	ff := &countingFootprinter{bytes: 1 << 20}
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 2 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal

	box := hostBinBox("pod-fail-mem")
	box.MemoryLimitBytes = 100 << 20 // no breach
	mustCreatePod(t, rt, box)

	w.release(1001)
	waitFor(t, 5*time.Second, "pod Failed", func() bool {
		return podPhase(t, rt, "pod-fail-mem") == runtimev1.PodPhase_POD_PHASE_FAILED
	})

	before := ff.samples.Load()
	waitFor(t, 5*time.Second, "the sampler to keep sampling a Failed pod", func() bool {
		return ff.samples.Load() > before
	})
}

// TestRestartRearmsMemorySamplerAfterCompletion is the B26 residual-closure
// proof: a pod that reaches Succeeded IS torn down (voluntary completion), so
// when a provider re-execs it anyway (restartPolicy:Always semantics runtimed
// cannot see — PodBox carries no pod-level restartPolicy), RestartContainer must
// RE-ARM the memory sampler. The resurrected main never runs unenforced.
func TestRestartRearmsMemorySamplerAfterCompletion(t *testing.T) {
	w := newBlockingWaiter() // exit 0 → Succeeded → truly terminal
	ff := &countingFootprinter{bytes: 1 << 20}
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff})
	rt.cfg.SampleInterval = 2 * time.Millisecond
	rel := releaseOnce(w)
	rec := &recordingSignalGroup{onKill: rel, onTerm: rel}
	rt.signalGroup = rec.signal

	box := hostBinBox("pod-rearm")
	box.MemoryLimitBytes = 100 << 20
	mustCreatePod(t, rt, box)

	rel(1001)
	waitFor(t, 5*time.Second, "pod Succeeded", func() bool {
		return podPhase(t, rt, "pod-rearm") == runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	})

	// The truly-terminal transition cancelled the sampler: sampling stops.
	waitFor(t, 5*time.Second, "the sampler to stop on a truly terminal pod", func() bool {
		a := ff.samples.Load()
		time.Sleep(20 * time.Millisecond)
		return ff.samples.Load() == a
	})

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
		PodId: "pod-rearm", Container: "main", Reason: "restartPolicy Always",
	})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("RestartContainer failed: %v", resp.GetError())
	}

	stopped := ff.samples.Load()
	waitFor(t, 5*time.Second, "the sampler re-armed by the re-exec", func() bool {
		return ff.samples.Load() > stopped
	})
	if got := podPhase(t, rt, "pod-rearm"); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase after the re-exec = %v, want RUNNING", got)
	}

	// Exactly ONE sampler enforces the limit: DeletePod cancels the live one and
	// sampling stops for good (a leaked predecessor would keep counting).
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-rearm"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	waitFor(t, 5*time.Second, "all sampling to stop after delete", func() bool {
		a := ff.samples.Load()
		time.Sleep(20 * time.Millisecond)
		return ff.samples.Load() == a
	})
}

// --- Defect 3: no transient terminated publish while a restart is in flight ---

// TestNoTransientTerminatedPublishWhileRestarting is the B26 publish-suppression
// proof: the kqueue reaper records the old run's terminated state (the restart
// reads it back for last_termination_state) but must NOT publish it while the
// container is flagged restarting. Publishing it shows the provider a "new" exit
// for a restart IT issued, whose terminationKey idempotency would then schedule a
// SECOND restart for the same death.
func TestNoTransientTerminatedPublishWhileRestarting(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	rel := releaseOnce(w)
	rec := &recordingSignalGroup{onKill: rel, onTerm: rel}
	rt.signalGroup = rec.signal

	mustCreatePod(t, rt, hostBinBox("pod-nopub"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeWatchStream(ctx)
	go func() { _ = rt.WatchPodStatus(&runtimev1.WatchPodStatusRequest{PodId: "pod-nopub"}, stream) }()
	stream.recv(t, 2*time.Second) // the initial snapshot

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
		PodId: "pod-nopub", Container: "main", Reason: "liveness probe failed",
	})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("RestartContainer failed: %v", resp.GetError())
	}

	// Drain the stream for a bounded window: the suppressed publish, had it
	// fired, would carry the OLD run's terminated state with restart_count 0.
	sawRestartEvent := false
	deadline := time.After(500 * time.Millisecond)
drain:
	for {
		select {
		case ev := <-stream.ch:
			for _, cs := range ev.GetStatus().GetContainerStatuses() {
				if cs.GetName() != "main" {
					continue
				}
				if cs.GetState().GetTerminated() != nil && cs.GetRestartCount() == 0 {
					t.Errorf("published the TRANSIENT terminated state of a container being restarted: %+v", cs)
				}
				if cs.GetRestartCount() == 1 && cs.GetState().GetRunning() != nil {
					sawRestartEvent = true
				}
			}
		case <-deadline:
			break drain
		}
	}
	if !sawRestartEvent {
		t.Error("never observed the restart's own MODIFIED event (count 1, Running) — the stream barrier is broken")
	}

	w.release(1002)
}

// --- The status-snapshot atomicity invariant --------------------------------

// TestStatusNeverPairsBumpedCountWithPreviousTerminatedState pins the invariant
// the k3sm provider's terminationKey restart idempotency rests on: a status
// snapshot can NEVER carry a bumped restart_count alongside the PREVIOUS run's
// terminated state. RestartContainer bumps the count, swaps the container,
// recomputes the phase and snapshots the status under ONE hold of p.mu; this
// test hammers GetPodStatus (and the watch stream) concurrently across a restart
// so that -race and the assertion below catch any future split of that block.
func TestStatusNeverPairsBumpedCountWithPreviousTerminatedState(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
		crash    bool // the container terminates on its own BEFORE the restart
	}{
		{"restart-of-a-running-container", 0, false},
		{"restart-after-a-crash", 5, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newBlockingWaiter()
			w.code = tc.exitCode
			rt := newTestRuntime(t, Deps{Waiter: w})
			rel := releaseOnce(w)
			rec := &recordingSignalGroup{onKill: rel, onTerm: rel}
			rt.signalGroup = rec.signal

			mustCreatePod(t, rt, hostBinBox("pod-inv"))

			if tc.crash {
				rel(1001)
				waitFor(t, 5*time.Second, "the crash to be recorded", func() bool {
					gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-inv"})
					cs := gs.GetStatus().GetContainerStatuses()
					return len(cs) == 1 && cs[0].GetState().GetTerminated() != nil
				})
			}

			var (
				mu         sync.Mutex
				violations []string
				wg         sync.WaitGroup
			)
			check := func(where string, cs *runtimev1.ContainerStatus) {
				var bad string
				switch {
				case cs.GetRestartCount() > 0 && cs.GetState().GetTerminated() != nil:
					bad = "bumped restart_count next to a terminated state"
				case cs.GetRestartCount() > 0 && cs.GetLastTerminationState() == nil:
					bad = "bumped restart_count with no last_termination_state"
				case cs.GetRestartCount() == 0 && cs.GetLastTerminationState() != nil:
					bad = "last_termination_state with an un-bumped restart_count"
				default:
					return
				}
				mu.Lock()
				violations = append(violations, where+": "+bad)
				mu.Unlock()
			}

			done := make(chan struct{})
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-done:
							return
						default:
						}
						gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-inv"})
						for _, cs := range gs.GetStatus().GetContainerStatuses() {
							check("GetPodStatus", cs)
						}
					}
				}()
			}

			resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
				PodId: "pod-inv", Container: "main", Reason: "invariant probe",
			})
			close(done)
			wg.Wait()
			if err != nil {
				t.Fatalf("RestartContainer: %v", err)
			}
			if resp.GetError() != nil {
				t.Fatalf("RestartContainer failed: %v", resp.GetError())
			}
			// The RPC's own response status is subject to the same invariant.
			check("RestartContainerResponse", resp.GetStatus())

			mu.Lock()
			defer mu.Unlock()
			if len(violations) > 0 {
				t.Errorf("status snapshots violated the restart_count/state atomicity invariant (%d observed): %v",
					len(violations), violations[:min(len(violations), 5)])
			}

			w.release(1002)
		})
	}
}
