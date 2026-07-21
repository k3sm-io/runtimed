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
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// sidecarBox builds a PodBox whose init list declares native sidecars (KEP-753:
// init containers with restart_policy ALWAYS) named scNames, plus the hostBinBox
// main container. The pod grace is 30s so graceful teardown SIGTERMs first.
func sidecarBox(podID string, scNames ...string) *runtimev1.PodBox {
	box := hostBinBox(podID)
	box.TerminationGracePeriodSeconds = 30
	for _, n := range scNames {
		box.InitContainers = append(box.InitContainers, &runtimev1.Container{
			Name:          n,
			Image:         "/bin/sleep",
			RestartPolicy: runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS,
		})
	}
	return box
}

// waitFor polls cond until it holds or the timeout expires (the pkg has no clock
// seam; the transitions under test are event-driven and land in milliseconds).
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// podPhase reads the pod's current phase via GetPodStatus.
func podPhase(t *testing.T, rt *Runtime, podID string) runtimev1.PodPhase {
	t.Helper()
	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	return gs.GetStatus().GetPhase()
}

// TestNativeSidecarStaysRunning is the M10.2-a1 sequencing proof (sidecar-not-
// waited): an init list [sidecar(ALWAYS), plain-init(UNSPECIFIED)] spawns the
// sidecar, does NOT wait it (spawn-equals-started), runs the plain init to
// completion while the sidecar is still up, starts the main, and reaches
// Running. The sidecar reports under init_container_statuses as running with
// started=true, and is tracked with the pod's long-lived containers.
func TestNativeSidecarStaysRunning(t *testing.T) {
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})

	box := sidecarBox("pod-sc", "sc")
	// Append a PLAIN init container AFTER the sidecar: it must run to completion
	// (pid 1002, pre-released below) while the sidecar (pid 1001) stays blocked.
	box.InitContainers = append(box.InitContainers, &runtimev1.Container{Name: "ip", Image: "/bin/true"})
	w.release(1002) // the plain init exits 0 the moment it is waited

	// CreatePod must NOT block on the (never-released) sidecar: run it with a
	// timeout guard so a wait-on-sidecar regression fails fast instead of hanging.
	type createResult struct {
		resp *runtimev1.CreatePodResponse
		err  error
	}
	done := make(chan createResult, 1)
	go func() {
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		done <- createResult{resp, err}
	}()
	var res createResult
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CreatePod blocked: the sidecar was waited to completion (must proceed once started)")
	}
	if res.err != nil {
		t.Fatalf("CreatePod: %v", res.err)
	}
	if res.resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", res.resp.GetError(), res.resp.GetFailureReason())
	}
	if res.resp.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase = %v, want RUNNING", res.resp.GetStatus().GetPhase())
	}

	// sidecar + plain init + main all spawned.
	sp.mu.Lock()
	n := len(sp.specs)
	sp.mu.Unlock()
	if n != 3 {
		t.Errorf("spawned %d processes, want 3 (sidecar + init + main)", n)
	}

	// The sidecar reports in init_container_statuses: running, started=true; the
	// main is the only container_statuses entry (the status split).
	st := res.resp.GetStatus()
	ics := st.GetInitContainerStatuses()
	if len(ics) != 1 || ics[0].GetName() != "sc" {
		t.Fatalf("init_container_statuses = %+v, want the one sidecar", ics)
	}
	if ics[0].GetState().GetRunning() == nil {
		t.Errorf("sidecar state = %+v, want Running", ics[0].GetState())
	}
	if !ics[0].GetStarted() || !ics[0].GetStartedSet() {
		t.Errorf("sidecar started/started_set = %v/%v, want true/true (spawn-equals-started)",
			ics[0].GetStarted(), ics[0].GetStartedSet())
	}
	cs := st.GetContainerStatuses()
	if len(cs) != 1 || cs[0].GetName() != "main" {
		t.Fatalf("container_statuses = %+v, want only main", cs)
	}

	// The sidecar is tracked long-lived: findable by name (GetLogs resolves it).
	stream := newFakeLogStream(context.Background())
	if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-sc", Container: "sc"}, stream); err != nil {
		t.Errorf("GetLogs(sidecar) = %v, want found (sidecar must be tracked by name)", err)
	}

	w.release(1001)
	w.release(1003)
}

// TestInitContainerUnsetLegacyBlocks pins the byte-legacy contract (M10.2): an
// init container with restart_policy UNSPECIFIED runs TO COMPLETION exactly as
// before the field existed — CreatePod blocks on it (no main starts until it
// exits) and a non-zero exit fails the create.
func TestInitContainerUnsetLegacyBlocks(t *testing.T) {
	t.Run("blocks-until-init-exits", func(t *testing.T) {
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})

		box := hostBinBox("pod-legacy")
		box.InitContainers = []*runtimev1.Container{{Name: "ip", Image: "/bin/true"}} // UNSPECIFIED

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		}()

		// While the init container has not exited, the create must be parked on it:
		// exactly one spawn (the init), no main, no return.
		time.Sleep(50 * time.Millisecond)
		select {
		case <-done:
			t.Fatal("CreatePod returned before the UNSPECIFIED init container exited (legacy wait lost)")
		default:
		}
		sp.mu.Lock()
		n := len(sp.specs)
		sp.mu.Unlock()
		if n != 1 {
			t.Fatalf("spawns while init running = %d, want 1 (main must not start)", n)
		}

		w.release(1001) // init exits 0
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("CreatePod did not complete after the init container exited")
		}
		sp.mu.Lock()
		n = len(sp.specs)
		sp.mu.Unlock()
		if n != 2 {
			t.Errorf("spawns after init exit = %d, want 2 (init + main)", n)
		}
		w.release(1002)
	})

	t.Run("nonzero-init-exit-fails-create", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{Waiter: instantWaiter{code: 1}})
		box := hostBinBox("pod-legacy-fail")
		box.InitContainers = []*runtimev1.Container{{Name: "ip", Image: "/bin/false"}}
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() == nil {
			t.Fatal("a failing UNSPECIFIED init container must fail the create (legacy behavior)")
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_SPAWN {
			t.Errorf("reason = %v, want SPAWN", resp.GetFailureReason())
		}
	})
}

// TestSidecarMainsOnlyPhase is the M10.2 phase proof: the pod's terminal phase
// derives from the MAIN containers only. A main exiting 0 makes the pod
// Succeeded; a main exiting non-zero makes it Failed; a sidecar exit alone —
// even a crash — never flips the phase.
//
// It is ALSO the B26 truly-terminal proof on the teardown axis: only the
// Succeeded transition (voluntary completion) tears the sidecar down. A FAILED
// pod is the restart-expected case (CrashLoopBackOff — the provider re-execs it
// via RestartContainer), so its sidecars MUST survive; DeletePod remains the
// backstop that stops them for a pod that is never restarted.
func TestSidecarMainsOnlyPhase(t *testing.T) {
	const (
		pidSC   = 1001
		pidMain = 1002
	)
	cases := []struct {
		name         string
		exitCode     int // every released pid reports this code
		wantPhase    runtimev1.PodPhase
		wantTeardown bool
	}{
		{"main-exit-0-pod-succeeded-tears-sidecar-down", 0, runtimev1.PodPhase_POD_PHASE_SUCCEEDED, true},
		{"main-exit-nonzero-pod-failed-sidecar-survives", 5, runtimev1.PodPhase_POD_PHASE_FAILED, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newBlockingWaiter()
			w.code = tc.exitCode
			rt := newTestRuntime(t, Deps{Waiter: w})
			rec := &recordingSignalGroup{onTerm: func(pid int) { w.release(pid) }}
			rt.signalGroup = rec.signal

			mustCreatePod(t, rt, sidecarBox("pod-ph", "sc"))

			// Subscribe BEFORE the main exits: the MODIFIED event for that exit is
			// published at the END of watchContainerExit, strictly AFTER the
			// teardown block — so observing it is a race-free barrier for the
			// negative (no-teardown) assertion below.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := newFakeWatchStream(ctx)
			go func() { _ = rt.WatchPodStatus(&runtimev1.WatchPodStatusRequest{PodId: "pod-ph"}, stream) }()
			stream.recv(t, 2*time.Second) // the initial snapshot

			w.release(pidMain) // the main terminates on its own
			waitFor(t, 5*time.Second, "terminal phase on mains alone", func() bool {
				return podPhase(t, rt, "pod-ph") == tc.wantPhase
			})

			sidecarTermed := func() bool {
				for _, s := range rec.sentSignals() {
					if s.pid == pidSC && s.sig == termSignal {
						return true
					}
				}
				return false
			}
			if tc.wantTeardown {
				// Voluntary-completion teardown: the still-running sidecar was stopped
				// (SIGTERM under the 30s pod grace; the hook released it).
				waitFor(t, 5*time.Second, "sidecar teardown signal", sidecarTermed)
				if rec.sawKill() {
					t.Error("sidecar honored SIGTERM within grace; must not escalate to SIGKILL")
				}
				return
			}

			// Barrier: the terminated-main publish means watchContainerExit ran its
			// teardown block to completion. Any signal it would have sent is
			// already recorded.
			waitFor(t, 5*time.Second, "the main's terminated publish", func() bool {
				ev := stream.recv(t, 5*time.Second)
				for _, cs := range ev.GetStatus().GetContainerStatuses() {
					if cs.GetName() == "main" && cs.GetState().GetTerminated() != nil {
						return true
					}
				}
				return false
			})
			if sidecarTermed() || rec.sawKill() {
				t.Errorf("sidecar was torn down on a FAILED pod: %+v — a failed pod is restart-expected, "+
					"tearing it down leaves a re-execed main with no sidecars", rec.sentSignals())
			}
			// It is still RUNNING and reported as such.
			gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-ph"})
			ics := gs.GetStatus().GetInitContainerStatuses()
			if len(ics) != 1 || ics[0].GetState().GetRunning() == nil {
				t.Errorf("sidecar status after a FAILED main = %+v, want still Running", ics)
			}
		})
	}

	t.Run("sidecar-exit-alone-never-flips-phase", func(t *testing.T) {
		w := newBlockingWaiter()
		w.code = 7 // the sidecar CRASHES
		rt := newTestRuntime(t, Deps{Waiter: w})

		mustCreatePod(t, rt, sidecarBox("pod-scx", "sc")) // sc=1001, main=1002

		w.release(1001) // only the sidecar exits
		waitFor(t, 5*time.Second, "sidecar terminated status", func() bool {
			gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-scx"})
			ics := gs.GetStatus().GetInitContainerStatuses()
			return len(ics) == 1 && ics[0].GetState().GetTerminated() != nil
		})
		if got := podPhase(t, rt, "pod-scx"); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase after sidecar crash = %v, want RUNNING (a sidecar never concludes the pod)", got)
		}
		// runtimed performs NO exit-driven sidecar restart: no new spawn happened.
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-scx"})
		if rc := gs.GetStatus().GetInitContainerStatuses()[0].GetRestartCount(); rc != 0 {
			t.Errorf("sidecar restart_count = %d, want 0 (the provider is the restart authority)", rc)
		}
		w.release(1002)
	})
}

// TestSidecarReverseOrderTeardown is the M10.2-a1 teardown proof: two sidecars
// started A-then-B are stopped B-then-A, both on voluntary completion (the last
// main exits by itself) and on DeletePod (mains stopped first, then the
// sidecars) — all SIGTERM-only while the shared grace budget lasts.
func TestSidecarReverseOrderTeardown(t *testing.T) {
	// Spawn order (fakeSpawner pids): sidecar A=1001, sidecar B=1002, main=1003.
	const (
		pidA    = 1001
		pidB    = 1002
		pidMain = 1003
	)

	t.Run("voluntary-completion", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		rec := &recordingSignalGroup{onTerm: func(pid int) { w.release(pid) }}
		rt.signalGroup = rec.signal

		mustCreatePod(t, rt, sidecarBox("pod-rev", "sc-a", "sc-b"))

		w.release(pidMain) // the last main terminates voluntarily
		waitFor(t, 5*time.Second, "both sidecars SIGTERMed", func() bool {
			return len(rec.sentSignals()) >= 2
		})

		got := rec.sentSignals()
		if len(got) != 2 || got[0].pid != pidB || got[1].pid != pidA {
			t.Errorf("teardown signal order = %+v, want [B(%d) A(%d)] (reverse start order)", got, pidB, pidA)
		}
		for _, s := range got {
			if s.sig != termSignal {
				t.Errorf("signal to pid %d = %v, want SIGTERM (grace budget untouched by voluntary mains)", s.pid, s.sig)
			}
		}
		waitFor(t, 5*time.Second, "pod Succeeded", func() bool {
			return podPhase(t, rt, "pod-rev") == runtimev1.PodPhase_POD_PHASE_SUCCEEDED
		})
	})

	t.Run("delete-pod-two-phase", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		rec := &recordingSignalGroup{onTerm: func(pid int) { w.release(pid) }}
		rt.signalGroup = rec.signal

		mustCreatePod(t, rt, sidecarBox("pod-del", "sc-a", "sc-b"))

		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-del"}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}

		// Two-phase order: the main first (phase 1), then the sidecars in reverse
		// start order with the budget's remainder (phase 2) — all within grace, so
		// SIGTERM only, exactly once each (DeletePod claims the teardown; the
		// delete-driven main exit must not double-stop the sidecars).
		got := rec.sentSignals()
		if len(got) != 3 || got[0].pid != pidMain || got[1].pid != pidB || got[2].pid != pidA {
			t.Errorf("signal order = %+v, want [main(%d) B(%d) A(%d)]", got, pidMain, pidB, pidA)
		}
		for _, s := range got {
			if s.sig != termSignal {
				t.Errorf("signal to pid %d = %v, want SIGTERM", s.pid, s.sig)
			}
		}
	})
}

// TestDeletePodSidecarRemainingGrace proves the ONE-pod-level-budget remainder
// rule (M10.2, bounded timing): with a 1s grace and a main that ignores SIGTERM,
// phase 1 consumes the entire budget (SIGTERM → 1s timer → SIGKILL), so the
// sidecars' remainder is <= 0 and phase 2 takes the immediate-SIGKILL path — no
// sidecar SIGTERM — still in reverse start order.
func TestDeletePodSidecarRemainingGrace(t *testing.T) {
	const (
		pidA    = 1001
		pidB    = 1002
		pidMain = 1003
	)
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	// Only SIGKILL releases a process: the main IGNORES SIGTERM and burns the
	// whole budget; the sidecars then exit on their immediate SIGKILLs.
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal

	box := sidecarBox("pod-rem", "sc-a", "sc-b")
	box.TerminationGracePeriodSeconds = 1 // the smallest non-zero budget
	mustCreatePod(t, rt, box)

	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-rem"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}

	want := []sentSignal{
		{pidMain, termSignal}, // phase 1: graceful attempt on the main
		{pidMain, killSignal}, // ... escalated at the 1s deadline
		{pidB, killSignal},    // phase 2: remainder <= 0 → immediate SIGKILL, reverse order
		{pidA, killSignal},
	}
	got := rec.sentSignals()
	if len(got) != len(want) {
		t.Fatalf("signals = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("signal[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// profileRecordingBackend records the SBPL profile handed to each WrapCommand so
// a test can assert a restarted sidecar re-enters the IDENTICAL confinement.
type profileRecordingBackend struct {
	mu       sync.Mutex
	profiles []string
}

func (b *profileRecordingBackend) Available() bool { return true }
func (b *profileRecordingBackend) Name() string    { return "profile-recording" }
func (b *profileRecordingBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	b.mu.Lock()
	b.profiles = append(b.profiles, profile)
	b.mu.Unlock()
	return fakeBackend{available: true}.WrapCommand(ctx, profile, argv, spec)
}

func (b *profileRecordingBackend) recorded() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.profiles...)
}

// TestSidecarRestartPreservesClass proves a provider-driven RestartContainer on
// an init-declared sidecar re-spawns it with the IDENTICAL confinement (the
// pod-scoped SBPL profile through WrapCommand) AND the same lifecycle class:
// still reported under init_container_statuses, still excluded from the
// mains-only phase, and still torn down after the mains.
func TestSidecarRestartPreservesClass(t *testing.T) {
	// Spawn order: sidecar=1001, main=1002, restarted sidecar=1003.
	const (
		pidSC    = 1001
		pidMain  = 1002
		pidNewSC = 1003
	)
	w := newBlockingWaiter()
	backend := &profileRecordingBackend{}
	rt := newTestRuntime(t, Deps{Waiter: w, Backend: backend})
	rec := &recordingSignalGroup{
		onTerm: func(pid int) { w.release(pid) },
		onKill: func(pid int) { w.release(pid) },
	}
	rt.signalGroup = rec.signal

	mustCreatePod(t, rt, sidecarBox("pod-rc", "sc"))

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
		PodId: "pod-rc", Container: "sc", Reason: "liveness probe failed",
	})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("RestartContainer failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	if resp.GetStatus().GetState().GetRunning() == nil {
		t.Fatalf("restarted sidecar state = %+v, want Running", resp.GetStatus().GetState())
	}

	// (1) Identical confinement: the re-spawn's WrapCommand profile is byte-equal
	// to the sidecar's first spawn (the pod-scoped SBPL).
	profiles := backend.recorded()
	if len(profiles) != 3 {
		t.Fatalf("WrapCommand calls = %d, want 3 (sidecar, main, restarted sidecar)", len(profiles))
	}
	if profiles[2] != profiles[0] {
		t.Errorf("restarted sidecar profile differs from its first spawn:\nfirst:\n%s\nrestart:\n%s",
			profiles[0], profiles[2])
	}

	// (2) Same lifecycle class: still an init_container_statuses entry (not
	// re-classified as a main), restart_count bumped, started again.
	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-rc"})
	ics := gs.GetStatus().GetInitContainerStatuses()
	if len(ics) != 1 || ics[0].GetName() != "sc" {
		t.Fatalf("init_container_statuses after restart = %+v, want the one sidecar", ics)
	}
	if rc := ics[0].GetRestartCount(); rc != 1 {
		t.Errorf("restart_count = %d, want 1", rc)
	}
	if !ics[0].GetStarted() || !ics[0].GetStartedSet() {
		t.Errorf("restarted sidecar started/started_set = %v/%v, want true/true",
			ics[0].GetStarted(), ics[0].GetStartedSet())
	}
	if cs := gs.GetStatus().GetContainerStatuses(); len(cs) != 1 || cs[0].GetName() != "main" {
		t.Fatalf("container_statuses after restart = %+v, want only main (class must not flip)", cs)
	}

	// (3) Still excluded from the mains-only phase AND still torn down after the
	// mains: the main's voluntary exit concludes the pod and stops the NEW pid.
	w.release(pidMain)
	waitFor(t, 5*time.Second, "pod Succeeded on mains alone", func() bool {
		return podPhase(t, rt, "pod-rc") == runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	})
	waitFor(t, 5*time.Second, "restarted sidecar torn down", func() bool {
		for _, s := range rec.sentSignals() {
			if s.pid == pidNewSC && s.sig == termSignal {
				return true
			}
		}
		return false
	})
}
