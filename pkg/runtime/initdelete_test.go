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
	"slices"
	"syscall"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// procTable is the fake process table behind tree tracking
// (supervisor.TrackTree): one entry per live group, its leader alone, with the
// start time testDeps' ProcStartTime reports, so every live leader is a tree
// member proven ours by exact instance.
func (g *liveGroups) procTable() ([]supervisor.ProcEntry, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []supervisor.ProcEntry
	for pid, l := range g.live {
		if l {
			out = append(out, supervisor.ProcEntry{Pid: pid, Ppid: 1, Pgid: pid, Sid: pid, StartUnixNano: 1, Comm: "fake"})
		}
	}
	return out, true
}

// killProcess is the per-pid kill seam the tree sweep uses. It records the
// signal under the pid in the same per-pgid ledger signal keeps (a leader's pid
// is its pgid), and, deaf, ignores it.
func (g *liveGroups) killProcess(pid int, sig syscall.Signal) error {
	return g.signal(pid, sig)
}

// initStepFixture is a pod whose one plain init container is started through
// StartContainer (its image heals after the create), whose resumed init
// sequence runs synchronously inside the RPC, so the pod is registered and
// deletable while the step waits. Every group ignores signals
// (liveGroups.deaf).
type initStepFixture struct {
	g    *liveGroups
	rt   *Runtime
	pull *fakePuller
	p    *pod
}

const (
	initStepPodID   = "pod-delete-during-init"
	initStepInitRef = "example.com/init:v1"
	initStepPID     = 3001 // the first spawn: the init
)

func newInitStepFixture(t *testing.T) *initStepFixture {
	t.Helper()
	g := newLiveGroups(t)
	g.deaf = true
	pull := &fakePuller{errByRef: map[string]error{
		initStepInitRef: errors.New("manifest unknown: no such image"),
	}}
	rt := newTestRuntime(t, Deps{
		Puller:      pull,
		Unpacker:    &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Spawner:     g,
		Waiter:      g,
		SignalGroup: g.signal,
		ProcGroup:   g.procGroup,
		ProcTable:   g.procTable,
		KillProcess: g.killProcess,
	})
	rt.drainGrace = 50 * time.Millisecond
	rt.exitObsGrace = 50 * time.Millisecond
	// Registered after the runtime, so it runs before rt.Close.
	t.Cleanup(g.exitAll)

	box := pullBox(rt, initStepPodID, pulledContainer("main", "example.com/main:v1"))
	box.InitContainers = []*runtimev1.Container{pulledContainer("init", initStepInitRef)}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	if got := g.spawned(); got != 0 {
		t.Fatalf("%d groups spawned by a create whose init image failed, want 0", got)
	}
	rt.mu.Lock()
	p := rt.pods[initStepPodID]
	rt.mu.Unlock()
	if p == nil {
		t.Fatal("created pod is not registered")
	}
	pull.healRef(initStepInitRef)
	return &initStepFixture{g: g, rt: rt, pull: pull, p: p}
}

// startInit calls StartContainer on the init in the background and returns the
// channel its response arrives on, once a published MODIFIED event shows the
// init running: the install is published before the step is waited, so the
// entry is tracked by then.
func (f *initStepFixture) startInit(t *testing.T, timeout <-chan time.Time) <-chan *runtimev1.StartContainerResponse {
	t.Helper()
	events, cancel := f.rt.broker.subscribe(initStepPodID)
	defer cancel()
	started := make(chan *runtimev1.StartContainerResponse, 1)
	go func() {
		got, err := f.rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: initStepPodID, Container: "init"})
		if err != nil {
			t.Errorf("StartContainer: %v", err)
		}
		started <- got
	}()
	for running := false; !running; {
		select {
		case ev := <-events:
			for _, cs := range ev.GetStatus().GetInitContainerStatuses() {
				if cs.GetName() == "init" && cs.GetState().GetRunning() != nil {
					running = true
				}
			}
		case <-timeout:
			t.Fatal("timed out waiting for the init container to run")
		}
	}
	return started
}

// initTracked reports whether the pod still tracks the init's process.
func (f *initStepFixture) initTracked() bool {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	for _, cp := range f.p.containers {
		if cp.name == "init" && cp.proc != nil && cp.proc.PID() == initStepPID {
			return true
		}
	}
	return false
}

// TestDeletePodDuringAPlainInitStopsItsGroup pins when an init step keeps a
// plain init container owned by its pod: iff its Wait returned an error and the
// supervision context the wait ran under has ended, because the error then
// says nothing about whether the process still runs.
//
// The first row is the DeletePod it exists for. DeletePod cancels that
// context, which ends the init step's Wait while the process may still run.
// stopHostPod's first phase stops the running init with the delete's grace
// (here 0, an immediate SIGKILL; TestDeletePodGivesARunningInitItsGrace pins
// the grace), but the group ignores it, and once watchContainerExit has
// written the init Terminated, what still reaches the group is the pod-tree
// sweep (sweepPodTrees) over the kept entry, and the reap record survives only
// while that sweep reports the group as a survivor. Dropping the entry on the cancelled wait races the
// sweep, and the retirement then drops the record that is the only thing
// naming the group. The group ignores every signal, so it is still running
// through the whole stop: it must get a SIGKILL, its reap record must be kept
// naming it, and its entry must still be tracked once the step has returned.
//
// The second row is a wait error under a live context: the entry is dropped,
// as an observed exit drops it, or it would refuse every later StartContainer
// of the init as already started for the life of the pod.
//
// The remaining rows drive finishInitStep directly over each wait outcome, so
// the error class and the context's state are each set exactly.
func TestDeletePodDuringAPlainInitStopsItsGroup(t *testing.T) {
	t.Run("cancelled-by-the-delete-keeps-it", func(t *testing.T) {
		f := newInitStepFixture(t)
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		started := f.startInit(t, timeout.C)

		if _, err := f.rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: initStepPodID}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		select {
		case got := <-started:
			if got.GetError() != nil {
				t.Errorf("StartContainer failed: %v", got.GetError())
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for StartContainer to return after the delete")
		}

		// The fixture's premise: the init's group is still running.
		if !slices.Contains(f.g.livePIDs(), initStepPID) {
			t.Fatalf("init pgid %d is not live after the delete; the fixture lost its premise", initStepPID)
		}
		if sigs := f.g.signalsTo(initStepPID); !slices.Contains(sigs, killSignal) {
			t.Errorf("init pgid %d, running through the delete, was signalled %v, want a SIGKILL from the stop", initStepPID, sigs)
		}
		records, _, err := f.rt.listPodProcRecords()
		if err != nil {
			t.Fatal(err)
		}
		kept := false
		for _, rec := range records {
			if rec.PodID == initStepPodID && rec.Pgid == initStepPID {
				kept = true
			}
		}
		if !kept {
			t.Errorf("the reap record of init pgid %d was dropped while its group runs; records = %+v", initStepPID, records)
		}
		if !f.initTracked() {
			t.Errorf("the init step dropped its still-running container from the tracked set on a cancelled wait")
		}
	})

	t.Run("another-wait-error-drops-it", func(t *testing.T) {
		f := newInitStepFixture(t)
		// The init's wait fails at once with an exit status that cannot be
		// read: not the context's end, and the pod is not being deleted.
		f.g.mu.Lock()
		f.g.waitErr[initStepPID] = supervisor.ErrExitUnknown
		f.g.mu.Unlock()
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		started := f.startInit(t, timeout.C)
		select {
		case got := <-started:
			if got.GetError() != nil {
				t.Errorf("StartContainer failed: %v", got.GetError())
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for StartContainer to return")
		}

		if f.initTracked() {
			t.Errorf("the init step kept its container in the tracked set on a non-cancel wait error (%v)", supervisor.ErrExitUnknown)
		}
		// Kept, the entry would refuse the init's next start as already
		// started (NOT_UPDATABLE) for the life of the pod.
		again, err := f.rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: initStepPodID, Container: "init"})
		if err != nil {
			t.Fatalf("second StartContainer: %v", err)
		}
		if again.GetFailureReason() == runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("second StartContainer of the init was refused as already started: %v", again.GetError())
		}
	})

	// Each row's process is already reaped with waitErr as its exit error. An
	// ended context is an endedCtx: Err is set but Wait never selects its Done
	// arm, so Wait reports the reaper's recorded error rather than its own
	// ctx.Err(), the order a shim-backed wait produces when the waiter's error
	// races the cancel. kept is (a wait error) && (the context ended).
	cases := []struct {
		name    string
		waitErr error
		ctx     context.Context
		kept    bool
	}{
		{
			name:    "wrapped-cancel-with-the-context-ended-keeps-it",
			waitErr: fmt.Errorf("shim wait: %w", context.Canceled),
			ctx:     endedCtx{context.Background()},
			kept:    true,
		},
		{
			name:    "non-cancel-error-after-the-context-ended-keeps-it",
			waitErr: supervisor.ErrExitUnknown,
			ctx:     endedCtx{context.Background()},
			kept:    true,
		},
		{
			name:    "deadline-wrapped-error-with-a-live-context-drops-it",
			waitErr: fmt.Errorf("%w: %w", supervisor.ErrShimCrashed, context.DeadlineExceeded),
			ctx:     context.Background(),
			kept:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{})
			proc := supervisor.NewProcess(&fakeSpawner{}, errWaiter{err: tc.waitErr},
				supervisor.SpawnSpec{Path: "/init", Argv: []string{"/init"}}, nil)
			if err := proc.Start(context.Background()); err != nil {
				t.Fatalf("start the init process: %v", err)
			}
			<-proc.Done()
			cp := &containerProc{
				name: "init", proc: proc, initDeclared: true,
				spec:  &runtimev1.Container{Name: "init"},
				state: &runtimev1.ContainerStatus{Name: "init"},
			}
			p := &pod{box: &runtimev1.PodBox{PodId: "pod-init-wait"}, containers: []*containerProc{cp}}

			_, err := rt.finishInitStep(tc.ctx, p, cp)
			if err == nil {
				t.Fatalf("finishInitStep returned no error for a wait that failed with %v", tc.waitErr)
			}
			p.mu.Lock()
			tracked := slices.Contains(p.containers, cp)
			p.mu.Unlock()
			if tracked != tc.kept {
				t.Errorf("wait error %v, context ended %v: entry tracked = %v, want %v",
					tc.waitErr, tc.ctx.Err() != nil, tracked, tc.kept)
			}
		})
	}
}

// endedCtx is a context whose Err reports cancellation while its Done channel
// is nil, so a select on it never takes that arm (see the finishInitStep rows).
type endedCtx struct{ context.Context }

func (endedCtx) Done() <-chan struct{} { return nil }
func (endedCtx) Err() error            { return context.Canceled }

// errWaiter is an ExitWaiter whose wait fails at once with err.
type errWaiter struct{ err error }

func (w errWaiter) WaitExit(context.Context, int) (int, int, error) { return 0, 0, w.err }

// TestDeletePodGivesARunningInitItsGrace pins that DeletePod stops a plain
// init container still running when it arrives as the kubelet's pod kill does
// every running container: SIGTERM first, then a wait of up to the pod's
// grace, then SIGKILL only if the init is still running. stopHostPod's first
// phase once skipped init-declared entries, so such an init got no SIGTERM and
// no grace, only the late SIGKILL or the pod-tree sweep.
//
// The grace is DeletePod's own, in whole seconds, and runs on the stop's real
// timer: the deaf row waits it out once, and its SIGKILL is checked to come no
// sooner than the grace after the SIGTERM.
func TestDeletePodGivesARunningInitItsGrace(t *testing.T) {
	const graceSecs = 1
	grace := graceSecs * time.Second
	cases := []struct {
		name string
		// deaf makes the init ignore SIGTERM, so only the SIGKILL ends it.
		deaf bool
	}{
		{name: "an-init-that-exits-on-sigterm-gets-no-sigkill", deaf: false},
		{name: "an-init-that-ignores-sigterm-is-killed-after-the-grace", deaf: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInitStepFixture(t)
			f.g.mu.Lock()
			f.g.deaf = tc.deaf
			f.g.mu.Unlock()
			timeout := time.NewTimer(10 * time.Second)
			defer timeout.Stop()
			started := f.startInit(t, timeout.C)

			if _, err := f.rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{
				PodId: initStepPodID, GracePeriodSeconds: graceSecs,
			}); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			select {
			case <-started:
			case <-timeout.C:
				t.Fatal("timed out waiting for StartContainer to return after the delete")
			}

			sigs := f.g.signalsTo(initStepPID)
			if len(sigs) == 0 || sigs[0] != termSignal {
				t.Fatalf("init pgid %d, running when the delete arrived, was signalled %v, want SIGTERM first", initStepPID, sigs)
			}
			if !tc.deaf {
				if slices.Contains(sigs, killSignal) {
					t.Errorf("init pgid %d exited on SIGTERM but was signalled %v, want no SIGKILL", initStepPID, sigs)
				}
				return
			}
			kill := slices.Index(sigs, killSignal)
			if kill < 0 {
				t.Fatalf("init pgid %d ignored SIGTERM and was signalled %v, want a SIGKILL after the grace", initStepPID, sigs)
			}
			at := f.g.signalTimes(initStepPID)
			if waited := at[kill].Sub(at[0]); waited < grace {
				t.Errorf("init pgid %d was SIGKILLed %v after its SIGTERM, want no sooner than the %v grace", initStepPID, waited, grace)
			}
		})
	}
}
