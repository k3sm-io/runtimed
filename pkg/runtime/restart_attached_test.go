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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// attachedPod is a two-container pod created by one runtime (rt1) and
// re-attached, after that runtime's death, by a second runtime (rt2) over the
// same root: the shape a `launchctl kickstart -k` leaves behind.
type attachedPod struct {
	rt1, rt2 *Runtime
	be1, be2 *recordingExecBackend
	box      *runtimev1.PodBox
	adopt    unknownExitWaiter
	// profile1 is the profile runtime 1 handed WrapCommand for c0's spawn.
	profile1 string
	// records are runtime 1's reap records, by container.
	records map[string]podProcRecord
	// attachErr is AttachPod's error on runtime 2.
	attachErr error
}

// attachedPodOpts varies the harness per case.
type attachedPodOpts struct {
	// cfg2 edits runtime 2's Config (it starts as runtime 1's Root/PodLogsDir).
	cfg2 func(*Config)
	// dead names containers whose process group is gone by the time runtime 2
	// attaches (died while the daemon was down).
	dead map[string]bool
	// before runs between runtime 1's death and runtime 2's attach.
	before func(t *testing.T, a *attachedPod)
	// logLine1 / logLine2 are the fake spawners' output lines.
	logLine1, logLine2 string
}

// newAttachedPod builds an attachedPod. Runtime 1's fake spawner hands out
// pids 1001 (c0) and 1002 (c1); runtime 2's starts at 1011 so a re-spawned
// instance never shares a pid with the adopted one it replaces.
func newAttachedPod(t *testing.T, o attachedPodOpts) *attachedPod {
	t.Helper()
	all := fakeGroups{members: map[int][]supervisor.ProcMember{1001: {mem(1001, 1)}, 1002: {mem(1002, 1)}}}
	a := &attachedPod{be1: &recordingExecBackend{}, be2: &recordingExecBackend{}, adopt: unknownExitWaiter{newBlockingWaiter()}}
	a.rt1 = newTestRuntime(t, Deps{
		Spawner:   &fakeSpawner{logLine: o.logLine1},
		Backend:   a.be1,
		ProcGroup: all.inspect,
	})
	a.box = hostBinBox(a.rt1, "p1")
	a.box.Containers = []*runtimev1.Container{
		{Name: "c0", Image: "/bin/sleep"},
		{Name: "c1", Image: "/bin/sleep"},
	}
	mustCreatePod(t, a.rt1, proto.Clone(a.box).(*runtimev1.PodBox))
	a.profile1 = a.be1.profiles[0]
	recs, _, err := a.rt1.listPodProcRecords()
	if err != nil {
		t.Fatal(err)
	}
	a.records = map[string]podProcRecord{}
	for _, rec := range recs {
		a.records[rec.Container] = rec
	}
	if len(a.records) != 2 || a.records["c0"].Pgid != 1001 || a.records["c1"].Pgid != 1002 {
		t.Fatalf("runtime 1 records = %+v, want c0=1001 c1=1002", recs)
	}
	if err := a.rt1.Close(); err != nil {
		t.Fatalf("Close runtime 1: %v", err)
	}

	live := fakeGroups{members: map[int][]supervisor.ProcMember{}}
	for name, rec := range a.records {
		if !o.dead[name] {
			live.members[rec.Pgid] = []supervisor.ProcMember{mem(rec.Pgid, 1)}
		}
	}
	cfg := Config{Root: a.rt1.cfg.Root, PodLogsDir: a.rt1.cfg.PodLogsDir}
	if o.cfg2 != nil {
		o.cfg2(&cfg)
	}
	sig := &recordingSignalGroup{onKill: a.adopt.release, onTerm: a.adopt.release}
	a.rt2 = newTestRuntimeCfg(t, cfg, Deps{
		Spawner:       &fakeSpawner{next: 10, logLine: o.logLine2},
		Backend:       a.be2,
		ProcGroup:     live.inspect,
		AdoptedWaiter: a.adopt,
		SignalGroup:   sig.signal,
	})
	if o.before != nil {
		o.before(t, a)
	}
	_, a.attachErr = a.rt2.AttachPod(context.Background(), proto.Clone(a.box).(*runtimev1.PodBox))
	return a
}

// status2 is runtime 2's status of the named container.
func (a *attachedPod) status2(t *testing.T, name string) *runtimev1.ContainerStatus {
	t.Helper()
	p, ok := a.rt2.lookupPod("p1")
	if !ok {
		t.Fatal("pod p1 is not registered on runtime 2")
	}
	for _, cs := range a.rt2.podStatus(p).GetContainerStatuses() {
		if cs.GetName() == name {
			return cs
		}
	}
	t.Fatalf("no status for container %s", name)
	return nil
}

// TestRestartContainerOnAttachedPodRebuildsItsSandbox is the B409 runtimed
// gate. A pod re-attached after a daemon restart recompiles its sandbox profile
// from the spec and this daemon's posture, verifies it against the digest each
// container recorded at spawn, and so restarts ONE container in place — the
// kubelet's shape, where the CRI sandbox config survives a kubelet restart —
// instead of refusing and forcing the whole pod to be recreated.
//
// Red on main: the attached pod carried no profile, so RestartContainer and
// StopContainer refused it (FailedPrecondition, "its sandbox profile was not
// rebuilt"), and ProfileSHA256 / compileProfile did not exist.
func TestRestartContainerOnAttachedPodRebuildsItsSandbox(t *testing.T) {
	t.Run("restart one container in place", func(t *testing.T) {
		a := newAttachedPod(t, attachedPodOpts{})
		if a.attachErr != nil {
			t.Fatalf("AttachPod: %v", a.attachErr)
		}
		c1Before := a.status2(t, "c1")

		resp, err := a.rt2.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: "p1", Container: "c0", Reason: "liveness"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() != nil {
			t.Fatalf("RestartContainer refused: %v (%v)", resp.GetError(), resp.GetFailureReason())
		}
		st := resp.GetStatus()
		if st.GetRestartCount() != 1 {
			t.Fatalf("restart_count = %d, want 1", st.GetRestartCount())
		}
		if want := filepath.Join(a.box.GetLogDirectory(), "c0", "1.log"); st.GetLogPath() != want {
			t.Fatalf("log_path = %q, want %q", st.GetLogPath(), want)
		}
		if got := a.be2.lastProfile(); got != a.profile1 {
			t.Fatalf("the restarted container's profile differs from the one runtime 1 compiled:\n--- runtime 2\n%s\n--- runtime 1\n%s", got, a.profile1)
		}
		last := st.GetLastTerminationState().GetTerminated()
		if last.GetReason() != ExitStatusUnknownReason || last.GetExitCode() != exitCodeUnknown {
			t.Fatalf("last_termination_state = %+v, want %s / %d: a killed adopted instance's status is unknown, never Completed/0",
				last, ExitStatusUnknownReason, exitCodeUnknown)
		}
		if last.GetContainerId() != a.records["c0"].containerID() {
			t.Fatalf("last_termination_state container_id = %q, want the adopted instance's %q", last.GetContainerId(), a.records["c0"].containerID())
		}
		if want := filepath.Join(a.box.GetLogDirectory(), "c0", "0.log"); last.GetLogPath() != want {
			t.Fatalf("last_termination_state log_path = %q, want the adopted instance's %q", last.GetLogPath(), want)
		}
		if st.GetContainerId() == a.records["c0"].containerID() {
			t.Fatal("the replacement must carry a new container_id")
		}

		c1 := a.status2(t, "c1")
		if c1.GetContainerId() != c1Before.GetContainerId() || c1.GetContainerId() != a.records["c1"].containerID() ||
			c1.GetState().GetRunning() == nil || c1.GetRestartCount() != 0 {
			t.Fatalf("sibling c1 = %+v, want untouched (running, id %s, restart_count 0)", c1, a.records["c1"].containerID())
		}
		p, _ := a.rt2.lookupPod("p1")
		p.mu.Lock()
		var c1PID int
		for _, cp := range p.containers {
			if cp.name == "c1" {
				c1PID = cp.proc.PID()
			}
		}
		p.mu.Unlock()
		if c1PID != 1002 {
			t.Fatalf("sibling c1 pid = %d, want the adopted 1002", c1PID)
		}
	})

	t.Run("stop a container of an attached pod", func(t *testing.T) {
		a := newAttachedPod(t, attachedPodOpts{})
		if a.attachErr != nil {
			t.Fatalf("AttachPod: %v", a.attachErr)
		}
		resp, err := a.rt2.StopContainer(context.Background(), &runtimev1.StopContainerRequest{PodId: "p1", Container: "c1"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() != nil {
			t.Fatalf("StopContainer refused: %v", resp.GetError())
		}
		term := resp.GetStatus().GetState().GetTerminated()
		if term == nil || term.GetReason() != ExitStatusUnknownReason {
			t.Fatalf("stopped state = %+v, want Terminated %s", resp.GetStatus().GetState(), ExitStatusUnknownReason)
		}
	})

	t.Run("exec on an attached pod is still refused", func(t *testing.T) {
		a := newAttachedPod(t, attachedPodOpts{})
		if a.attachErr != nil {
			t.Fatalf("AttachPod: %v", a.attachErr)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "p1", Container: "c0", Command: []string{"/bin/echo"}})
		st.closeSend()
		if err := a.rt2.Exec(st); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("Exec = %v, want FailedPrecondition", err)
		}
	})

	t.Run("a drifted posture refuses the attach", func(t *testing.T) {
		a := newAttachedPod(t, attachedPodOpts{cfg2: func(c *Config) {
			c.PodLogsDir = filepath.Join(c.Root, "other-podlogs")
		}})
		if !errors.Is(a.attachErr, ErrNothingToAttach) || !strings.Contains(a.attachErr.Error(), "sandbox profile drift") {
			t.Fatalf("AttachPod = %v, want ErrNothingToAttach naming the sandbox profile drift", a.attachErr)
		}
		if _, ok := a.rt2.lookupPod("p1"); ok {
			t.Fatal("a refused attach must register nothing")
		}
	})

	t.Run("a record without a profile digest refuses the attach", func(t *testing.T) {
		a := newAttachedPod(t, attachedPodOpts{before: func(t *testing.T, a *attachedPod) {
			rec := a.records["c1"]
			rec.ProfileSHA256 = ""
			seedPodProcRecord(t, a.rt2, rec)
		}})
		if !errors.Is(a.attachErr, ErrNothingToAttach) {
			t.Fatalf("AttachPod = %v, want ErrNothingToAttach", a.attachErr)
		}
		if _, ok := a.rt2.lookupPod("p1"); ok {
			t.Fatal("a refused attach must register nothing")
		}
	})

	t.Run("a mixed pod adopts the live container and starts the dead one under one profile", func(t *testing.T) {
		// c0's reap record is live and its digest matches; c1 died while the
		// daemon was down and has no adoptable record at all. AttachPod must
		// adopt c0, report c1 Terminated (the recordless container is exempt
		// from the digest check, attach.go's "!ok -> continue"), and both
		// StartContainer(c1) and RestartContainer(c0) must re-spawn under the
		// pod's one recompiled-and-verified profile — never a per-container one.
		a := newAttachedPod(t, attachedPodOpts{dead: map[string]bool{"c1": true}})
		if a.attachErr != nil {
			t.Fatalf("AttachPod: %v", a.attachErr)
		}
		c0 := a.status2(t, "c0")
		if c0.GetState().GetRunning() == nil || c0.GetContainerId() != a.records["c0"].containerID() {
			t.Fatalf("adopted c0 = %+v, want running with the recorded id %s", c0, a.records["c0"].containerID())
		}
		c1 := a.status2(t, "c1")
		if term := c1.GetState().GetTerminated(); term == nil || term.GetReason() != ExitStatusUnknownReason {
			t.Fatalf("dead c1 = %+v, want Terminated %s", c1, ExitStatusUnknownReason)
		}

		startResp, err := a.rt2.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: "p1", Container: "c1"})
		if err != nil {
			t.Fatal(err)
		}
		if startResp.GetError() != nil {
			t.Fatalf("StartContainer(c1) refused: %v", startResp.GetError())
		}
		if got := a.be2.lastProfile(); got != a.profile1 {
			t.Fatalf("StartContainer(c1) profile:\n--- got\n%s\n--- want the pod's verified profile\n%s", got, a.profile1)
		}

		restartResp, err := a.rt2.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: "p1", Container: "c0", Reason: "liveness"})
		if err != nil {
			t.Fatal(err)
		}
		if restartResp.GetError() != nil {
			t.Fatalf("RestartContainer(c0) refused: %v", restartResp.GetError())
		}
		if got := a.be2.lastProfile(); got != a.profile1 {
			t.Fatalf("RestartContainer(c0) profile:\n--- got\n%s\n--- want the pod's verified profile\n%s", got, a.profile1)
		}
	})

	t.Run("a mismatched digest on the live container refuses the whole mixed pod", func(t *testing.T) {
		// Same mixed shape (c0 live, c1 dead/recordless) but c0's own record
		// now disagrees with the freshly compiled profile. The recordless c1 is
		// exempt from the compare (attach.go's "!ok -> continue"), so this pins
		// that the loop still refuses on c0's mismatch rather than the exempt
		// sibling papering over it: nothing is adopted, and c1 is never spawned.
		a := newAttachedPod(t, attachedPodOpts{
			dead: map[string]bool{"c1": true},
			before: func(t *testing.T, a *attachedPod) {
				rec := a.records["c0"]
				mismatched := strings.Repeat("0", 64)
				if mismatched == rec.ProfileSHA256 {
					t.Fatal("test bug: the mismatched digest equals the real one")
				}
				rec.ProfileSHA256 = mismatched
				seedPodProcRecord(t, a.rt2, rec)
			},
		})
		if !errors.Is(a.attachErr, ErrNothingToAttach) {
			t.Fatalf("AttachPod = %v, want ErrNothingToAttach", a.attachErr)
		}
		if _, ok := a.rt2.lookupPod("p1"); ok {
			t.Fatal("a refused attach must register nothing: neither the adopted c0 nor the dead c1")
		}
		if len(a.be2.profiles) != 0 {
			t.Fatalf("c1 must never have been spawned: be2 recorded %d profile(s)", len(a.be2.profiles))
		}
	})

	t.Run("an unknown exit reads -1 in either order", func(t *testing.T) {
		started := timestamppb.New(time.Unix(0, 5000))
		unknown := containerExit{err: supervisor.ErrExitUnknown}
		for _, reaperFirst := range []bool{true, false} {
			t.Run("reaper wrote first="+strconv.FormatBool(reaperFirst), func(t *testing.T) {
				p := &pod{}
				cp := &containerProc{name: "c0", state: &runtimev1.ContainerStatus{
					ContainerId: "adopted-id",
					LogPath:     "/logs/c0/0.log",
					State:       &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: started}},
				}}
				if reaperFirst {
					// watchContainerExit's write, with what the adopted waiter reports.
					terminatedStateLocked(p, cp, 0, 0, supervisor.ErrExitUnknown)
				}
				// RestartContainer's read (RestartContainer holds p.mu here).
				got := lastTerminationState(p, cp, unknown, started, "liveness").GetTerminated()
				if got.GetExitCode() != exitCodeUnknown || got.GetReason() != ExitStatusUnknownReason {
					t.Fatalf("last_termination_state = %+v, want %d / %s", got, exitCodeUnknown, ExitStatusUnknownReason)
				}
				if got.GetContainerId() != "adopted-id" || got.GetLogPath() != "/logs/c0/0.log" {
					t.Fatalf("last_termination_state = %+v, want the adopted instance's id and log path", got)
				}
			})
		}
	})

	t.Run("start a container that died while the daemon was down", func(t *testing.T) {
		a := newAttachedPod(t, attachedPodOpts{
			dead: map[string]bool{"c1": true},
			before: func(t *testing.T, a *attachedPod) {
				// c1 had restarted up to instance 5 before it died unwatched.
				dir := filepath.Join(a.box.GetLogDirectory(), "c1")
				for i := 1; i <= 5; i++ {
					if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)+".log"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			},
		})
		if a.attachErr != nil {
			t.Fatalf("AttachPod: %v", a.attachErr)
		}
		if cs := a.status2(t, "c1"); cs.GetRestartCount() != 5 || cs.GetState().GetTerminated().GetReason() != ExitStatusUnknownReason {
			t.Fatalf("attached c1 = %+v, want Terminated %s at restart_count 5", cs, ExitStatusUnknownReason)
		}
		resp, err := a.rt2.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: "p1", Container: "c1"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() != nil {
			t.Fatalf("StartContainer refused: %v", resp.GetError())
		}
		st := resp.GetStatus()
		if want := filepath.Join(a.box.GetLogDirectory(), "c1", "6.log"); st.GetLogPath() != want {
			t.Fatalf("log_path = %q, want %q", st.GetLogPath(), want)
		}
		if st.GetRestartCount() != 6 {
			t.Fatalf("restart_count = %d, want 6 (never the claimed entry's 5)", st.GetRestartCount())
		}
		if last := st.GetLastTerminationState().GetTerminated(); last.GetReason() != ExitStatusUnknownReason || last.GetExitCode() != exitCodeUnknown {
			t.Fatalf("last_termination_state = %+v, want %s / %d", last, ExitStatusUnknownReason, exitCodeUnknown)
		}
		if got := a.be2.lastProfile(); got != a.profile1 {
			t.Fatal("the started container's profile differs from the one runtime 1 compiled")
		}
	})

	t.Run("a live adopted capture tail hands off across the restart", func(t *testing.T) {
		var capture supervisor.FileCapture
		a := newAttachedPod(t, attachedPodOpts{
			logLine1: "before",
			logLine2: "restarted",
			before: func(t *testing.T, a *attachedPod) {
				var err error
				if capture, err = a.rt2.containerCapture("p1", "c0"); err != nil {
					t.Fatal(err)
				}
				// Written while no daemon was watching.
				appendFile(t, capture.Stdout, "during\n")
			},
		})
		if a.attachErr != nil {
			t.Fatalf("AttachPod: %v", a.attachErr)
		}
		log0 := filepath.Join(a.box.GetLogDirectory(), "c0", "0.log")
		log1 := filepath.Join(a.box.GetLogDirectory(), "c0", "1.log")
		waitPayload := func(path, want string) {
			t.Helper()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(path); err == nil {
					got := crilogPayloads(t, path)
					if len(got) > 0 && got[len(got)-1] == want {
						return
					}
				}
				if time.Now().After(deadline) {
					t.Fatalf("timed out waiting for %q in %s", want, path)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		appendFile(t, capture.Stdout, "live\n")
		waitPayload(log0, "live")
		// The adopted instance's last words, written as it is killed: the
		// adopted tail's final drain owns them, never the replacement's.
		appendFile(t, capture.Stdout, "last\n")

		resp, err := a.rt2.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: "p1", Container: "c0"})
		if err != nil || resp.GetError() != nil {
			t.Fatalf("RestartContainer = %v, %v", resp.GetError(), err)
		}
		waitPayload(log1, "restarted")

		got0 := crilogPayloads(t, log0)
		if len(got0) != 5 || got0[0] != "before" || !strings.HasPrefix(got0[1], "k3sm: daemon restarted at ") ||
			got0[2] != "during" || got0[3] != "live" || got0[4] != "last" {
			t.Fatalf("0.log payloads = %q, want before, the restart info line, during, live, last — each once", got0)
		}
		if got1 := crilogPayloads(t, log1); len(got1) != 1 || got1[0] != "restarted" {
			t.Fatalf("1.log payloads = %q, want only the replacement's own output", got1)
		}
	})
}
