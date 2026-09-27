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
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// unknownExitWaiter is a non-child waiter that blocks until released, then
// reports what supervisor.AdoptedExitWaiter reports for a non-child exit.
type unknownExitWaiter struct{ *blockingWaiter }

func (w unknownExitWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	if _, _, err := w.blockingWaiter.WaitExit(ctx, pid); err != nil {
		return 0, 0, err
	}
	return 0, 0, supervisor.ErrExitUnknown
}

// TestAttachPopulatesOwnedBeforeTheStartupReap is the B124 runtimed gate. The
// table pins attachDecision: only a record whose leader is alive under the
// recorded pgid with EXACTLY the recorded start, written by this very build, is
// adopted — the reap's own kill predicate plus the fingerprint, never a window.
// The wiring subtest pins the ordering invariant: AttachPod puts the adopted pgid
// in the set the startup reap must not touch before startupPodReapDecision runs,
// so that group is never signalled while an unattached orphan still is.
func TestAttachPopulatesOwnedBeforeTheStartupReap(t *testing.T) {
	const fp = "cdhash:aaaa"
	rec := func(pgid int, start int64, version string) podProcRecord {
		return podProcRecord{PodID: "p1", Container: "main", Pgid: pgid, StartUnixNano: start, RuntimeVersion: version}
	}
	exactStart := func(table map[int]int64) procStartTime {
		return func(pid int) (int64, bool) {
			v, ok := table[pid]
			return v, ok
		}
	}
	cases := []struct {
		name      string
		record    podProcRecord
		groups    fakeGroups
		starts    map[int]int64
		wantAdopt bool
	}{
		{
			name:      "exact leader start and matching fingerprint adopted",
			record:    rec(100, 5000, fp),
			groups:    fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}},
			starts:    map[int]int64{100: 5000},
			wantAdopt: true,
		},
		{
			name:   "leader start one nanosecond later not adopted",
			record: rec(100, 5000, fp),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5001)}}},
			starts: map[int]int64{100: 5001},
		},
		{
			name:   "leader start one nanosecond earlier not adopted",
			record: rec(100, 5000, fp),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 4999)}}},
			starts: map[int]int64{100: 4999},
		},
		{
			name:   "per-pid probe disagrees with the group probe not adopted",
			record: rec(100, 5000, fp),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}},
			starts: map[int]int64{100: 5001},
		},
		{
			name:   "keep-warn group (leader gone, grandchild alive) not adopted",
			record: rec(100, 5000, fp),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(150, 9000)}}},
			starts: map[int]int64{150: 9000},
		},
		{
			name:   "dead group not adopted",
			record: rec(100, 5000, fp),
			groups: fakeGroups{},
		},
		{
			name:   "uninspectable group not adopted",
			record: rec(100, 5000, fp),
			groups: fakeGroups{failInspect: map[int]bool{100: true}},
			starts: map[int]int64{100: 5000},
		},
		{
			name:   "fingerprint mismatch not adopted",
			record: rec(100, 5000, "cdhash:bbbb"),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}},
			starts: map[int]int64{100: 5000},
		},
		{
			name:   "old record without a fingerprint not adopted",
			record: rec(100, 5000, ""),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}},
			starts: map[int]int64{100: 5000},
		},
		{
			name:   "zero-identity record not adopted",
			record: rec(100, 0, fp),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 0)}}},
			starts: map[int]int64{100: 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adopt, remaining := attachDecision([]podProcRecord{tc.record}, tc.groups.inspect, exactStart(tc.starts), fp)
			if got := len(adopt) == 1; got != tc.wantAdopt {
				t.Fatalf("adopted = %v (%+v), want %v", got, adopt, tc.wantAdopt)
			}
			if len(adopt)+len(remaining) != 1 {
				t.Fatalf("adopt %+v and remaining %+v must partition the one record", adopt, remaining)
			}
		})
	}

	t.Run("an empty daemon fingerprint adopts nothing", func(t *testing.T) {
		r := podProcRecord{PodID: "p1", Container: "main", Pgid: 100, StartUnixNano: 5000}
		groups := fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}}
		adopt, _ := attachDecision([]podProcRecord{r}, groups.inspect, exactStart(map[int]int64{100: 5000}), "")
		if len(adopt) != 0 {
			t.Fatalf("adopt = %+v, want none", adopt)
		}
	})

	t.Run("attach owns the pgid before the reap decides", func(t *testing.T) {
		var mu sync.Mutex
		var signalled []int
		groups := fakeGroups{members: map[int][]supervisor.ProcMember{
			100: {mem(100, 5000)}, // the attached pod's live leader
			200: {mem(200, 7000)}, // an orphan nothing attaches
		}}
		rt := newTestRuntime(t, Deps{
			ProcGroup:     groups.inspect,
			ProcStartTime: exactStart(map[int]int64{100: 5000, 200: 7000}),
			SignalGroup: func(pgid int, _ os.Signal) error {
				mu.Lock()
				defer mu.Unlock()
				signalled = append(signalled, pgid)
				return nil
			},
		})
		seedPodProcRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: 100, StartUnixNano: 5000})
		seedPodProcRecord(t, rt, podProcRecord{PodID: "p2", Container: "main", Pgid: 200, StartUnixNano: 7000})

		records, _, err := rt.listPodProcRecords()
		if err != nil {
			t.Fatal(err)
		}
		// Before the attach the attached group is squarely in the kill bucket:
		// this is the hazard the ordering invariant exists for.
		if kill, _, _ := startupPodReapDecision(records, nil, rt.procGroup); !equalInts(pgidsOf(kill), []int{100, 200}) {
			t.Fatalf("pre-attach kill = %v, want [100 200]", pgidsOf(kill))
		}

		st, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p1"))
		if err != nil {
			t.Fatalf("AttachPod: %v", err)
		}
		if st.GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Fatalf("attached phase = %v, want RUNNING", st.GetPhase())
		}

		// The owned set exactly as the reap builds it, taken now — after the
		// attach and before startupPodReapDecision runs.
		owned := map[int]bool{}
		rt.mu.Lock()
		for _, p := range rt.pods {
			for _, pid := range p.containerPIDs() {
				owned[pid] = true
			}
		}
		rt.mu.Unlock()
		if !owned[100] {
			t.Fatalf("owned = %v, want the attached pgid 100 in it before the reap", owned)
		}
		if kill, _, _ := startupPodReapDecision(records, owned, rt.procGroup); !equalInts(pgidsOf(kill), []int{200}) {
			t.Fatalf("post-attach kill = %v, want only the unattached orphan [200]", pgidsOf(kill))
		}

		if err := rt.ReapOrphanedPods(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		got := append([]int(nil), signalled...)
		mu.Unlock()
		if !equalInts(got, []int{200}) {
			t.Fatalf("signalled = %v, want [200]: the attached group must not be signalled", got)
		}

		// An attach after the reap began is refused, never raced.
		if _, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p2")); !errors.Is(err, ErrNothingToAttach) {
			t.Fatalf("attach after the reap: err = %v, want ErrNothingToAttach", err)
		}
	})
}

func pgidsOf(recs []podProcRecord) []int {
	out := make([]int, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Pgid)
	}
	return out
}

// TestAttachPodReportsWhatItCannotRebuild pins the attached pod's status for a
// container spawned before file capture (no raw or offset files: its output went
// to pipes that died with the old daemon): the container keeps its published
// identity, the pod carries the log-stream-lost condition and the CPU note, the
// CRI log gets the gap marker, there is no shim-inactive verdict, Exec and
// RestartContainer refuse, and an exit is reported as ExitStatusUnknown with a
// non-zero code.
func TestAttachPodReportsWhatItCannotRebuild(t *testing.T) {
	waiter := unknownExitWaiter{newBlockingWaiter()}
	groups := fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}}
	rt := newTestRuntime(t, Deps{
		ProcGroup:     groups.inspect,
		ProcStartTime: func(int) (int64, bool) { return 5000, true },
		AdoptedWaiter: waiter,
	})
	want := podProcRecord{PodID: "p1", Container: "main", Pgid: 100, StartUnixNano: 5000}
	seedPodProcRecord(t, rt, want)

	st, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p1"))
	if err != nil {
		t.Fatalf("AttachPod: %v", err)
	}
	if len(st.GetContainerStatuses()) != 1 {
		t.Fatalf("container statuses = %+v", st.GetContainerStatuses())
	}
	cs := st.GetContainerStatuses()[0]
	if cs.GetContainerId() != want.containerID() {
		t.Fatalf("container_id = %q, want the record derivation %q", cs.GetContainerId(), want.containerID())
	}
	if got := cs.GetState().GetRunning().GetStartedAt().AsTime(); !got.Equal(time.Unix(0, 5000)) {
		t.Fatalf("started_at = %v, want the recorded leader start", got)
	}
	var lost bool
	for _, c := range st.GetConditions() {
		switch c.GetType() {
		case LogStreamLostConditionType:
			lost = c.GetStatus() == runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
		case ShimInactiveConditionType:
			t.Fatalf("an attached pod must carry no shim verdict, got %+v", c)
		}
	}
	if !lost {
		t.Fatalf("conditions = %+v, want %s True", st.GetConditions(), LogStreamLostConditionType)
	}
	if !strings.Contains(st.GetMessage(), "CPU accounting restarted") || !strings.Contains(st.GetMessage(), "was not captured") {
		t.Fatalf("message = %q, want the CPU note", st.GetMessage())
	}
	logBytes, err := os.ReadFile(cs.GetLogPath())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(logBytes), logStreamLostMarker) {
		t.Fatalf("log = %q, want the gap marker", logBytes)
	}

	resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: "p1", Container: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if codes.Code(resp.GetError().GetCode()) != codes.FailedPrecondition {
		t.Fatalf("restart error = %v, want FailedPrecondition", resp.GetError())
	}

	waiter.release(100)
	deadline := time.Now().Add(5 * time.Second)
	for {
		sts := rt.snapshotStatuses("p1")
		if len(sts) == 1 {
			if term := sts[0].GetContainerStatuses()[0].GetState().GetTerminated(); term != nil {
				if term.GetReason() != ExitStatusUnknownReason || term.GetExitCode() == 0 {
					t.Fatalf("terminated = %+v, want reason %s and a non-zero code", term, ExitStatusUnknownReason)
				}
				if sts[0].GetPhase() != runtimev1.PodPhase_POD_PHASE_FAILED {
					t.Fatalf("phase = %v, want FAILED (an unknown exit is never a success)", sts[0].GetPhase())
				}
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the attached container's exit was never reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "p1"}); err != nil {
		t.Fatal(err)
	}
}

// TestAttachPodWithNothingAdoptable pins the fallback signal: a pod with no
// adoptable record returns ErrNothingToAttach and registers nothing.
func TestAttachPodWithNothingAdoptable(t *testing.T) {
	rt := newTestRuntime(t, Deps{
		ProcGroup:     fakeGroups{}.inspect, // every group dead
		ProcStartTime: func(int) (int64, bool) { return 5000, true },
	})
	seedPodProcRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: 100, StartUnixNano: 5000})
	if _, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p1")); !errors.Is(err, ErrNothingToAttach) {
		t.Fatalf("err = %v, want ErrNothingToAttach", err)
	}
	if _, ok := rt.lookupPod("p1"); ok {
		t.Fatal("a refused attach must register nothing")
	}
}

// TestAttachPodReprobesBeforeAdopt pins the decision→adopt TOCTOU narrowing:
// attachDecision runs before AttachPod's per-container file I/O, so the leader
// can exit (or its pgid be recycled) before AdoptProcess. AttachPod re-probes
// the record's exact identity immediately before adopting, the way the reap
// re-probes before signalGroup, and refuses a group that no longer matches.
// The fake process table changes the instant attachDecision's start-time probe
// returns, i.e. between the decision and the adopt.
func TestAttachPodReprobesBeforeAdopt(t *testing.T) {
	const pgid, start = 100, 5000
	cases := []struct {
		name  string
		after []supervisor.ProcMember // the group as the re-probe sees it
		want  bool                    // attached
	}{
		{name: "the leader is unchanged: adopted", after: []supervisor.ProcMember{mem(pgid, start)}, want: true},
		{name: "the leader exited, the group lives on via a grandchild: refused", after: []supervisor.ProcMember{mem(pgid+1, start+1)}},
		{name: "the pgid was recycled to a new leader: refused", after: []supervisor.ProcMember{mem(pgid, start+1)}},
		{name: "the whole group exited: refused", after: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			members := []supervisor.ProcMember{mem(pgid, start)}
			rt := newTestRuntime(t, Deps{
				ProcGroup: func(g int) ([]supervisor.ProcMember, bool) {
					mu.Lock()
					defer mu.Unlock()
					if g != pgid {
						return nil, true
					}
					return members, true
				},
				ProcStartTime: func(int) (int64, bool) {
					mu.Lock()
					defer mu.Unlock()
					members = tc.after // the decision has read the table; it changes now
					return start, true
				},
				// Never reach the real process table with the fake pgid.
				SignalGroup: func(int, os.Signal) error { return nil },
			})
			seedPodProcRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: pgid, StartUnixNano: start})

			st, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p1"))
			_, registered := rt.lookupPod("p1")
			if tc.want {
				if err != nil || st.GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING || !registered {
					t.Fatalf("AttachPod = (%v, %v), registered=%v; want a RUNNING attached pod", st.GetPhase(), err, registered)
				}
				return
			}
			if !errors.Is(err, ErrNothingToAttach) {
				t.Fatalf("err = %v, want ErrNothingToAttach: a group that stopped matching its record must never be adopted", err)
			}
			if registered {
				t.Fatal("a refused attach must register nothing")
			}
		})
	}
}

// crilogPayloads returns the payload of every CRI line in path.
func crilogPayloads(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, l := range readCRILog(t, path) {
		out = append(out, l.payload)
	}
	return out
}

// TestAttachPodResumesTheCaptureTail is the file-capture half of re-adoption:
// a container spawned by one daemon keeps writing across that daemon's death,
// and the next daemon's AttachPod resumes its capture tail from the persisted
// offset — every line reaches the CRI log exactly once, the gap is named in one
// info line, and the pod carries NO log-stream-lost condition.
func TestAttachPodResumesTheCaptureTail(t *testing.T) {
	// pgid 1001 is the fake spawner's first pid and 1 the default leader start,
	// so the group stays "alive" across the restart and the record is kept.
	alive := fakeGroups{members: map[int][]supervisor.ProcMember{1001: {mem(1001, 1)}}}
	sp := &fakeSpawner{logLine: "before"}
	rt1 := newTestRuntime(t, Deps{Spawner: sp, ProcGroup: alive.inspect})
	box := hostBinBox(rt1, "p1")
	mustCreatePod(t, rt1, box)
	logPath := filepath.Join(box.GetLogDirectory(), "main", "0.log")
	capture, err := rt1.containerCapture("p1", "main")
	if err != nil {
		t.Fatal(err)
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	offsetAtEnd := func() bool {
		b, err := os.ReadFile(supervisor.OffsetPath(capture.Stdout))
		st, serr := os.Stat(capture.Stdout)
		return err == nil && serr == nil && string(b) == strconv.FormatInt(st.Size(), 10) && st.Size() > 0
	}
	waitFor("the first daemon to capture the line", offsetAtEnd)

	// The daemon stops. The container lives on and keeps writing into its
	// capture file (appended here as the child would).
	if err := rt1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	appendFile(t, capture.Stdout, "during-1\nduring-2\n")

	rt2 := newTestRuntimeCfg(t, Config{Root: rt1.cfg.Root, PodLogsDir: rt1.cfg.PodLogsDir}, Deps{ProcGroup: alive.inspect})
	st, err := rt2.AttachPod(context.Background(), hostBinBox(rt2, "p1"))
	if err != nil {
		t.Fatalf("AttachPod: %v", err)
	}
	for _, c := range st.GetConditions() {
		if c.GetType() == LogStreamLostConditionType {
			t.Fatalf("a file-captured pod must not carry %s: %+v", LogStreamLostConditionType, c)
		}
	}
	if strings.Contains(st.GetMessage(), "was not captured") {
		t.Fatalf("message = %q claims lost output for a file-captured pod", st.GetMessage())
	}
	appendFile(t, capture.Stdout, "after\n")
	waitFor("the resumed tail to reach the live write", offsetAtEnd)
	waitFor("the live write in the CRI log", func() bool {
		got := crilogPayloads(t, logPath)
		return len(got) > 0 && got[len(got)-1] == "after"
	})

	got := crilogPayloads(t, logPath)
	if len(got) != 5 || got[0] != "before" || !strings.HasPrefix(got[1], "k3sm: daemon restarted at ") ||
		got[2] != "during-1" || got[3] != "during-2" || got[4] != "after" {
		t.Fatalf("CRI log payloads = %q, want before, the restart info line, during-1, during-2, after — each once", got)
	}
	if strings.Contains(strings.Join(got, "\n"), logStreamLostMarker) {
		t.Fatal("a file-captured pod's log must not carry the lost-stream marker")
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
