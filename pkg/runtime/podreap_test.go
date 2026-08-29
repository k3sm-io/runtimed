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
	"os"
	"path/filepath"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// fakeGroups is a fake kernel view of process GROUPS: pgid → live members
// (pid + start time). A pgid absent from the map is an inspectable-but-empty
// group (a dead group); a pgid in failInspect returns ok=false (a sysctl
// failure).
type fakeGroups struct {
	members     map[int][]supervisor.ProcMember
	failInspect map[int]bool
}

func (f fakeGroups) inspect(pgid int) ([]supervisor.ProcMember, bool) {
	if f.failInspect[pgid] {
		return nil, false
	}
	m, present := f.members[pgid]
	if !present {
		return nil, true // existing-but-empty group (dead)
	}
	return m, true
}

// mem is a terse ProcMember constructor for the fixtures below.
func mem(pid int, startUnixNano int64) supervisor.ProcMember {
	return supervisor.ProcMember{Pid: pid, StartUnixNano: startUnixNano}
}

// TestStartupPodReapDecision is the B115 gate: a table over a fake process
// GROUP table + recorded-pgid set → kill set. It pins the decision's safety
// contract — only recorded pgids are considered, each guarded by a group probe
// and a member start-time identity.
func TestStartupPodReapDecision(t *testing.T) {
	rec := func(pod string, pgid int, start int64) podProcRecord {
		return podProcRecord{PodID: pod, Container: "c", Pgid: pgid, StartUnixNano: start}
	}
	pgids := func(recs []podProcRecord) []int {
		out := make([]int, 0, len(recs))
		for _, r := range recs {
			out = append(out, r.Pgid)
		}
		return out
	}

	cases := []struct {
		name         string
		records      []podProcRecord
		owned        map[int]bool
		groups       fakeGroups
		wantKill     []int
		wantDrop     []int
		wantKeepWarn []int
	}{
		{
			name:     "empty node no-op",
			records:  nil,
			groups:   fakeGroups{},
			wantKill: nil,
			wantDrop: nil,
		},
		{
			name:     "live owned pod kept",
			records:  []podProcRecord{rec("p1", 100, 5)},
			owned:    map[int]bool{100: true},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}}},
			wantKill: nil,
			wantDrop: nil,
		},
		{
			// Leader member (Pid==pgid) with the EXACT recorded start → our
			// instance → kill.
			name:     "orphan leader reaped (group alive, identity matches)",
			records:  []podProcRecord{rec("p1", 100, 5)},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}}},
			wantKill: []int{100},
			wantDrop: nil,
		},
		{
			// Dead-leader / live-grandchild: the leader (Pid==100) is gone; only
			// a grandchild (Pid 150, start 9) keeps the group alive. With no
			// leader member to match, the group can no longer be PROVEN ours, so
			// it is keep-and-warn — kept, never killed, never dropped.
			name:         "dead leader, live grandchild kept-and-warned",
			records:      []podProcRecord{rec("p1", 100, 5)},
			groups:       fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(150, 9)}}},
			wantKill:     nil,
			wantDrop:     nil,
			wantKeepWarn: []int{100},
		},
		{
			// Recycled to a NEW leader: Pid==pgid exists but with a different
			// (earlier) immutable start → not ours → drop.
			name:     "recycled pgid skipped (leader start differs, earlier)",
			records:  []podProcRecord{rec("p1", 100, 50)},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 10)}}},
			wantKill: nil,
			wantDrop: []int{100},
		},
		{
			// The exact-equality regression guard: a leader member whose start is
			// LATER than the recorded floor (9 > 5). Under the old `start >= floor`
			// rule this KILLED (a wrong-target root SIGKILL on a recycled pgid);
			// under exact equality 9 != 5 → it must DROP. This case is green ONLY
			// after the exact-instance fix (the start<floor case dropped under the
			// old rule too, so it proves nothing).
			name:     "recycled pgid, leader start LATER than floor (drop)",
			records:  []podProcRecord{rec("p1", 100, 5)},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 9)}}},
			wantKill: nil,
			wantDrop: []int{100},
		},
		{
			name:     "dead group record dropped unsignaled",
			records:  []podProcRecord{rec("p1", 100, 5)},
			groups:   fakeGroups{}, // pgid absent → empty group
			wantKill: nil,
			wantDrop: []int{100},
		},
		{
			name:     "uninspectable group kept (not dropped, not killed)",
			records:  []podProcRecord{rec("p1", 100, 5)},
			groups:   fakeGroups{failInspect: map[int]bool{100: true}},
			wantKill: nil,
			wantDrop: nil,
		},
		{
			name:     "zero-identity record never signaled",
			records:  []podProcRecord{rec("p1", 100, 0)},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}}},
			wantKill: nil,
			wantDrop: []int{100},
		},
		{
			name:     "pgid<=1 refused even if it slips through",
			records:  []podProcRecord{rec("p1", 1, 5)},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{1: {mem(1, 5)}}},
			wantKill: nil,
			wantDrop: []int{1},
		},
		{
			// A teeming process table of unrecorded groups: none can be selected
			// because the decision iterates records only.
			name:     "bystander never matched",
			records:  []podProcRecord{rec("p1", 100, 5)},
			groups:   fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}, 200: {mem(200, 7)}, 300: {mem(300, 9)}}},
			wantKill: []int{100},
			wantDrop: nil,
		},
		{
			name: "mixed population",
			records: []podProcRecord{
				rec("p1", 100, 5),  // orphan alive, leader matches → kill
				rec("p2", 200, 6),  // owned → keep
				rec("p3", 300, 50), // recycled (leader start differs) → drop
				rec("p4", 400, 8),  // dead group → drop
				rec("p5", 500, 8),  // uninspectable → keep
				rec("p6", 600, 8),  // leader gone, grandchild alive → keep-and-warn
			},
			owned: map[int]bool{200: true},
			groups: fakeGroups{
				members: map[int][]supervisor.ProcMember{
					100: {mem(100, 5)},
					200: {mem(200, 6)},
					300: {mem(300, 10)},
					600: {mem(650, 12)},
				},
				failInspect: map[int]bool{500: true},
			},
			wantKill:     []int{100},
			wantDrop:     []int{300, 400},
			wantKeepWarn: []int{600},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kill, drop, keepWarn := startupPodReapDecision(tc.records, tc.owned, tc.groups.inspect)
			if got := pgids(kill); !equalInts(got, tc.wantKill) {
				t.Errorf("kill = %v, want %v", got, tc.wantKill)
			}
			if got := pgids(drop); !equalInts(got, tc.wantDrop) {
				t.Errorf("drop = %v, want %v", got, tc.wantDrop)
			}
			if got := pgids(keepWarn); !equalInts(got, tc.wantKeepWarn) {
				t.Errorf("keepWarn = %v, want %v", got, tc.wantKeepWarn)
			}
		})
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPodProcRecordRoundTrip pins the durable record store: write → list →
// remove, malformed-file quarantine, transient-read retention, and pgid<=1
// refusal.
func TestPodProcRecordRoundTrip(t *testing.T) {
	rt := newTestRuntime(t, Deps{
		ProcStartTime: func(int) (int64, bool) { return 55, true },
	})

	if _, err := rt.recordPodProc("pod-a", "main", 4242); err != nil {
		t.Fatalf("recordPodProc: %v", err)
	}
	if _, err := rt.recordPodProc("pod-x", "main", 1); err == nil {
		t.Fatal("recordPodProc(pgid=1) must be refused")
	}
	// A malformed record file must be quarantined, not break listing.
	badDir, badDirErr := rt.podReapDir("pod-b")
	if badDirErr != nil {
		t.Fatalf("podReapDir: %v", badDirErr)
	}
	if err := os.MkdirAll(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(badDir, "9.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	records, quarantine, err := rt.listPodProcRecords()
	if err != nil {
		t.Fatalf("listPodProcRecords: %v", err)
	}
	if len(records) != 1 || records[0].PodID != "pod-a" || records[0].Pgid != 4242 || records[0].StartUnixNano != 55 {
		t.Fatalf("records = %+v, want one pod-a/4242/start=55", records)
	}
	if len(quarantine) != 1 || quarantine[0] != bad {
		t.Fatalf("quarantine = %v, want [%s]", quarantine, bad)
	}

	rt.removePodProcRecord("pod-a", 4242)
	records, _, err = rt.listPodProcRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records after remove = %+v, want none", records)
	}
}

// TestReapOrphanedPods pins the startup wiring end to end over fakes: an
// orphaned group is SIGKILLed and its record removed; recycled and dead-group
// records are removed unsignaled; the reap runs exactly once per Runtime.
func TestReapOrphanedPods(t *testing.T) {
	var mu sync.Mutex
	var killed []int
	rt := newTestRuntime(t, Deps{
		ProcStartTime: func(int) (int64, bool) { return 5, true },
		ProcGroup: fakeGroups{members: map[int][]supervisor.ProcMember{
			100: {mem(100, 5)},  // orphan alive, leader matches → kill
			300: {mem(300, 10)}, // recycled: leader start differs from record (50)
		}}.inspect,
		SignalGroup: func(pgid int, _ os.Signal) error {
			mu.Lock()
			defer mu.Unlock()
			killed = append(killed, pgid)
			return nil
		},
	})

	seed := []podProcRecord{
		{PodID: "p1", Container: "c", Pgid: 100, StartUnixNano: 5},  // orphan → kill
		{PodID: "p3", Container: "c", Pgid: 300, StartUnixNano: 50}, // recycled → drop
		{PodID: "p4", Container: "c", Pgid: 400, StartUnixNano: 8},  // dead group → drop
	}
	for _, rec := range seed {
		seedPodProcRecord(t, rt, rec)
	}

	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	mu.Lock()
	got := append([]int(nil), killed...)
	mu.Unlock()
	if !equalInts(got, []int{100}) {
		t.Fatalf("killed = %v, want [100]", got)
	}
	records, _, err := rt.listPodProcRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records after reap = %+v, want none", records)
	}

	// Sticky once-per-Runtime: seeding a new record and re-running must not
	// signal again.
	seedPodProcRecord(t, rt, podProcRecord{PodID: "p9", Container: "c", Pgid: 100, StartUnixNano: 5})
	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(killed)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("killed count after second run = %d, want 1 (once-per-Runtime)", n)
	}
}

// TestReapKeepsRecordOnKillFailure pins the retry contract: a real signal
// failure keeps the record so the NEXT daemon start retries the reap.
func TestReapKeepsRecordOnKillFailure(t *testing.T) {
	rt := newTestRuntime(t, Deps{
		ProcStartTime: func(int) (int64, bool) { return 5, true },
		ProcGroup:     fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}}}.inspect,
		SignalGroup: func(pgid int, _ os.Signal) error {
			return os.ErrPermission
		},
	})
	seedPodProcRecord(t, rt, podProcRecord{PodID: "p1", Container: "c", Pgid: 100, StartUnixNano: 5})

	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	records, _, err := rt.listPodProcRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Pgid != 100 {
		t.Fatalf("records after failed kill = %+v, want the pgid-100 record kept", records)
	}
}

// seedPodProcRecord writes a record file directly (simulating a previous
// daemon run's spawn-time record) with the record's own start time.
func seedPodProcRecord(t *testing.T, rt *Runtime, rec podProcRecord) {
	t.Helper()
	saved := rt.procStart
	rt.procStart = func(int) (int64, bool) { return rec.StartUnixNano, true }
	if _, err := rt.recordPodProc(rec.PodID, rec.Container, rec.Pgid); err != nil {
		t.Fatal(err)
	}
	rt.procStart = saved
}
