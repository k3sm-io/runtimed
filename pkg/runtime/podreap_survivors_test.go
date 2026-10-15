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
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPodReapRecordSurvivorsRoundTrip pins the additive survivors field: a
// record kept with survivors reads back with them through the exported reader
// an uninstaller uses, a record without any carries no "survivors" key, and a
// record written before the field existed still decodes, with none.
func TestPodReapRecordSurvivorsRoundTrip(t *testing.T) {
	rt := newTestRuntime(t, Deps{ProcStartTime: func(int) (int64, bool) { return 77, true }})
	if _, err := rt.recordPodProc("pod-a", "main", 4242, "", ""); err != nil {
		t.Fatal(err)
	}
	want := []ReapSurvivor{{Pid: 5001, StartUnixNano: 11, Sid: 5001}, {Pid: 5002, StartUnixNano: 12, Sid: 4242}}
	if err := rt.retainPodProcRecord("pod-a", "main", 4242, want); err != nil {
		t.Fatal(err)
	}
	// A pod with no record yet gets a minimal one naming the survivors.
	if err := rt.retainPodProcRecord("pod-b", "side", 4343, want[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPodReapRecords(rt.cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	byPod := map[string]PodReapRecord{}
	for _, rec := range got {
		byPod[rec.PodID] = rec
	}
	a := byPod["pod-a"]
	if a.StartUnixNano != 77 || a.RuntimeVersion != "test-build" || !reflect.DeepEqual(a.Survivors, want) {
		t.Fatalf("pod-a record = %+v, want the original identity plus %+v", a, want)
	}
	if b := byPod["pod-b"]; b.Pgid != 4343 || b.Container != "side" || !reflect.DeepEqual(b.Survivors, want[:1]) {
		t.Fatalf("pod-b record = %+v", b)
	}

	plain, err := json.Marshal(PodReapRecord{PodID: "p", Container: "c", Pgid: 9, StartUnixNano: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "survivors") {
		t.Fatalf("a record without survivors carries the key: %s", plain)
	}
	var old PodReapRecord
	if err := json.Unmarshal([]byte(`{"podId":"p","container":"c","pgid":9,"startUnixNano":1,"shimDir":"/x","childPid":10,"childStartUnixNano":2}`), &old); err != nil {
		t.Fatalf("an old record no longer decodes: %v", err)
	}
	if old.Pgid != 9 || old.ChildPid != 10 || old.Survivors != nil {
		t.Fatalf("old record decoded as %+v", old)
	}
}

// TestReapOrphanedPodsKillsRecordedSurvivors pins the startup reap's half of
// the survivors contract: a survivor still alive under exactly its recorded
// start is SIGKILLed by pid, a survivor whose pid now reports another start (a
// recycled pid) is never signalled, and a record is dropped only once none of
// its survivors is alive; one whose survivor will not die is kept naming it.
// A record naming the daemon's own pid, a process in the daemon's own
// session, or a process whose session is no longer the recorded one never
// drives a signal.
func TestReapOrphanedPodsKillsRecordedSurvivors(t *testing.T) {
	var mu sync.Mutex
	self := os.Getpid()
	const selfSid = 4000
	live := map[int]int64{700: 7, 701: 99, 800: 8, 900: 9, 901: 10, self: 11} // 701 recycled (recorded 8)
	sessions := map[int]int{700: 700, 701: 701, 800: 800, 900: selfSid, 901: 555, self: selfSid}
	unkillable := map[int]bool{800: true}
	var killed []int
	rt := newTestRuntime(t, Deps{
		ProcStartTime: func(pid int) (int64, bool) {
			mu.Lock()
			defer mu.Unlock()
			s, ok := live[pid]
			return s, ok
		},
		ProcSession: func(pid int) (int, bool) {
			mu.Lock()
			defer mu.Unlock()
			if _, ok := live[pid]; !ok {
				return 0, false
			}
			return sessions[pid], true
		},
		ProcGroup: fakeGroups{}.inspect, // every group dead
		KillProcess: func(pid int, _ unix.Signal) error {
			mu.Lock()
			defer mu.Unlock()
			killed = append(killed, pid)
			if !unkillable[pid] {
				delete(live, pid)
			}
			return nil
		},
	})
	rt.exitObsGrace = 150 * time.Millisecond
	for _, rec := range []podProcRecord{
		{PodID: "gone", Container: "c", Pgid: 100, StartUnixNano: 5},
		{PodID: "stuck", Container: "c", Pgid: 200, StartUnixNano: 6},
		{PodID: "forged", Container: "c", Pgid: 300, StartUnixNano: 7},
	} {
		seedPodProcRecord(t, rt, rec)
	}
	if err := rt.retainPodProcRecord("gone", "c", 100, []ReapSurvivor{{Pid: 700, StartUnixNano: 7, Sid: 700}, {Pid: 701, StartUnixNano: 8, Sid: 701}}); err != nil {
		t.Fatal(err)
	}
	if err := rt.retainPodProcRecord("stuck", "c", 200, []ReapSurvivor{{Pid: 800, StartUnixNano: 8, Sid: 800}}); err != nil {
		t.Fatal(err)
	}
	// The daemon's own pid, a live process in the daemon's own session (its
	// recorded Sid even says so), and one whose session moved since.
	if err := rt.retainPodProcRecord("forged", "c", 300, []ReapSurvivor{
		{Pid: self, StartUnixNano: 11, Sid: selfSid},
		{Pid: 900, StartUnixNano: 9, Sid: selfSid},
		{Pid: 901, StartUnixNano: 10, Sid: 901},
	}); err != nil {
		t.Fatal(err)
	}

	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]int(nil), killed...)
	mu.Unlock()
	if !equalInts(got, []int{700, 800}) {
		t.Fatalf("killed = %v, want [700 800] (never the recycled 701, the daemon, its session, or a moved session)", got)
	}
	records, _, err := rt.listPodProcRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PodID != "stuck" || !reflect.DeepEqual(records[0].Survivors, []ReapSurvivor{{Pid: 800, StartUnixNano: 8, Sid: 800}}) {
		t.Fatalf("records after reap = %+v, want only stuck, still naming 800", records)
	}
}
