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
	"os"
	"path/filepath"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestPodProcessCountsFromLedger is the runtimed gate: PodProcessCounts
// counts, per pod, the live members of the process groups the pod-reap ledger
// records, through the injected procGroup seam and nothing else. Each case seeds
// ledger records over a fake process-group table.
func TestPodProcessCountsFromLedger(t *testing.T) {
	type want struct {
		count   uint64
		present bool
	}
	cases := []struct {
		name       string
		records    []podProcRecord
		groups     fakeGroups
		quarantine bool // also drop a malformed record file into pod-q's dir
		want       map[string]want
	}{
		{
			name:    "a pod with N live members reports N",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5), mem(101, 6), mem(102, 7)},
			}},
			want: map[string]want{"pod-a": {3, true}},
		},
		{
			name: "every recorded group of a pod is summed",
			records: []podProcRecord{
				{PodID: "pod-a", Container: "c1", Pgid: 100, StartUnixNano: 5},
				{PodID: "pod-a", Container: "c2", Pgid: 200, StartUnixNano: 8},
			},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5), mem(101, 6)},
				200: {mem(200, 8)},
			}},
			want: map[string]want{"pod-a": {3, true}},
		},
		{
			// The group table reports live members only: a member that exited is
			// simply not in it, so it is not counted.
			name:    "a member that exited is not counted",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5), mem(102, 7)}, // 101 exited
			}},
			want: map[string]want{"pod-a": {2, true}},
		},
		{
			name: "two pods are counted separately",
			records: []podProcRecord{
				{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5},
				{PodID: "pod-b", Container: "c", Pgid: 300, StartUnixNano: 9},
			},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5), mem(101, 6)},
				300: {mem(300, 9), mem(301, 9), mem(302, 9), mem(303, 9)},
			}},
			want: map[string]want{"pod-a": {2, true}, "pod-b": {4, true}},
		},
		{
			name:    "a pod with zero live members reports a present 0",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			groups:  fakeGroups{}, // the recorded group is empty
			want:    map[string]want{"pod-a": {0, true}},
		},
		{
			// A pgid the kernel recycled to a new leader is not the pod's group.
			name:    "a recycled pgid is not counted",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 50), mem(101, 51)},
			}},
			want: map[string]want{"pod-a": {0, true}},
		},
		{
			name:    "a zero-identity record proves no group",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 0}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5)},
			}},
			want: map[string]want{"pod-a": {0, true}},
		},
		{
			// A resident shim died; the container it hosted is still the group's
			// member under exactly the recorded child identity, so the group is
			// still the pod's.
			name:    "a leaderless group proven by its recorded child is counted",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5, ShimDir: "/s", ChildPid: 101, ChildStartUnixNano: 6}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(101, 6), mem(102, 7)},
			}},
			want: map[string]want{"pod-a": {2, true}},
		},
		{
			name:    "a leaderless group with no proven member is not counted",
			records: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(102, 7)},
			}},
			want: map[string]want{"pod-a": {0, true}},
		},
		{
			// An uninspectable group makes the pod's count unknown, never a
			// partial sum.
			name: "a pod with an uninspectable group is absent",
			records: []podProcRecord{
				{PodID: "pod-a", Container: "c1", Pgid: 100, StartUnixNano: 5},
				{PodID: "pod-a", Container: "c2", Pgid: 200, StartUnixNano: 8},
				{PodID: "pod-b", Container: "c", Pgid: 300, StartUnixNano: 9},
			},
			groups: fakeGroups{
				members:     map[int][]supervisor.ProcMember{100: {mem(100, 5)}, 300: {mem(300, 9)}},
				failInspect: map[int]bool{200: true},
			},
			want: map[string]want{"pod-a": {0, false}, "pod-b": {1, true}},
		},
		{
			name:       "a quarantined record is skipped",
			records:    []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			groups:     fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}}},
			quarantine: true,
			want:       map[string]want{"pod-a": {1, true}, "pod-q": {0, false}},
		},
		{
			name:    "a pod with no record is absent",
			records: nil,
			groups:  fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5)}}},
			want:    map[string]want{"pod-a": {0, false}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{ProcGroup: tc.groups.inspect})
			for _, rec := range tc.records {
				seedPodProcRecordFull(t, rt, rec)
			}
			if tc.quarantine {
				dir, err := rt.podReapDir("pod-q")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "1.json"), []byte(`{"podId":"pod-q","pgid":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := rt.PodProcessCounts()
			if err != nil {
				t.Fatalf("PodProcessCounts: %v", err)
			}
			for pod, w := range tc.want {
				n, ok := got[pod]
				if ok != w.present || n != w.count {
					t.Errorf("%s = (%d, present %v), want (%d, present %v)", pod, n, ok, w.count, w.present)
				}
			}
			for pod := range got {
				if _, named := tc.want[pod]; !named {
					t.Errorf("unexpected pod %s in counts %v", pod, got)
				}
			}
		})
	}
}

// seedPodProcRecordFull writes rec to the ledger verbatim, child identity
// included, through the ledger's own writer.
func seedPodProcRecordFull(t *testing.T, rt *Runtime, rec podProcRecord) {
	t.Helper()
	if err := rt.writePodProcRecord(rec); err != nil {
		t.Fatal(err)
	}
}

// TestListPodStatsCarriesProcessCount pins the wire half: ListPodStats
// carries each pod's ledger-derived process count in PodStats.process, a
// present message even when the count is 0.
func TestListPodStatsCarriesProcessCount(t *testing.T) {
	w := newBlockingWaiter()
	ff := runtimeFakeFootprinter{bytes: 4 << 20}
	// testDeps records every leader with start 1 (its ProcStartTime fake). The
	// fake spawner's first two pids are the pods' process groups: pod-a's has
	// three live members, pod-b's is empty.
	groups := fakeGroups{members: map[int][]supervisor.ProcMember{
		1001: {mem(1001, 1), mem(5001, 2), mem(5002, 3)},
	}}
	rt := newTestRuntime(t, Deps{Waiter: w, Footprinter: ff, ProcGroup: groups.inspect})
	rt.cfg.SampleInterval = 5 * time.Millisecond
	rt.signalGroup = (&recordingSignalGroup{}).signal

	mustCreatePod(t, rt, hostBinBox(rt, "pod-a"))
	mustCreatePod(t, rt, hostBinBox(rt, "pod-b"))

	var resp *runtimev1.ListPodStatsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ = rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{})
		if len(resp.GetPodStats()) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(resp.GetPodStats()) != 2 {
		t.Fatalf("ListPodStats = %d pods, want 2", len(resp.GetPodStats()))
	}
	byID := map[string]*runtimev1.PodStats{}
	for _, ps := range resp.GetPodStats() {
		byID[ps.GetPodId()] = ps
	}
	for id, want := range map[string]uint64{"pod-a": 3, "pod-b": 0} {
		ps := byID[id]
		if ps.GetProcess() == nil {
			t.Fatalf("%s PodStats.process is nil, want a present count", id)
		}
		if got := ps.GetProcess().GetProcessCount(); got != want {
			t.Errorf("%s process_count = %d, want %d", id, got, want)
		}
	}

	w.release(1001)
	w.release(1002)
}
