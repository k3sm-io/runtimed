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
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestPodProcessCountsCountsVMHelper is the gate: a vm pod's host
// processes are its k3sm-vmhost helper's process group, recorded in the vm
// orphan store rather than the pod-reap ledger, and PodProcessCounts reports
// them exactly as it reports a native pod's: the live members of a group the
// record still proves (leader at the recorded start), a present 0 for a dead
// or unprovable group, and an absent pod when a group cannot be inspected.
func TestPodProcessCountsCountsVMHelper(t *testing.T) {
	type want struct {
		count   uint64
		present bool
	}
	cases := []struct {
		name      string
		native    []podProcRecord
		vm        []sandbox.VMHelperGroup
		vmErr     error
		groups    fakeGroups
		want      map[string]want
		listStats bool // also assert ListPodStats carries the vm pod's count
	}{
		{
			name: "a vm pod with a live helper group reports its live member count",
			vm:   []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 11}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				400: {mem(400, 11), mem(401, 12)},
			}},
			want: map[string]want{"pod-vm": {2, true}},
		},
		{
			name:   "a dead helper counts a present 0",
			vm:     []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 11}},
			groups: fakeGroups{}, // the recorded group is empty
			want:   map[string]want{"pod-vm": {0, true}},
		},
		{
			name: "a recycled pgid counts a present 0",
			vm:   []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 11}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				400: {mem(400, 99), mem(401, 100)},
			}},
			want: map[string]want{"pod-vm": {0, true}},
		},
		{
			// The helper exited and a descendant keeps its group alive: the
			// sweep cannot prove that group is ours, and neither can the count.
			name: "a leaderless helper group counts a present 0",
			vm:   []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 11}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				400: {mem(401, 12)},
			}},
			want: map[string]want{"pod-vm": {0, true}},
		},
		{
			name: "a zero-identity helper record proves no group",
			vm:   []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 0}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				400: {mem(400, 0)},
			}},
			want: map[string]want{"pod-vm": {0, true}},
		},
		{
			name: "a helper group that cannot be inspected leaves the vm pod absent",
			vm:   []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 11}},
			groups: fakeGroups{
				members:     map[int][]supervisor.ProcMember{400: {mem(400, 11)}},
				failInspect: map[int]bool{400: true},
			},
			want: map[string]want{"pod-vm": {0, false}},
		},
		{
			name:   "an unreadable vm store leaves vm pods absent and native pods counted",
			native: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			vmErr:  errors.New("the vm reap store is unreadable"),
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5), mem(101, 6)},
			}},
			want: map[string]want{"pod-a": {2, true}, "pod-vm": {0, false}},
		},
		{
			name:   "native and vm pods are counted side by side",
			native: []podProcRecord{{PodID: "pod-a", Container: "c", Pgid: 100, StartUnixNano: 5}},
			vm:     []sandbox.VMHelperGroup{{PodID: "pod-vm", Pgid: 400, StartUnixNano: 11}},
			groups: fakeGroups{members: map[int][]supervisor.ProcMember{
				100: {mem(100, 5)},
				400: {mem(400, 11), mem(401, 12), mem(402, 13)},
			}},
			want:      map[string]want{"pod-a": {1, true}, "pod-vm": {3, true}},
			listStats: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vmb := &fakeVMBackend{available: true, helperGroups: tc.vm, helperGroupsErr: tc.vmErr}
			deps := Deps{ProcGroup: tc.groups.inspect, VMBackend: vmb}
			if tc.listStats {
				deps.GuestDialer, _ = startFakeGuestAgent(t, &guestStatsAgent{
					bootedPod: "pod-vm",
					sample: &guestv1.StatsResponse{
						Timestamp:  timestamppb.New(time.Unix(1_700_000_000, 0)),
						Containers: []*guestv1.GuestContainerStats{{Container: "app", CpuUsageUsec: 1, MemoryWorkingSetBytes: 1 << 20}},
					},
				})
			}
			rt := newTestRuntime(t, deps)
			for _, rec := range tc.native {
				seedPodProcRecordFull(t, rt, rec)
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
			if !tc.listStats {
				return
			}
			addVMPod(t, rt, "pod-vm", "app")
			resp, err := rt.ListPodStats(context.Background(), &runtimev1.ListPodStatsRequest{PodId: "pod-vm"})
			if err != nil {
				t.Fatalf("ListPodStats: %v", err)
			}
			ps := statsByPodID(resp)["pod-vm"]
			if ps == nil {
				t.Fatalf("vm pod missing from ListPodStats: %+v", resp.GetPodStats())
			}
			if ps.GetProcess() == nil {
				t.Fatal("vm pod's PodStats.process is nil, want its helper group's count")
			}
			if n := ps.GetProcess().GetProcessCount(); n != tc.want["pod-vm"].count {
				t.Errorf("vm pod's process_count = %d, want %d", n, tc.want["pod-vm"].count)
			}
		})
	}
}
