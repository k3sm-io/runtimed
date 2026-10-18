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
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestAttachCarriesContainerStartedAt pins a re-attached container's
// running.startedAt to the container's real start, for both backends: a pod
// that survived a daemon restart must not read as restarted.
//
// The native row reads the start from the podreap record. The vm rows drive
// the guest's replay through the fold exactly as the event stream does: the
// adopting daemon seeds the start its predecessor persisted beside the helper
// record, and the replay of the same run (same guest pid) keeps it. A helper
// with nothing persisted (one spawned before the starts were recorded) reports
// the replay time, as every daemon did before, and persists it so the next
// restart keeps it.
func TestAttachCarriesContainerStartedAt(t *testing.T) {
	realStart := time.Unix(1792284512, 656831000)
	const guestPid = 7

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{name: "a native record with start T reports T", run: func(t *testing.T) {
			const pgid = 100
			waiter := unknownExitWaiter{newBlockingWaiter()}
			t.Cleanup(func() { waiter.release(pgid) })
			start := realStart.UnixNano()
			rt := newTestRuntime(t, Deps{
				ProcGroup:     fakeGroups{members: map[int][]supervisor.ProcMember{pgid: {mem(pgid, start)}}}.inspect,
				ProcStartTime: func(int) (int64, bool) { return start, true },
				AdoptedWaiter: waiter,
				SignalGroup:   func(int, os.Signal) error { return nil },
			})
			seedPodProcRecord(t, rt, attachableRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: pgid, StartUnixNano: start}))
			st, err := rt.AttachPod(context.Background(), hostBinBox(rt, "p1"))
			if err != nil {
				t.Fatalf("AttachPod: %v", err)
			}
			assertStartedAt(t, st, "main", realStart)
		}},
		{name: "a vm record with start T reports T after the guest's replay", run: func(t *testing.T) {
			rt, vmb, p := attachedVMPod(t, &sandbox.VMContainerStart{Pid: guestPid, StartUnixNano: realStart.UnixNano()})
			replayStarted(rt, p, guestPid)
			assertStartedAt(t, rt.podStatus(p), "main", realStart)
			if got := vmb.VMContainerStarts(p.box.GetPodId())["main"]; got.StartUnixNano != realStart.UnixNano() || got.Pid != guestPid {
				t.Fatalf("persisted start = %+v, want the seeded one unchanged", got)
			}
		}},
		{name: "a vm record with no start reports the replay time and persists it", run: func(t *testing.T) {
			rt, vmb, p := attachedVMPod(t, nil)
			before := time.Now()
			replayStarted(rt, p, guestPid)
			after := time.Now()
			got := startedAtOf(t, rt.podStatus(p), "main")
			if got.Before(before) || got.After(after) {
				t.Fatalf("started_at = %v, want the replay time in [%v, %v] (the compatibility window)", got, before, after)
			}
			if rec := vmb.VMContainerStarts(p.box.GetPodId())["main"]; rec.StartUnixNano != got.UnixNano() || rec.Pid != guestPid {
				t.Fatalf("persisted start = %+v, want {pid %d, %d}: the next restart must keep this start", rec, guestPid, got.UnixNano())
			}
		}},
		{name: "a seed after now is clamped to the replay time and persisted", run: func(t *testing.T) {
			future := time.Now().Add(time.Hour)
			rt, vmb, p := attachedVMPod(t, &sandbox.VMContainerStart{Pid: guestPid, StartUnixNano: future.UnixNano()})
			before := time.Now()
			replayStarted(rt, p, guestPid)
			after := time.Now()
			got := startedAtOf(t, rt.podStatus(p), "main")
			if got.Before(before) || got.After(after) {
				t.Fatalf("started_at = %v, want the replay time in [%v, %v]: a host clock step back must never publish a future start", got, before, after)
			}
			if rec := vmb.VMContainerStarts(p.box.GetPodId())["main"]; rec.StartUnixNano != got.UnixNano() {
				t.Fatalf("persisted start = %+v, want the clamped %d", rec, got.UnixNano())
			}
		}},
		{name: "an event replay after the attach keeps the start", run: func(t *testing.T) {
			rt, _, p := attachedVMPod(t, &sandbox.VMContainerStart{Pid: guestPid, StartUnixNano: realStart.UnixNano()})
			replayStarted(rt, p, guestPid)
			time.Sleep(5 * time.Millisecond)
			replayStarted(rt, p, guestPid) // a resubscribe replays the same run
			assertStartedAt(t, rt.podStatus(p), "main", realStart)

			rt2, _, p2 := attachedVMPod(t, nil)
			replayStarted(rt2, p2, guestPid)
			first := startedAtOf(t, rt2.podStatus(p2), "main")
			time.Sleep(5 * time.Millisecond)
			replayStarted(rt2, p2, guestPid)
			assertStartedAt(t, rt2.podStatus(p2), "main", first)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// attachedVMPod attaches a vm pod over a fake backend that holds seed as the
// persisted start of its one container "main" (nil: nothing persisted).
func attachedVMPod(t *testing.T, seed *sandbox.VMContainerStart) (*Runtime, *fakeVMBackend, *pod) {
	t.Helper()
	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{
		VMBackend: vmb,
		Network:   &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
		Resolver:  fakeResolver{},
	})
	const podID = "pod-vm-attach-start"
	if seed != nil {
		if err := vmb.RecordVMContainerStart(podID, "main", *seed); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rt.AttachPod(context.Background(), vmPodBox(rt, podID, 0)); err != nil {
		t.Fatalf("AttachPod: %v", err)
	}
	p, ok := rt.lookupPod(podID)
	if !ok {
		t.Fatal("the attached vm pod is not registered")
	}
	return rt, vmb, p
}

// replayStarted folds the guest's started event for "main", as the guest's
// ContainerEvents replay delivers it.
func replayStarted(rt *Runtime, p *pod, pid int32) {
	rt.applyGuestContainerEvent(p, &guestv1.ContainerEvent{
		Container: "main",
		Started:   &guestv1.ContainerStarted{Pid: pid},
	})
}

func startedAtOf(t *testing.T, st *runtimev1.PodStatus, name string) time.Time {
	t.Helper()
	for _, cs := range st.GetContainerStatuses() {
		if cs.GetName() != name {
			continue
		}
		at := cs.GetState().GetRunning().GetStartedAt()
		if at == nil {
			t.Fatalf("container %s state = %+v, want running with a start", name, cs.GetState())
		}
		return at.AsTime()
	}
	t.Fatalf("no status for container %s in %+v", name, st.GetContainerStatuses())
	return time.Time{}
}

func assertStartedAt(t *testing.T, st *runtimev1.PodStatus, name string, want time.Time) {
	t.Helper()
	if got := startedAtOf(t, st, name); !got.Equal(want) {
		t.Fatalf("container %s started_at = %v, want %v", name, got, want)
	}
}
