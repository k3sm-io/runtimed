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
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/supervisor"
)

// guardProcTable is a fake process-group table the create guard reads
// through the procGroup seam.
type guardProcTable struct {
	mu     sync.Mutex
	groups map[int][]supervisor.ProcMember
}

func (g *guardProcTable) set(pgid int, members ...supervisor.ProcMember) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.groups[pgid] = members
}

func (g *guardProcTable) procGroup(pgid int) ([]supervisor.ProcMember, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]supervisor.ProcMember(nil), g.groups[pgid]...), true
}

// guardNetwork counts the pod network setups still in place.
type guardNetwork struct {
	mu    sync.Mutex
	setup map[string]int
}

func (n *guardNetwork) Setup(_ context.Context, podID string) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.setup[podID]++
	return "10.1.2.3", nil
}

func (n *guardNetwork) Teardown(podID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.setup, podID)
	return nil
}

func (n *guardNetwork) count(podID string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.setup[podID]
}

type guardFixture struct {
	rt     *Runtime
	procs  *guardProcTable
	net    *guardNetwork
	sigs   *recordingSignalGroup
	marker string
}

func newGuardFixture(t *testing.T, podID string) *guardFixture {
	t.Helper()
	f := &guardFixture{
		procs: &guardProcTable{groups: map[int][]supervisor.ProcMember{}},
		net:   &guardNetwork{setup: map[string]int{}},
		sigs:  &recordingSignalGroup{},
	}
	f.rt = newTestRuntime(t, Deps{Network: f.net, ProcGroup: f.procs.procGroup, SignalGroup: f.sigs.signal})
	podDir, err := f.rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	f.marker = filepath.Join(rootfs, "survivor-marker")
	if err := os.WriteFile(f.marker, []byte("live"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *guardFixture) create(podID string) (*runtimev1.CreatePodResponse, error) {
	return f.rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(f.rt, podID)})
}

// assertRefused checks a refusal left everything about the pod as it was.
func (f *guardFixture) assertRefused(t *testing.T, podID string, resp *runtimev1.CreatePodResponse, err error) {
	t.Helper()
	if !errors.Is(err, ErrPodGroupStillAlive) {
		t.Fatalf("CreatePod = (%v, %v), want ErrPodGroupStillAlive", resp, err)
	}
	if _, ok := f.rt.lookupPod(podID); ok {
		t.Error("the refused pod was registered")
	}
	if b, err := os.ReadFile(f.marker); err != nil || string(b) != "live" {
		t.Errorf("rootfs marker = (%q, %v), want it intact", b, err)
	}
	if n := f.net.count(podID); n != 0 {
		t.Errorf("%d network setups remain for the refused pod", n)
	}
	f.sigs.mu.Lock()
	n := len(f.sigs.sent)
	f.sigs.mu.Unlock()
	if n != 0 {
		t.Errorf("%d signals sent; the guard must never signal", n)
	}
}

func assertCreated(t *testing.T, resp *runtimev1.CreatePodResponse, err error) {
	t.Helper()
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod = (%v, %v), want success", resp, err)
	}
}

// TestCreatePodRefusesBesideALiveNativeGroup pins that a create for a pod id
// whose recorded process group an earlier run left alive is refused before
// anything about the pod is touched, and is re-evaluated on every create.
func TestCreatePodRefusesBesideALiveNativeGroup(t *testing.T) {
	const (
		podID = "pod-survivor"
		pgid  = 4242
		start = int64(777)
	)
	seed := func(t *testing.T, f *guardFixture, rec podProcRecord) {
		t.Helper()
		rec.PodID = podID
		if rec.Container == "" {
			rec.Container = "main"
		}
		if err := f.rt.writePodProcRecord(rec); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("live leader with the recorded start refuses, then the group empties and the create succeeds", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		seed(t, f, podProcRecord{Pgid: pgid, StartUnixNano: start})
		f.procs.set(pgid, supervisor.ProcMember{Pid: pgid, StartUnixNano: start}, supervisor.ProcMember{Pid: pgid + 1, StartUnixNano: start + 1})
		resp, err := f.create(podID)
		f.assertRefused(t, podID, resp, err)

		// Re-evaluated on every create: still alive, still refused.
		resp, err = f.create(podID)
		f.assertRefused(t, podID, resp, err)

		f.procs.set(pgid)
		resp, err = f.create(podID)
		assertCreated(t, resp, err)
	})

	t.Run("recycled pgid allows", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		seed(t, f, podProcRecord{Pgid: pgid, StartUnixNano: start})
		f.procs.set(pgid, supervisor.ProcMember{Pid: pgid, StartUnixNano: start + 99})
		resp, err := f.create(podID)
		assertCreated(t, resp, err)
	})

	t.Run("recycled pgid with the recorded container alive refuses", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		seed(t, f, podProcRecord{Pgid: pgid, StartUnixNano: start, ShimDir: "/nonexistent/shim", ChildPid: pgid + 5, ChildStartUnixNano: start + 5})
		f.procs.set(pgid,
			supervisor.ProcMember{Pid: pgid, StartUnixNano: start + 99},
			supervisor.ProcMember{Pid: pgid + 5, StartUnixNano: start + 5})
		resp, err := f.create(podID)
		f.assertRefused(t, podID, resp, err)
	})

	t.Run("leaderless non-empty group refuses", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		seed(t, f, podProcRecord{Pgid: pgid, StartUnixNano: start})
		f.procs.set(pgid, supervisor.ProcMember{Pid: pgid + 3, StartUnixNano: start + 3})
		resp, err := f.create(podID)
		f.assertRefused(t, podID, resp, err)

		f.procs.set(pgid)
		resp, err = f.create(podID)
		assertCreated(t, resp, err)
	})

	t.Run("unexpired recorded survivor of an empty group refuses", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		// testDeps' procStart reports start 1 for every pid.
		seed(t, f, podProcRecord{Pgid: pgid, StartUnixNano: start, Survivors: []ReapSurvivor{{Pid: pgid + 7, StartUnixNano: 1, Sid: pgid}}})
		resp, err := f.create(podID)
		f.assertRefused(t, podID, resp, err)
	})

	t.Run("expired recorded survivor of an empty group allows", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		seed(t, f, podProcRecord{Pgid: pgid, StartUnixNano: start, Survivors: []ReapSurvivor{{Pid: pgid + 7, StartUnixNano: 2, Sid: pgid}}})
		resp, err := f.create(podID)
		assertCreated(t, resp, err)
	})

	t.Run("owned pod does not refuse", func(t *testing.T) {
		f := newGuardFixture(t, podID)
		resp, err := f.create(podID)
		assertCreated(t, resp, err)
		p, ok := f.rt.lookupPod(podID)
		if !ok {
			t.Fatal("created pod not registered")
		}
		pgids := p.containerPgids()
		if len(pgids) == 0 {
			t.Fatal("created pod owns no process group")
		}
		// The pod's own record names its group, and the group is alive under
		// the recorded leader start (testDeps' procStart reports 1).
		for _, g := range pgids {
			f.procs.set(g, supervisor.ProcMember{Pid: g, StartUnixNano: 1})
		}
		if has, ok := f.rt.podHasReapRecord(podID); !has || !ok {
			t.Fatalf("podHasReapRecord = (%v, %v), want the owned pod's record", has, ok)
		}
		if err := f.rt.refuseBesideLiveNativeGroup(podID); err != nil {
			t.Fatalf("guard refused an owned pod: %v", err)
		}
		resp, err = f.create(podID)
		assertCreated(t, resp, err)
	})

	t.Run("unreadable record directory refuses for this id only", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("a mode-000 directory is readable by root")
		}
		const other = "pod-other"
		f := newGuardFixture(t, podID)
		unreadable := func(id string) {
			t.Helper()
			dir, err := f.rt.podReapDir(id)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		}
		unreadable(podID)
		unreadable(other)
		resp, err := f.create(podID)
		f.assertRefused(t, podID, resp, err)

		// Neither unreadable directory is this id's: the create proceeds.
		third, err := f.create("pod-third")
		assertCreated(t, third, err)
	})
}
