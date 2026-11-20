/*
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
*/

package runtime

import (
	"context"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"k3sm.io/runtimed/pkg/supervisor"
)

// policyAnswer is a fake process's Seatbelt policy: whether it is sandboxed,
// whether it allows a write to the pod's grant and to the canary, and whether
// each query fails.
type policyAnswer struct {
	sandboxed, grant, canary bool
	grantErr, canaryErr      bool
}

func fakeProbe(id podIdentity, answers map[int]policyAnswer) podPolicyProbe {
	return func(pid int, path string) (bool, bool, bool) {
		a, known := answers[pid]
		if !known {
			return false, false, false
		}
		switch path {
		case id.grant:
			return a.sandboxed, a.grant, !a.grantErr
		case id.canary:
			return a.sandboxed, a.canary, !a.canaryErr
		}
		// Any other path: a pod policy denies it, an unsandboxed process may.
		return a.sandboxed, !a.sandboxed, true
	}
}

// TestPodIdentityHolds pins the identity rule case by case: only a sandboxed
// process whose policy allows the pod's rootfs AND denies the pods root is the
// pod's, and every doubt answers "not the pod's".
func TestPodIdentityHolds(t *testing.T) {
	id := podIdentity{grant: "/r/pods/a/rootfs", canary: "/r/pods"}
	for _, tc := range []struct {
		name string
		a    policyAnswer
		pid  int
		want bool
	}{
		{"the pod's process", policyAnswer{sandboxed: true, grant: true}, 10, true},
		{"unsandboxed same-user process (allows everything)", policyAnswer{grant: true, canary: true}, 10, false},
		{"permissive sandbox (allows the pods root)", policyAnswer{sandboxed: true, grant: true, canary: true}, 10, false},
		{"another pod's process (denied this rootfs)", policyAnswer{sandboxed: true}, 10, false},
		{"grant query failed", policyAnswer{sandboxed: true, grant: true, grantErr: true}, 10, false},
		{"canary query failed", policyAnswer{sandboxed: true, grant: true, canaryErr: true}, 10, false},
		{"launchd", policyAnswer{sandboxed: true, grant: true}, 1, false},
		{"pid zero", policyAnswer{sandboxed: true, grant: true}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := fakeProbe(id, map[int]policyAnswer{tc.pid: tc.a})
			if got := id.holds(probe, tc.pid); got != tc.want {
				t.Errorf("holds = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("degenerate identities never hold", func(t *testing.T) {
		probe := func(int, string) (bool, bool, bool) { return true, true, true }
		for _, bad := range []podIdentity{{}, {grant: "/x"}, {canary: "/x"}, {grant: "/x", canary: "/x"}} {
			if bad.holds(probe, 10) {
				t.Errorf("%+v holds", bad)
			}
		}
		if id.holds(nil, 10) {
			t.Error("a nil probe holds")
		}
	})
}

func TestStartupSweepPodIDs(t *testing.T) {
	records := []podProcRecord{
		{PodID: "a", Pgid: 1}, {PodID: "b", Pgid: 2}, {PodID: "a", Pgid: 3}, {PodID: ""}, {PodID: "c", Pgid: 4},
	}
	got := startupSweepPodIDs(records, map[string]bool{"b": true})
	if want := []string{"a", "c"}; !slices.Equal(got, want) {
		t.Errorf("startupSweepPodIDs = %v, want %v (adopted b skipped, a once, empty id dropped)", got, want)
	}
}

// fakeHost is a process table whose processes die on the signals the test says.
type fakeHost struct {
	mu      sync.Mutex
	procs   map[int]int64 // pid -> start time
	ignores map[int]bool  // ignores SIGTERM
	sent    []pidSignal
}

type pidSignal struct {
	pid int
	sig syscall.Signal
}

func (h *fakeHost) table() ([]supervisor.ProcEntry, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]supervisor.ProcEntry, 0, len(h.procs))
	for pid, st := range h.procs {
		out = append(out, supervisor.ProcEntry{Pid: pid, StartUnixNano: st})
	}
	return out, true
}

func (h *fakeHost) start(pid int) (int64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.procs[pid]
	return st, ok
}

func (h *fakeHost) kill(pid int, sig syscall.Signal) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent = append(h.sent, pidSignal{pid, sig})
	if sig == syscall.SIGKILL || !h.ignores[pid] {
		delete(h.procs, pid)
	}
	return nil
}

func (h *fakeHost) signals() []pidSignal {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.sent)
}

// sweepRig is a runtime whose sweep sees only fakeHost, with the pod's rootfs
// on disk so its identity can be derived.
func sweepRig(t *testing.T, podID string, h *fakeHost, answers func(podIdentity) map[int]policyAnswer) (*Runtime, podIdentity) {
	t.Helper()
	rt := newTestRuntime(t, Deps{
		Spawner:       &mcProbeSpawner{},
		Waiter:        newBlockingWaiter(),
		ProcTable:     h.table,
		ProcStartTime: h.start,
		KillProcess:   h.kill,
	})
	if err := os.MkdirAll(derivedRootfs(t, rt, podID), 0o755); err != nil {
		t.Fatal(err)
	}
	id, ok := rt.podIdentityFor(podID)
	if !ok {
		t.Fatal("podIdentityFor: no identity for a pod whose rootfs exists")
	}
	rt.policyProbe = fakeProbe(id, answers(id))
	return rt, id
}

// podMix: 100 and 101 are the pod's (101 ignores SIGTERM), 200 is another
// pod's, 300 is an unsandboxed same-user process, 400 sits under a permissive
// sandbox.
func podMix(podIdentity) map[int]policyAnswer {
	return map[int]policyAnswer{
		100: {sandboxed: true, grant: true},
		101: {sandboxed: true, grant: true},
		200: {sandboxed: true},
		300: {grant: true, canary: true},
		400: {sandboxed: true, grant: true, canary: true},
	}
}

func newMixHost() *fakeHost {
	return &fakeHost{
		procs:   map[int]int64{100: 10, 101: 11, 200: 20, 300: 30, 400: 40},
		ignores: map[int]bool{101: true},
	}
}

func alive(h *fakeHost, pids ...int) []int {
	var out []int
	for _, p := range pids {
		if _, ok := h.start(p); ok {
			out = append(out, p)
		}
	}
	return out
}

func TestSweepPodDescendantsKillsOnlyThePods(t *testing.T) {
	t.Run("grace escalates SIGTERM to SIGKILL for an ignorer only", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newMixHost()
			rt, _ := sweepRig(t, "pod-sw", h, podMix)
			if n := rt.sweepPodDescendants(context.Background(), "pod-sw", podSweep{grace: time.Second}); n != 2 {
				t.Errorf("signalled %d processes, want 2", n)
			}
			if got := alive(h, 100, 101); len(got) != 0 {
				t.Errorf("pod processes %v survived", got)
			}
			if got := alive(h, 200, 300, 400); len(got) != 3 {
				t.Errorf("only %v of the non-pod processes 200, 300, 400 survived", got)
			}
			want := []pidSignal{{100, syscall.SIGTERM}, {101, syscall.SIGTERM}, {101, syscall.SIGKILL}}
			got := h.signals()
			slices.SortFunc(got[:2], func(a, b pidSignal) int { return a.pid - b.pid })
			if !slices.Equal(got, want) {
				t.Errorf("signals = %v, want %v", got, want)
			}
		})
	})
	t.Run("grace zero is SIGKILL at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newMixHost()
			rt, _ := sweepRig(t, "pod-sw0", h, podMix)
			rt.sweepPodDescendants(context.Background(), "pod-sw0", podSweep{})
			for _, s := range h.signals() {
				if s.sig != syscall.SIGKILL || (s.pid != 100 && s.pid != 101) {
					t.Errorf("unexpected signal %v", s)
				}
			}
			if got := alive(h, 200, 300, 400); len(got) != 3 {
				t.Errorf("only %v of the non-pod processes survived", got)
			}
		})
	})
	t.Run("bornBefore spares a process started after the daemon", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newMixHost()
			rt, _ := sweepRig(t, "pod-swb", h, podMix)
			rt.sweepPodDescendants(context.Background(), "pod-swb", podSweep{bornBefore: 11})
			if got := alive(h, 100, 101); !slices.Equal(got, []int{101}) {
				t.Errorf("alive pod processes = %v, want [101] (started at the cutoff)", got)
			}
		})
	})
	t.Run("a pod id registered again aborts the sweep", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newMixHost()
			rt, _ := sweepRig(t, "pod-swr", h, podMix)
			rt.sweepPodDescendants(context.Background(), "pod-swr", podSweep{mayProceed: func() bool { return false }})
			if s := h.signals(); len(s) != 0 {
				t.Errorf("signals %v sent although the sweep may not proceed", s)
			}
		})
	})
	t.Run("a reused pid is not signalled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newMixHost()
			rt, id := sweepRig(t, "pod-swp", h, podMix)
			// The member was read as pid 100 started at 9; pid 100 now names
			// the instance started at 10, so it is a different process.
			if rt.signalMember(id, podMember{pid: 100, start: 9}, syscall.SIGKILL) {
				t.Error("signalMember signalled a pid whose start time changed")
			}
			if s := h.signals(); len(s) != 0 {
				t.Errorf("signals %v sent to a reused pid", s)
			}
		})
	})
	t.Run("a pod without a rootfs is not swept", func(t *testing.T) {
		h := newMixHost()
		rt, _ := sweepRig(t, "pod-swn", h, podMix)
		if n := rt.sweepPodDescendants(context.Background(), "pod-gone", podSweep{}); n != 0 || len(h.signals()) != 0 {
			t.Errorf("swept %d processes of a pod with no rootfs (signals %v)", n, h.signals())
		}
	})
	t.Run("an unwired probe turns the sweep off", func(t *testing.T) {
		h := newMixHost()
		rt, _ := sweepRig(t, "pod-swo", h, podMix)
		rt.policyProbe = nil
		if n := rt.sweepPodDescendants(context.Background(), "pod-swo", podSweep{}); n != 0 || len(h.signals()) != 0 {
			t.Errorf("an unwired sweep signalled %d processes", n)
		}
	})
}
