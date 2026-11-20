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
	"slices"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// policyAnswer is a fake process's Seatbelt policy: whether it is sandboxed,
// whether it allows a stat of the pod's dir, a stat of the reap store root and
// a write to the pods root, and which query fails.
type policyAnswer struct {
	sandboxed, anchor, statCanary, writeCanary bool
	failOn                                     string
}

// The four policies the identity must tell apart.
var (
	podPolicy        = policyAnswer{sandboxed: true, anchor: true}
	otherPodPolicy   = policyAnswer{sandboxed: true}
	unsandboxed      = policyAnswer{anchor: true, statCanary: true, writeCanary: true}
	permissivePolicy = policyAnswer{sandboxed: true, anchor: true, statCanary: true, writeCanary: true}
	// appSandboxPolicy stats the whole filesystem and writes none of it.
	appSandboxPolicy = policyAnswer{sandboxed: true, anchor: true, statCanary: true}
)

func fakeProbe(id podIdentity, answers map[int]policyAnswer) podPolicyProbe {
	return func(pid int, op sandbox.PolicyOp, path string) (bool, bool, bool) {
		a, known := answers[pid]
		if !known {
			return false, false, false
		}
		switch {
		case path == id.anchor && op == sandbox.PolicyReadMetadata:
			return a.sandboxed, a.anchor, a.failOn != "anchor"
		case path == id.statCanary && op == sandbox.PolicyReadMetadata:
			return a.sandboxed, a.statCanary, a.failOn != "statCanary"
		case path == id.writeCanary && op == sandbox.PolicyWriteData:
			return a.sandboxed, a.writeCanary, a.failOn != "writeCanary"
		}
		// The identity asks nothing else; an unexpected query fails.
		return false, false, false
	}
}

// TestPodIdentityHolds pins the identity rule case by case: only a sandboxed
// process whose policy allows a stat of the pod's own dir AND denies both
// canaries is the pod's, and every doubt answers "not the pod's".
func TestPodIdentityHolds(t *testing.T) {
	id := podIdentity{anchor: "/r/pods/a", statCanary: "/r/podreap", writeCanary: "/r/pods"}
	withFail := func(a policyAnswer, on string) policyAnswer { a.failOn = on; return a }
	for _, tc := range []struct {
		name string
		a    policyAnswer
		pid  int
		want bool
	}{
		{"the pod's process", podPolicy, 10, true},
		{"unsandboxed same-user process (allows everything)", unsandboxed, 10, false},
		{"permissive sandbox (allows everything)", permissivePolicy, 10, false},
		{"app sandbox (stats everything, writes nothing here)", appSandboxPolicy, 10, false},
		{"sandbox that stats only the pod dir but may write the pods root", policyAnswer{sandboxed: true, anchor: true, writeCanary: true}, 10, false},
		{"another pod's process (denied this pod dir)", otherPodPolicy, 10, false},
		{"anchor query failed", withFail(podPolicy, "anchor"), 10, false},
		{"stat canary query failed", withFail(podPolicy, "statCanary"), 10, false},
		{"write canary query failed", withFail(podPolicy, "writeCanary"), 10, false},
		{"launchd", podPolicy, 1, false},
		{"pid zero", podPolicy, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := fakeProbe(id, map[int]policyAnswer{tc.pid: tc.a})
			if got := id.holds(probe, tc.pid); got != tc.want {
				t.Errorf("holds = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("degenerate identities never hold", func(t *testing.T) {
		// A probe that would vouch for anything: allowed where the identity
		// wants allowed, denied where it wants denied.
		probe := func(_ int, op sandbox.PolicyOp, path string) (bool, bool, bool) {
			return true, op == sandbox.PolicyReadMetadata && path == "/x", true
		}
		for _, bad := range []podIdentity{
			{}, {anchor: "/x"}, {anchor: "/x", statCanary: "/y"},
			{anchor: "/x", statCanary: "/x", writeCanary: "/z"},
			{anchor: "/x", statCanary: "/y", writeCanary: "/x"},
			{anchor: "/x", statCanary: "/y", writeCanary: "/y"},
		} {
			if bad.holds(probe, 10) {
				t.Errorf("%+v holds", bad)
			}
		}
		if id.holds(nil, 10) {
			t.Error("a nil probe holds")
		}
	})
}

// TestPodIdentityNamesOnlyNodesAPodCannotReplace: the probe resolves symlinks,
// so the identity must name the pod dir, the reap store root and the pods
// root, and never the pod's rootfs, which the pod may replace with a link.
func TestPodIdentityNamesOnlyNodesAPodCannotReplace(t *testing.T) {
	rt := newTestRuntime(t, Deps{Spawner: &mcProbeSpawner{}, Waiter: newBlockingWaiter()})
	const podID = "pod-idn"
	rootfs := derivedRootfs(t, rt, podID)
	if _, ok := rt.podIdentityFor(podID); ok {
		t.Fatal("an identity was derived for a pod with no dir")
	}
	for _, dir := range []string{rootfs, rt.podReapRoot()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id, ok := rt.podIdentityFor(podID)
	if !ok {
		t.Fatal("no identity for a pod whose dir exists")
	}
	want := podIdentity{anchor: filepath.Dir(rootfs), statCanary: rt.podReapRoot(), writeCanary: rt.cache.PodsRoot()}
	if id != want {
		t.Errorf("identity = %+v, want %+v", id, want)
	}
	// A pod that replaced its rootfs with a link to another pod's changes
	// nothing the identity names.
	if err := os.Remove(rootfs); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), rootfs); err != nil {
		t.Fatal(err)
	}
	if again, ok := rt.podIdentityFor(podID); !ok || again != want {
		t.Errorf("identity after the rootfs became a link = %+v (ok %v), want %+v", again, ok, want)
	}
	// A pod dir that is itself a link is refused.
	if err := os.RemoveAll(filepath.Dir(rootfs)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Dir(rootfs)); err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.podIdentityFor(podID); ok {
		t.Error("an identity was derived through a symlinked pod dir")
	}
	if _, ok := rt.podIdentityFor("../escape"); ok {
		t.Error("an identity was derived for an illegal pod id")
	}
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
	for _, dir := range []string{derivedRootfs(t, rt, podID), rt.podReapRoot()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id, ok := rt.podIdentityFor(podID)
	if !ok {
		t.Fatal("podIdentityFor: no identity for a pod whose dir exists")
	}
	rt.policyProbe = fakeProbe(id, answers(id))
	return rt, id
}

// podMix: 100 and 101 are the pod's (101 ignores SIGTERM), 200 is another
// pod's, 300 is an unsandboxed same-user process, 400 sits under a permissive
// sandbox, 500 under an app sandbox.
func podMix(podIdentity) map[int]policyAnswer {
	return map[int]policyAnswer{
		100: podPolicy,
		101: podPolicy,
		200: otherPodPolicy,
		300: unsandboxed,
		400: permissivePolicy,
		500: appSandboxPolicy,
	}
}

func newMixHost() *fakeHost {
	return &fakeHost{
		procs:   map[int]int64{100: 10, 101: 11, 200: 20, 300: 30, 400: 40, 500: 50},
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
			if got := alive(h, 200, 300, 400, 500); len(got) != 4 {
				t.Errorf("only %v of the non-pod processes 200, 300, 400, 500 survived", got)
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
			if got := alive(h, 200, 300, 400, 500); len(got) != 4 {
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
	t.Run("a pod without a dir is not swept", func(t *testing.T) {
		h := newMixHost()
		rt, _ := sweepRig(t, "pod-swn", h, podMix)
		if n := rt.sweepPodDescendants(context.Background(), "pod-gone", podSweep{}); n != 0 || len(h.signals()) != 0 {
			t.Errorf("swept %d processes of a pod with no dir (signals %v)", n, h.signals())
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
