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
	"strings"
	"testing"
	"time"
)

// wedgedWaiter is an ExitWaiter whose reap for the named pids IGNORES ctx —
// modelling a reaper that does not come back when the shutdown cancel fires (on
// a real node: a kevent/wait4 blocked in the kernel). Every other pid honors
// ctx, as KqueueReaper does at its poll-loop check. The wedged waits are
// released at test cleanup so no goroutine outlives the test.
type wedgedWaiter struct {
	wedged map[int]bool
	stop   chan struct{}
}

func newWedgedWaiter(pids ...int) *wedgedWaiter {
	w := &wedgedWaiter{wedged: make(map[int]bool, len(pids)), stop: make(chan struct{})}
	for _, pid := range pids {
		w.wedged[pid] = true
	}
	return w
}

func (w *wedgedWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	if w.wedged[pid] {
		<-w.stop
		return 0, 0, nil
	}
	<-ctx.Done()
	return 0, 0, ctx.Err()
}

func (w *wedgedWaiter) release() { close(w.stop) }

// closed reports whether ch is closed within a short bound (the supervision
// goroutine still has to be scheduled after the cancel).
func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// TestRuntimeCloseSweepsSupervision pins B40's shutdown sweep: every live pod's
// supervision — the per-container kqueue reapers and the ~1 Hz memory sampler —
// is stopped when the daemon shuts down, not left to be collected by process
// exit. Before this existed, only DeletePod fired those cancels, so a shutdown
// with N live pods left N samplers and N reapers running.
func TestRuntimeCloseSweepsSupervision(t *testing.T) {
	t.Run("every-live-pod-is-swept", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: w})
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal

		// Three pods, one of them memory-limited so a sampler is actually armed
		// (the goroutine with a root SIGKILL in its hand — the one that most has
		// to stop).
		ids := []string{"pod-a", "pod-b", "pod-limited"}
		for _, id := range ids {
			box := hostBinBox(rt, id)
			if id == "pod-limited" {
				box.MemoryLimitBytes = 100 << 20
			}
			mustCreatePod(t, rt, box)
		}

		type snapshot struct {
			supCtx  context.Context
			procs   []<-chan struct{}
			sampler <-chan struct{}
		}
		snaps := make(map[string]snapshot, len(ids))
		for _, id := range ids {
			rt.mu.Lock()
			p := rt.pods[id]
			rt.mu.Unlock()
			if p == nil {
				t.Fatalf("pod %s not registered", id)
			}
			s := snapshot{supCtx: p.supCtx}
			p.mu.Lock()
			for _, cp := range p.containers {
				s.procs = append(s.procs, cp.proc.Done())
			}
			if p.memSampler != nil {
				s.sampler = p.memSampler.Done()
			}
			p.mu.Unlock()
			snaps[id] = s
		}
		if snaps["pod-limited"].sampler == nil {
			t.Fatal("no memory sampler armed for the limited pod: the sweep would not be proving anything about it")
		}

		if err := rt.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		for id, s := range snaps {
			if s.supCtx.Err() == nil {
				t.Errorf("pod %s: supervision context still live after Close", id)
			}
			for i, done := range s.procs {
				if !closed(done) {
					t.Errorf("pod %s: container %d reaper still running after Close", id, i)
				}
			}
			if s.sampler != nil && !closed(s.sampler) {
				t.Errorf("pod %s: memory sampler still running after Close", id)
			}
		}

		// Close stops SUPERVISION, not the workloads: the pod processes outlive
		// the daemon and the startup reap reconciles them, so a shutdown must send
		// no signal and must not forget the pods it is still supervising.
		if got := rec.signals(); len(got) != 0 {
			t.Errorf("Close signalled the pod process groups (%v); a daemon restart must not kill the node's workloads", got)
		}
		rt.mu.Lock()
		registered := len(rt.pods)
		rt.mu.Unlock()
		if registered != len(ids) {
			t.Errorf("registered pods after Close = %d, want %d (the pods are still running)", registered, len(ids))
		}

		// Idempotent: the cancels are, and a second call just re-observes.
		if err := rt.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
		w.release(1001)
		w.release(1002)
		w.release(1003)
	})

	t.Run("a-wedged-pod-does-not-abort-the-sweep", func(t *testing.T) {
		// pids 1001/1002 are the first two the fake spawner serves; those reapers
		// ignore the shutdown cancel, so their waits must time out — without
		// stranding, or silencing, the pods swept around them. TWO of them is the
		// point: a sweep that stops at the first miss reports one and abandons the
		// rest, which is how a shutdown leaves goroutines behind unseen.
		ww := newWedgedWaiter(1001, 1002)
		t.Cleanup(ww.release)
		rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: ww})
		rt.closeGrace = 100 * time.Millisecond // small + real: the timeout arm is fast

		wedged := []string{"pod-wedged-1", "pod-wedged-2"} // pids 1001, 1002
		for _, id := range wedged {
			mustCreatePod(t, rt, hostBinBox(rt, id))
		}
		healthy := []string{"pod-ok-1", "pod-ok-2"}
		for _, id := range healthy {
			mustCreatePod(t, rt, hostBinBox(rt, id))
		}

		err := rt.Close()
		if err == nil {
			t.Fatal("Close: nil error, want the wedged pods' supervision reported")
		}
		if !errors.Is(err, ErrSupervisionNotStopped) {
			t.Errorf("Close error = %v, want ErrSupervisionNotStopped", err)
		}
		for _, id := range wedged {
			if !strings.Contains(err.Error(), id) {
				t.Errorf("Close error = %v, want it to name %s: a sweep that stops at the first miss hides the others", err, id)
			}
		}
		for _, id := range healthy {
			if strings.Contains(err.Error(), id) {
				t.Errorf("Close error = %v, wrongly reports the healthy pod %s", err, id)
			}
			rt.mu.Lock()
			p := rt.pods[id]
			rt.mu.Unlock()
			if p.supCtx.Err() == nil {
				t.Errorf("pod %s: supervision context still live — the sweep stopped at the wedged pod", id)
			}
			p.mu.Lock()
			procs := make([]<-chan struct{}, 0, len(p.containers))
			for _, cp := range p.containers {
				procs = append(procs, cp.proc.Done())
			}
			p.mu.Unlock()
			for i, done := range procs {
				if !closed(done) {
					t.Errorf("pod %s: container %d reaper still running — a wedged pod must not strand its successors", id, i)
				}
			}
		}
	})

	t.Run("no-pods-is-a-no-op", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		if err := rt.Close(); err != nil {
			t.Fatalf("Close on an empty runtime: %v", err)
		}
	})
}

// TestCloseGraceDefault pins the shutdown bound's default, so shrinking it in a
// test cannot hide a production value of zero (an unbounded wait).
func TestCloseGraceDefault(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	if got := rt.closeGraceDuration(); got != defaultCloseGrace {
		t.Errorf("closeGraceDuration = %v, want %v", got, defaultCloseGrace)
	}
	rt.closeGrace = 5 * time.Millisecond
	if got := rt.closeGraceDuration(); got != 5*time.Millisecond {
		t.Errorf("closeGraceDuration = %v, want the field override", got)
	}
}
