//go:build darwin && cgo

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

package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// zombieReapBound is how long these tests wait for an abandoned child to leave
// the process table. reapDetached's backoff caps at detachedReapMaxPoll, so a
// SIGKILLed child is collected within roughly one of those; the bound is set far
// above that so a failure means the BEHAVIOUR is wrong (nothing ever wait4s the
// child) and not that a loaded machine scheduled a goroutine late.
const zombieReapBound = 15 * time.Second

// startSleeper spawns a real long-lived child through the PRODUCTION
// PosixSpawner + KqueueReaper under ctx, returning the Process and its pid.
//
// It is a real spawn in the unit tier for the same reason TestSpawnHonorsWorkingDir
// is: the subject is what the KERNEL does with a process this daemon forked, and
// a reaper that abandons its child is indistinguishable from a correct one at
// every seam short of the host process table. /bin/sleep is a stock platform
// binary, takes no privilege and no network.
func startSleeper(t *testing.T, ctx context.Context) (*Process, int) {
	t.Helper()
	p := NewProcess(PosixSpawner{}, KqueueReaper{},
		SpawnSpec{Path: "/bin/sleep", Argv: []string{"/bin/sleep", "300"}, Env: []string{}}, nil)
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start /bin/sleep: %v", err)
	}
	pid := p.PID()
	if pid <= 0 {
		t.Fatalf("Start returned pid %d", pid)
	}
	// Belt and braces: whatever the test proves or fails to prove, neither a live
	// sleeper nor an uncollected zombie outlives this test binary.
	t.Cleanup(func() {
		_ = unix.Kill(pid, unix.SIGKILL)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var ws unix.WaitStatus
			wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
			if wpid == pid || errors.Is(err, unix.ECHILD) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return p, pid
}

// awaitReaperReturn waits for the supervision goroutine to record a final status,
// which is the observable edge "WaitExit has returned". After a cancellation it
// is what makes the test's ordering deterministic: the reaper is provably gone
// before the child is killed, so nothing but the detached handoff can collect it.
func awaitReaperReturn(t *testing.T, p *Process) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper did not return within 5s of the ctx cancellation")
	}
}

// awaitReaped waits for pid to leave the process table entirely, which is the
// observable difference between "dead" and "reaped": a SIGKILLed child nobody
// wait4s stays a ZOMBIE, and a zombie still accepts kill(pid, 0) — the kernel
// keeps its entry alive precisely so a parent can still collect it. Only the
// wait4 releases the entry, after which kill reports ESRCH. The probe is
// deliberately non-destructive: a wait4-based probe would COLLECT the child
// itself, proving the test rather than the daemon.
func awaitReaped(t *testing.T, pid int, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		err := unix.Kill(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d is still in the process table %s after it was SIGKILLed "+
				"(kill(pid,0) = %v): the daemon abandoned its child without a wait4, "+
				"leaving an OS zombie", pid, bound, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCancelledWaitStillReapsTheChild is the zombie-abandonment gate. It pins the
// invariant that a supervision context cancelled out from under KqueueReaper —
// the ORDINARY DeletePod teardown, where GracefulStop's exit-observation bound
// expires and pkg/runtime cancels the pod-lifetime context for a group it has
// just SIGKILLed — still ends with the child collected.
//
// Red before the fix: WaitExit returned ctx.Err() at its poll-loop ctx check
// BEFORE the wait4, and nothing else in the daemon ever wait4s a pod pid (kqueue
// is the sole reaper), so the SIGKILLed process stayed a zombie in the host
// process table until the daemon itself exited — one leaked process-table slot
// per pod whose exit missed the 2s observation bound.
func TestCancelledWaitStillReapsTheChild(t *testing.T) {
	t.Run("cancel then kill: the reaper is gone before the child dies", func(t *testing.T) {
		// The deterministic ordering, and the worst case: WaitExit has ALREADY
		// returned on ctx by the time the process dies, so nothing is left racing
		// for the exit and only the detached handoff can collect it.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, pid := startSleeper(t, ctx)

		cancel()
		awaitReaperReturn(t, p)

		if err := unix.Kill(pid, unix.SIGKILL); err != nil {
			t.Fatalf("SIGKILL pid %d: %v", pid, err)
		}
		awaitReaped(t, pid, zombieReapBound)
	})

	t.Run("kill then cancel: the audited teardown ordering", func(t *testing.T) {
		// The sequence DeletePod actually runs — SIGKILL, then the cancel that can
		// preempt the reaper at its ctx check. Whichever side wins that race, the
		// child must not survive as a zombie.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, pid := startSleeper(t, ctx)

		if err := unix.Kill(pid, unix.SIGKILL); err != nil {
			t.Fatalf("SIGKILL pid %d: %v", pid, err)
		}
		cancel()
		awaitReaped(t, pid, zombieReapBound)
	})
}

// TestCancelledWaitStillReportsCancellation pins the half of the contract the fix
// must NOT disturb. The detached handoff collects the corpse; it does not change
// what the cancelled call REPORTS. WaitExit still returns ctx.Err(), so
// Process.reap still records "context canceled" as the container's exit error and
// GracefulStop's observed == false note still describes what actually happened —
// the status-honesty semantics stay exactly as documented, and a later, silently
// collected exit status never overwrites them.
func TestCancelledWaitStillReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, pid := startSleeper(t, ctx)

	cancel()
	awaitReaperReturn(t, p)

	code, sig, err := p.Wait(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait after cancellation: err = %v, want context.Canceled", err)
	}
	if code != 0 || sig != 0 {
		t.Fatalf("Wait after cancellation: code/signal = %d/%d, want 0/0 (no status was observed)", code, sig)
	}
	if got := p.State(); got != StateExited {
		t.Fatalf("state after a cancelled wait = %s, want %s", got, StateExited)
	}

	// And the corpse is still collected.
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatalf("SIGKILL pid %d: %v", pid, err)
	}
	awaitReaped(t, pid, zombieReapBound)
}
