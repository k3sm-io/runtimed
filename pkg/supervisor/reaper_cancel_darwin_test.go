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
	"os/exec"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// quietWindow is how long WaitExit is left blocked on a context that is not yet
// done while the test watches whether it consults that context. The old reaper
// woke every 250 ms and called ctx.Err() on each wake, so three poll intervals
// fit in the window. Nothing here is a latency bound: an event-driven wait makes
// zero context calls however long the window runs, and host load can only make a
// polling loop wake LESS often (a false pass), never make the event-driven one
// wake at all. That is what keeps this test from failing on a loaded host.
const quietWindow = 750 * time.Millisecond

// returnBound is a liveness bound only, for "the reaper returned at all".
// It is generous on purpose; the property under test is decided by quietWindow.
const returnBound = 30 * time.Second

// probeCtx is a context whose Done channel the test closes by hand and whose
// Done and Err calls are counted. Err reports context.Canceled from the start,
// so a reaper that polls ctx.Err() returns during the quiet window, and one that
// polls ctx.Done() shows up in the Done count. The event-driven reaper reads
// Done once (its trigger goroutine) and Err only after the EVFILT_USER wakeup.
type probeCtx struct {
	context.Context
	done  chan struct{}
	dones atomic.Int64
	errs  atomic.Int64
}

func newProbeCtx() *probeCtx {
	return &probeCtx{Context: context.Background(), done: make(chan struct{})}
}

func (c *probeCtx) Done() <-chan struct{} {
	c.dones.Add(1)
	return c.done
}

func (c *probeCtx) Err() error {
	c.errs.Add(1)
	return context.Canceled
}

// TestKqueueReaperCancelIsImmediate is the gate: WaitExit's cancellation
// path is event-driven (an EVFILT_USER wakeup on the reaper's own kqueue), not
// a 250 ms poll, and the exit-status path it shares the kqueue with is
// unchanged: a normal exit and a signalled exit still report through, and the
// trigger goroutine is gone once WaitExit has returned.
func TestKqueueReaperCancelIsImmediate(t *testing.T) {
	t.Run("the reaper does not poll its context and wakes on cancel", func(t *testing.T) {
		cmd := exec.Command("/bin/sleep", "300")
		if err := cmd.Start(); err != nil {
			t.Fatalf("start /bin/sleep: %v", err)
		}
		pid := cmd.Process.Pid
		// WaitExit hands an unreaped child to reapDetached on cancellation;
		// killing it lets that collect it. cmd.Wait is never called: the
		// reaper under test must stay the sole wait4 caller.
		t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })

		ctx := newProbeCtx()
		type result struct {
			code, sig int
			err       error
		}
		ret := make(chan result, 1)
		go func() {
			code, sig, err := KqueueReaper{}.WaitExit(ctx, pid)
			ret <- result{code, sig, err}
		}()

		select {
		case r := <-ret:
			t.Fatalf("WaitExit returned (%d, %d, %v) before cancellation: it consulted ctx.Err() "+
				"instead of blocking on the kqueue", r.code, r.sig, r.err)
		case <-time.After(quietWindow):
		}
		if n := ctx.errs.Load(); n != 0 {
			t.Fatalf("ctx.Err() called %d times while the context was not done: the reaper polls", n)
		}
		if n := ctx.dones.Load(); n > 1 {
			t.Fatalf("ctx.Done() called %d times while the context was not done, want at most 1 "+
				"(the trigger goroutine): the reaper polls", n)
		}

		close(ctx.done)
		select {
		case r := <-ret:
			if !errors.Is(r.err, context.Canceled) {
				t.Fatalf("WaitExit after cancellation: err = %v, want context.Canceled", r.err)
			}
		case <-time.After(returnBound):
			t.Fatalf("WaitExit did not return within %s of cancellation: the cancel path does not wake the kqueue", returnBound)
		}
		if n := ctx.errs.Load(); n != 1 {
			t.Fatalf("ctx.Err() called %d times in total, want exactly 1 (after the EVFILT_USER wakeup)", n)
		}
	})

	t.Run("cancelling a supervised process returns context.Canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		p, _ := startSleeper(t, ctx)
		cancel()
		select {
		case <-p.Done():
		case <-time.After(returnBound):
			t.Fatalf("the reaper did not return within %s of cancellation", returnBound)
		}
		if _, _, err := p.Wait(context.Background()); !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait after cancellation: err = %v, want context.Canceled", err)
		}
	})

	tests := []struct {
		name     string
		argv     []string
		wantCode int
		wantSig  int
		kill     bool
	}{
		{name: "normal exit reports the status", argv: []string{"/bin/sh", "-c", "exit 7"}, wantCode: 7},
		{name: "signalled exit reports the signal", argv: []string{"/bin/sleep", "300"}, kill: true,
			wantCode: 128 + int(unix.SIGKILL), wantSig: int(unix.SIGKILL)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := runtime.NumGoroutine()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := NewProcess(PosixSpawner{}, KqueueReaper{},
				SpawnSpec{Path: tc.argv[0], Argv: tc.argv, Env: []string{}}, nil)
			if err := p.Start(ctx); err != nil {
				t.Fatalf("Start %v: %v", tc.argv, err)
			}
			if tc.kill {
				time.Sleep(20 * time.Millisecond)
				if err := unix.Kill(p.PID(), unix.SIGKILL); err != nil {
					t.Fatalf("SIGKILL: %v", err)
				}
			}
			code, sig, err := p.Wait(context.Background())
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
			if code != tc.wantCode || sig != tc.wantSig {
				t.Fatalf("code/signal = %d/%d, want %d/%d", code, sig, tc.wantCode, tc.wantSig)
			}
			// The cancellation-trigger goroutine must not outlive WaitExit. On
			// this path the child was reaped in-line (no detached handoff), so
			// the goroutine count returns to its starting point once the
			// reaper's own goroutine has finished closing up.
			deadline := time.Now().Add(2 * time.Second)
			for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := runtime.NumGoroutine(); got > before {
				t.Fatalf("goroutines after a reaped exit = %d, want <= %d: a WaitExit helper leaked", got, before)
			}
		})
	}
}
