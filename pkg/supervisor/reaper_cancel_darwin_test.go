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
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// cancelBound is the latency a cancelled WaitExit must beat. The old reaper
// polled kevent every 250 ms and looked at ctx.Err() on each wake, so a
// cancellation landed anywhere in [0, 250 ms) before it was noticed; an
// event-driven wake is sub-millisecond, and 50 ms leaves room for a loaded
// -race run without ever admitting the poll.
const cancelBound = 50 * time.Millisecond

// cancelTrials is how many sequential cancellations must ALL beat cancelBound.
// One trial is not a test of the poll: a cancel that happens to land within
// 50 ms of a poll wake passes by luck one time in five. Five trials make the
// polling reaper fail with probability 1 - 0.2^5, i.e. every run in practice.
const cancelTrials = 5

// TestKqueueReaperCancelIsImmediate is the B255 gate: WaitExit's cancellation
// path is event-driven (an EVFILT_USER wakeup on the reaper's own kqueue), not
// a 250 ms poll — and the exit-status path it shares the kqueue with is
// unchanged: a normal exit and a signalled exit still report through, and the
// trigger goroutine is gone once WaitExit has returned.
func TestKqueueReaperCancelIsImmediate(t *testing.T) {
	t.Run("cancel wakes the reaper well inside the old poll interval", func(t *testing.T) {
		var worst time.Duration
		for i := 0; i < cancelTrials; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			p, _ := startSleeper(t, ctx)
			// Let the reaper reach its blocking wait before cancelling, so the
			// measurement is the wake latency and not the spawn.
			time.Sleep(20 * time.Millisecond)
			start := time.Now()
			cancel()
			select {
			case <-p.Done():
			case <-time.After(5 * time.Second):
				t.Fatalf("trial %d: the reaper did not return within 5s of cancellation", i)
			}
			if d := time.Since(start); d > worst {
				worst = d
			}
			if _, _, err := p.Wait(context.Background()); !errors.Is(err, context.Canceled) {
				t.Fatalf("trial %d: Wait after cancellation: err = %v, want context.Canceled", i, err)
			}
		}
		if worst > cancelBound {
			t.Fatalf("worst cancel-to-return latency over %d trials = %s, want < %s "+
				"(a 250 ms poll loop would show up here)", cancelTrials, worst, cancelBound)
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
