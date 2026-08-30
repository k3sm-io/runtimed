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

package guestinit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// reapResult is one queued wait4(2) answer.
type reapResult struct {
	pid    int
	status WaitStatus
}

// fakeProc is the Proc seam's test double. It models the kernel's side of the
// contract: children exist or they do not, an exited child is reaped once, and
// every signal and poweroff is recorded in ONE ordered log so the stop
// sequence's ordering can be asserted rather than timed.
type fakeProc struct {
	mu          sync.Mutex
	ready       []reapResult
	kids        int
	log         []string
	poweroffs   int
	poweroffErr error
	killErr     error

	sigchld chan struct{}
	termed  chan int
	killed  chan int
	powered chan struct{}
}

func newFakeProc() *fakeProc {
	return &fakeProc{
		sigchld: make(chan struct{}, 1),
		termed:  make(chan int, 64),
		killed:  make(chan int, 64),
		powered: make(chan struct{}, 4),
	}
}

func (f *fakeProc) Wait4() (int, WaitStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ready) > 0 {
		r := f.ready[0]
		f.ready = f.ready[1:]
		return r.pid, r.status, nil
	}
	if f.kids > 0 {
		return 0, WaitStatus{}, nil
	}
	return 0, WaitStatus{}, ErrNoChildren
}

func (f *fakeProc) Kill(pid int, sig Signal) error {
	f.mu.Lock()
	switch sig {
	case SignalTerm:
		f.log = append(f.log, fmt.Sprintf("term:%d", pid))
	case SignalKill:
		f.log = append(f.log, fmt.Sprintf("kill:%d", pid))
	default:
		f.log = append(f.log, fmt.Sprintf("sig%d:%d", sig, pid))
	}
	err := f.killErr
	f.mu.Unlock()

	switch sig {
	case SignalTerm:
		f.termed <- pid
	case SignalKill:
		f.killed <- pid
	}
	return err
}

func (f *fakeProc) Poweroff() error {
	f.mu.Lock()
	f.poweroffs++
	f.log = append(f.log, "poweroff")
	err := f.poweroffErr
	f.mu.Unlock()
	f.powered <- struct{}{}
	return err
}

// spawn registers a live child.
func (f *fakeProc) spawn(pid int) {
	f.mu.Lock()
	f.kids++
	f.mu.Unlock()
}

// exit makes a live child exited and pokes the SIGCHLD channel.
func (f *fakeProc) exit(pid int, status WaitStatus) {
	f.mu.Lock()
	f.ready = append(f.ready, reapResult{pid: pid, status: status})
	if f.kids > 0 {
		f.kids--
	}
	f.mu.Unlock()
	select {
	case f.sigchld <- struct{}{}:
	default:
	}
}

// mark inserts a test-controlled marker into the same ordered log the signals
// land in. It is what makes "no SIGKILL before the grace timer fired" a
// deterministic ordering assertion instead of a sleep.
func (f *fakeProc) mark(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakeProc) snapshotLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.log...)
}

func (f *fakeProc) poweroffCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.poweroffs
}

// recorder collects ExitEvents. The reaper documents its callback as safe for
// concurrent use, so the recorder locks.
type recorder struct {
	mu     sync.Mutex
	events []ExitEvent
	ch     chan ExitEvent
}

func newRecorder() *recorder { return &recorder{ch: make(chan ExitEvent, 64)} }

func (r *recorder) onExit(ev ExitEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	r.ch <- ev
}

func (r *recorder) snapshot() []ExitEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ExitEvent{}, r.events...)
}

// waitEvents drains n events or fails the test.
func (r *recorder) waitEvents(t *testing.T, n int) []ExitEvent {
	t.Helper()
	var got []ExitEvent
	deadline := time.After(5 * time.Second)
	for len(got) < n {
		select {
		case ev := <-r.ch:
			got = append(got, ev)
		case <-deadline:
			t.Fatalf("timed out waiting for %d exit events; got %d: %+v", n, len(got), got)
		}
	}
	return got
}

// startReaper wires a reaper over the fake and runs its loop for the test's
// lifetime.
func startReaper(t *testing.T, f *fakeProc, opts ReaperOptions) *Reaper {
	t.Helper()
	r := NewReaper(f, f.sigchld, opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("reaper Run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("reaper Run did not return after context cancellation")
		}
	})
	return r
}

// TestPID1ReapAndForward pins the reap half of the PID 1 contract: every
// tracked child's exit reaches the callback exactly once and with its real
// status, every orphan is reaped and NOT forwarded, and neither property
// depends on whether the child was reaped before or after its Track landed.
func TestPID1ReapAndForward(t *testing.T) {
	t.Parallel()

	t.Run("every tracked exit is forwarded once with its own status", func(t *testing.T) {
		t.Parallel()
		f, rec := newFakeProc(), newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})

		want := map[string]WaitStatus{
			"init-db":  {ExitCode: 0},
			"postgres": {ExitCode: 137},
			"sidecar":  {Signal: 9},
		}
		pids := map[string]int{"init-db": 11, "postgres": 12, "sidecar": 13}
		for name, pid := range pids {
			f.spawn(pid)
			r.Track(name, pid)
		}
		for name, pid := range pids {
			f.exit(pid, want[name])
		}

		got := rec.waitEvents(t, len(want))
		seen := map[string]int{}
		for _, ev := range got {
			seen[ev.Container]++
			if ev.Status != want[ev.Container] {
				t.Errorf("container %q: status = %+v, want %+v", ev.Container, ev.Status, want[ev.Container])
			}
			if ev.PID != pids[ev.Container] {
				t.Errorf("container %q: pid = %d, want %d", ev.Container, ev.PID, pids[ev.Container])
			}
		}
		for name := range want {
			if seen[name] != 1 {
				t.Errorf("container %q forwarded %d times, want exactly 1", name, seen[name])
			}
		}
	})

	t.Run("an inherited orphan is reaped but never forwarded", func(t *testing.T) {
		t.Parallel()
		f, rec := newFakeProc(), newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})

		for _, pid := range []int{900, 901, 902} {
			f.spawn(pid)
		}
		f.spawn(20)
		r.Track("postgres", 20)

		for _, pid := range []int{900, 901, 902} {
			f.exit(pid, WaitStatus{ExitCode: 1})
		}
		f.exit(20, WaitStatus{ExitCode: 0})

		got := rec.waitEvents(t, 1)
		if got[0].Container != "postgres" {
			t.Fatalf("forwarded %+v, want only the tracked container", got)
		}
		// Nothing else may arrive: an orphan's exit belongs to no container.
		select {
		case ev := <-rec.ch:
			t.Fatalf("an untracked orphan was forwarded: %+v", ev)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("a child reaped before its Track is not lost", func(t *testing.T) {
		t.Parallel()
		f, rec := newFakeProc(), newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})

		// The kernel can reap a short-lived child before the executor has
		// recorded its pid; the status must be delivered by the late Track.
		f.spawn(30)
		f.exit(30, WaitStatus{ExitCode: 42})
		waitFor(t, func() bool { return r.pendingLen() == 1 })

		r.Track("fast", 30)
		got := rec.waitEvents(t, 1)
		if got[0].Container != "fast" || got[0].Status.ExitCode != 42 {
			t.Fatalf("late Track delivered %+v, want fast/exit 42", got[0])
		}
	})

	t.Run("concurrent starts race the reap loop", func(t *testing.T) {
		t.Parallel()
		f, rec := newFakeProc(), newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})

		const n = 32
		var wg sync.WaitGroup
		for i := range n {
			pid := 1000 + i
			f.spawn(pid)
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Track and exit race deliberately: half the goroutines let
				// the exit land first.
				if pid%2 == 0 {
					r.Track(fmt.Sprintf("c%d", pid), pid)
					f.exit(pid, WaitStatus{ExitCode: pid % 256})
					return
				}
				f.exit(pid, WaitStatus{ExitCode: pid % 256})
				r.Track(fmt.Sprintf("c%d", pid), pid)
			}()
		}
		wg.Wait()

		got := rec.waitEvents(t, n)
		if len(got) != n {
			t.Fatalf("got %d exit events, want %d", len(got), n)
		}
		for _, ev := range got {
			if want := ev.PID % 256; ev.Status.ExitCode != want {
				t.Errorf("%s: exit code %d, want %d", ev.Container, ev.Status.ExitCode, want)
			}
		}
	})

	t.Run("the reaped-before-Track map is bounded", func(t *testing.T) {
		t.Parallel()
		f, rec := newFakeProc(), newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})

		const orphans = maxPendingReaps + 16
		for pid := range orphans {
			f.spawn(pid + 1)
		}
		for pid := range orphans {
			f.exit(pid+1, WaitStatus{ExitCode: 0})
		}
		waitFor(t, func() bool { return r.pendingLen() == maxPendingReaps })
		if n := r.pendingLen(); n != maxPendingReaps {
			t.Fatalf("pending map holds %d entries, want it capped at %d", n, maxPendingReaps)
		}
	})
}

// TestReaperWaitSequencesAnInitContainer pins Wait, which is how an init
// container's run-to-completion step is sequenced. PID 1 is the only process
// that may wait(2), so os/exec's own Wait cannot be used and the exit has to
// come back through the reaper.
func TestReaperWaitSequencesAnInitContainer(t *testing.T) {
	t.Parallel()

	t.Run("Wait blocks until the container exits and returns its status", func(t *testing.T) {
		t.Parallel()
		f := newFakeProc()
		r := startReaper(t, f, ReaperOptions{})
		f.spawn(50)
		r.Track("init-db", 50)

		type result struct {
			status WaitStatus
			err    error
		}
		done := make(chan result, 1)
		go func() {
			st, err := r.Wait(context.Background(), "init-db")
			done <- result{st, err}
		}()
		select {
		case res := <-done:
			t.Fatalf("Wait returned %+v before the container exited", res)
		case <-time.After(100 * time.Millisecond):
		}

		f.exit(50, WaitStatus{ExitCode: 7})
		select {
		case res := <-done:
			if res.err != nil || res.status.ExitCode != 7 {
				t.Fatalf("Wait = (%+v, %v), want exit 7 and no error", res.status, res.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Wait did not return after the container exited")
		}
	})

	t.Run("Wait after the exit returns the recorded status", func(t *testing.T) {
		t.Parallel()
		f := newFakeProc()
		r := startReaper(t, f, ReaperOptions{})
		f.spawn(51)
		r.Track("init-db", 51)
		f.exit(51, WaitStatus{Signal: 9})
		waitFor(t, func() bool {
			st, err := r.Wait(context.Background(), "init-db")
			return err == nil && st.Signal == 9
		})
	})

	t.Run("Wait unblocks when the guest stops instead", func(t *testing.T) {
		t.Parallel()
		f := newFakeProc()
		r := startReaper(t, f, ReaperOptions{})
		f.spawn(52)
		r.Track("stuck", 52)

		errCh := make(chan error, 1)
		go func() {
			_, err := r.Wait(context.Background(), "stuck")
			errCh <- err
		}()
		if err := r.Stop(context.Background(), 0); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		select {
		case err := <-errCh:
			if !errors.Is(err, ErrStopped) {
				t.Fatalf("Wait error = %v, want ErrStopped", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Wait did not unblock on Stop")
		}
	})
}

// TestStopTermGraceKillPoweroff pins the ORDER of the stop state machine.
//
// The assertion is over one ordered log into which the test itself inserts the
// "grace timer fired" marker, so "SIGKILL never precedes the grace deadline"
// is decided by sequence rather than by sleeping. A mutant that kills before
// the grace elapses reds twice: the 100ms window below sees the kill, and the
// log shows kill ahead of the marker.
func TestStopTermGraceKillPoweroff(t *testing.T) {
	t.Parallel()
	f := newFakeProc()
	timerCh := make(chan time.Time, 1)
	var timerMu sync.Mutex
	timerStops := 0
	r := startReaper(t, f, ReaperOptions{
		NewTimer: func(time.Duration) (<-chan time.Time, func() bool) {
			return timerCh, func() bool {
				timerMu.Lock()
				timerStops++
				timerMu.Unlock()
				return true
			}
		},
	})

	for _, pid := range []int{10, 11} {
		f.spawn(pid)
		r.Track(fmt.Sprintf("c%d", pid), pid)
	}

	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop(context.Background(), 30*time.Second) }()

	// Both containers are asked to terminate, in deterministic pid order.
	for _, want := range []int{10, 11} {
		select {
		case got := <-f.termed:
			if got != want {
				t.Fatalf("SIGTERM went to pid %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for SIGTERM")
		}
	}

	// Nothing may be killed while the grace budget is still running.
	select {
	case pid := <-f.killed:
		t.Fatalf("pid %d was SIGKILLed before the grace budget elapsed", pid)
	case <-f.powered:
		t.Fatal("the guest powered off before the grace budget elapsed")
	case <-time.After(100 * time.Millisecond):
	}

	f.mark("grace-elapsed")
	timerCh <- time.Now()

	for range 2 {
		select {
		case <-f.killed:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for SIGKILL after the grace budget elapsed")
		}
	}
	if err := <-stopped; err != nil {
		t.Fatalf("Stop: %v", err)
	}

	want := []string{"term:10", "term:11", "grace-elapsed", "kill:10", "kill:11", "poweroff"}
	if got := f.snapshotLog(); !reflect.DeepEqual(got, want) {
		t.Fatalf("stop sequence =\n  %v\nwant\n  %v", got, want)
	}
	timerMu.Lock()
	defer timerMu.Unlock()
	if timerStops != 1 {
		t.Errorf("grace timer stopped %d times, want exactly 1 (a leaked timer is a leaked goroutine)", timerStops)
	}
}

// TestStopSkipsKillWhenContainersExitInGrace pins the other side of the grace
// contract: containers that honour SIGTERM are never SIGKILLed, and the stop
// does not wait out the remaining budget once they are all gone.
func TestStopSkipsKillWhenContainersExitInGrace(t *testing.T) {
	t.Parallel()
	f := newFakeProc()
	timerCh := make(chan time.Time)
	r := startReaper(t, f, ReaperOptions{
		NewTimer: func(time.Duration) (<-chan time.Time, func() bool) { return timerCh, func() bool { return true } },
	})
	for _, pid := range []int{10, 11} {
		f.spawn(pid)
		r.Track(fmt.Sprintf("c%d", pid), pid)
	}

	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop(context.Background(), time.Hour) }()

	for range 2 {
		pid := <-f.termed
		f.exit(pid, WaitStatus{Signal: int(SignalTerm)})
	}

	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return once every container had exited (it waited out the grace budget)")
	}

	want := []string{"term:10", "term:11", "poweroff"}
	if got := f.snapshotLog(); !reflect.DeepEqual(got, want) {
		t.Fatalf("stop sequence =\n  %v\nwant\n  %v (no SIGKILL is owed to a container that exited)", got, want)
	}
}

// TestStopAlwaysPowersOff pins the property that no stop path may skip the
// poweroff. A guest that stops without powering off is a VM with no pod, which
// the host can only reap by timeout.
func TestStopAlwaysPowersOff(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		grace   time.Duration
		setup   func(t *testing.T, f *fakeProc, r *Reaper)
		ctx     func() (context.Context, context.CancelFunc)
		wantErr bool
	}{
		{
			name:  "no containers were ever started",
			grace: time.Second,
			setup: func(*testing.T, *fakeProc, *Reaper) {},
		},
		{
			name:  "zero grace goes straight to SIGKILL",
			grace: 0,
			setup: func(t *testing.T, f *fakeProc, r *Reaper) {
				f.spawn(70)
				r.Track("stuck", 70)
			},
		},
		{
			name:  "every signal fails",
			grace: 0,
			setup: func(t *testing.T, f *fakeProc, r *Reaper) {
				f.spawn(71)
				r.Track("stuck", 71)
				f.mu.Lock()
				f.killErr = errors.New("ESRCH")
				f.mu.Unlock()
			},
			wantErr: true,
		},
		{
			name:  "the context is already cancelled",
			grace: time.Hour,
			setup: func(t *testing.T, f *fakeProc, r *Reaper) {
				f.spawn(72)
				r.Track("stuck", 72)
			},
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
		},
		{
			name:  "the poweroff itself fails",
			grace: 0,
			setup: func(t *testing.T, f *fakeProc, r *Reaper) {
				f.mu.Lock()
				f.poweroffErr = errors.New("EPERM")
				f.mu.Unlock()
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeProc()
			r := startReaper(t, f, ReaperOptions{})
			tc.setup(t, f, r)

			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()

			err := r.Stop(ctx, tc.grace)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Stop error = %v, wantErr = %v", err, tc.wantErr)
			}
			if got := f.poweroffCount(); got != 1 {
				t.Fatalf("poweroff called %d times, want exactly 1", got)
			}
		})
	}
}

// TestStopIsIdempotent pins the once-only guarantee: a second Stop must not
// power off a second time (the host may call Stop while a SIGTERM-driven stop
// is already running).
func TestStopIsIdempotent(t *testing.T) {
	t.Parallel()
	f := newFakeProc()
	f.poweroffErr = errors.New("EPERM")
	r := startReaper(t, f, ReaperOptions{})

	first := r.Stop(context.Background(), 0)
	second := r.Stop(context.Background(), 0)
	if first == nil {
		t.Fatal("Stop swallowed the poweroff failure")
	}
	if !errors.Is(second, first) && second.Error() != first.Error() {
		t.Fatalf("second Stop returned %v, want the first call's error %v", second, first)
	}
	if got := f.poweroffCount(); got != 1 {
		t.Fatalf("poweroff called %d times across two Stops, want exactly 1", got)
	}
}

// TestStopIsIdempotentUnderConcurrency runs the same guarantee through the
// race detector: the host's Stop RPC and PID 1's own SIGTERM handler can call
// Stop at the same instant.
func TestStopIsIdempotentUnderConcurrency(t *testing.T) {
	t.Parallel()
	f := newFakeProc()
	r := startReaper(t, f, ReaperOptions{})
	f.spawn(80)
	r.Track("stuck", 80)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Stop(context.Background(), 0); err != nil {
				t.Errorf("Stop: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := f.poweroffCount(); got != 1 {
		t.Fatalf("poweroff called %d times across 8 concurrent Stops, want exactly 1", got)
	}
}

// TestReaperRunReportsSeamFailure pins that a broken seam ends the loop with
// an error rather than spinning: a wait4 that fails for a reason other than
// ECHILD/EINTR is not something PID 1 can retry its way out of.
func TestReaperRunReportsSeamFailure(t *testing.T) {
	t.Parallel()
	f := &brokenProc{err: errors.New("EFAULT")}
	r := NewReaper(f, nil, ReaperOptions{})
	err := r.Run(context.Background())
	if err == nil || !errors.Is(err, f.err) {
		t.Fatalf("Run error = %v, want the seam's error wrapped", err)
	}
}

// TestReaperRunRetriesEINTR pins that an interrupted wait is retried. PID 1
// takes signals constantly, so treating EINTR as fatal would end the reap loop
// at the first SIGTERM.
func TestReaperRunRetriesEINTR(t *testing.T) {
	t.Parallel()
	f := &brokenProc{err: ErrInterrupted, thenNoChildren: 3}
	r := NewReaper(f, nil, ReaperOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled after the EINTR retries", err)
	}
	if f.calls < 3 {
		t.Fatalf("Wait4 called %d times, want at least the 3 EINTR retries", f.calls)
	}
}

// brokenProc answers Wait4 with a fixed error.
type brokenProc struct {
	err            error
	thenNoChildren int
	calls          int
}

func (b *brokenProc) Wait4() (int, WaitStatus, error) {
	b.calls++
	if b.thenNoChildren > 0 && b.calls > b.thenNoChildren {
		return 0, WaitStatus{}, ErrNoChildren
	}
	return 0, WaitStatus{}, b.err
}
func (b *brokenProc) Kill(int, Signal) error { return nil }
func (b *brokenProc) Poweroff() error        { return nil }

// waitFor polls cond until it holds or the test's patience runs out. It exists
// for the handful of assertions about state the reaper reaches asynchronously
// with no channel to observe.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not hold within 5s")
}

// pendingLen observes the reaped-before-Track map's size. It is a test-only
// accessor: the map is an internal race-closing detail with no reason to be
// part of the package's surface.
func (r *Reaper) pendingLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
