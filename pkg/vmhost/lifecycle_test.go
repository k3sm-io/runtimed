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

package vmhost

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
)

// fakeMachine is the machineRunner seam: it records the order of the calls it
// received and lets a test decide when Wait returns.
//
// The ORDER RECORD is the point. Shutdown correctness here is not "did every step
// happen" but "did they happen in the order that keeps a graceful stop from
// becoming a power cut", so every seam appends to one shared log and the
// assertions read that log.
type fakeMachine struct {
	startErr error
	stopErr  error

	// exit is closed (or sent to) when the machine should leave Running.
	exit    chan error
	rec     *callLog
	stopped chan struct{}
}

func newFakeMachine(rec *callLog) *fakeMachine {
	return &fakeMachine{exit: make(chan error, 1), rec: rec, stopped: make(chan struct{})}
}

func (m *fakeMachine) Start(ctx context.Context) error {
	m.rec.add("machine.Start")
	return m.startErr
}

func (m *fakeMachine) Wait(ctx context.Context) error {
	select {
	case err := <-m.exit:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *fakeMachine) Stop(ctx context.Context) error {
	m.rec.add("machine.Stop")
	if m.stopErr != nil {
		return m.stopErr
	}
	// A hard stop ends the machine, so the wait must come back too — modelling
	// the real runner, whose Stop leaves the machine stopped.
	select {
	case m.exit <- nil:
	default:
	}
	close(m.stopped)
	return nil
}

// fakeAgent is the agentStopper seam. onStop lets a case decide what the guest
// does in response: exit within the budget, ignore the request, or refuse it.
type fakeAgent struct {
	rec    *callLog
	err    error
	onStop func(grace time.Duration)
}

func (a *fakeAgent) Stop(ctx context.Context, grace time.Duration) error {
	a.rec.add("agent.Stop")
	if a.onStop != nil {
		a.onStop(grace)
	}
	return a.err
}

// callLog is an ordered, concurrency-safe record of seam calls.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *callLog) add(s string) {
	c.mu.Lock()
	c.calls = append(c.calls, s)
	c.mu.Unlock()
}

func (c *callLog) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

// manualTimer is the NewTimer seam: the grace budget expires exactly when a test
// says so, never by sleeping. Without it every ordering assertion below would be a
// race between a real timer and a goroutine schedule.
type manualTimer struct {
	ch     chan time.Time
	asked  chan time.Duration
	stopMu sync.Mutex
	fired  bool
}

func newManualTimer() *manualTimer {
	return &manualTimer{ch: make(chan time.Time, 1), asked: make(chan time.Duration, 4)}
}

func (m *manualTimer) new(d time.Duration) (<-chan time.Time, func() bool) {
	m.asked <- d
	return m.ch, func() bool { return true }
}

func (m *manualTimer) fire() {
	m.stopMu.Lock()
	defer m.stopMu.Unlock()
	if !m.fired {
		m.fired = true
		m.ch <- time.Now()
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestLifecycleStateMachine is B227's lifecycle gate. It drives the New -> Starting
// -> Running -> Stopping -> Stopped|Failed machine through every transition and
// pins the shutdown ORDER, which is the property the whole design turns on
// (the M11 plan's Resolution 5).
//
// EVERY assertion is a t.Run subtest of this ONE function on purpose: the gate runs
// `go test -run '^TestLifecycleStateMachine$'`, so a sibling top-level Test* would
// be silently filtered out and never run.
//
// Deterministic by construction: the grace budget is a manual timer, so nothing
// here sleeps and nothing races a wall clock. Hermetic: no VM, no framework.
func TestLifecycleStateMachine(t *testing.T) {
	t.Run("starts-and-reaches-running", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger()})
		if lc.State() != StateNew {
			t.Fatalf("initial state = %v, want New", lc.State())
		}

		done := make(chan error, 1)
		go func() { done <- lc.Run(context.Background()) }()

		waitForState(t, lc, StateRunning)
		// The guest then powers itself off on its own terms.
		m.exit <- nil
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if lc.State() != StateStopped {
			t.Errorf("final state = %v, want Stopped", lc.State())
		}
		if got := rec.snapshot(); len(got) != 1 || got[0] != "machine.Start" {
			t.Errorf("calls = %v; a guest that ended on its own must not be stopped again", got)
		}
	})

	t.Run("a-start-failure-is-terminal-and-Failed", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		m.startErr = errors.New("no entitlement")
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger()})
		if err := lc.Run(context.Background()); err == nil {
			t.Fatal("Run returned nil on a machine that could not start")
		}
		if lc.State() != StateFailed {
			t.Errorf("state = %v, want Failed", lc.State())
		}
	})

	t.Run("a-failed-start-is-still-torn-down", func(t *testing.T) {
		// THE LEAK THIS CLOSES. The darwin runner races the framework's boot
		// against ctx, so a Start that reports ctx.Err() can have left a machine
		// that goes on to finish booting — a VM with no supervisor, outliving the
		// process that made it. Run is the last holder of the runner, so if it
		// returns without a Stop nothing can ever halt that machine.
		rec := &callLog{}
		m := newFakeMachine(rec)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		m.startErr = ctx.Err()
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger()})
		if err := lc.Run(ctx); err == nil {
			t.Fatal("Run returned nil on a cancelled start")
		}
		got := rec.snapshot()
		if len(got) != 2 || got[0] != "machine.Start" || got[1] != "machine.Stop" {
			t.Errorf("calls = %v; want [machine.Start machine.Stop] — a cancelled Start must force the teardown, or a half-booted machine outlives the helper", got)
		}
		if lc.State() != StateFailed {
			t.Errorf("state = %v, want Failed", lc.State())
		}
	})

	t.Run("a-failed-start-whose-stop-also-fails-still-reports-the-start-error", func(t *testing.T) {
		// The teardown is best-effort SALVAGE, not a second failure mode: the
		// caller needs to read WHY the machine could not start, and a stop error
		// on a machine that never started would bury it.
		rec := &callLog{}
		m := newFakeMachine(rec)
		m.startErr = errors.New("no entitlement")
		m.stopErr = errors.New("nothing to halt")
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger()})
		err := lc.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no entitlement") {
			t.Errorf("Run err = %v; want the START error, not the salvage stop's", err)
		}
	})

	t.Run("an-abnormal-machine-exit-is-Failed", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger()})
		done := make(chan error, 1)
		go func() { done <- lc.Run(context.Background()) }()
		waitForState(t, lc, StateRunning)
		m.exit <- errors.New("guest kernel panic")
		if err := <-done; err == nil {
			t.Fatal("Run returned nil after an abnormal machine exit")
		}
		if lc.State() != StateFailed {
			t.Errorf("state = %v, want Failed", lc.State())
		}
	})

	// --- the shutdown order, which is the whole point ------------------------

	t.Run("the-agent-is-asked-before-the-machine-is-halted", func(t *testing.T) {
		// A hard stop is a power cut: for a pod mid-write it is data loss, and for
		// a PVC it is data loss that outlives the pod. So the graceful leg must
		// come first, and the hard stop only after the budget is spent.
		rec := &callLog{}
		m := newFakeMachine(rec)
		timer := newManualTimer()
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{
			Logger: quietLogger(), NewTimer: timer.new,
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)

		cancel()
		waitForState(t, lc, StateStopping)
		// The guest ignores the request; the budget expires.
		<-timer.asked
		timer.fire()

		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []string{"machine.Start", "agent.Stop", "machine.Stop"}
		assertCalls(t, rec.snapshot(), want)
		if lc.State() != StateStopped {
			t.Errorf("state = %v, want Stopped", lc.State())
		}
	})

	t.Run("a-guest-that-exits-within-grace-is-never-halted", func(t *testing.T) {
		// The other half of the same rule: the hard stop must NOT fire when the
		// graceful path worked. A machine.Stop here would be the power cut the
		// grace budget existed to avoid.
		rec := &callLog{}
		m := newFakeMachine(rec)
		timer := newManualTimer()
		agent := &fakeAgent{rec: rec, onStop: func(time.Duration) { m.exit <- nil }}
		lc := NewLifecycle(m, agent, LifecycleOptions{Logger: quietLogger(), NewTimer: timer.new})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)
		cancel()

		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "agent.Stop"})
		if lc.State() != StateStopped {
			t.Errorf("state = %v, want Stopped", lc.State())
		}
	})

	t.Run("an-unreachable-agent-still-halts-the-machine", func(t *testing.T) {
		// The agent is a DIFFERENT FAILURE DOMAIN — it lives in the guest, over
		// vsock — so its failure must not become the helper's. A helper that
		// returned here would leave a running VM with no pod, reapable only by
		// timeout.
		rec := &callLog{}
		m := newFakeMachine(rec)
		timer := newManualTimer()
		agent := &fakeAgent{rec: rec, err: errors.New("vsock: connection refused")}
		lc := NewLifecycle(m, agent, LifecycleOptions{Logger: quietLogger(), NewTimer: timer.new})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)
		cancel()
		waitForState(t, lc, StateStopping)
		<-timer.asked
		timer.fire()

		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "agent.Stop", "machine.Stop"})
	})

	t.Run("no-agent-transport-halts-the-machine-directly", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		timer := newManualTimer()
		lc := NewLifecycle(m, nil, LifecycleOptions{Logger: quietLogger(), NewTimer: timer.new})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)
		cancel()
		waitForState(t, lc, StateStopping)
		<-timer.asked
		timer.fire()

		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "machine.Stop"})
	})

	t.Run("a-failed-hard-stop-is-Failed", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		m.stopErr = errors.New("hypervisor refused")
		timer := newManualTimer()
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger(), NewTimer: timer.new})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)
		cancel()
		waitForState(t, lc, StateStopping)
		<-timer.asked
		timer.fire()

		if err := <-done; err == nil {
			t.Fatal("Run returned nil though the machine could not be halted")
		}
		if lc.State() != StateFailed {
			t.Errorf("state = %v, want Failed", lc.State())
		}
	})

	// --- the grace clamp -----------------------------------------------------

	t.Run("grace-is-clamped-into-the-launchd-exit-budget", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			ask  time.Duration
			want time.Duration
		}{
			{"zero-takes-the-default", 0, DefaultStopGrace},
			{"negative-takes-the-default", -5 * time.Second, DefaultStopGrace},
			{"in-range-is-carried", 5 * time.Second, 5 * time.Second},
			// A grace beyond the daemon's launchd ExitTimeOut does not buy a
			// gentler shutdown — it buys a SIGKILL, which is the ungraceful stop
			// the budget existed to avoid.
			{"over-the-max-is-clamped", 10 * time.Minute, MaxStopGrace},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rec := &callLog{}
				m := newFakeMachine(rec)
				timer := newManualTimer()
				var sawGrace time.Duration
				var mu sync.Mutex
				agent := &fakeAgent{rec: rec, onStop: func(g time.Duration) {
					mu.Lock()
					sawGrace = g
					mu.Unlock()
					m.exit <- nil
				}}
				lc := NewLifecycle(m, agent, LifecycleOptions{
					Grace: tc.ask, Logger: quietLogger(), NewTimer: timer.new,
				})
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- lc.Run(ctx) }()
				waitForState(t, lc, StateRunning)
				cancel()
				if err := <-done; err != nil {
					t.Fatalf("Run: %v", err)
				}
				mu.Lock()
				got := sawGrace
				mu.Unlock()
				if got != tc.want {
					t.Errorf("the guest was sent a grace of %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("a-lifecycle-drives-exactly-one-machine", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Logger: quietLogger()})
		done := make(chan error, 1)
		go func() { done <- lc.Run(context.Background()) }()
		waitForState(t, lc, StateRunning)
		if err := lc.Run(context.Background()); err == nil {
			t.Error("a second Run was accepted; one Lifecycle drives one machine")
		}
		m.exit <- nil
		<-done
	})

	t.Run("state-strings-are-stable-machine-tokens", func(t *testing.T) {
		for state, want := range map[State]string{
			StateNew: "New", StateStarting: "Starting", StateRunning: "Running",
			StateStopping: "Stopping", StateStopped: "Stopped", StateFailed: "Failed",
		} {
			if got := state.String(); got != want {
				t.Errorf("State(%d).String() = %q, want %q — operators grep these", int(state), got, want)
			}
		}
		if got := State(99).String(); got != "Unknown(99)" {
			t.Errorf("State(99).String() = %q, want it to NAME the unknown value rather than fold it into a known one", got)
		}
	})
}

// waitForState blocks until lc reaches want, failing the test on timeout. It polls
// rather than subscribing because State is the observable the lifecycle actually
// exposes; a test hook would assert something the production reader cannot see.
func waitForState(t *testing.T, lc *Lifecycle, want State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lc.State() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for state %v; still %v", want, lc.State())
}

// assertCalls compares an ordered seam-call log against the expected sequence.
func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v, want %v (differ at %d)", got, want, i)
		}
	}
}

// TestStopGraceBoundsAreSingleValued binds this helper's grace bounds to the
// daemon's mirrored copies, exactly as TestRosettaShareCapabilityIsSingleValued
// binds the Rosetta capability and for the same import reason: pkg/sandbox is
// linked into the daemon and this package imports Code-Hex/vz, so neither may
// import the other, and a test that can import both is where the agreement lives.
//
// A DISAGREEMENT IS THE POWER-CUT BUG. The daemon computes the grace the helper
// will actually honour (sandbox.clampStopGrace, applying these same two bounds)
// and makes its own SIGTERM->SIGKILL escalation at least that long. If the
// daemon's ceiling were the LOWER of the two, it would SIGKILL a helper still
// inside its graceful sequence — the guest asked to stop, mid-sync — which is the
// hard stop the whole grace protocol exists to avoid. If it were the higher, a
// deleted pod's teardown would idle for the difference on every vm pod.
func TestStopGraceBoundsAreSingleValued(t *testing.T) {
	if DefaultStopGrace != sandbox.VMHostDefaultStopGrace {
		t.Errorf("vmhost.DefaultStopGrace = %s but sandbox.VMHostDefaultStopGrace = %s; "+
			"the daemon would time its escalation against a budget this helper never uses",
			DefaultStopGrace, sandbox.VMHostDefaultStopGrace)
	}
	if MaxStopGrace != sandbox.VMHostMaxStopGrace {
		t.Errorf("vmhost.MaxStopGrace = %s but sandbox.VMHostMaxStopGrace = %s; "+
			"a lower daemon-side ceiling SIGKILLs a helper mid-graceful-stop (a power cut for the guest); "+
			"a higher one idles every vm pod's teardown by the difference",
			MaxStopGrace, sandbox.VMHostMaxStopGrace)
	}
}
