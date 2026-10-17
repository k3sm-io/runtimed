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
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// timerSet is a NewTimer seam that hands every armed timer to the test, in
// order, so a case can tell the grace deadline from the short fallback and fire
// exactly the one it means.
type timerSet struct {
	made chan *armedTimer
	// onNew, if set, runs as each timer is armed. A case uses it to move the
	// fake clock, standing in for time that passes between the signal and the
	// Stop RPC.
	onNew func(d time.Duration)
}

type armedTimer struct {
	d  time.Duration
	ch chan time.Time
}

func newTimerSet() *timerSet { return &timerSet{made: make(chan *armedTimer, 8)} }

func (s *timerSet) new(d time.Duration) (<-chan time.Time, func() bool) {
	if s.onNew != nil {
		s.onNew(d)
	}
	t := &armedTimer{d: d, ch: make(chan time.Time, 1)}
	s.made <- t
	return t.ch, func() bool { return true }
}

// next returns the next armed timer, failing the test if none is armed in time.
func (s *timerSet) next(t *testing.T) *armedTimer {
	t.Helper()
	select {
	case at := <-s.made:
		return at
	case <-time.After(5 * time.Second):
		t.Fatal("no timer was armed")
		return nil
	}
}

// none asserts no further timer is armed within a short window.
func (s *timerSet) none(t *testing.T) {
	t.Helper()
	select {
	case at := <-s.made:
		t.Fatalf("an unexpected %s timer was armed", at.d)
	case <-time.After(50 * time.Millisecond):
	}
}

func (a *armedTimer) fire() { a.ch <- time.Now() }

// fakeClock is the Now seam.
type fakeClock struct{ ns atomic.Int64 }

func (c *fakeClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// gateAgent is the agentStopper for the gate: it records the grace it was sent
// and either answers at once (err) or, when block is set, holds the RPC until its
// context ends, which is what a wedged guest agent looks like from the host.
type gateAgent struct {
	rec      *callLog
	err      error
	block    bool
	entered  chan struct{}
	returned atomic.Bool

	mu    sync.Mutex
	grace time.Duration
}

func newGateAgent(rec *callLog) *gateAgent {
	return &gateAgent{rec: rec, entered: make(chan struct{})}
}

func (a *gateAgent) Stop(ctx context.Context, grace time.Duration) error {
	a.rec.add("agent.Stop")
	a.mu.Lock()
	a.grace = grace
	a.mu.Unlock()
	close(a.entered)
	defer a.returned.Store(true)
	if a.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return a.err
}

func (a *gateAgent) sentGrace() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grace
}

// TestStopDeliversTheGraceFromSigterm is B712's gate. The daemon times its
// SIGKILL of the helper from the SIGTERM it sent, so the helper must spend the
// guest's grace on that same clock: a deadline that started when the Stop RPC
// returned always expired after the daemon's, and a guest that used its whole
// grace ended with the daemon killing the helper (escalated=true) rather than
// the helper halting its machine.
//
// every assertion is a t.Run subtest of this one function on purpose: the gate
// runs `go test -run '^TestStopDeliversTheGraceFromSigterm$'`.
//
// Deterministic: timers and the clock are fakes; nothing sleeps against a grace.
func TestStopDeliversTheGraceFromSigterm(t *testing.T) {
	const grace = 30 * time.Second

	start := func(t *testing.T, agent agentStopper, timers *timerSet, clock *fakeClock) (*fakeMachine, *Lifecycle, *callLog, context.CancelFunc, <-chan error) {
		t.Helper()
		rec := &callLog{}
		if ga, ok := agent.(*gateAgent); ok {
			ga.rec = rec
		}
		m := newFakeMachine(rec)
		lc := NewLifecycle(m, agent, LifecycleOptions{
			Grace: grace, Logger: quietLogger(), NewTimer: timers.new, Now: clock.now,
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)
		return m, lc, rec, cancel, done
	}

	t.Run("the-deadline-starts-at-sigterm-not-at-the-rpc-return", func(t *testing.T) {
		// A WEDGED agent: the RPC never returns on its own. The grace deadline
		// must already be armed while it is in flight, and firing it must halt
		// the machine without waiting for the RPC.
		clock := &fakeClock{}
		timers := newTimerSet()
		// One second passes between the signal and the RPC going out.
		timers.onNew = func(time.Duration) { clock.advance(time.Second) }
		agent := newGateAgent(nil)
		agent.block = true
		_, lc, rec, cancel, done := start(t, agent, timers, clock)

		cancel()
		deadline := timers.next(t)
		if want := grace + GuestStopReserve; deadline.d != want {
			t.Fatalf("the first timer armed at shutdown is %s, want the grace plus the guest's sync reserve (%s) from the signal", deadline.d, want)
		}
		<-agent.entered
		if agent.returned.Load() {
			t.Fatal("the agent RPC returned before the deadline fired; the fake did not wedge")
		}
		// The guest is sent the configured grace in whole seconds, not the
		// remainder after the second that passed: flooring the remainder sent 29 s.
		if got := agent.sentGrace(); got != grace {
			t.Errorf("the guest was sent a grace of %s, want %s", got, grace)
		}
		if lc.State() != StateStopping {
			t.Fatalf("state = %v, want Stopping", lc.State())
		}
		deadline.fire()
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "agent.Stop", "machine.Stop"})
		// The RPC is cancelled on the way out rather than left running.
		waitFor(t, agent.returned.Load, "the wedged agent RPC was never cancelled")
	})

	t.Run("a-guest-off-at-grace-minus-one-second-is-not-halted", func(t *testing.T) {
		clock := &fakeClock{}
		timers := newTimerSet()
		agent := newGateAgent(nil)
		m, lc, rec, cancel, done := start(t, agent, timers, clock)

		cancel()
		if d := timers.next(t).d; d != grace+GuestStopReserve {
			t.Fatalf("first timer = %s, want the grace plus the reserve %s", d, grace+GuestStopReserve)
		}
		<-agent.entered
		waitFor(t, agent.returned.Load, "the agent RPC did not return")
		// The guest spends all but one second of its grace, then powers off. The
		// deadline is never fired: one second is left on it.
		clock.advance(grace - time.Second)
		m.exit <- nil
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "agent.Stop"})
		if lc.State() != StateStopped {
			t.Errorf("state = %v, want Stopped", lc.State())
		}
		timers.none(t)
	})

	t.Run("an-unreachable-agent-hard-stops-after-the-short-bound", func(t *testing.T) {
		// No request reached the guest, so nothing in it is spending the grace;
		// the helper waits only AgentUnreachableWait, never the rest of the budget.
		clock := &fakeClock{}
		timers := newTimerSet()
		agent := newGateAgent(nil)
		agent.err = errors.New("vsock: connection refused")
		_, _, rec, cancel, done := start(t, agent, timers, clock)

		cancel()
		deadline := timers.next(t)
		if deadline.d != grace+GuestStopReserve {
			t.Fatalf("first timer = %s, want the grace plus the reserve %s", deadline.d, grace+GuestStopReserve)
		}
		fallback := timers.next(t)
		if fallback.d != AgentUnreachableWait {
			t.Fatalf("fallback timer = %s, want AgentUnreachableWait %s", fallback.d, AgentUnreachableWait)
		}
		fallback.fire()
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "agent.Stop", "machine.Stop"})
	})

	t.Run("no-agent-transport-hard-stops-after-the-short-bound", func(t *testing.T) {
		clock := &fakeClock{}
		timers := newTimerSet()
		_, _, rec, cancel, done := start(t, nil, timers, clock)

		cancel()
		_ = timers.next(t) // the grace deadline
		fallback := timers.next(t)
		if fallback.d != AgentUnreachableWait {
			t.Fatalf("fallback timer = %s, want AgentUnreachableWait %s", fallback.d, AgentUnreachableWait)
		}
		fallback.fire()
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		assertCalls(t, rec.snapshot(), []string{"machine.Start", "machine.Stop"})
	})

	t.Run("the-guest-is-sent-whole-seconds-never-below-one", func(t *testing.T) {
		// A 1 s pod grace once reached the guest as 0, which the guest reads as
		// SIGKILL with no SIGTERM at all.
		for _, tc := range []struct{ ask, want time.Duration }{
			{time.Second, time.Second},
			{400 * time.Millisecond, time.Second},
			{1600 * time.Millisecond, 2 * time.Second},
			{90 * time.Second, 90 * time.Second},
		} {
			rec := &callLog{}
			m := newFakeMachine(rec)
			agent := newGateAgent(rec)
			timers := newTimerSet()
			lc := NewLifecycle(m, agent, LifecycleOptions{
				Grace: tc.ask, Logger: quietLogger(), NewTimer: timers.new, Now: (&fakeClock{}).now,
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- lc.Run(ctx) }()
			waitForState(t, lc, StateRunning)
			cancel()
			deadline := timers.next(t)
			<-agent.entered
			if got := agent.sentGrace(); got != tc.want {
				t.Errorf("grace %s reached the guest as %s, want %s", tc.ask, got, tc.want)
			}
			if deadline.d != tc.want+GuestStopReserve {
				t.Errorf("grace %s: deadline %s, want %s", tc.ask, deadline.d, tc.want+GuestStopReserve)
			}
			m.exit <- nil
			if err := <-done; err != nil {
				t.Fatalf("Run: %v", err)
			}
		}
	})

	t.Run("the-proxy-listener-is-open-during-stopping", func(t *testing.T) {
		// The daemon's execs and log follows go through the proxy. SIGTERM begins
		// the guest's shutdown; it must not cut the daemon off from a guest that
		// is still running and answering.
		sock := shortSocketPath(t)
		lis, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		guests := make(chan net.Conn, 4)
		dial := func(context.Context) (net.Conn, error) {
			a, b := net.Pipe()
			guests <- b
			return a, nil
		}
		proxy := NewProxy(lis, dial, quietLogger())

		rec := &callLog{}
		m := newFakeMachine(rec)
		timers := newTimerSet()
		clock := &fakeClock{}
		agent := newGateAgent(rec)
		lc := NewLifecycle(m, agent, LifecycleOptions{
			Grace: grace, Logger: quietLogger(), NewTimer: timers.new, Now: clock.now,
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- RunWithProxy(ctx, lc, proxy) }()
		waitForState(t, lc, StateRunning)

		cancel()
		deadline := timers.next(t)
		waitForState(t, lc, StateStopping)

		client, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial the agent socket during Stopping: %v; the proxy closed on the signal", err)
		}
		defer func() { _ = client.Close() }()
		guest := <-guests
		go func() { _, _ = client.Write([]byte("ping")) }()
		if got := readN(t, guest, 4); got != "ping" {
			t.Fatalf("relayed %q during Stopping, want %q", got, "ping")
		}

		deadline.fire()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("RunWithProxy: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("RunWithProxy did not return after the hard stop; the proxy did not drain")
		}
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			t.Error("the agent socket still accepts after the machine was halted")
		}
	})
}

// waitFor polls cond until it holds, failing with msg on timeout.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}
