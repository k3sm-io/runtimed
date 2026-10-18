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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
)

// TestShortenGraceSignalReachesTheGuest is B718's gate: a stopper whose bound
// is shorter than a pod's grace asks the helper, on its real control socket and
// before any SIGTERM, to start the stop with the grace that fits, and that
// grace is what the guest agent is sent and what the helper's clock runs on.
//
// Everything between the request and the agent is production code: the
// daemon's client (sandbox.ShortenVMHostStop), the helper's server
// (sandbox.ServeVMHostControlStop, as cmd/k3sm-vmhost wires it), the shared
// formula (sandbox.ShortenedStopGrace) and the lifecycle's one shutdown path.
// Only the machine and the agent are fakes. The run context is never
// cancelled in the first case, so the stop can only have come from the request.
func TestShortenGraceSignalReachesTheGuest(t *testing.T) {
	const bound = 45 * time.Second // the stop-all bound
	cut := bound - sandbox.VMHelperStopMargin

	t.Run("a request before SIGTERM starts the stop with the shortened grace", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		sent := make(chan time.Duration, 2)
		agent := &fakeAgent{rec: rec, onStop: func(g time.Duration) { sent <- g; m.exit <- nil }}
		timers := newManualTimer()
		lc := NewLifecycle(m, agent, LifecycleOptions{Grace: 90 * time.Second, Logger: quietLogger(), NewTimer: timers.new})
		socket := serveControl(t, lc)

		done := make(chan error, 1)
		go func() { done <- lc.Run(context.Background()) }()
		waitForState(t, lc, StateRunning)

		out, err := sandbox.ShortenVMHostStop(context.Background(), socket, os.Getpid(), bound)
		if err != nil {
			t.Fatalf("ShortenVMHostStop: %v", err)
		}
		if out.Result != sandbox.VMHostShortened || out.From != 90*time.Second || out.To != cut {
			t.Fatalf("outcome = %+v, want shortened from 90s to %s", out, cut)
		}
		if g := recv(t, sent); g != cut {
			t.Errorf("the guest agent was sent %s, want the shortened %s", g, cut)
		}
		if d := recv(t, timers.asked); d != cut+GuestStopReserve {
			t.Errorf("the helper's clock was armed for %s, want the shortened grace plus the reserve %s", d, cut+GuestStopReserve)
		}
		if err := recvErr(t, done); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if lc.State() != StateStopped {
			t.Errorf("state = %v, want Stopped", lc.State())
		}
	})

	t.Run("a late request is a no-op", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		sent := make(chan time.Duration, 2)
		agent := &fakeAgent{rec: rec, onStop: func(g time.Duration) { sent <- g }}
		timers := newManualTimer()
		lc := NewLifecycle(m, agent, LifecycleOptions{Grace: 90 * time.Second, Logger: quietLogger(), NewTimer: timers.new})
		socket := serveControl(t, lc)

		ctx, sigterm := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)
		sigterm()
		if g := recv(t, sent); g != 90*time.Second {
			t.Fatalf("the SIGTERM stop sent %s, want the full 90s", g)
		}

		out, err := sandbox.ShortenVMHostStop(context.Background(), socket, os.Getpid(), bound)
		if err != nil {
			t.Fatalf("ShortenVMHostStop: %v", err)
		}
		if out.Result != sandbox.VMHostAlreadyStopping || out.From != 90*time.Second {
			t.Errorf("outcome = %+v, want already-stopping at 90s", out)
		}
		select {
		case g := <-sent:
			t.Errorf("a late request reached the guest again with %s", g)
		case <-time.After(50 * time.Millisecond):
		}
		if d := recv(t, timers.asked); d != 90*time.Second+GuestStopReserve {
			t.Errorf("the clock was armed for %s, want the unshortened %s", d, 90*time.Second+GuestStopReserve)
		}
		timers.fire()
		if err := recvErr(t, done); err != nil {
			t.Fatalf("Run: %v", err)
		}
		select {
		case d := <-timers.asked:
			t.Errorf("a late request re-armed the clock for %s", d)
		default:
		}
	})

	t.Run("the grace is never extended", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		sent := make(chan time.Duration, 2)
		agent := &fakeAgent{rec: rec, onStop: func(g time.Duration) { sent <- g; m.exit <- nil }}
		lc := NewLifecycle(m, agent, LifecycleOptions{Grace: 10 * time.Second, Logger: quietLogger()})
		socket := serveControl(t, lc)

		done := make(chan error, 1)
		go func() { done <- lc.Run(context.Background()) }()
		waitForState(t, lc, StateRunning)

		out, err := sandbox.ShortenVMHostStop(context.Background(), socket, os.Getpid(), bound)
		if err != nil {
			t.Fatalf("ShortenVMHostStop: %v", err)
		}
		if out.Result != sandbox.VMHostShortened || out.To != 10*time.Second {
			t.Errorf("outcome = %+v, want the 10s grace kept", out)
		}
		if g := recv(t, sent); g != 10*time.Second {
			t.Errorf("the guest agent was sent %s, want the unextended 10s", g)
		}
		if err := recvErr(t, done); err != nil {
			t.Fatalf("Run: %v", err)
		}
	})

	t.Run("a bound below the floor is refused", func(t *testing.T) {
		rec := &callLog{}
		m := newFakeMachine(rec)
		lc := NewLifecycle(m, &fakeAgent{rec: rec}, LifecycleOptions{Grace: 90 * time.Second, Logger: quietLogger()})
		socket := serveControl(t, lc)

		ctx, sigterm := context.WithCancel(context.Background())
		defer sigterm()
		done := make(chan error, 1)
		go func() { done <- lc.Run(ctx) }()
		waitForState(t, lc, StateRunning)

		low := sandbox.VMHostMinShortenBound - time.Millisecond
		if _, err := sandbox.ShortenVMHostStop(context.Background(), socket, os.Getpid(), low); !errors.Is(err, sandbox.ErrVMHostShortenBound) {
			t.Errorf("the client sent a bound below the floor: err = %v", err)
		}
		// The helper refuses it too, whoever sends it.
		if got := rawShorten(t, socket, low); got != "refused" {
			t.Errorf("the helper answered a bound below the floor with %q, want refused", got)
		}
		if s := lc.State(); s != StateRunning {
			t.Errorf("state = %v after a refused request, want Running: nothing may start", s)
		}
		if calls := rec.snapshot(); len(calls) != 1 {
			t.Errorf("calls = %v, want only machine.Start", calls)
		}
		sigterm()
		m.exit <- nil
		<-done
	})
}

// serveControl serves lc's control socket as cmd/k3sm-vmhost does, from this
// process, and returns its path.
func serveControl(t *testing.T, lc *Lifecycle) string {
	t.Helper()
	// A short directory: a unix socket path is capped near 104 bytes.
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, sandbox.VMHostControlSocketName)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		_ = sandbox.ServeVMHostControlStop(lis, sandbox.VMHostControl{
			Version: sandbox.VMHostVersion{Protocol: sandbox.VMHostProtocolVersion, Pid: os.Getpid()},
			Stop:    lc,
			PodID:   "p1",
			Logger:  quietLogger(),
		})
	}()
	return socket
}

// rawShorten sends a shorten request by hand, bypassing the client's own
// floor check, and returns the helper's result.
func rawShorten(t *testing.T, socket string, bound time.Duration) string {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadBytes('\n'); err != nil {
		t.Fatalf("banner: %v", err)
	}
	req, _ := json.Marshal(map[string]any{"op": "shorten-stop", "boundNanos": int64(bound)})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		t.Fatalf("request: %v", err)
	}
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	var rep struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(line, &rep); err != nil {
		t.Fatalf("decode reply %q: %v", line, err)
	}
	return rep.Result
}

func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
		var zero T
		return zero
	}
}

func recvErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	return recv(t, ch)
}
