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
	"math"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	guestv1 "k3sm.io/apis/guest/v1"
)

// stopAgent is an in-process guest agent that serves only Stop. Each request is
// handed to the test on got. With release nil the handler answers at once;
// otherwise it holds the call open until the test closes release (an accepted
// request) or the call's context ends, in which case it closes cancelled, so a
// case can see the client's cancel arrive on the server side.
type stopAgent struct {
	guestv1.UnimplementedGuestAgentServer
	fail      error // when set, the handler returns it once the request is in
	got       chan *guestv1.StopRequest
	release   chan struct{}
	cancelled chan struct{}
}

func (a *stopAgent) Stop(ctx context.Context, req *guestv1.StopRequest) (*guestv1.StopResponse, error) {
	a.got <- req
	if a.fail != nil {
		return nil, a.fail
	}
	if a.release == nil {
		return &guestv1.StopResponse{}, nil
	}
	select {
	case <-a.release:
		return &guestv1.StopResponse{}, nil
	case <-ctx.Done():
		close(a.cancelled)
		return nil, ctx.Err()
	}
}

// serveStopAgent runs agent on a bufconn and returns the vsockDialer that
// reaches it, the same seam the VZ machine hands NewAgentStopper. No VM, no
// vsock: the bytes cross an in-memory pipe, the gRPC on either side is real.
func serveStopAgent(t *testing.T, agent *stopAgent) vsockDialer {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	guestv1.RegisterGuestAgentServer(srv, agent)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(lis) // returns once Stop below closes the listener
	}()
	t.Cleanup(func() {
		srv.Stop()
		<-served
	})
	return func(ctx context.Context) (net.Conn, error) { return lis.DialContext(ctx) }
}

// newStopAgent returns a stopAgent; with block set it holds each call open
// until release is closed or the call's context ends.
func newStopAgent(block bool) *stopAgent {
	a := &stopAgent{got: make(chan *guestv1.StopRequest, 1), cancelled: make(chan struct{})}
	if block {
		a.release = make(chan struct{})
	}
	return a
}

// countDials wraps dial so a test can see how many times the client dialed.
func countDials(dial vsockDialer) (vsockDialer, *atomic.Int32) {
	var dialed atomic.Int32
	return func(ctx context.Context) (net.Conn, error) {
		dialed.Add(1)
		return dial(ctx)
	}, &dialed
}

// startBlockingAgent serves a blocking stopAgent and returns it with a
// counting vsockDialer onto it.
func startBlockingAgent(t *testing.T) (*stopAgent, vsockDialer, *atomic.Int32) {
	t.Helper()
	agent := newStopAgent(true)
	dial, dialed := countDials(serveStopAgent(t, agent))
	return agent, dial, dialed
}

// stopWatchdog bounds every wait in these tests. It is a hang guard, not a
// latency bound: generous enough that no loaded machine reaches it, so a red
// from it names a wait that would never have ended.
const stopWatchdog = 60 * time.Second

// await receives one value from ch, failing with what (the thing awaited) if
// the watchdog fires first, so a regression that never delivers is a named
// failure instead of a hang.
func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	timer := time.NewTimer(stopWatchdog)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v
	case <-timer.C:
		t.Fatalf("watchdog: %s did not arrive within %v", what, stopWatchdog)
		var zero T
		return zero
	}
}

// countingConn counts Close calls on the connection the stopper dialed, so a
// case can see the deferred conn.Close in call reach the transport.
type countingConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c countingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// countingDialer wraps dial so every connection it returns counts its closes
// into closes.
func countingDialer(dial vsockDialer, closes *atomic.Int32) vsockDialer {
	return func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return countingConn{Conn: c, closes: closes}, nil
	}
}

// TestGuestStopperIssuesStopRPC drives the production agentStopper,
// NewAgentStopper, over a real gRPC connection to an in-process guest agent:
// the Stop RPC arrives carrying the grace graceSeconds computes, graceSeconds
// saturates at both bounds, and a Stop whose context is cancelled while the
// guest holds the call returns with the one outcome on its channel, the server
// having seen the cancel.
//
// Every wait goes through await: no latency bound, only the generous
// watchdog, so a Stop that never reaches the guest, or never delivers its
// outcome, fails naming the wait instead of hanging the package.
func TestGuestStopperIssuesStopRPC(t *testing.T) {
	t.Run("the-rpc-carries-the-computed-grace", func(t *testing.T) {
		cases := []struct {
			name  string
			grace time.Duration
			want  int32
		}{
			{"whole-seconds-truncate", 7*time.Second + 900*time.Millisecond, 7},
			{"zero", 0, 0},
			{"saturates-high", time.Duration(math.MaxInt64), math.MaxInt32},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				agent := newStopAgent(false)
				stopper := NewAgentStopper(serveStopAgent(t, agent))

				done := stopper.Stop(t.Context(), tc.grace)

				req := await(t, agent.got, "the Stop request at the guest")
				if got := req.GetGraceSeconds(); got != tc.want {
					t.Errorf("Stop RPC grace_seconds = %d, want %d", got, tc.want)
				}
				if got, computed := req.GetGraceSeconds(), graceSeconds(tc.grace); got != computed {
					t.Errorf("Stop RPC grace_seconds = %d, graceSeconds(%v) = %d", got, tc.grace, computed)
				}
				if err := await(t, done, "the Stop outcome"); err != nil {
					t.Errorf("Stop outcome = %v, want nil for an accepted request", err)
				}
			})
		}
	})

	t.Run("graceSeconds-saturates", func(t *testing.T) {
		cases := []struct {
			name string
			in   time.Duration
			want int32
		}{
			{"min-int64", time.Duration(math.MinInt64), 0},
			{"negative", -time.Second, 0},
			{"zero", 0, 0},
			{"sub-second", 999 * time.Millisecond, 0},
			{"one-second", time.Second, 1},
			{"fraction-truncates", 1500 * time.Millisecond, 1},
			{"max-int32-seconds", math.MaxInt32 * time.Second, math.MaxInt32},
			{"one-past-max-int32", (math.MaxInt32 + 1) * time.Second, math.MaxInt32},
			{"max-int64", time.Duration(math.MaxInt64), math.MaxInt32},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := graceSeconds(tc.in); got != tc.want {
					t.Errorf("graceSeconds(%v) = %d, want %d", tc.in, got, tc.want)
				}
			})
		}
	})

	t.Run("cancel-ends-the-call", func(t *testing.T) {
		agent := newStopAgent(true)
		stopper := NewAgentStopper(serveStopAgent(t, agent))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// Stop returns while the guest still holds the call: the request has
		// started, its outcome is not in yet.
		done := stopper.Stop(ctx, 5*time.Second)

		await(t, agent.got, "the Stop request at the guest")
		select {
		case err := <-done:
			t.Fatalf("Stop delivered %v while the guest still held the call", err)
		default:
		}

		cancel()

		// The handler holds the call until its context ends, so it closes
		// cancelled only once the client's cancel has crossed the wire.
		await(t, agent.cancelled, "the cancel at the guest")
		// Receiving the outcome is what proves the RPC goroutine finished: it
		// sends exactly once, as its last act, so a drained channel leaves
		// nothing behind.
		err := await(t, done, "the Stop outcome")
		if code := status.Code(err); code != codes.Canceled {
			t.Errorf("Stop outcome = %v (code %v), want codes.Canceled", err, code)
		}
	})
}

// TestGuestStopperStartsRPCBeforeStopReturns pins Stop's handshake: when Stop
// returns, the request goroutine is already running (it has begun the dial, or
// the call has ended). The onRunning seam is the goroutine's first act; it
// writes ran with no synchronisation of its own, so the only thing ordering
// that write before the read below is the handshake. Without it the read finds
// ran false, and under -race the unordered pair is a reported race either way.
func TestGuestStopperStartsRPCBeforeStopReturns(t *testing.T) {
	agent := newStopAgent(false)
	ran := false
	stopper := &guestStopper{
		dial:      serveStopAgent(t, agent),
		onRunning: func() { ran = true },
	}

	done := stopper.Stop(t.Context(), time.Second)
	if !ran {
		t.Error("Stop returned before the request goroutine was running")
	}

	await(t, agent.got, "the Stop request at the guest")
	if err := await(t, done, "the Stop outcome"); err != nil {
		t.Errorf("Stop outcome = %v, want nil for an accepted request", err)
	}
}

// TestGuestStopperErrorOutcomes drives call's failure paths and pins that each
// failure is the one value on the outcome channel, never nil, wrapped under the
// "guest agent Stop: " prefix with its gRPC status intact, and that a
// connection the stopper dialed is closed by the time the outcome arrives.
//
// call's other prefix, "dial the guest agent: ", wraps a grpc.NewClient
// failure, which a fixed passthrough target with valid options cannot produce;
// it is not reachable from a dialer and is not asserted here.
func TestGuestStopperErrorOutcomes(t *testing.T) {
	const prefix = "guest agent Stop: "

	t.Run("failing-dialer", func(t *testing.T) {
		dialErr := errors.New("vsock connect refused by the test")
		var dials atomic.Int32
		stopper := NewAgentStopper(func(context.Context) (net.Conn, error) {
			dials.Add(1)
			return nil, dialErr
		})

		err := await(t, stopper.Stop(t.Context(), time.Second), "the Stop outcome")
		if err == nil {
			t.Fatal("Stop outcome = nil, want the dial failure")
		}
		if !strings.HasPrefix(err.Error(), prefix) {
			t.Errorf("Stop outcome %q lacks the %q prefix", err, prefix)
		}
		if code := status.Code(err); code != codes.Unavailable {
			t.Errorf("Stop outcome code = %v, want codes.Unavailable for a dial failure", code)
		}
		if !strings.Contains(err.Error(), dialErr.Error()) {
			t.Errorf("Stop outcome %q does not carry the dial error %q", err, dialErr)
		}
		if dials.Load() == 0 {
			t.Error("the dialer was never called")
		}
	})

	for _, code := range []codes.Code{codes.Internal, codes.Unavailable} {
		t.Run("handler-returns-"+code.String(), func(t *testing.T) {
			want := status.Error(code, "guest refused the stop")
			agent := newStopAgent(false)
			agent.fail = want
			var closes atomic.Int32
			stopper := NewAgentStopper(countingDialer(serveStopAgent(t, agent), &closes))

			done := stopper.Stop(t.Context(), time.Second)
			await(t, agent.got, "the Stop request at the guest")
			err := await(t, done, "the Stop outcome")

			if err == nil {
				t.Fatalf("Stop outcome = nil, want the guest's %v", code)
			}
			if !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("Stop outcome %q lacks the %q prefix", err, prefix)
			}
			if got := status.Code(err); got != code {
				t.Errorf("Stop outcome code = %v, want %v", got, code)
			}
			if !errors.Is(err, want) {
				t.Errorf("Stop outcome %v does not wrap the guest's status %v", err, want)
			}
			if n := closes.Load(); n == 0 {
				t.Error("the dialed connection was not closed by the time the outcome arrived")
			}
		})
	}

	t.Run("success-closes-the-connection", func(t *testing.T) {
		agent := newStopAgent(false)
		var closes atomic.Int32
		stopper := NewAgentStopper(countingDialer(serveStopAgent(t, agent), &closes))

		done := stopper.Stop(t.Context(), time.Second)
		await(t, agent.got, "the Stop request at the guest")
		if err := await(t, done, "the Stop outcome"); err != nil {
			t.Fatalf("Stop outcome = %v, want nil for an accepted request", err)
		}
		if n := closes.Load(); n == 0 {
			t.Error("the dialed connection was not closed by the time the outcome arrived")
		}
	})
}

// stopWithin calls s.Stop and fails the test if it does not return promptly: a
// Stop that waited for the RPC would otherwise hang the test instead of failing
// it.
func stopWithin(t *testing.T, s agentStopper, ctx context.Context, grace time.Duration) <-chan error {
	t.Helper()
	returned := make(chan (<-chan error), 1)
	go func() { returned <- s.Stop(ctx, grace) }()
	select {
	case done := <-returned:
		return done
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return while the call was still in flight")
		return nil
	}
}

// TestGuestStopperStopReturnsBeforeTheCall pins the production agentStopper to
// the seam's contract: Stop returns while the RPC is still in flight, and does
// not wait on a dial that hangs; the channel then delivers exactly one value;
// and a ctx already done before Stop still returns an error rather than a hang.
// A ctx cancelled mid-call is TestGuestStopperIssuesStopRPC's
// cancel-ends-the-call case.
func TestGuestStopperStopReturnsBeforeTheCall(t *testing.T) {
	t.Run("returns-before-the-rpc-completes-and-delivers-one-value", func(t *testing.T) {
		agent, dial, dialed := startBlockingAgent(t)
		done := stopWithin(t, NewAgentStopper(dial), context.Background(), 7*time.Second)

		select {
		case err := <-done:
			t.Fatalf("Stop's channel delivered %v before the agent answered", err)
		default:
		}

		if got := (<-agent.got).GetGraceSeconds(); got != 7 {
			t.Errorf("grace sent = %d s, want 7", got)
		}
		// The handler holds the RPC open: still no outcome.
		select {
		case err := <-done:
			t.Fatalf("Stop's channel delivered %v while the RPC was still open", err)
		default:
		}

		if n := dialed.Load(); n != 1 {
			t.Errorf("the agent was dialed %d times, want 1", n)
		}
		close(agent.release)
		if err := <-done; err != nil {
			t.Fatalf("Stop outcome = %v, want nil for an accepted request", err)
		}
		select {
		case err, ok := <-done:
			t.Fatalf("Stop's channel delivered a second value (%v, open=%v); want exactly one", err, ok)
		case <-time.After(20 * time.Millisecond):
		}
	})

	t.Run("a-wedged-dial-does-not-hold-stop", func(t *testing.T) {
		// Stop waits for the dial to BEGIN, never for it to finish: a vsock dial
		// that hangs must not hang the shutdown that is about to fall back to
		// the hard stop.
		entered := make(chan struct{})
		dial := func(ctx context.Context) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := stopWithin(t, NewAgentStopper(dial), ctx, time.Second)
		<-entered
		select {
		case err := <-done:
			t.Fatalf("Stop's channel delivered %v while the dial was still wedged", err)
		default:
		}
		cancel()
		if err := <-done; err == nil {
			t.Fatal("Stop outcome = nil for a dial that never connected, want an error")
		}
	})

	t.Run("an-already-cancelled-ctx-returns-without-waiting-for-a-dial", func(t *testing.T) {
		// A ctx done before Stop may mean the client never dials at all; Stop
		// must then return on the call's end, not wait for a dial that never
		// comes.
		_, dial, _ := startBlockingAgent(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := stopWithin(t, NewAgentStopper(dial), ctx, time.Second)
		if err := <-done; err == nil {
			t.Fatal("Stop outcome = nil for an already-cancelled ctx, want an error")
		}
	})
}
