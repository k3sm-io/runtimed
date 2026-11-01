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
	"math"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	guestv1 "k3sm.io/apis/guest/v1"
)

// stopAgent is an in-process guest agent that serves only Stop. Each request is
// handed to the test on got; with block set, the handler holds the call open
// until its context ends and then closes cancelled, so a case can see the
// client's cancel arrive on the server side.
type stopAgent struct {
	guestv1.UnimplementedGuestAgentServer
	block     bool
	got       chan *guestv1.StopRequest
	cancelled chan struct{}
}

func (a *stopAgent) Stop(ctx context.Context, req *guestv1.StopRequest) (*guestv1.StopResponse, error) {
	a.got <- req
	if a.block {
		<-ctx.Done()
		close(a.cancelled)
		return nil, ctx.Err()
	}
	return &guestv1.StopResponse{}, nil
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

func newStopAgent(block bool) *stopAgent {
	return &stopAgent{block: block, got: make(chan *guestv1.StopRequest, 1), cancelled: make(chan struct{})}
}

// TestGuestStopperIssuesStopRPC drives the production agentStopper,
// NewAgentStopper, over a real gRPC connection to an in-process guest agent:
// the Stop RPC arrives carrying the grace graceSeconds computes, graceSeconds
// saturates at both bounds, and a Stop whose context is cancelled while the
// guest holds the call returns with the one outcome on its channel, the server
// having seen the cancel.
//
// Every wait is a plain channel receive with no wall-clock bound: a Stop that
// never reaches the guest, or never delivers its outcome, hangs the case and
// the go test timeout reports it with every goroutine's stack.
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

				req := <-agent.got
				if got := req.GetGraceSeconds(); got != tc.want {
					t.Errorf("Stop RPC grace_seconds = %d, want %d", got, tc.want)
				}
				if got, computed := req.GetGraceSeconds(), graceSeconds(tc.grace); got != computed {
					t.Errorf("Stop RPC grace_seconds = %d, graceSeconds(%v) = %d", got, tc.grace, computed)
				}
				if err := <-done; err != nil {
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

		<-agent.got
		select {
		case err := <-done:
			t.Fatalf("Stop delivered %v while the guest still held the call", err)
		default:
		}

		cancel()

		// The handler holds the call until its context ends, so it closes
		// cancelled only once the client's cancel has crossed the wire.
		<-agent.cancelled
		// Receiving the outcome is what proves the RPC goroutine finished: it
		// sends exactly once, as its last act, so a drained channel leaves
		// nothing behind.
		err := <-done
		if code := status.Code(err); code != codes.Canceled {
			t.Errorf("Stop outcome = %v (code %v), want codes.Canceled", err, code)
		}
	})
}
