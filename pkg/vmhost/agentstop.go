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
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	guestv1 "k3sm.io/apis/guest/v1"
)

// guestStopper is the production agentStopper: one guest/v1 Stop RPC over the
// same vsock transport the proxy relays.
//
// this IS the one place the HELPER SPEAKS gRPC, and it is deliberately not the
// proxy (see Proxy's doc for why the relay stays a byte pump). The asymmetry is
// the point: the helper ORIGINATES exactly one call, to a message type it
// controls, and never PARSES anything a guest chose to send it — the Stop response
// is empty by contract, so there is no guest-shaped data to interpret.
type guestStopper struct {
	dial vsockDialer

	// onRunning is a test seam, nil in production: when set, the request
	// goroutine calls it as its first act, before the call that signals Stop
	// to return, so a test can see what Stop's return is ordered after.
	onRunning func()
}

// NewAgentStopper builds the guest-agent stop seam over dial. It is used by
// cmd/k3sm-vmhost to give the lifecycle its graceful leg.
func NewAgentStopper(dial vsockDialer) agentStopper { return &guestStopper{dial: dial} }

// Stop asks the guest to terminate its containers within grace, then sync and
// power off.
//
// The grace it SENDS is the grace it was given: the lifecycle's clamped budget
// (MaxStopGrace), already rounded to whole seconds with a floor of one
// (guestGrace), and the lifecycle leaves GuestStopReserve past it before the hard
// stop. guest.proto says the host clamps before sending "so the guest can treat
// it as already-budgeted", and this is that promise being kept. The
// int32 conversion is saturated rather than truncated: a wrapped negative grace
// would read to the guest as "kill immediately", turning a clamping bug into data
// loss.
//
// The RPC runs on its own goroutine, and Stop returns once the dial to the guest
// agent has begun: the moment the gRPC client first calls the vsock dialer, so
// the request is under way before the caller can reach its hard stop (see
// agentStopper). If the call ends without ever dialing (the client could not be
// built, or ctx was already done), Stop returns when it ends instead, so it
// never waits on a dial that will not come. The outcome is the one value on the
// returned channel.
func (s *guestStopper) Stop(ctx context.Context, grace time.Duration) <-chan error {
	done := make(chan error, 1)
	finished := make(chan struct{})
	dialing := make(chan struct{})
	var once sync.Once
	began := func() { once.Do(func() { close(dialing) }) }
	go func() {
		if s.onRunning != nil {
			s.onRunning()
		}
		defer close(finished)
		done <- s.call(ctx, grace, began)
	}()
	select {
	case <-dialing:
	case <-finished:
	}
	return done
}

// call is the one guest/v1 Stop RPC. began is called each time the client
// opens a connection to the agent, before the vsock dial itself; the caller
// makes it idempotent.
//
// A fresh connection per call, closed here: this call happens once per machine
// lifetime, on the way out.
func (s *guestStopper) call(ctx context.Context, grace time.Duration, began func()) error {
	conn, err := grpc.NewClient("passthrough:///guest-agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(dctx context.Context, _ string) (net.Conn, error) {
			began()
			return s.dial(dctx)
		}),
	)
	if err != nil {
		return fmt.Errorf("dial the guest agent: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := guestv1.NewGuestAgentClient(conn).Stop(ctx, &guestv1.StopRequest{
		GraceSeconds: graceSeconds(grace),
	}); err != nil {
		return fmt.Errorf("guest agent Stop: %w", err)
	}
	return nil
}

// graceSeconds converts a grace duration to the proto's int32 seconds, saturating
// at both ends. See Stop for why saturation rather than truncation.
func graceSeconds(d time.Duration) int32 {
	if d <= 0 {
		return 0
	}
	secs := int64(d / time.Second)
	if secs > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(secs)
}
