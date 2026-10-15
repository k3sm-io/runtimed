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

package guestagent

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guestv1 "k3sm.io/apis/guest/v1"
)

// fakeRestarter records what the agent asked the executor to restart. block,
// when set, holds the call until it is closed, which is how a test keeps a
// restart in flight.
type fakeRestarter struct {
	err   error
	block chan struct{}

	mu       sync.Mutex
	calls    []string
	grace    time.Duration
	ctxAlive bool
	entered  chan struct{}
}

func (r *fakeRestarter) RestartContainer(ctx context.Context, container string, grace time.Duration) error {
	r.mu.Lock()
	r.calls = append(r.calls, container)
	r.grace = grace
	entered, block := r.entered, r.block
	r.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if block != nil {
		<-block
	}
	r.mu.Lock()
	r.ctxAlive = ctx.Err() == nil
	r.mu.Unlock()
	return r.err
}

func (r *fakeRestarter) snapshot() ([]string, time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...), r.grace, r.ctxAlive
}

// TestGuestAgentRestartContainer pins the agent's half of the in-guest restart:
// the single-pod and roster checks every RPC makes, the grace clamp, the
// mapping of the executor's answer onto a status, and the one-restart-per-
// container rule.
func TestGuestAgentRestartContainer(t *testing.T) {
	const podID = "pod-booted"

	t.Run("restarts-the-named-container-with-the-clamped-grace", func(t *testing.T) {
		rs := &fakeRestarter{}
		client := testAgent(t, podID, Deps{Runner: &fakeRunner{names: []string{"app", "side"}}, Restarter: rs})
		if _, err := client.RestartContainer(context.Background(), &guestv1.RestartContainerRequest{
			PodId: podID, Container: "side", GraceSeconds: 99999,
		}); err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		calls, grace, _ := rs.snapshot()
		if len(calls) != 1 || calls[0] != "side" {
			t.Errorf("executor calls = %v, want [side]", calls)
		}
		if grace != maxStopGraceSeconds*time.Second {
			t.Errorf("grace = %v, want the guest's clamp %v", grace, maxStopGraceSeconds*time.Second)
		}
	})

	for _, tc := range []struct {
		name      string
		req       *guestv1.RestartContainerRequest
		restarter Restarter
		want      codes.Code
	}{
		{"a-foreign-pod-id", &guestv1.RestartContainerRequest{PodId: "pod-someone-else", Container: "app"}, &fakeRestarter{}, codes.InvalidArgument},
		{"an-undeclared-container", &guestv1.RestartContainerRequest{PodId: podID, Container: "ghost"}, &fakeRestarter{}, codes.NotFound},
		{"no-executor", &guestv1.RestartContainerRequest{PodId: podID, Container: "app"}, nil, codes.Unimplemented},
		{"the-executor-does-not-know-it", &guestv1.RestartContainerRequest{PodId: podID, Container: "app"},
			&fakeRestarter{err: fmt.Errorf("%w: app", ErrNotFound)}, codes.NotFound},
		{"the-start-failed", &guestv1.RestartContainerRequest{PodId: podID, Container: "app"},
			&fakeRestarter{err: fmt.Errorf("start container app: exec format error")}, codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testAgent(t, podID, Deps{Restarter: tc.restarter})
			_, err := client.RestartContainer(context.Background(), tc.req)
			if got := status.Code(err); got != tc.want {
				t.Errorf("code = %v (%v), want %v", got, err, tc.want)
			}
		})
	}

	t.Run("a-second-restart-of-the-same-container-is-refused-while-one-is-in-flight", func(t *testing.T) {
		rs := &fakeRestarter{block: make(chan struct{}), entered: make(chan struct{}, 2)}
		client := testAgent(t, podID, Deps{Restarter: rs})
		first := make(chan error, 1)
		go func() {
			_, err := client.RestartContainer(context.Background(), &guestv1.RestartContainerRequest{PodId: podID, Container: "app"})
			first <- err
		}()
		<-rs.entered
		_, err := client.RestartContainer(context.Background(), &guestv1.RestartContainerRequest{PodId: podID, Container: "app"})
		if got := status.Code(err); got != codes.FailedPrecondition {
			t.Errorf("concurrent restart code = %v (%v), want FailedPrecondition", got, err)
		}
		close(rs.block)
		if err := <-first; err != nil {
			t.Fatalf("first restart: %v", err)
		}
		// The claim is released with the restart, so the next one proceeds.
		rs.mu.Lock()
		rs.block = nil
		rs.mu.Unlock()
		if _, err := client.RestartContainer(context.Background(), &guestv1.RestartContainerRequest{PodId: podID, Container: "app"}); err != nil {
			t.Errorf("restart after the first concluded: %v", err)
		}
	})

	t.Run("the-restart-outlives-a-client-that-goes-away", func(t *testing.T) {
		// A stop without its start is a dead container, so the client's cancel
		// must not reach the executor.
		rs := &fakeRestarter{block: make(chan struct{}), entered: make(chan struct{}, 1)}
		client := testAgent(t, podID, Deps{Restarter: rs})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = client.RestartContainer(ctx, &guestv1.RestartContainerRequest{PodId: podID, Container: "app"})
		}()
		<-rs.entered
		cancel()
		<-done
		close(rs.block)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if calls, _, alive := rs.snapshot(); len(calls) == 1 && alive {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("the executor saw the client's cancellation; a restart must not be torn in half")
	})
}

// TestCaptureResetStartsAFreshInstance pins the capture half of a restart: the
// old instance's rings were closed by its exit, and a closed ring drops what is
// appended to it, so without Reset the new instance's output is lost.
func TestCaptureResetStartsAFreshInstance(t *testing.T) {
	c := NewCapture(0, 0, 0)
	w := c.Writer("app", StreamStdout)
	_, _ = w.Write([]byte("old\n"))
	c.Close("app")

	c.Reset("app")
	w = c.Writer("app", StreamStdout)
	_, _ = w.Write([]byte("new\n"))
	_ = w.Close()

	ch, cancel, err := c.Stream(context.Background(), "app", Selector{})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer cancel()
	var lines []string
	for e := range ch {
		lines = append(lines, string(e.Line))
	}
	if len(lines) != 1 || lines[0] != "new" {
		t.Errorf("lines = %q, want only the new instance's output", lines)
	}
}
