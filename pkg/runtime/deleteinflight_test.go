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

package runtime

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// gatedNetwork is a recordingNetwork whose Teardown parks until the test
// opens the gate, holding DeletePod inside its teardown (the network release
// runs in stopHostPod's swept step). entered is closed when the first
// Teardown arrives.
type gatedNetwork struct {
	recordingNetwork

	once    sync.Once
	entered chan struct{}
	gate    chan struct{}
}

func newGatedNetwork() *gatedNetwork {
	return &gatedNetwork{entered: make(chan struct{}), gate: make(chan struct{})}
}

func (n *gatedNetwork) Teardown(podID string) error {
	n.once.Do(func() { close(n.entered) })
	<-n.gate
	return n.recordingNetwork.Teardown(podID)
}

type deleteResult struct {
	resp *runtimev1.DeletePodResponse
	err  error
}

// startDelete runs DeletePod for podID on its own goroutine and returns the
// channel its result arrives on.
func startDelete(ctx context.Context, rt *Runtime, podID string) <-chan deleteResult {
	ch := make(chan deleteResult, 1)
	go func() {
		resp, err := rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: podID})
		ch <- deleteResult{resp: resp, err: err}
	}()
	return ch
}

// awaitDelete waits a bounded time for a DeletePod result.
func awaitDelete(t *testing.T, ch <-chan deleteResult, what string) deleteResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: DeletePod did not return", what)
		return deleteResult{}
	}
}

// heldDelete creates a host pod and starts a DeletePod for it that is held
// inside its network teardown until the returned network's gate is opened.
func heldDelete(t *testing.T, podID string) (*Runtime, *gatedNetwork, <-chan deleteResult) {
	t.Helper()
	pn := newGatedNetwork()
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Network: pn, Waiter: w})
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)}); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	w.release(1001)
	first := startDelete(context.Background(), rt, podID)
	select {
	case <-pn.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first DeletePod never reached its network teardown")
	}
	return rt, pn, first
}

// TestSecondDeletePodWaitsForTheFirstTeardown: a DeletePod for a pod whose
// teardown is already running must not report success before that teardown
// has finished — a caller that retries after its deadline reads success as
// "torn down".
func TestSecondDeletePodWaitsForTheFirstTeardown(t *testing.T) {
	const podID = "pod-twice"

	t.Run("second-waits-and-returns-the-first-result", func(t *testing.T) {
		rt, pn, first := heldDelete(t, podID)

		second := startDelete(context.Background(), rt, podID)
		select {
		case res := <-second:
			t.Fatalf("second DeletePod returned (%v, %v) while the first teardown was still running", res.resp, res.err)
		case <-time.After(100 * time.Millisecond):
		}

		close(pn.gate)
		f := awaitDelete(t, first, "first")
		s := awaitDelete(t, second, "second")
		if f.err != nil || f.resp == nil {
			t.Fatalf("first DeletePod = (%v, %v), want success", f.resp, f.err)
		}
		if s.err != f.err || (s.resp == nil) != (f.resp == nil) {
			t.Fatalf("second DeletePod = (%v, %v), want the first's result (%v, %v)", s.resp, s.err, f.resp, f.err)
		}
		if got := pn.teardownCalls(); len(got) != 1 {
			t.Fatalf("network Teardown calls = %v, want exactly one", got)
		}
	})

	t.Run("second-with-short-deadline-returns-deadline-error", func(t *testing.T) {
		rt, pn, first := heldDelete(t, podID)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		s := awaitDelete(t, startDelete(ctx, rt, podID), "second")
		if code := status.Code(s.err); code != codes.DeadlineExceeded {
			t.Fatalf("second DeletePod = (%v, %v), want a DeadlineExceeded status, not success", s.resp, s.err)
		}

		close(pn.gate)
		if f := awaitDelete(t, first, "first"); f.err != nil {
			t.Fatalf("first DeletePod: %v", f.err)
		}
	})

	t.Run("record-is-gone-after-the-teardown", func(t *testing.T) {
		rt, pn, first := heldDelete(t, podID)
		close(pn.gate)
		if f := awaitDelete(t, first, "first"); f.err != nil {
			t.Fatalf("first DeletePod: %v", f.err)
		}
		rt.mu.Lock()
		td, inFlight := rt.deleting[podID]
		rt.mu.Unlock()
		if inFlight {
			t.Fatalf("teardown record %p still present after the teardown returned", td)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		later := awaitDelete(t, startDelete(ctx, rt, podID), "later")
		if later.err != nil || later.resp == nil {
			t.Fatalf("later DeletePod = (%v, %v), want the idempotent success", later.resp, later.err)
		}
		if got := pn.teardownCalls(); len(got) != 1 {
			t.Fatalf("network Teardown calls = %v, want exactly one", got)
		}
	})
}
