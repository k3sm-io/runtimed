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
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// reconcilingNetwork is a recordingNetwork that additionally implements the
// optional NetworkReconciler seam, recording every event ("reconcile",
// "setup:<pod>", "teardown:<pod>") in call order so a test can assert the
// startup reconcile runs BEFORE any pod networking is touched.
type reconcilingNetwork struct {
	recordingNetwork
	reconcileErr error

	emu    sync.Mutex
	events []string
}

func (n *reconcilingNetwork) record(ev string) {
	n.emu.Lock()
	n.events = append(n.events, ev)
	n.emu.Unlock()
}

func (n *reconcilingNetwork) ReconcileStartup(_ context.Context) error {
	n.record("reconcile")
	return n.reconcileErr
}

func (n *reconcilingNetwork) Setup(ctx context.Context, podID string) (string, error) {
	n.record("setup:" + podID)
	return n.recordingNetwork.Setup(ctx, podID)
}

func (n *reconcilingNetwork) Teardown(podID string) error {
	n.record("teardown:" + podID)
	return n.recordingNetwork.Teardown(podID)
}

func (n *reconcilingNetwork) eventLog() []string {
	n.emu.Lock()
	defer n.emu.Unlock()
	return append([]string{}, n.events...)
}

// TestDeletePodReleasesPodNetwork is M10.1 acceptance (teardown half): DeletePod
// releases the pod's networking through PodNetwork.Teardown — with real IPAM
// behind the seam that is the pod's /32 lo0 alias, without which every pod churn
// leaks one address of the 253/node pool — and a Teardown ERROR never blocks the
// delete (log-and-continue; the pod is still forgotten).
func TestDeletePodReleasesPodNetwork(t *testing.T) {
	t.Run("teardown-called-with-pod-id", func(t *testing.T) {
		pn := &recordingNetwork{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Network: pn, Waiter: w})

		if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-td")}); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if got := pn.teardownCalls(); len(got) != 0 {
			t.Fatalf("Teardown called during a successful create: %v", got)
		}

		w.release(1001)
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-td"}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if got := pn.teardownCalls(); len(got) != 1 || got[0] != "pod-td" {
			t.Errorf("Teardown calls = %v, want [pod-td]", got)
		}
	})

	t.Run("teardown-error-never-blocks-delete", func(t *testing.T) {
		pn := &recordingNetwork{teardownErr: errors.New("alias release failed")}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Network: pn, Waiter: w})

		if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-td-err")}); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		w.release(1001)
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-td-err"}); err != nil {
			t.Fatalf("DeletePod must succeed despite a Teardown error: %v", err)
		}
		// The pod is really forgotten (a re-delete is the idempotent no-op).
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-td-err"}); err != nil {
			t.Fatalf("idempotent DeletePod after Teardown error: %v", err)
		}
	})
}

// TestCreatePodUnwindReleasesPodNetwork is M10.1 acceptance (unwind half): when
// a create step AFTER a successful network Setup fails (here the spawn), the
// pod's networking is torn down before CreatePod returns — otherwise the failed
// create leaks the /32 (DeletePod never runs for a pod that was never created).
func TestCreatePodUnwindReleasesPodNetwork(t *testing.T) {
	pn := &recordingNetwork{}
	rt := newTestRuntime(t, Deps{
		Network: pn,
		Spawner: &fakeSpawner{err: errors.New("spawn boom")},
	})

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-uw")})
	if err != nil {
		t.Fatalf("CreatePod transport error: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatal("CreatePod should fail (spawner errors)")
	}
	if got := pn.setupCount(); got != 1 {
		t.Fatalf("Setup called %d times, want 1", got)
	}
	if got := pn.teardownCalls(); len(got) != 1 || got[0] != "pod-uw" {
		t.Errorf("unwind Teardown calls = %v, want [pod-uw]", got)
	}
}

// TestNetworkReconcileStartup is M10.1 acceptance (reconcile half): a
// Deps.Network implementing the optional NetworkReconciler seam is reconciled
// exactly ONCE, BEFORE the server accepts any CreatePod — the real IPAM
// adapter's in-memory allocator must re-sync with the durable lo0 aliases a
// `kickstart -k` restart left behind, or new allocations collide and orphans
// leak. A reconcile failure fails Serve (never serving over an inconsistent
// alias table), and the no-op NodeNetwork default — no reconciler — still
// serves unchanged.
func TestNetworkReconcileStartup(t *testing.T) {
	t.Run("called-once-before-serve", func(t *testing.T) {
		pn := &reconcilingNetwork{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Network: pn, Waiter: w})

		lis := bufconn.Listen(1 << 20)
		srv := NewServer(rt)
		_, cancel, errc := serveTestServer(t, srv, lis)

		client := dialClient(t, func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		})
		ctx, cctx := context.WithTimeout(context.Background(), 5*time.Second)
		defer cctx()
		if resp, err := client.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-rec")}); err != nil || resp.GetError() != nil {
			t.Fatalf("CreatePod over bufconn: %v / %v", err, resp.GetError())
		}

		// The reconcile ran exactly once and STRICTLY BEFORE the pod's Setup.
		events := pn.eventLog()
		if len(events) < 2 || events[0] != "reconcile" {
			t.Fatalf("event order = %v, want reconcile first", events)
		}
		count := 0
		for _, ev := range events {
			if ev == "reconcile" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("reconcile ran %d times, want 1", count)
		}

		cancel()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after ctx cancel")
		}

		// A SECOND server over the same Runtime does not re-reconcile (once per
		// Runtime, not per Serve).
		lis2 := bufconn.Listen(1 << 20)
		srv2 := NewServer(rt)
		_, cancel2, errc2 := serveTestServer(t, srv2, lis2)
		client2 := dialClient(t, func(ctx context.Context, _ string) (net.Conn, error) {
			return lis2.DialContext(ctx)
		})
		if _, err := client2.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{}); err != nil {
			t.Fatalf("GetRuntimeInfo over second server: %v", err)
		}
		count = 0
		for _, ev := range pn.eventLog() {
			if ev == "reconcile" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("reconcile ran %d times across two Serves, want 1", count)
		}
		cancel2()
		select {
		case <-errc2:
		case <-time.After(5 * time.Second):
			t.Fatal("second Serve did not return after ctx cancel")
		}
		w.release(1001)
	})

	t.Run("reconcile-failure-fails-serve", func(t *testing.T) {
		pn := &reconcilingNetwork{reconcileErr: errors.New("stale alias sweep failed")}
		rt := newTestRuntime(t, Deps{Network: pn})

		lis := bufconn.Listen(1 << 20)
		defer func() { _ = lis.Close() }()
		srv := NewServer(rt)
		err := srv.Serve(context.Background(), lis)
		if err == nil || !strings.Contains(err.Error(), "reconcile pod network") {
			t.Fatalf("Serve = %v, want a reconcile failure (fail closed before serving)", err)
		}
	})

	t.Run("no-op-default-still-serves", func(t *testing.T) {
		// The NodeNetwork default implements no reconciler: Serve must not care.
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Network: supervisor.NodeNetwork{IP: "10.1.2.3"}, Waiter: w})

		lis := bufconn.Listen(1 << 20)
		srv := NewServer(rt)
		_, cancel, errc := serveTestServer(t, srv, lis)
		client := dialClient(t, func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		})
		ctx, cctx := context.WithTimeout(context.Background(), 5*time.Second)
		defer cctx()
		if resp, err := client.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-noop")}); err != nil || resp.GetError() != nil {
			t.Fatalf("CreatePod with NodeNetwork default: %v / %v", err, resp.GetError())
		}
		w.release(1001)
		if resp, err := client.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: "pod-noop"}); err != nil || resp == nil {
			t.Fatalf("DeletePod with NodeNetwork default: %v", err)
		}
		cancel()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after ctx cancel")
		}
	})
}

// TestNodeNetworkTeardownNoop pins the no-op default: NodeNetwork allocates
// nothing per pod, so Teardown returns nil for any podID.
func TestNodeNetworkTeardownNoop(t *testing.T) {
	if err := (supervisor.NodeNetwork{}).Teardown("any-pod"); err != nil {
		t.Fatalf("NodeNetwork.Teardown = %v, want nil", err)
	}
}
