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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// serveTestServer starts s.Serve(ctx, lis) on a goroutine and returns a channel
// carrying the Serve error so a test can assert a clean shutdown. The caller
// cancels ctx (or closes lis) to stop it.
func serveTestServer(t *testing.T, s *Server, lis net.Listener) (context.Context, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx, lis) }()
	return ctx, cancel, errc
}

// shortSocketPath returns a unix-socket path short enough to fit darwin's 104-byte
// sun_path limit (t.TempDir() embeds the long test name and overflows it). The dir
// is removed at test end. NO root: the socket is owned by the test user.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "runtimed.sock")
}

// dialClient builds a runtime/v1 client over an arbitrary dialer (a unix socket
// or a bufconn pipe), so the seam test drives the SAME gRPC surface the daemon
// serves without depending on root or a real network.
func dialClient(t *testing.T, dial func(context.Context, string) (net.Conn, error)) runtimev1.RuntimeClient {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///runtimed",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return runtimev1.NewRuntimeClient(cc)
}

// TestServerServesRuntimeSurfaceOverUnixSocket maps to acceptance M2.1-a1: the
// daemon registers the existing *runtime.Runtime with a gRPC server over a unix
// socket and serves the full runtime/v1 surface end-to-end across the IPC
// boundary. It uses a unix socket under t.TempDir() (owned by the test user — NO
// root; real-root e2e over the production socket is m2.sh on a capable host), so
// it faithfully exercises Listen → register → Serve → client roundtrip.
func TestServerServesRuntimeSurfaceOverUnixSocket(t *testing.T) {
	sockPath := shortSocketPath(t)
	lis, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Listen must tighten the socket to 0600 in a 0700 dir (root-daemon posture).
	if fi, err := os.Stat(sockPath); err != nil {
		t.Fatalf("stat socket: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perm = %o, want 0600", perm)
	}
	if fi, err := os.Stat(filepath.Dir(sockPath)); err != nil {
		t.Fatalf("stat socket dir: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket dir perm = %o, want 0700", perm)
	}

	rt := newTestRuntime(t, Deps{})
	srv := NewServer(rt)
	_, cancel, errc := serveTestServer(t, srv, lis)

	client := dialClient(t, func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sockPath)
	})

	ctx, cctx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cctx()

	// Exercise a representative cross-section of the surface over the wire:
	// unary GetRuntimeInfo, a mutating CreatePod, a read GetPodStatus, and a
	// server-streaming GetLogs — proving the relocation preserves the contract.
	info, err := client.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeInfo over socket: %v", err)
	}
	if info.GetRuntimeName() != RuntimeName {
		t.Errorf("runtime name = %q, want %q", info.GetRuntimeName(), RuntimeName)
	}

	cresp, err := client.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-grpc")})
	if err != nil {
		t.Fatalf("CreatePod over socket: %v", err)
	}
	if cresp.GetError() != nil {
		t.Fatalf("CreatePod rejected: %v (%s)", cresp.GetError(), cresp.GetFailureReason())
	}
	if cresp.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase = %v, want RUNNING", cresp.GetStatus().GetPhase())
	}

	gs, err := client.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: "pod-grpc"})
	if err != nil {
		t.Fatalf("GetPodStatus over socket: %v", err)
	}
	if gs.GetStatus().GetPodId() != "pod-grpc" {
		t.Errorf("GetPodStatus pod id = %q", gs.GetStatus().GetPodId())
	}

	logStream, err := client.GetLogs(ctx, &runtimev1.GetLogsRequest{PodId: "pod-grpc", Container: "main"})
	if err != nil {
		t.Fatalf("GetLogs over socket: %v", err)
	}
	// Drain to EOF — the buffer is empty but the stream must open and close cleanly.
	for {
		if _, err := logStream.Recv(); err != nil {
			break
		}
	}

	// The M2.2 ListPodStats RPC must answer over the wire too. pod-grpc carries no
	// memory limit, which now selects OOM enforcement only, not metering — so it is
	// sampled like any other pod and appears in the snapshot.
	stats, err := client.ListPodStats(ctx, &runtimev1.ListPodStatsRequest{})
	if err != nil {
		t.Fatalf("ListPodStats over socket: %v", err)
	}
	if len(stats.GetPodStats()) != 1 || stats.GetPodStats()[0].GetPodId() != "pod-grpc" {
		t.Errorf("ListPodStats = %+v, want exactly pod-grpc (an unlimited pod is metered)", stats.GetPodStats())
	}

	// Clean ctx-driven shutdown: cancel → GracefulStop → Serve returns nil, no leak.
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("Serve returned %v, want nil on ctx-cancel shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx cancel (goroutine leak)")
	}
}

// TestServerServesOverBufconn maps to acceptance M2.1-a1 via a pure in-process
// transport (no socket, no fd): it confirms the seam is transport-agnostic and
// the registered surface answers over an in-memory pipe.
func TestServerServesOverBufconn(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	rt := newTestRuntime(t, Deps{})
	srv := NewServer(rt)
	_, cancel, errc := serveTestServer(t, srv, lis)
	defer cancel()

	client := dialClient(t, func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})

	ctx, cctx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cctx()
	if _, err := client.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{}); err != nil {
		t.Fatalf("GetRuntimeInfo over bufconn: %v", err)
	}

	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

// TestServerStopUnblocksServe maps to acceptance M2.1-a1's lifecycle half: an
// explicit Stop() drains and unblocks a Serve that was started without a
// cancelled context, proving the daemon has a clean non-ctx shutdown path too.
func TestServerStopUnblocksServe(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	rt := newTestRuntime(t, Deps{})
	srv := NewServer(rt)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(context.Background(), lis) }()

	// Give Serve a beat to begin accepting, then stop explicitly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := lis.DialContext(context.Background())
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.Stop()

	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("Serve returned %v after Stop, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Stop()")
	}
}

// TestListenRemovesStaleSocket maps to acceptance M2.1-a1's robustness: a stale
// socket node from an unclean prior shutdown must not wedge the daemon — Listen
// removes it and binds cleanly.
func TestListenRemovesStaleSocket(t *testing.T) {
	sockPath := shortSocketPath(t)

	// First bind, then close WITHOUT removing the node (simulates a crash that
	// leaves the socket file behind).
	lis1, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	if ul, ok := lis1.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := lis1.Close(); err != nil {
		t.Fatalf("close first listener: %v", err)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("expected stale socket node to remain: %v", err)
	}

	// Second Listen must remove the stale node and succeed.
	lis2, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("second Listen over stale socket: %v", err)
	}
	if err := lis2.Close(); err != nil {
		t.Fatalf("close second listener: %v", err)
	}
}
