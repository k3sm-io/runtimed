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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
	shimv1 "k3sm.io/apis/shim/v1"
)

// fakeShim is a ContainerShim behind the ShimDialer seam: it answers Status from
// its identity (or fails), records what it was asked, and plays canned answers
// on Exec and Follow.
type fakeShim struct {
	shimv1.UnimplementedContainerShimServer
	pid, child    int32
	start, cstart int64
	failStatus    bool
	statusCalls   atomic.Int32
	reopens       atomic.Int32
	mu            sync.Mutex
	execs         []*runtimev1.ExecRequest
}

func (f *fakeShim) Status(_ context.Context, req *shimv1.StatusRequest) (*shimv1.StatusResponse, error) {
	f.statusCalls.Add(1)
	if f.failStatus {
		return nil, status.Error(codes.Unavailable, "wedged")
	}
	return &shimv1.StatusResponse{ApiVersion: shimv1.APIVersion, ShimPid: f.pid, ShimStartUnixNano: f.start,
		ChildPid: f.child, ChildStartUnixNano: f.cstart, Running: true}, nil
}

func (f *fakeShim) Exec(stream shimv1.ContainerShim_ExecServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.execs = append(f.execs, first)
	f.mu.Unlock()
	if err := stream.Send(&runtimev1.ExecResponse{Stdout: []byte("from-shim\n")}); err != nil {
		return err
	}
	return stream.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 7}})
}

func (f *fakeShim) Follow(_ *shimv1.FollowRequest, stream shimv1.ContainerShim_FollowServer) error {
	if err := stream.Send(&runtimev1.AttachResponse{Stdout: []byte("live\n")}); err != nil {
		return err
	}
	return stream.Send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
}

func (f *fakeShim) ReopenLog(context.Context, *shimv1.ReopenLogRequest) (*shimv1.ReopenLogResponse, error) {
	f.reopens.Add(1)
	return &shimv1.ReopenLogResponse{}, nil
}

// claimDialer dials real sockets and claims the recorded pid as the peer; it
// counts dials so a test can prove a refusal came before any.
type claimDialer struct {
	pid   int
	dials atomic.Int32
}

func (d *claimDialer) DialShim(ctx context.Context, path string) (net.Conn, int, error) {
	d.dials.Add(1)
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "unix", path)
	return c, d.pid, err
}

// serveShim serves srv in a fresh short shim dir and returns the dir.
func serveShim(t *testing.T, srv shimv1.ContainerShimServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rshim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", supervisor.ShimSockPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	shimv1.RegisterContainerShimServer(g, srv)
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(g.Stop)
	return dir
}

// seedRecord writes rec verbatim (every resident-shim field included).
func seedRecord(t *testing.T, rt *Runtime, rec podProcRecord) {
	t.Helper()
	if rec.RuntimeVersion == "" {
		rec.RuntimeVersion = rt.fingerprint
	}
	if err := rt.writePodProcRecord(rec); err != nil {
		t.Fatal(err)
	}
}

// lostReason returns the pod's log-stream-lost reason, "" when it has none.
func lostReason(st *runtimev1.PodStatus) string {
	for _, c := range st.GetConditions() {
		if c.GetType() == LogStreamLostConditionType {
			return c.GetReason()
		}
	}
	return ""
}

// TestAttachReconnectsToTheShim is the runtime half of the resident shim: a pod
// whose containers run beside shims is re-attached THROUGH the shims after a
// daemon restart. Every case runs against a fake shim behind the ShimDialer
// seam, over a real socket.
func TestAttachReconnectsToTheShim(t *testing.T) {
	const pgid, start, child, cstart = 100, int64(5000), 101, int64(5500)
	type world struct {
		rt     *Runtime
		shim   *fakeShim
		dir    string
		dialer *claimDialer
		waiter unknownExitWaiter
		rec    podProcRecord
	}
	setup := func(t *testing.T, groups map[int][]supervisor.ProcMember, starts map[int]int64, shim *fakeShim) world {
		t.Helper()
		w := world{shim: shim, dialer: &claimDialer{pid: pgid}, waiter: unknownExitWaiter{newBlockingWaiter()}}
		w.dir = serveShim(t, shim)
		w.rt = newTestRuntime(t, Deps{
			ProcGroup: fakeGroups{members: groups}.inspect,
			ProcStartTime: func(pid int) (int64, bool) {
				v, ok := starts[pid]
				return v, ok
			},
			AdoptedWaiter: w.waiter,
			ShimDialer:    w.dialer,
			SignalGroup:   func(int, os.Signal) error { return nil },
		})
		w.rec = attachableRecord(t, w.rt, podProcRecord{PodID: "p1", Container: "main", Pgid: pgid, StartUnixNano: start,
			ShimDir: w.dir, ChildPid: child, ChildStartUnixNano: cstart})
		seedRecord(t, w.rt, w.rec)
		return w
	}
	live := func() (map[int][]supervisor.ProcMember, map[int]int64) {
		return map[int][]supervisor.ProcMember{pgid: {mem(pgid, start), mem(child, cstart)}}, map[int]int64{pgid: start, child: cstart}
	}
	healthy := func() *fakeShim { return &fakeShim{pid: pgid, start: start, child: child, cstart: cstart} }
	attach := func(t *testing.T, w world) *runtimev1.PodStatus {
		t.Helper()
		st, err := w.rt.AttachPod(context.Background(), hostBinBox(w.rt, "p1"))
		if err != nil {
			t.Fatalf("AttachPod: %v", err)
		}
		t.Cleanup(func() { _, _ = w.rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "p1"}) })
		return st
	}
	execOnce := func(t *testing.T, w world) (string, int32, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s := newFakeExecStream(ctx)
		s.feed(&runtimev1.ExecRequest{PodId: "p1", Command: []string{"/bin/echo", "hi"}})
		s.closeSend()
		errc := make(chan error, 1)
		go func() { errc <- w.rt.Exec(s) }()
		select {
		case err := <-errc:
			if err != nil {
				return "", 0, err
			}
		case <-ctx.Done():
			t.Fatal("exec never returned")
		}
		out, code := s.collect(t)
		return string(out), code, nil
	}

	t.Run("attached Running with the container's real start and no lost stream", func(t *testing.T) {
		g, s := live()
		w := setup(t, g, s, healthy())
		st := attach(t, w)
		cs := st.GetContainerStatuses()[0]
		if got := cs.GetState().GetRunning().GetStartedAt().AsTime(); !got.Equal(time.Unix(0, cstart)) {
			t.Fatalf("started_at = %v, want the container's own start %v", got, time.Unix(0, cstart))
		}
		if r := lostReason(st); r != "" {
			t.Fatalf("a reconnected shim must not lose the stream, got reason %q", r)
		}
		if b, err := os.ReadFile(cs.GetLogPath()); err == nil && strings.Contains(string(b), logStreamLostMarker) {
			t.Fatal("a reconnected shim's log got the gap marker")
		}
		if w.rt.pods["p1"].containerPIDs()[0] != child || w.rt.pods["p1"].containerPgids()[0] != pgid {
			t.Fatalf("metering must name the container (%d) and the reap the group (%d)", child, pgid)
		}
	})

	t.Run("exec is proxied to the shim", func(t *testing.T) {
		g, s := live()
		w := setup(t, g, s, healthy())
		attach(t, w)
		out, code, err := execOnce(t, w)
		if err != nil || out != "from-shim\n" || code != 7 {
			t.Fatalf("exec = %q, %d, %v; want the shim's own answer", out, code, err)
		}
		w.shim.mu.Lock()
		defer w.shim.mu.Unlock()
		if len(w.shim.execs) != 1 || w.shim.execs[0].GetContainer() != "main" || w.shim.execs[0].GetCommand()[0] != "/bin/echo" {
			t.Fatalf("the shim saw %+v, want one exec of /bin/echo naming container main", w.shim.execs)
		}
	})

	t.Run("reopen log creates the new file then asks the shim", func(t *testing.T) {
		g, s := live()
		w := setup(t, g, s, healthy())
		st := attach(t, w)
		path := st.GetContainerStatuses()[0].GetLogPath()
		_ = os.Remove(path) // the node renamed it away
		if _, err := w.rt.ReopenContainerLog(context.Background(), &runtimev1.ReopenContainerLogRequest{PodId: "p1", Container: "main"}); err != nil {
			t.Fatalf("ReopenContainerLog: %v", err)
		}
		if _, err := os.Stat(path); err != nil || w.shim.reopens.Load() != 1 {
			t.Fatalf("new file %v, shim reopens %d; want the file created and one ReopenLog", err, w.shim.reopens.Load())
		}
	})

	t.Run("attach follows the shim", func(t *testing.T) {
		g, s := live()
		w := setup(t, g, s, healthy())
		attach(t, w)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		as := newFakeAttachStream(ctx)
		as.in <- &runtimev1.AttachRequest{PodId: "p1"}
		if err := w.rt.Attach(as); err != nil {
			t.Fatalf("Attach: %v", err)
		}
		first, second := <-as.out, <-as.out
		if string(first.GetStdout()) != "live\n" || second.GetExit() == nil {
			t.Fatalf("attach got %+v then %+v, want the shim's chunk then its exit", first, second)
		}
	})

	t.Run("the shim's exit record is the real termination", func(t *testing.T) {
		g, s := live()
		w := setup(t, g, s, healthy())
		attach(t, w)
		if err := supervisor.WriteExitRecord(w.dir, supervisor.ExitRecord{ExitCode: 3, FinishedAtUnixNano: time.Now().UnixNano()}); err != nil {
			t.Fatal(err)
		}
		w.waiter.release(pgid) // the shim exits: a non-child, so the waiter knows no status
		term := awaitTerminated(t, w.rt)
		if term.GetExitCode() != 3 || term.GetReason() != "Error" {
			t.Fatalf("terminated = %+v, want the recorded exit 3 (Error), never ExitStatusUnknown", term)
		}
	})

	t.Run("a dead shim over a live container degrades", func(t *testing.T) {
		groups := map[int][]supervisor.ProcMember{pgid: {mem(child, cstart)}} // the leader is gone
		w := setup(t, groups, map[int]int64{child: cstart}, healthy())
		st := attach(t, w)
		if r := lostReason(st); r != logStreamLostShimCrashed {
			t.Fatalf("log-stream-lost reason = %q, want %s", r, logStreamLostShimCrashed)
		}
		if w.dialer.dials.Load() != 0 {
			t.Fatal("a dead shim must not be dialed")
		}
		if _, _, err := execOnce(t, w); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("exec = %v, want FailedPrecondition", err)
		}
		w.waiter.release(child)
		if term := awaitTerminated(t, w.rt); term.GetReason() != ExitStatusUnknownReason {
			t.Fatalf("terminated = %+v, want %s", term, ExitStatusUnknownReason)
		}
	})

	t.Run("a shim failing two Status calls is ShimUnresponsive", func(t *testing.T) {
		g, s := live()
		shim := healthy()
		shim.failStatus = true
		w := setup(t, g, s, shim)
		st := attach(t, w)
		if r := lostReason(st); r != logStreamLostShimUnresponsive {
			t.Fatalf("log-stream-lost reason = %q, want %s", r, logStreamLostShimUnresponsive)
		}
		if n := shim.statusCalls.Load(); n != 2 {
			t.Fatalf("Status called %d times, want exactly 2", n)
		}
		if _, _, err := execOnce(t, w); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("exec = %v, want FailedPrecondition", err)
		}
	})

	t.Run("a drifted posture is refused before any shim is dialed", func(t *testing.T) {
		g, s := live()
		w := setup(t, g, s, healthy())
		drifted := w.rec
		drifted.ProfileSHA256 = "0000"
		seedRecord(t, w.rt, drifted)
		if _, err := w.rt.AttachPod(context.Background(), hostBinBox(w.rt, "p1")); !errors.Is(err, ErrNothingToAttach) {
			t.Fatalf("AttachPod = %v, want ErrNothingToAttach", err)
		}
		if w.dialer.dials.Load() != 0 {
			t.Fatalf("a drifted pod was dialed %d times before its refusal", w.dialer.dials.Load())
		}
	})

	t.Run("an older daemon reaps shim-shaped records by the unchanged leader identity", func(t *testing.T) {
		foreign := podProcRecord{PodID: "p1", Container: "main", Pgid: pgid, StartUnixNano: start, RuntimeVersion: "cdhash:other",
			ShimDir: "/x", ChildPid: child, ChildStartUnixNano: cstart}
		g, s := live()
		groups := fakeGroups{members: g}
		if kill, _, _ := startupPodReapDecision([]podProcRecord{foreign}, nil, groups.inspect); len(kill) != 1 {
			t.Fatalf("kill = %+v, want the shim's group by its (Pgid, StartUnixNano)", kill)
		}
		adopt, degraded, _ := attachDecision([]podProcRecord{foreign}, groups.inspect, func(pid int) (int64, bool) { v, ok := s[pid]; return v, ok }, "cdhash:mine")
		if len(adopt)+len(degraded) != 0 {
			t.Fatal("a foreign build's shim must never be adopted")
		}
		// The leader gone: only the container's exact identity can authorize the
		// kill, and a recycled child pid must not.
		dead := fakeGroups{members: map[int][]supervisor.ProcMember{pgid: {mem(child, cstart)}}}
		if kill, _, _ := startupPodReapDecision([]podProcRecord{foreign}, nil, dead.inspect); len(kill) != 1 {
			t.Fatalf("kill = %+v, want the group by the container's identity", kill)
		}
		recycled := fakeGroups{members: map[int][]supervisor.ProcMember{pgid: {mem(child, cstart+1)}}}
		if kill, _, keep := startupPodReapDecision([]podProcRecord{foreign}, nil, recycled.inspect); len(kill) != 0 || len(keep) != 1 {
			t.Fatalf("kill = %+v keep = %+v, want keep-and-warn for a container that is not the recorded one", kill, keep)
		}
	})
}

// awaitTerminated waits for p1's main container to report a termination.
func awaitTerminated(t *testing.T, rt *Runtime) *runtimev1.ContainerStateTerminated {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range rt.snapshotStatuses("p1") {
			if term := st.GetContainerStatuses()[0].GetState().GetTerminated(); term != nil {
				return term
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the container's exit was never reported")
	return nil
}

// TestStartupSweepsUnownedShimDirs pins the startup sweep: after the reap, a shim
// dir no registered pod owns (its pod was deleted while no daemon ran) is
// removed, and an attached pod's dir is kept.
func TestStartupSweepsUnownedShimDirs(t *testing.T) {
	rt := newTestRuntime(t, Deps{ProcGroup: fakeGroups{}.inspect})
	owned, err := rt.allocShimDir()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := rt.allocShimDir()
	if err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	rt.pods["p1"] = &pod{box: hostBinBox(rt, "p1"), shimDirs: map[string]string{"main": owned}}
	rt.mu.Unlock()
	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); err != nil {
		t.Fatalf("an owned shim dir was swept: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("an unowned shim dir survived the sweep: %v", err)
	}
}
