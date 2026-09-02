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
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"k3sm.io/runtimed/pkg/guestagent"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- the guest side: the real agent over the real five seams ----------------

// stubRunner / stubSampler / stubLogs / stubExecer / stubStatus are the guest's
// five seams. They stand in for the LINUX EXECUTOR — the cgroup reader, the log
// capture, the fork/exec — and for nothing else: the guest/v1 service itself is
// the shipped guestagent.Server, reached over a real gRPC connection.
//
// That is exactly the line this test draws. Everything between the daemon's
// handler and the agent's handler is production code; only the two ends' contact
// with a kernel is faked, because a test cannot have a Linux guest.
type stubRunner struct{ names []string }

func (r stubRunner) Containers() []string { return append([]string(nil), r.names...) }
func (r stubRunner) Stop(context.Context, time.Duration) error {
	return nil
}

type stubSampler struct {
	samples map[string]guestagent.ContainerSample
}

func (s stubSampler) Sample(_ context.Context, container string) (guestagent.ContainerSample, error) {
	sample, ok := s.samples[container]
	if !ok {
		return guestagent.ContainerSample{}, guestagent.ErrNotFound
	}
	return sample, nil
}

type stubLogs struct {
	entries map[string][]guestagent.LogEntry
}

func (l stubLogs) Stream(_ context.Context, container string, _ guestagent.Selector) (<-chan guestagent.LogEntry, func(), error) {
	ch := make(chan guestagent.LogEntry, len(l.entries[container])+1)
	for _, e := range l.entries[container] {
		ch <- e
	}
	close(ch)
	return ch, func() {}, nil
}

// stubExecer echoes a scripted stdout/stderr pair and exits with a scripted code,
// after draining whatever stdin the daemon relayed.
type stubExecer struct {
	stdout, stderr string
	code           int32
	sawStdin       chan []byte
}

func (e stubExecer) Exec(_ context.Context, spec guestagent.ExecSpec, plumbing guestagent.ExecIO) (guestagent.ExecResult, error) {
	if e.sawStdin != nil && plumbing.Stdin != nil {
		b, _ := io.ReadAll(plumbing.Stdin)
		select {
		case e.sawStdin <- b:
		default:
		}
	}
	// Interleaved, so a route that merged the two streams or reordered within one
	// cannot pass.
	if e.stdout != "" {
		if _, err := plumbing.Stdout.Write([]byte(e.stdout)); err != nil {
			return guestagent.ExecResult{}, err
		}
	}
	if e.stderr != "" {
		if _, err := plumbing.Stderr.Write([]byte(e.stderr)); err != nil {
			return guestagent.ExecResult{}, err
		}
	}
	return guestagent.ExecResult{ExitCode: e.code}, nil
}

type stubStatus struct{ st guestagent.Status }

func (s stubStatus) Status(context.Context) guestagent.Status { return s.st }

// startRealGuestAgent serves the shipped guestagent.Server on an in-process
// bufconn and returns a GuestDialer reaching it.
//
// The GuestDialer seam is the only thing replaced: production dials the unix
// socket the per-pod vmhost proxies to the guest's vsock port, and here the same
// dial reaches a listener in this process. Everything else — the daemon's client
// conn, its receive bound, the codec, both stream implementations, the agent's
// handlers — is the code that ships.
func startRealGuestAgent(t *testing.T, podID string, deps guestagent.Deps) GuestDialer {
	t.Helper()
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	guestagent.NewServer(podID, deps).Register(srv)
	served := make(chan struct{})
	go func() { defer close(served); _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		<-served
		_ = lis.Close()
	})
	return func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }
}

// TestGuestAgentServesTheHostRoutes is B228's gate, and it exists to retire a
// standing caveat rather than to add coverage.
//
// pkg/runtime's vm routes — execGuest, getLogsGuest, vmPodStats — shipped in
// B101/B107 and guest_test.go says outright that they are exercised "against
// in-process FAKE agents": nothing anywhere answered guest/v1, so the far end of
// every one of those routes was a test double written to satisfy the near end.
// A contract asserted only against a fake of itself is not asserted.
//
// This drives the real host routes against the real guestagent.Server over a real
// gRPC connection, through the existing GuestDialer seam. There is no VM, no
// vmhost and no vsock anywhere — and there does not need to be, because what was
// unproven was the two halves agreeing, not the transport.
//
// every assertion is a t.Run subtest of this one function on purpose: the gate runs
// `go test -run '^TestGuestAgentServesTheHostRoutes$'`, so a sibling top-level
// Test* would be silently filtered out and never run.
func TestGuestAgentServesTheHostRoutes(t *testing.T) {
	const podID = "pod-vm"

	t.Run("exec-round-trips-through-both-real-halves", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			code int32
		}{
			{"zero", 0},
			{"nonzero", 7},
			{"signal-mapped", 137},
		} {
			t.Run(tc.name, func(t *testing.T) {
				sawStdin := make(chan []byte, 1)
				dial := startRealGuestAgent(t, podID, guestagent.Deps{
					Runner: stubRunner{names: []string{"app"}},
					Execer: stubExecer{stdout: "out-a", stderr: "err-1", code: tc.code, sawStdin: sawStdin},
				})
				rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
				p := addVMPod(t, rt, podID, "app")

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				st := newFakeExecStream(ctx)
				first := &runtimev1.ExecRequest{
					PodId: podID, Container: "app", Command: []string{"/bin/echo", "hi"},
					Stdin: true, Stdout: true, Stderr: true,
				}
				st.feed(&runtimev1.ExecRequest{StdinData: []byte("piped-in")})
				st.closeSend()

				if err := rt.execGuest(st, p, first); err != nil {
					t.Fatalf("execGuest: %v", err)
				}
				out := drainExec(st)
				if string(out.stdout) != "out-a" || string(out.stderr) != "err-1" {
					t.Errorf("stdout=%q stderr=%q; the two streams must stay demultiplexed byte for byte across both halves",
						out.stdout, out.stderr)
				}
				if out.exit == nil || out.exit.GetExitCode() != tc.code {
					t.Errorf("exit = %+v, want code %d — a shell's `kubectl exec … && …` reads exactly this number", out.exit, tc.code)
				}
				select {
				case got := <-sawStdin:
					if string(got) != "piped-in" {
						t.Errorf("the guest saw stdin %q, want %q", got, "piped-in")
					}
				case <-time.After(5 * time.Second):
					t.Error("the guest never saw the client's stdin; the host's input pump and the agent's are not connected")
				}
			})
		}
	})

	t.Run("attach-round-trips-through-both-real-halves", func(t *testing.T) {
		// The strongest form of the attach assertion: the daemon's attachGuest
		// against the SHIPPED guestagent.Server, over a real gRPC connection,
		// with a real Capture, a real Events fan-out and a real AttachHub behind
		// it. Only the endpoint itself is a stand-in for a pty master, because a
		// test has no Linux guest to allocate one in.
		capture := guestagent.NewCapture(0, 0, 0)
		events := guestagent.NewEvents(0)
		t.Cleanup(events.Close)
		hub := guestagent.NewAttachHub()
		sink := &fullstackStdin{typed: make(chan []byte, 4)}
		_ = capture.Writer("app", guestagent.StreamStdout)
		hub.Register("app", guestagent.AttachEndpoints{Stdin: sink})

		w := capture.Writer("app", guestagent.StreamStdout)
		if _, err := w.Write([]byte("already-buffered\n")); err != nil {
			t.Fatalf("write: %v", err)
		}

		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Logs:   capture,
			Events: events,
			Attach: hub,
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		st := newFakeAttachStream(ctx)
		st.feed(&runtimev1.AttachRequest{StdinData: []byte("typed")})

		done := make(chan error, 1)
		go func() {
			done <- rt.attachGuest(st, p, &runtimev1.AttachRequest{
				PodId: podID, Container: "app", Stdin: true, Stdout: true, Stderr: true,
			})
		}()

		// The retained buffer is replayed first...
		if got := string(st.recv(t, 5*time.Second).GetStdout()); got != "already-buffered\n" {
			t.Errorf("first frame = %q, want the replayed buffer", got)
		}
		// ...the stream then follows live output...
		if _, err := w.Write([]byte("live\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := string(st.recv(t, 5*time.Second).GetStdout()); got != "live\n" {
			t.Errorf("second frame = %q, want the live line", got)
		}
		// ...and the client's keystrokes reach the container's retained stdin
		// through both input pumps.
		select {
		case got := <-sink.typed:
			if string(got) != "typed" {
				t.Errorf("the container's stdin endpoint saw %q, want %q", got, "typed")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the client's stdin never reached the retained endpoint; the host's input pump and the agent's are not connected")
		}

		// The container exits: the reaper publishes it and closes the ring.
		events.Publish(guestagent.ContainerEvent{Container: "app", At: time.Now(),
			Exited: &guestagent.ContainerExited{ExitCode: 7}})
		capture.Close("app")

		if ex := st.recv(t, 5*time.Second).GetExit(); ex == nil || ex.GetExitCode() != 7 {
			t.Errorf("terminal frame = %+v, want exit code 7", ex)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("attachGuest: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("attachGuest did not return after the guest ended the stream")
		}
		// DETACH IS NOT KILL, end to end: nothing in either half closed the
		// container's retained endpoint.
		if sink.isClosed() {
			t.Error("the attach closed the container's stdin endpoint")
		}
	})

	t.Run("attach-refuses-stdin-against-a-container-that-retains-none", func(t *testing.T) {
		// The agent's FailedPrecondition, with its remedy, crossing the daemon
		// intact — the one thing that makes a container spawned without stdin
		// actionable rather than mysterious.
		capture := guestagent.NewCapture(0, 0, 0)
		_ = capture.Writer("app", guestagent.StreamStdout)
		hub := guestagent.NewAttachHub()
		hub.Register("app", guestagent.AttachEndpoints{})

		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Logs:   capture,
			Attach: hub,
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		st := newFakeAttachStream(ctx)
		err := rt.attachGuest(st, p, &runtimev1.AttachRequest{
			PodId: podID, Container: "app", Stdin: true, Stdout: true,
		})
		if code := status.Code(err); code != codes.FailedPrecondition {
			t.Fatalf("attach = %v (code %s), want FailedPrecondition", err, code)
		}
		if !strings.Contains(err.Error(), "stdin: true") {
			t.Errorf("the agent's remedy did not survive the relay: %v", err)
		}
	})

	t.Run("the-agent-advertises-the-capabilities-the-host-negotiates-on", func(t *testing.T) {
		// The two ends of the negotiation, joined: the shipped agent's Health
		// answer, read by the daemon's own lease poll, recorded on the pod, and
		// then accepted by requireGuestCapability. A token renamed on either
		// side breaks here rather than in a lab.
		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Status: stubStatus{st: guestagent.Status{Ready: true, GuestIP: "10.0.0.9"}},
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, reason := rt.pollGuestLease(ctx, p); reason != guestLeaseReasonValid {
			t.Fatalf("lease poll reason = %s, want %s", reason, guestLeaseReasonValid)
		}
		for _, tok := range guestagent.Capabilities() {
			if err := rt.requireGuestCapability("attach", tok, p); err != nil {
				t.Errorf("the host did not record the agent's %q capability: %v", tok, err)
			}
		}
	})

	t.Run("the-agent-rejects-a-pod-id-the-host-did-not-resolve", func(t *testing.T) {
		// The single-pod assertion, end to end. The host re-stamps the pod id it
		// resolved onto the first frame, so this drives the agent for a different
		// booted pod and asserts the daemon relays the agent's own refusal —
		// rather than swallowing it or reporting a generic transport failure.
		dial := startRealGuestAgent(t, "pod-someone-else", guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Execer: stubExecer{stdout: "should not run"},
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		st := newFakeExecStream(ctx)
		st.closeSend()
		err := rt.execGuest(st, p, &runtimev1.ExecRequest{
			PodId: podID, Container: "app", Command: []string{"/bin/true"},
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v (code %v), want the agent's own InvalidArgument", err, status.Code(err))
		}
		if !strings.Contains(err.Error(), "pod-someone-else") {
			t.Errorf("err = %v; it must carry the agent's message naming the pod that guest actually booted", err)
		}
		if out := drainExec(st); out.frames != 0 {
			t.Errorf("the client received %d frames from a rejected exec; a refusal must produce no output", out.frames)
		}
	})

	t.Run("logs-round-trip-with-the-selection-presentation-split", func(t *testing.T) {
		base := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Logs: stubLogs{entries: map[string][]guestagent.LogEntry{"app": {
				{At: base, Line: []byte("first"), Stream: guestagent.StreamStdout},
				{At: base.Add(time.Second), Line: []byte("second"), Stream: guestagent.StreamStderr},
			}}},
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ls := newFakeLogStream(ctx)
		if err := rt.getLogsGuest(&runtimev1.GetLogsRequest{
			PodId: podID, Container: "app", TailLines: 10,
		}, ls, p); err != nil {
			t.Fatalf("getLogsGuest: %v", err)
		}
		if got := sentLines(ls); len(got) != 2 || got[0] != "first" || got[1] != "second" {
			t.Errorf("lines = %v, want [first second]", got)
		}
	})

	t.Run("logs-timestamps-are-rendered-host-side", func(t *testing.T) {
		// The PRESENTATION half of the split. The guest supplies the entry's time;
		// the host renders the prefix, because rendering guest-side would
		// double-prefix every line once the host applied its own option.
		base := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Logs: stubLogs{entries: map[string][]guestagent.LogEntry{"app": {
				{At: base, Line: []byte("hello"), Stream: guestagent.StreamStdout},
			}}},
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ls := newFakeLogStream(ctx)
		if err := rt.getLogsGuest(&runtimev1.GetLogsRequest{
			PodId: podID, Container: "app", Timestamps: true,
		}, ls, p); err != nil {
			t.Fatalf("getLogsGuest: %v", err)
		}
		got := sentLines(ls)
		if len(got) != 1 {
			t.Fatalf("lines = %v, want one", got)
		}
		if !strings.Contains(got[0], "2026-08-31T12:00:00") {
			t.Errorf("line = %q; the host must render the guest-supplied timestamp", got[0])
		}
		if !strings.Contains(got[0], "hello") {
			t.Errorf("line = %q; the payload was lost", got[0])
		}
	})

	t.Run("stats-round-trip-with-the-omit-rather-than-zero-rule", func(t *testing.T) {
		// Both halves independently refuse to fabricate a figure: the agent omits
		// a container it cannot sample, and the host walks the pod's declared
		// roster. This asserts they compose — one container reported, the other
		// absent rather than zeroed.
		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app", "sidecar"}},
			Sampler: stubSampler{samples: map[string]guestagent.ContainerSample{
				"app": {CPUUsageUsec: 1500, MemoryWorkingSetBytes: 4096},
			}},
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app", "sidecar")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ps := rt.vmPodStats(ctx, p)
		if ps == nil {
			t.Fatal("vmPodStats returned nil though the guest reported a readable sample")
		}
		if len(ps.GetContainers()) != 1 {
			t.Fatalf("got %d container samples, want 1 (the unsampled container must be OMITTED, never reported as zeros — a zero working set is indistinguishable from an idle container)",
				len(ps.GetContainers()))
		}
		cs := ps.GetContainers()[0]
		if cs.GetName() != "app" {
			t.Errorf("sample is for %q, want app", cs.GetName())
		}
		// The microsecond -> nanosecond conversion is the host's, and it is the
		// one place a units mistake becomes a CPU rate that is wrong by 1000x.
		if got := cs.GetCpu().GetUsageCoreNanoSeconds(); got != 1500*1000 {
			t.Errorf("cpu = %d ns, want %d (usage_usec x 1000)", got, 1500*1000)
		}
		if got := cs.GetMemory().GetWorkingSetBytes(); got != 4096 {
			t.Errorf("working set = %d, want 4096", got)
		}
	})

	t.Run("stats-report-unavailable-when-the-agent-refuses", func(t *testing.T) {
		// The pod says why it has no figures rather than reporting zeros. Driving
		// it through the real agent proves the host reads the agent's actual
		// refusal, not a transport error it would have produced anyway.
		dial := startRealGuestAgent(t, "pod-someone-else", guestagent.Deps{
			Runner:  stubRunner{names: []string{"app"}},
			Sampler: stubSampler{samples: map[string]guestagent.ContainerSample{"app": {CPUUsageUsec: 1}}},
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if ps := rt.vmPodStats(ctx, p); ps != nil {
			t.Fatalf("vmPodStats returned %+v though the agent refused the pod id; zeros are worse than absence", ps)
		}
		p.mu.Lock()
		cond := guestStatsConditionLocked(p)
		p.mu.Unlock()
		if cond == nil {
			t.Fatal("no guest-stats condition after a refused sample; 'this pod has no figures' must be a STATED fact")
		}
		if cond.GetReason() != guestStatsReasonUnreachable {
			t.Errorf("reason = %q, want %q", cond.GetReason(), guestStatsReasonUnreachable)
		}
	})

	t.Run("container-events-round-trip-including-OOMKilled", func(t *testing.T) {
		// The only source of OOM truth for a vm pod: the kill happens in the guest
		// kernel's cgroup, which the host cannot observe at all. If this fact does
		// not survive both halves, a vm pod's OOM is invisible — and upstream
		// treats OOMKilled as the pod's own fault, restarting it and charging a
		// Job's backoff.
		events := guestagent.NewEvents(16)
		dial := startRealGuestAgent(t, podID, guestagent.Deps{
			Runner: stubRunner{names: []string{"app"}},
			Events: events,
		})
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, podID, "app")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		watched := make(chan error, 1)
		go func() { watched <- rt.watchGuestContainerEvents(ctx, p) }()

		// Give the subscription time to land: a subscriber that arrives after an
		// event misses it, by design (the fan-out keeps no history).
		time.Sleep(100 * time.Millisecond)
		events.Publish(guestagent.ContainerEvent{
			Container: "app",
			At:        time.Now(),
			Exited:    &guestagent.ContainerExited{ExitCode: 0, Signal: 9, OOMKilled: true},
		})

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			p.mu.Lock()
			st := p.guestContainers["app"]
			latched := p.oomKilled
			p.mu.Unlock()
			// both the container's termination reason and the pod-level latch:
			// the reason is what an operator reads in `kubectl describe`, and the
			// latch is what the pod status reports. A half that did not survive
			// would leave the other telling a different story.
			if st.GetState().GetTerminated().GetReason() == "OOMKilled" && latched {
				events.Close()
				<-watched
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		events.Close()
		<-watched
		t.Fatal("the OOMKilled transition never reached the pod's container status; for a vm pod this stream is the only place that fact exists")
	})
}

// fullstackStdin stands in for a container's retained stdin endpoint: a pty
// master in a guest, and here a channel a test can read.
//
// The closed flag is what "detach is not kill" reduces to mechanically —
// nobody but the guest's exit watcher may ever call Close on this.
type fullstackStdin struct {
	typed chan []byte

	mu     sync.Mutex
	closed bool
}

func (s *fullstackStdin) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case s.typed <- cp:
	default:
	}
	return len(p), nil
}

func (s *fullstackStdin) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *fullstackStdin) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
