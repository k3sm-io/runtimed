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
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- the five fake seams --------------------------------------------------

type fakeRunner struct {
	names []string

	mu         sync.Mutex
	stopCalls  int
	lastGrace  time.Duration
	stopSignal chan struct{}
}

func (r *fakeRunner) Containers() []string { return append([]string(nil), r.names...) }

func (r *fakeRunner) Stop(_ context.Context, grace time.Duration) error {
	r.mu.Lock()
	r.stopCalls++
	r.lastGrace = grace
	ch := r.stopSignal
	r.mu.Unlock()
	if ch != nil {
		close(ch)
	}
	return nil
}

func (r *fakeRunner) stopped() (int, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopCalls, r.lastGrace
}

type fakeSampler struct {
	samples map[string]ContainerSample
}

func (s *fakeSampler) Sample(_ context.Context, container string) (ContainerSample, error) {
	sample, ok := s.samples[container]
	if !ok {
		return ContainerSample{}, ErrNotFound
	}
	return sample, nil
}

type fakeLogs struct {
	entries map[string][]LogEntry
	err     error

	mu      sync.Mutex
	lastSel Selector
}

func (l *fakeLogs) Stream(_ context.Context, container string, sel Selector) (<-chan LogEntry, func(), error) {
	if l.err != nil {
		return nil, nil, l.err
	}
	l.mu.Lock()
	l.lastSel = sel
	l.mu.Unlock()
	ch := make(chan LogEntry, len(l.entries[container]))
	for _, e := range l.entries[container] {
		ch <- e
	}
	close(ch)
	return ch, func() {}, nil
}

func (l *fakeLogs) selector() Selector {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSel
}

type fakeExecer struct {
	stdout, stderr []byte
	code           int32
	err            error

	mu       sync.Mutex
	lastSpec ExecSpec
	stdinGot []byte
}

func (e *fakeExecer) Exec(_ context.Context, spec ExecSpec, plumbing ExecIO) (ExecResult, error) {
	e.mu.Lock()
	e.lastSpec = spec
	e.mu.Unlock()
	if plumbing.Stdin != nil {
		b, _ := io.ReadAll(plumbing.Stdin)
		e.mu.Lock()
		e.stdinGot = b
		e.mu.Unlock()
	}
	if len(e.stdout) > 0 {
		if _, err := plumbing.Stdout.Write(e.stdout); err != nil {
			return ExecResult{}, err
		}
	}
	if len(e.stderr) > 0 {
		if _, err := plumbing.Stderr.Write(e.stderr); err != nil {
			return ExecResult{}, err
		}
	}
	if e.err != nil {
		return ExecResult{}, e.err
	}
	return ExecResult{ExitCode: e.code}, nil
}

func (e *fakeExecer) spec() ExecSpec {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSpec
}

type fakeStatus struct{ st Status }

func (s *fakeStatus) Status(context.Context) Status { return s.st }

// testAgent serves a real Server over a real gRPC connection on a bufconn: nothing
// about the service is stubbed except the five seams, which is the whole point of
// their existing.
func testAgent(t *testing.T, podID string, deps Deps) guestv1.GuestAgentClient {
	t.Helper()
	if deps.Runner == nil {
		deps.Runner = &fakeRunner{names: []string{"app"}}
	}
	if deps.Sampler == nil {
		deps.Sampler = &fakeSampler{}
	}
	if deps.Logs == nil {
		deps.Logs = &fakeLogs{}
	}
	if deps.Execer == nil {
		deps.Execer = &fakeExecer{}
	}
	if deps.Status == nil {
		deps.Status = &fakeStatus{}
	}
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	NewServer(podID, deps).Register(srv)
	served := make(chan struct{})
	go func() { defer close(served); _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		<-served
		_ = lis.Close()
	})
	return guestv1.NewGuestAgentClient(conn)
}

// TestGuestAgentRejectsForeignPodID is B228's single-pod gate.
//
// guest.proto is explicit that "the agent must reject a pod_id that is not the pod
// it booted", and states why: the id is an ASSERTION that the caller reached the
// guest it meant to reach, not a selector over several pods. One VM hosts one pod,
// so an agent that ignored the field would happily answer Exec, Logs, Stats and
// ContainerEvents for a pod it is not — turning a host-side mix-up (a stale socket
// path, a reused pod dir, a mis-routed dial) from a loud error into a silent wrong
// answer about the wrong workload.
//
// every assertion is a t.Run subtest of this one function on purpose: the gate runs
// `go test -run '^TestGuestAgentRejectsForeignPodID$'`, so a sibling top-level
// Test* would be silently filtered out and never run.
//
// Hermetic: a real gRPC round trip over bufconn against the real Server. No VM, no
// vsock, no Linux.
func TestGuestAgentRejectsForeignPodID(t *testing.T) {
	const booted = "pod-booted"
	const foreign = "pod-someone-else"

	t.Run("every-pod-id-carrying-rpc-rejects-a-foreign-id", func(t *testing.T) {
		client := testAgent(t, booted, Deps{
			Runner:  &fakeRunner{names: []string{"app"}},
			Sampler: &fakeSampler{samples: map[string]ContainerSample{"app": {CPUUsageUsec: 1}}},
			Logs:    &fakeLogs{entries: map[string][]LogEntry{"app": {{Line: []byte("x")}}}},
			Execer:  &fakeExecer{},
			Status:  &fakeStatus{},
		})
		ctx := context.Background()

		t.Run("stats", func(t *testing.T) {
			_, err := client.Stats(ctx, &guestv1.StatsRequest{PodId: foreign})
			assertInvalidArgument(t, err, foreign, booted)
		})

		t.Run("logs", func(t *testing.T) {
			stream, err := client.Logs(ctx, &runtimev1.GetLogsRequest{PodId: foreign, Container: "app"})
			if err != nil {
				t.Fatalf("Logs: %v", err)
			}
			_, err = stream.Recv()
			assertInvalidArgument(t, err, foreign, booted)
		})

		t.Run("events", func(t *testing.T) {
			stream, err := client.ContainerEvents(ctx, &guestv1.ContainerEventsRequest{PodId: foreign})
			if err != nil {
				t.Fatalf("ContainerEvents: %v", err)
			}
			_, err = stream.Recv()
			assertInvalidArgument(t, err, foreign, booted)
		})

		t.Run("exec", func(t *testing.T) {
			stream, err := client.Exec(ctx)
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if err := stream.Send(&runtimev1.ExecRequest{
				PodId: foreign, Container: "app", Command: []string{"/bin/true"},
			}); err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("Send: %v", err)
			}
			_, err = stream.Recv()
			assertInvalidArgument(t, err, foreign, booted)
		})
	})

	t.Run("the-booted-pod-id-is-accepted", func(t *testing.T) {
		// The other half: the check must be an EQUALITY test, not a blanket
		// refusal that would pass the assertions above for the wrong reason.
		client := testAgent(t, booted, Deps{
			Runner:  &fakeRunner{names: []string{"app"}},
			Sampler: &fakeSampler{samples: map[string]ContainerSample{"app": {CPUUsageUsec: 5}}},
		})
		resp, err := client.Stats(context.Background(), &guestv1.StatsRequest{PodId: booted})
		if err != nil {
			t.Fatalf("Stats for the booted pod: %v", err)
		}
		if len(resp.GetContainers()) != 1 {
			t.Fatalf("got %d container samples, want 1", len(resp.GetContainers()))
		}
	})

	t.Run("an-empty-pod-id-is-foreign-too", func(t *testing.T) {
		// An unset field must not be a wildcard: that is exactly how a
		// mis-constructed request ends up answered rather than refused.
		client := testAgent(t, booted, Deps{})
		_, err := client.Stats(context.Background(), &guestv1.StatsRequest{})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("an empty pod_id got %v, want InvalidArgument", err)
		}
	})

	t.Run("a-container-the-pod-never-declared-is-NotFound", func(t *testing.T) {
		// A different refusal from a foreign pod id, and the codes must differ:
		// "wrong guest" and "no such container here" call for different actions.
		client := testAgent(t, booted, Deps{Runner: &fakeRunner{names: []string{"app"}}})
		stream, err := client.Logs(context.Background(), &runtimev1.GetLogsRequest{PodId: booted, Container: "ghost"})
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		if _, err := stream.Recv(); status.Code(err) != codes.NotFound {
			t.Errorf("err = %v, want NotFound", err)
		}
	})

	t.Run("a-later-exec-frame-cannot-re-aim-the-stream", func(t *testing.T) {
		// The parameters come from the FIRST frame alone; later frames are
		// narrowed to stdin and resize. This is the end that would actually RUN a
		// smuggled command, so the narrowing has to hold here and not only on the
		// host side.
		execer := &fakeExecer{stdout: []byte("ok")}
		client := testAgent(t, booted, Deps{
			Runner: &fakeRunner{names: []string{"app", "sidecar"}},
			Execer: execer,
		})
		stream, err := client.Exec(context.Background())
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if err := stream.Send(&runtimev1.ExecRequest{
			PodId: booted, Container: "app", Command: []string{"/bin/echo", "hello"}, Stdin: true,
		}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		// A second parameter-shaped frame naming another pod, container and
		// command. It must be inert.
		if err := stream.Send(&runtimev1.ExecRequest{
			PodId: foreign, Container: "sidecar", Command: []string{"/bin/sh", "-c", "curl evil"},
			StdinData: []byte("input"),
		}); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("Send: %v", err)
		}
		if err := stream.CloseSend(); err != nil {
			t.Fatalf("CloseSend: %v", err)
		}
		for {
			if _, err := stream.Recv(); err != nil {
				break
			}
		}
		got := execer.spec()
		if got.Container != "app" {
			t.Errorf("the exec ran in container %q; a later frame re-aimed the stream", got.Container)
		}
		if len(got.Argv) != 2 || got.Argv[0] != "/bin/echo" {
			t.Errorf("the exec ran %v; a later frame replaced the command", got.Argv)
		}
	})
}

// assertInvalidArgument checks the rejection is InvalidArgument and names both
// ids: an operator debugging a mis-routed dial needs to see which pod was asked
// for and which guest answered.
func assertInvalidArgument(t *testing.T, err error, asked, booted string) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v (code %v), want InvalidArgument", err, status.Code(err))
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, asked) || !strings.Contains(msg, booted) {
		t.Errorf("message %q does not name both the requested pod (%q) and the booted one (%q)", msg, asked, booted)
	}
}

// TestGuestAgentAnswersItsOwnRPCs covers the handler behaviour the pod-id gate does
// not: the api_version handshake, the omit-rather-than-zero stats rule, the
// selection/presentation split on Logs, and the detached Stop.
func TestGuestAgentAnswersItsOwnRPCs(t *testing.T) {
	const booted = "pod-booted"

	t.Run("health-carries-the-api-version-constant", func(t *testing.T) {
		// The handshake guest.proto specifies and which, until this package, had a
		// value on neither side — making the skew the docs call "unsupported but
		// legible" in fact illegible.
		client := testAgent(t, booted, Deps{Status: &fakeStatus{st: Status{
			Ready: true, GuestIP: "192.0.2.7", RosettaRegistered: false,
		}}})
		resp, err := client.Health(context.Background(), &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		if resp.GetApiVersion() != APIVersion {
			t.Errorf("api_version = %q, want %q", resp.GetApiVersion(), APIVersion)
		}
		if !resp.GetReady() || resp.GetGuestIp() != "192.0.2.7" {
			t.Errorf("health = %+v, want the status seam's values", resp)
		}
		if resp.GetRosettaRegistered() {
			t.Error("rosetta_registered is true; this build attaches no Rosetta share")
		}
	})

	t.Run("stats-omits-a-container-it-cannot-read", func(t *testing.T) {
		// Absence is the only honest encoding of "unknown": a zero working set is
		// indistinguishable from an idle container.
		client := testAgent(t, booted, Deps{
			Runner: &fakeRunner{names: []string{"app", "sidecar"}},
			Sampler: &fakeSampler{samples: map[string]ContainerSample{
				"app": {CPUUsageUsec: 42, MemoryWorkingSetBytes: 1024},
			}},
		})
		resp, err := client.Stats(context.Background(), &guestv1.StatsRequest{PodId: booted})
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if len(resp.GetContainers()) != 1 {
			t.Fatalf("got %d samples, want 1 (the unreadable container must be omitted, not zeroed)", len(resp.GetContainers()))
		}
		c := resp.GetContainers()[0]
		if c.GetContainer() != "app" || c.GetCpuUsageUsec() != 42 || c.GetMemoryWorkingSetBytes() != 1024 {
			t.Errorf("sample = %+v", c)
		}
	})

	t.Run("logs-forwards-selection-and-not-presentation", func(t *testing.T) {
		// follow/tail/since/previous are answered here because only the guest
		// holds the output; timestamps and limit_bytes are the HOST's, precisely
		// so an agent that ignored limit_bytes could not flood a client.
		logs := &fakeLogs{entries: map[string][]LogEntry{"app": {
			{At: time.Unix(100, 0), Line: []byte("one"), Stream: StreamStdout},
			{At: time.Unix(101, 0), Line: []byte("two"), Stream: StreamStderr},
		}}}
		client := testAgent(t, booted, Deps{Runner: &fakeRunner{names: []string{"app"}}, Logs: logs})
		stream, err := client.Logs(context.Background(), &runtimev1.GetLogsRequest{
			PodId: booted, Container: "app", TailLines: 5, Follow: true, Previous: true,
			Timestamps: true, LimitBytes: 10,
		})
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		var got []*runtimev1.LogEntry
		for {
			e, rerr := stream.Recv()
			if rerr != nil {
				break
			}
			got = append(got, e)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2", len(got))
		}
		if got[0].GetStream() != runtimev1.LogStream_LOG_STREAM_STDOUT ||
			got[1].GetStream() != runtimev1.LogStream_LOG_STREAM_STDERR {
			t.Error("the stdout/stderr split was not preserved; a merge here cannot be undone downstream")
		}
		sel := logs.selector()
		if sel.TailLines != 5 || !sel.Follow || !sel.Previous {
			t.Errorf("selector = %+v, want the selection options forwarded", sel)
		}
	})

	t.Run("exec-relays-both-streams-and-the-exit-code", func(t *testing.T) {
		execer := &fakeExecer{stdout: []byte("out"), stderr: []byte("err"), code: 7}
		client := testAgent(t, booted, Deps{Runner: &fakeRunner{names: []string{"app"}}, Execer: execer})
		stream, err := client.Exec(context.Background())
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if err := stream.Send(&runtimev1.ExecRequest{
			PodId: booted, Container: "app", Command: []string{"/bin/sh"},
		}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if err := stream.CloseSend(); err != nil {
			t.Fatalf("CloseSend: %v", err)
		}
		var stdout, stderr []byte
		var exit *runtimev1.ExecResult
		for {
			resp, rerr := stream.Recv()
			if rerr != nil {
				break
			}
			stdout = append(stdout, resp.GetStdout()...)
			stderr = append(stderr, resp.GetStderr()...)
			if ex := resp.GetExit(); ex != nil {
				exit = ex
			}
		}
		if string(stdout) != "out" || string(stderr) != "err" {
			t.Errorf("stdout=%q stderr=%q, want the two demultiplexed", stdout, stderr)
		}
		if exit == nil || exit.GetExitCode() != 7 {
			t.Errorf("exit = %+v, want code 7 — a shell's `&&` reads this number", exit)
		}
	})

	t.Run("exec-rejects-an-empty-command", func(t *testing.T) {
		client := testAgent(t, booted, Deps{Runner: &fakeRunner{names: []string{"app"}}})
		stream, err := client.Exec(context.Background())
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if err := stream.Send(&runtimev1.ExecRequest{PodId: booted, Container: "app"}); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("Send: %v", err)
		}
		if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Errorf("err = %v, want InvalidArgument", err)
		}
	})

	t.Run("stop-acknowledges-before-the-guest-is-gone", func(t *testing.T) {
		// guest.proto: shutdown is acknowledged by the call RETURNING, and the
		// guest powers off immediately after. A Stop that waited could never
		// return successfully — the poweroff takes the transport with it — and the
		// host would read every clean shutdown as a failure.
		runner := &fakeRunner{names: []string{"app"}, stopSignal: make(chan struct{})}
		client := testAgent(t, booted, Deps{Runner: runner})
		if _, err := client.Stop(context.Background(), &guestv1.StopRequest{GraceSeconds: 12}); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		select {
		case <-runner.stopSignal:
		case <-time.After(5 * time.Second):
			t.Fatal("the shutdown never ran after Stop returned")
		}
		calls, grace := runner.stopped()
		if calls != 1 {
			t.Errorf("Stop ran %d times, want 1", calls)
		}
		if grace != 12*time.Second {
			t.Errorf("grace = %v, want 12s", grace)
		}
	})

	t.Run("stop-clamps-a-grace-the-guest-will-not-honour", func(t *testing.T) {
		// The host is supposed to clamp before sending; this is the guest
		// declining to take that on trust. A grace the guest honours is a grace
		// during which PID 1 will not power off, so a bad value here is a VM that
		// outlives its pod.
		for _, tc := range []struct {
			name    string
			seconds int32
			want    time.Duration
		}{
			{"zero", 0, 0},
			{"negative", -30, 0},
			{"in-range", 30, 30 * time.Second},
			{"absurd", 1 << 20, maxStopGraceSeconds * time.Second},
		} {
			t.Run(tc.name, func(t *testing.T) {
				runner := &fakeRunner{names: []string{"app"}, stopSignal: make(chan struct{})}
				client := testAgent(t, booted, Deps{Runner: runner})
				if _, err := client.Stop(context.Background(), &guestv1.StopRequest{GraceSeconds: tc.seconds}); err != nil {
					t.Fatalf("Stop: %v", err)
				}
				select {
				case <-runner.stopSignal:
				case <-time.After(5 * time.Second):
					t.Fatal("the shutdown never ran")
				}
				if _, grace := runner.stopped(); grace != tc.want {
					t.Errorf("grace = %v, want %v", grace, tc.want)
				}
			})
		}
	})

	t.Run("events-stream-transitions-then-ends-cleanly", func(t *testing.T) {
		events := NewEvents(8)
		client := testAgent(t, booted, Deps{Runner: &fakeRunner{names: []string{"app"}}, Events: events})
		stream, err := client.ContainerEvents(context.Background(), &guestv1.ContainerEventsRequest{PodId: booted})
		if err != nil {
			t.Fatalf("ContainerEvents: %v", err)
		}
		// Give the subscription time to land before publishing: a subscriber that
		// arrives after an event misses it, by design.
		time.Sleep(50 * time.Millisecond)
		events.Publish(ContainerEvent{
			Container: "app", At: time.Unix(1, 0),
			Exited: &ContainerExited{ExitCode: 0, Signal: 9, OOMKilled: true},
		})
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.GetContainer() != "app" {
			t.Errorf("container = %q, want app", ev.GetContainer())
		}
		ex := ev.GetExited()
		if ex == nil || !ex.GetOomKilled() || ex.GetSignal() != 9 {
			t.Errorf("exited = %+v; OOMKilled is the ONLY source of OOM truth for a vm pod and must round-trip", ex)
		}
		events.Close()
		if _, err := stream.Recv(); err != io.EOF {
			t.Errorf("stream end = %v, want EOF; a host watching events must not hang on a guest that shut down", err)
		}
	})
}
