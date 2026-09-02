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
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// recordingStdin is a retained stdin endpoint that remembers what was written
// to it and whether anyone closed it.
//
// The closed flag is the assertion that matters most in this file: "detach is
// not kill" is, mechanically, "nobody but the exit watcher ever calls Close on
// this".
type recordingStdin struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
}

func (s *recordingStdin) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("write on a closed stdin endpoint")
	}
	s.buf = append(s.buf, p...)
	return len(p), nil
}

func (s *recordingStdin) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingStdin) written() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.buf)
}

func (s *recordingStdin) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// TestAttachHubRetainsAndReleasesEndpoints is the hub's own gate.
//
// The hub is the reason `kubectl attach` can exist at all: before it, a
// container's stdin write end and its pty master were locals in the spawn path
// that went out of scope at the fork, so the only process that could ever write
// to a running container was the one that started it. What has to be true of it
// is small and exact — a registered container is reachable, an unregistered or
// released one refuses stdin with a NAMED sentinel rather than swallowing it, a
// resize against a container with no terminal is refused separately (because
// the server drops that one instead of failing), and Release is the only thing
// in the package that ever closes an endpoint.
func TestAttachHubRetainsAndReleasesEndpoints(t *testing.T) {
	t.Run("registered-stdin-receives-writes", func(t *testing.T) {
		hub := NewAttachHub()
		sink := &recordingStdin{}
		hub.Register("app", AttachEndpoints{Stdin: sink})

		if err := hub.WriteStdin("app", []byte("hello")); err != nil {
			t.Fatalf("WriteStdin: %v", err)
		}
		if err := hub.WriteStdin("app", []byte(" world")); err != nil {
			t.Fatalf("WriteStdin: %v", err)
		}
		if got := sink.written(); got != "hello world" {
			t.Errorf("endpoint received %q, want %q", got, "hello world")
		}
	})

	t.Run("stdin-is-refused-by-name-never-dropped", func(t *testing.T) {
		hub := NewAttachHub()
		// A container with a terminal but NO retained stdin: `-t` without `-i`.
		hub.Register("no-stdin", AttachEndpoints{
			TTY:    true,
			Resize: func(uint16, uint16) error { return nil },
		})

		for _, name := range []string{"no-stdin", "never-registered"} {
			if err := hub.WriteStdin(name, []byte("x")); !errors.Is(err, ErrNoStdin) {
				t.Errorf("WriteStdin(%q) = %v, want ErrNoStdin — a client that believes it is "+
					"typing into a process must be told when it is not", name, err)
			}
		}
	})

	t.Run("resize-is-refused-separately-from-stdin", func(t *testing.T) {
		hub := NewAttachHub()
		var got []uint16
		hub.Register("tty", AttachEndpoints{
			TTY: true,
			Resize: func(rows, cols uint16) error {
				got = []uint16{rows, cols}
				return nil
			},
		})
		// A container with stdin but no terminal: `-i` without `-t`.
		hub.Register("pipe", AttachEndpoints{Stdin: &recordingStdin{}})

		if err := hub.Resize("tty", 40, 100); err != nil {
			t.Fatalf("Resize on a tty container: %v", err)
		}
		if len(got) != 2 || got[0] != 40 || got[1] != 100 {
			t.Errorf("Resize delivered %v, want rows=40 cols=100", got)
		}
		if err := hub.Resize("pipe", 40, 100); !errors.Is(err, ErrNoTTY) {
			t.Errorf("Resize on a non-tty container = %v, want ErrNoTTY (the server drops this one)", err)
		}
	})

	t.Run("release-closes-and-deregisters-and-is-idempotent", func(t *testing.T) {
		hub := NewAttachHub()
		sink := &recordingStdin{}
		hub.Register("app", AttachEndpoints{Stdin: sink})

		hub.Release("app")
		if !sink.isClosed() {
			t.Error("Release did not close the retained stdin endpoint")
		}
		if _, ok := hub.Endpoints("app"); ok {
			t.Error("Release did not deregister the container")
		}
		if err := hub.WriteStdin("app", []byte("x")); !errors.Is(err, ErrNoStdin) {
			t.Errorf("WriteStdin after Release = %v, want ErrNoStdin", err)
		}
		hub.Release("app") // idempotent: the reap path may be re-entered
	})

	t.Run("re-register-replaces-a-restarted-containers-endpoints", func(t *testing.T) {
		hub := NewAttachHub()
		first, second := &recordingStdin{}, &recordingStdin{}
		hub.Register("app", AttachEndpoints{Stdin: first})
		hub.Register("app", AttachEndpoints{Stdin: second})

		if err := hub.WriteStdin("app", []byte("x")); err != nil {
			t.Fatalf("WriteStdin: %v", err)
		}
		if first.written() != "" {
			t.Error("a write reached the PREVIOUS process's stdin endpoint")
		}
		if second.written() != "x" {
			t.Errorf("the current endpoint received %q, want %q", second.written(), "x")
		}
	})

	t.Run("concurrent-registration-lookup-and-writes-are-race-free", func(t *testing.T) {
		// Run under -race, this is the assertion that the hub's lock covers the
		// map and that the endpoints are invoked with the lock RELEASED — a hub
		// that called out under its own mutex would let one wedged container
		// stall every other container's attach and its exit-time Release.
		hub := NewAttachHub()
		const containers, writers = 8, 8
		names := make([]string, 0, containers)
		sinks := make([]*recordingStdin, 0, containers)
		for i := range containers {
			name := string(rune('a' + i))
			sink := &recordingStdin{}
			names = append(names, name)
			sinks = append(sinks, sink)
		}

		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hub.Register(name, AttachEndpoints{Stdin: sinks[i], TTY: true,
					Resize: func(uint16, uint16) error { return nil }})
			}()
			for range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = hub.WriteStdin(name, []byte("x"))
					_ = hub.Resize(name, 24, 80)
					_, _ = hub.Endpoints(name)
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				hub.Release(name)
			}()
		}
		wg.Wait()
	})
}

// TestAttachOutputSubscribesBeforeSnapshot is the gate on guest.proto's
// SUBSCRIBE-THEN-SNAPSHOT clause: "the agent subscribes the client to the live
// stream first, then replays the recent buffered output, then follows — so
// nothing produced while the attach was being set up is lost."
//
// The guarantee does not live in the attach handler; it lives in the ring's
// locking (Ring.Subscribe registers under the same mu Ring.Append records and
// fans out under) and in Capture.Stream doing the two steps in that order. So
// the test pins BOTH ends: the ordering property on the ring itself, its
// counterfactual — which shows the assertion is not vacuous, because the
// reversed order really does lose the entry — and then the seam the handler
// actually calls.
//
// The cost of this direction is a DUPLICATE: an entry landing between the
// subscribe and the snapshot is delivered twice. That is the deliberate trade
// (a repeated line beats a missing one) and it is asserted here rather than
// left as an accident.
func TestAttachOutputSubscribesBeforeSnapshot(t *testing.T) {
	t.Run("subscribe-then-snapshot-loses-nothing", func(t *testing.T) {
		r := NewRing(0, 0)
		r.Append(LogEntry{At: time.Now(), Line: []byte("before")})

		live, unsubscribe := r.Subscribe(0)
		defer unsubscribe()
		// The entry that lands in the setup window — the one the whole clause
		// exists for.
		r.Append(LogEntry{At: time.Now(), Line: []byte("during")})
		snapshot := r.Snapshot(Selector{})

		seen := map[string]int{}
		for _, e := range snapshot {
			seen[string(e.Line)]++
		}
		for {
			select {
			case e := <-live:
				seen[string(e.Line)]++
				continue
			default:
			}
			break
		}
		if seen["before"] == 0 {
			t.Error("the entry written before the subscribe was lost")
		}
		if seen["during"] == 0 {
			t.Error("the entry written in the setup window was LOST — this is the exact " +
				"failure subscribe-then-snapshot exists to prevent")
		}
		if seen["during"] != 2 {
			t.Errorf("the setup-window entry was seen %d times, want 2 (snapshot + live): "+
				"the duplicate is the deliberate price of losing nothing", seen["during"])
		}
	})

	t.Run("snapshot-then-subscribe-would-lose-it", func(t *testing.T) {
		// The counterfactual. Without it, the subtest above passes on a ring
		// whose ordering does not matter at all.
		r := NewRing(0, 0)
		r.Append(LogEntry{At: time.Now(), Line: []byte("before")})

		snapshot := r.Snapshot(Selector{})
		r.Append(LogEntry{At: time.Now(), Line: []byte("during")})
		live, unsubscribe := r.Subscribe(0)
		defer unsubscribe()

		for _, e := range snapshot {
			if string(e.Line) == "during" {
				t.Fatal("the snapshot cannot contain an entry appended after it was taken")
			}
		}
		select {
		case e := <-live:
			t.Fatalf("the live channel delivered %q from before the subscribe", e.Line)
		default:
		}
		// Neither half has it: the reversed order drops the entry entirely.
	})

	t.Run("capture-stream-subscribes-before-it-snapshots", func(t *testing.T) {
		// The seam the attach handler actually calls. Capture.Stream registers
		// the live subscriber SYNCHRONOUSLY before returning, so an entry
		// written after Stream returns but before the caller drains is still
		// delivered.
		c := NewCapture(0, 0, 0)
		w := c.Writer("app", StreamStdout)
		if _, err := w.Write([]byte("retained\n")); err != nil {
			t.Fatalf("write: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		entries, stop, err := c.Stream(ctx, "app", Selector{Follow: true})
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		defer stop()
		if _, err := w.Write([]byte("setup-window\n")); err != nil {
			t.Fatalf("write: %v", err)
		}

		want := map[string]bool{"retained": false, "setup-window": false}
		deadline := time.After(3 * time.Second)
		for !(want["retained"] && want["setup-window"]) {
			select {
			case e, ok := <-entries:
				if !ok {
					t.Fatalf("stream ended early; saw %v", want)
				}
				if _, known := want[string(e.Line)]; known {
					want[string(e.Line)] = true
				}
			case <-deadline:
				t.Fatalf("timed out; saw %v", want)
			}
		}
	})
}

// TestAttachServesTheGuestContract drives the real Server's Attach over a real
// gRPC round trip and asserts each clause guest.proto states for the verb.
//
// Every assertion is a t.Run subtest of this one function on purpose: the
// acceptance gate runs `go test -run '^TestAttachServesTheGuestContract$'`, so
// a sibling top-level Test* would be silently filtered out and never run.
func TestAttachServesTheGuestContract(t *testing.T) {
	const booted = "pod-booted"

	// newAttachAgent wires a real Capture, a real Events fan-out and a real hub
	// behind a real agent, and returns all four so a subtest can drive the guest
	// side (write output, publish an exit) and inspect the endpoint side.
	newAttachAgent := func(t *testing.T, ep AttachEndpoints, containers ...string) (guestv1.GuestAgentClient, *Capture, *Events, *AttachHub) {
		t.Helper()
		if len(containers) == 0 {
			containers = []string{"app"}
		}
		capture := NewCapture(0, 0, 0)
		events := NewEvents(0)
		hub := NewAttachHub()
		for _, name := range containers {
			// Registering BOTH rings is what the guest's pump does, and it is
			// what makes "no output yet" different from "never wired".
			_ = capture.Writer(name, StreamStdout)
			_ = capture.Raw(name)
			hub.Register(name, ep)
		}
		t.Cleanup(events.Close)
		client := testAgent(t, booted, Deps{
			Runner:    &fakeRunner{names: containers},
			Logs:      capture,
			RawOutput: capture,
			Events:    events,
			Attach:    hub,
		})
		return client, capture, events, hub
	}

	// write is the guest's output pump: one read tee'd into BOTH rings, which
	// is what cmd/k3sm-guest-init's consoleTee does. A test that wrote only the
	// line ring would be testing a guest that does not exist.
	write := func(t *testing.T, c *Capture, container string, kind LogStreamKind, b string) {
		t.Helper()
		if _, err := c.Writer(container, kind).Write([]byte(b)); err != nil {
			t.Fatalf("write: %v", err)
		}
		c.Raw(container).Append(kind, []byte(b))
	}

	open := func(t *testing.T, client guestv1.GuestAgentClient, first *runtimev1.AttachRequest) (guestv1.GuestAgent_AttachClient, context.CancelFunc) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := client.Attach(ctx)
		if err != nil {
			cancel()
			t.Fatalf("Attach: %v", err)
		}
		if err := stream.Send(first); err != nil && !errors.Is(err, io.EOF) {
			cancel()
			t.Fatalf("send the parameter frame: %v", err)
		}
		return stream, cancel
	}

	t.Run("stdin-against-a-container-with-none-is-FailedPrecondition", func(t *testing.T) {
		// guest.proto: "A first frame requesting stdin against a container that
		// has NO retained stdin endpoint (spawned with GuestContainer.stdin
		// false) fails with FailedPrecondition. Stdin is never silently
		// dropped."
		client, _, _, _ := newAttachAgent(t, AttachEndpoints{})
		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true,
		})
		defer cancel()

		_, err := stream.Recv()
		st, _ := status.FromError(err)
		if st.Code() != codes.FailedPrecondition {
			t.Fatalf("attach with stdin = %v (code %s), want FailedPrecondition", err, st.Code())
		}
		if !containsAll(st.Message(), "stdin: true", "kubectl exec -i") {
			t.Errorf("the refusal does not name the fix: %q", st.Message())
		}
	})

	t.Run("output-then-exit-code-ends-the-stream", func(t *testing.T) {
		client, capture, events, _ := newAttachAgent(t, AttachEndpoints{})
		write(t, capture, "app", StreamStdout, "retained\n")

		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdout: true, Stderr: true,
		})
		defer cancel()

		if got := recvStdout(t, stream); got != "retained\n" {
			t.Errorf("first frame = %q, want %q (the retained buffer is replayed)", got, "retained\n")
		}
		write(t, capture, "app", StreamStdout, "live\n")
		if got := recvStdout(t, stream); got != "live\n" {
			t.Errorf("second frame = %q, want %q (the stream then follows)", got, "live\n")
		}

		// The container exits: the reaper publishes it and closes the ring, in
		// that order (cmd/k3sm-guest-init).
		events.Publish(ContainerEvent{Container: "app", At: time.Now(),
			Exited: &ContainerExited{ExitCode: 7}})
		capture.Close("app")

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv the exit frame: %v", err)
		}
		if resp.GetExit().GetExitCode() != 7 {
			t.Errorf("exit frame = %+v, want exit code 7", resp.GetExit())
		}
		if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
			t.Errorf("after the exit frame the stream returned %v, want io.EOF", err)
		}
	})

	t.Run("a-signalled-container-reports-128-plus-signal", func(t *testing.T) {
		// The same convention Exec uses. A consumer must not read a different
		// number for the same death depending on which verb watched it.
		client, capture, events, _ := newAttachAgent(t, AttachEndpoints{})
		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdout: true,
		})
		defer cancel()

		events.Publish(ContainerEvent{Container: "app", At: time.Now(),
			Exited: &ContainerExited{Signal: 9}})
		capture.Close("app")

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv the exit frame: %v", err)
		}
		if got := resp.GetExit().GetExitCode(); got != 137 {
			t.Errorf("SIGKILL reported as %d, want 137", got)
		}
	})

	t.Run("stdin-reaches-the-retained-endpoint-and-detach-does-not-close-it", func(t *testing.T) {
		sink := &recordingStdin{}
		client, _, _, hub := newAttachAgent(t, AttachEndpoints{Stdin: sink})
		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true,
		})
		if err := stream.Send(&runtimev1.AttachRequest{StdinData: []byte("typed")}); err != nil {
			t.Fatalf("send stdin: %v", err)
		}
		waitFor(t, func() bool { return sink.written() == "typed" })

		// Detach — the client goes away. guest.proto: "closing the client stream
		// only unsubscribes that client. The container process is never
		// signaled, its stdio endpoints stay open, and a later attach reconnects
		// to the same process."
		_ = stream.CloseSend()
		cancel()

		time.Sleep(50 * time.Millisecond)
		if sink.isClosed() {
			t.Fatal("detaching CLOSED the container's stdin endpoint — detach is not kill")
		}
		if _, ok := hub.Endpoints("app"); !ok {
			t.Fatal("detaching deregistered the container from the hub")
		}
		if err := hub.WriteStdin("app", []byte("-again")); err != nil {
			t.Fatalf("the endpoint is unusable after a detach: %v", err)
		}
		if got := sink.written(); got != "typed-again" {
			t.Errorf("endpoint holds %q, want %q", got, "typed-again")
		}
	})

	t.Run("concurrent-attaches-both-see-output-and-both-can-type", func(t *testing.T) {
		sink := &recordingStdin{}
		client, capture, _, _ := newAttachAgent(t, AttachEndpoints{Stdin: sink})

		a, cancelA := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true})
		defer cancelA()
		b, cancelB := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true})
		defer cancelB()

		write(t, capture, "app", StreamStdout, "shared\n")
		if got := recvStdout(t, a); got != "shared\n" {
			t.Errorf("client A saw %q, want %q", got, "shared\n")
		}
		if got := recvStdout(t, b); got != "shared\n" {
			t.Errorf("client B saw %q, want %q", got, "shared\n")
		}

		if err := a.Send(&runtimev1.AttachRequest{StdinData: []byte("A")}); err != nil {
			t.Fatalf("A stdin: %v", err)
		}
		waitFor(t, func() bool { return sink.written() == "A" })
		if err := b.Send(&runtimev1.AttachRequest{StdinData: []byte("B")}); err != nil {
			t.Fatalf("B stdin: %v", err)
		}
		// Interleaved in arrival order; the agent arbitrates nothing.
		waitFor(t, func() bool { return sink.written() == "AB" })
	})

	t.Run("resize-reaches-a-tty-and-is-dropped-without-one", func(t *testing.T) {
		var mu sync.Mutex
		var sizes [][2]uint16
		client, capture, _, _ := newAttachAgent(t, AttachEndpoints{
			Stdin: &recordingStdin{},
			TTY:   true,
			Resize: func(rows, cols uint16) error {
				mu.Lock()
				sizes = append(sizes, [2]uint16{rows, cols})
				mu.Unlock()
				return nil
			},
		})
		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true, Tty: true})
		defer cancel()

		// runtime/v1 TerminalSize is width x height; a winsize is rows x cols.
		if err := stream.Send(&runtimev1.AttachRequest{
			Resize: &runtimev1.TerminalSize{Width: 100, Height: 40}}); err != nil {
			t.Fatalf("send resize: %v", err)
		}
		waitFor(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(sizes) == 1 && sizes[0] == [2]uint16{40, 100}
		})

		// A tty container's output is CRLF-delimited by the pty's own ONLCR, and
		// it arrives VERBATIM: the raw source neither strips the \r nor invents
		// one, so what reaches the client's terminal is what the pty emitted.
		write(t, capture, "app", StreamStdout, "line\r\n")
		if got := recvStdout(t, stream); got != "line\r\n" {
			t.Errorf("tty output frame = %q, want %q (verbatim, not re-delimited)", got, "line\r\n")
		}
	})

	t.Run("a-resize-against-a-container-with-no-tty-is-dropped-not-fatal", func(t *testing.T) {
		client, capture, _, _ := newAttachAgent(t, AttachEndpoints{Stdin: &recordingStdin{}})
		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true, Tty: true})
		defer cancel()

		if err := stream.Send(&runtimev1.AttachRequest{
			Resize: &runtimev1.TerminalSize{Width: 100, Height: 40}}); err != nil {
			t.Fatalf("send resize: %v", err)
		}
		// tty is ADVISORY on attach: the stream survives and keeps serving.
		write(t, capture, "app", StreamStdout, "still here\n")
		if got := recvStdout(t, stream); got != "still here\n" {
			t.Errorf("after a dropped resize the stream sent %q, want %q", got, "still here\n")
		}
	})

	t.Run("stderr-is-relayed-separately-and-only-when-asked-for", func(t *testing.T) {
		client, capture, _, _ := newAttachAgent(t, AttachEndpoints{})
		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdout: true, Stderr: true})
		defer cancel()

		write(t, capture, "app", StreamStderr, "oops\n")
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if string(resp.GetStderr()) != "oops\n" || len(resp.GetStdout()) != 0 {
			t.Errorf("frame = %+v, want the bytes on stderr only", resp)
		}

		// Now a client that did not ask for stderr.
		quiet, cancelQ := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdout: true})
		defer cancelQ()
		write(t, capture, "app", StreamStdout, "wanted\n")
		// The replayed stderr chunk is skipped; the stdout one arrives.
		if got := recvStdout(t, quiet); got != "wanted\n" {
			t.Errorf("a stdout-only client saw %q, want %q", got, "wanted\n")
		}
	})

	t.Run("a-foreign-pod-id-and-an-undeclared-container-are-rejected", func(t *testing.T) {
		client, _, _, _ := newAttachAgent(t, AttachEndpoints{})
		for _, tc := range []struct {
			name  string
			first *runtimev1.AttachRequest
			want  codes.Code
		}{
			{"foreign-pod", &runtimev1.AttachRequest{PodId: "pod-someone-else", Container: "app", Stdout: true}, codes.InvalidArgument},
			{"undeclared-container", &runtimev1.AttachRequest{PodId: booted, Container: "ghost", Stdout: true}, codes.NotFound},
		} {
			t.Run(tc.name, func(t *testing.T) {
				stream, cancel := open(t, client, tc.first)
				defer cancel()
				_, err := stream.Recv()
				if st, _ := status.FromError(err); st.Code() != tc.want {
					t.Errorf("code = %s (%v), want %s", st.Code(), err, tc.want)
				}
			})
		}
	})

	t.Run("later-frames-cannot-re-aim-the-stream", func(t *testing.T) {
		// The parameters come from the first frame alone: a later frame naming
		// another container is inert, because the handler read the selector once.
		sink, other := &recordingStdin{}, &recordingStdin{}
		capture := NewCapture(0, 0, 0)
		events := NewEvents(0)
		t.Cleanup(events.Close)
		hub := NewAttachHub()
		for _, n := range []string{"app", "other"} {
			_ = capture.Writer(n, StreamStdout)
			_ = capture.Raw(n)
		}
		hub.Register("app", AttachEndpoints{Stdin: sink})
		hub.Register("other", AttachEndpoints{Stdin: other})
		client := testAgent(t, booted, Deps{
			Runner: &fakeRunner{names: []string{"app", "other"}},
			Logs:   capture, RawOutput: capture, Events: events, Attach: hub,
		})

		stream, cancel := open(t, client, &runtimev1.AttachRequest{
			PodId: booted, Container: "app", Stdin: true, Stdout: true})
		defer cancel()
		if err := stream.Send(&runtimev1.AttachRequest{
			PodId: "pod-someone-else", Container: "other", StdinData: []byte("smuggled")}); err != nil {
			t.Fatalf("send: %v", err)
		}
		waitFor(t, func() bool { return sink.written() == "smuggled" })
		if other.written() != "" {
			t.Error("a later frame re-aimed the stream at another container")
		}
	})
}

// TestAgentAdvertisesItsCapabilities pins the tokens Health reports.
//
// They are what lets a host tell a guest that CAN serve a verb from one that
// cannot without an APIVersion bump, so their spelling is wire and the set must
// not silently shrink.
func TestAgentAdvertisesItsCapabilities(t *testing.T) {
	t.Run("health-reports-the-builds-own-tokens", func(t *testing.T) {
		client := testAgent(t, "pod-a", Deps{})
		resp, err := client.Health(context.Background(), &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		want := map[string]bool{CapabilityTTYExec: false, CapabilityAttach: false}
		for _, c := range resp.GetCapabilities() {
			if _, known := want[c]; known {
				want[c] = true
			}
		}
		for tok, seen := range want {
			if !seen {
				t.Errorf("Health did not advertise %q; capabilities = %v", tok, resp.GetCapabilities())
			}
		}
	})

	t.Run("a-seam-token-is-added-once-and-never-duplicates-a-builtin", func(t *testing.T) {
		client := testAgent(t, "pod-a", Deps{
			Status: &fakeStatus{st: Status{Capabilities: []string{CapabilityAttach, "extra", "extra", ""}}},
		})
		resp, err := client.Health(context.Background(), &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		counts := map[string]int{}
		for _, c := range resp.GetCapabilities() {
			counts[c]++
		}
		if counts[CapabilityAttach] != 1 {
			t.Errorf("%q advertised %d times, want once", CapabilityAttach, counts[CapabilityAttach])
		}
		if counts["extra"] != 1 {
			t.Errorf("a seam-supplied token was advertised %d times, want once", counts["extra"])
		}
		if counts[""] != 0 {
			t.Error("an empty token was advertised")
		}
	})
}

// --- helpers ---------------------------------------------------------------

// recvStdout reads one frame and returns its stdout bytes, failing on a frame
// that carried none.
func recvStdout(t *testing.T, stream guestv1.GuestAgent_AttachClient) string {
	t.Helper()
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if len(resp.GetStdout()) == 0 {
		t.Fatalf("frame carried no stdout: %+v", resp)
	}
	return string(resp.GetStdout())
}

// waitFor polls cond until it holds or the test's patience runs out. The attach
// input pump is a detached goroutine, so a write's arrival is observable only
// after the fact.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition never held")
}

// containsAll reports whether s contains every substring.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
