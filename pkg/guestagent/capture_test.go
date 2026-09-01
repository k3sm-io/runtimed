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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// writeTo pumps s into a container's stream sink and closes it, which is what the
// guest's pipe pump does at EOF.
func writeTo(t *testing.T, c *Capture, container string, kind LogStreamKind, s string) {
	t.Helper()
	w := c.Writer(container, kind)
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatalf("write to %s: %v", container, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close %s: %v", container, err)
	}
}

// collect drains a Stream to completion and returns its entries.
func collect(t *testing.T, c *Capture, container string, sel Selector) []LogEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch, done, err := c.Stream(ctx, container, sel)
	if err != nil {
		t.Fatalf("Stream(%s): %v", container, err)
	}
	defer done()
	var out []LogEntry
	for e := range ch {
		out = append(out, e)
	}
	return out
}

// lines renders entries as "stream:text" so a case table can state both facts.
func lines(entries []LogEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		kind := "out"
		if e.Stream == StreamStderr {
			kind = "err"
		}
		out = append(out, kind+":"+string(e.Line))
	}
	return out
}

// TestCaptureServesPerContainerOutput is the gate on `kubectl logs` for a vm pod,
// which returned, verbatim:
//
//	rpc error: code = Unavailable desc = logs: guest agent for pod …: logs: this
//	guest does not capture per-container output yet: containers inherit the init's
//	stdio, so their output is on the VM console log rather than in a per-container
//	buffer
//
// Containers were spawned on PID 1's stdio, so every container's output landed on
// the one guest console, undemultiplexed and unattributable, and there was no
// per-container stream to serve.
func TestCaptureServesPerContainerOutput(t *testing.T) {
	t.Run("output-is-retrievable-per-container", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "hello\nworld\n")
		got := lines(collect(t, c, "app", Selector{}))
		want := []string{"out:hello", "out:world"}
		if !equalStrings(got, want) {
			t.Errorf("app log = %v, want %v", got, want)
		}
	})

	t.Run("a-second-containers-output-never-appears-in-the-first", func(t *testing.T) {
		// The isolation the console could not provide: on the console both
		// containers' bytes are interleaved with no attribution at all.
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "from-app\n")
		writeTo(t, c, "sidecar", StreamStdout, "from-sidecar\n")

		app := lines(collect(t, c, "app", Selector{}))
		side := lines(collect(t, c, "sidecar", Selector{}))
		if !equalStrings(app, []string{"out:from-app"}) {
			t.Errorf("app log = %v, want only its own output", app)
		}
		if !equalStrings(side, []string{"out:from-sidecar"}) {
			t.Errorf("sidecar log = %v, want only its own output", side)
		}
	})

	t.Run("stdout-and-stderr-stay-demultiplexed", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "on-out\n")
		writeTo(t, c, "app", StreamStderr, "on-err\n")
		got := lines(collect(t, c, "app", Selector{}))
		if len(got) != 2 {
			t.Fatalf("app log = %v, want two entries", got)
		}
		joined := strings.Join(got, " ")
		if !strings.Contains(joined, "out:on-out") || !strings.Contains(joined, "err:on-err") {
			t.Errorf("app log = %v; the two streams must keep their labels", got)
		}
	})

	t.Run("a-final-line-with-no-newline-is-not-lost", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "done\nlast-without-newline")
		got := lines(collect(t, c, "app", Selector{}))
		if !equalStrings(got, []string{"out:done", "out:last-without-newline"}) {
			t.Errorf("app log = %v; a container's final write before exit usually has no trailing newline", got)
		}
	})

	t.Run("crlf-does-not-leave-a-stray-carriage-return", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "a\r\nb\r\n")
		got := lines(collect(t, c, "app", Selector{}))
		if !equalStrings(got, []string{"out:a", "out:b"}) {
			t.Errorf("app log = %v, want the CRs stripped", got)
		}
	})

	t.Run("a-container-with-no-capture-is-refused-not-answered-empty", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		_, _, err := c.Stream(context.Background(), "never-spawned", Selector{})
		if !errors.Is(err, ErrNoCapture) {
			t.Errorf("err = %v, want ErrNoCapture — an empty stream would assert the container produced nothing", err)
		}
	})

	t.Run("previous-is-refused-explicitly-rather-than-ignored", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "current\n")
		_, _, err := c.Stream(context.Background(), "app", Selector{Previous: true})
		if err == nil {
			t.Fatal("--previous must be refused; serving the current instance would answer a question about a crash with the output of the process that replaced it")
		}
	})
}

// TestCaptureSelectorAndBounds pins the two things a guest with no disk must get
// right: honouring the selection the caller asked for, and truncating VISIBLY
// rather than growing without limit.
func TestCaptureSelectorAndBounds(t *testing.T) {
	t.Run("tail-lines-counts-lines", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		var b strings.Builder
		for i := 0; i < 10; i++ {
			fmt.Fprintf(&b, "line-%d\n", i)
		}
		writeTo(t, c, "app", StreamStdout, b.String())
		got := lines(collect(t, c, "app", Selector{TailLines: 3}))
		if !equalStrings(got, []string{"out:line-7", "out:line-8", "out:line-9"}) {
			t.Errorf("tail 3 = %v; TailLines must mean LINES, which is what `kubectl logs --tail` means", got)
		}
	})

	t.Run("since-time-narrows-before-tail", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		writeTo(t, c, "app", StreamStdout, "old\n")
		cut := time.Now()
		time.Sleep(5 * time.Millisecond)
		writeTo(t, c, "app", StreamStdout, "new\n")
		got := lines(collect(t, c, "app", Selector{SinceTime: cut}))
		if !equalStrings(got, []string{"out:new"}) {
			t.Errorf("since = %v, want only the entry after the cut", got)
		}
	})

	t.Run("follow-delivers-live-output-then-ends-when-the-container-exits", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		w := c.Writer("app", StreamStdout)
		if _, err := io.WriteString(w, "first\n"); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ch, done, err := c.Stream(ctx, "app", Selector{Follow: true})
		if err != nil {
			t.Fatal(err)
		}
		defer done()
		if e := recvEntry(t, ch); string(e.Line) != "first" {
			t.Errorf("first entry = %q, want the retained line", e.Line)
		}
		if _, err := io.WriteString(w, "second\n"); err != nil {
			t.Fatal(err)
		}
		if e := recvEntry(t, ch); string(e.Line) != "second" {
			t.Errorf("second entry = %q, want the live line", e.Line)
		}
		// The container exits: a follower must see end-of-stream, not a hang.
		_ = w.Close()
		c.Close("app")
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("the stream kept delivering after the container exited")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a follow stream did not end when the container exited; `kubectl logs -f` would hang forever")
		}
	})

	t.Run("exceeding-the-bound-truncates-visibly-rather-than-growing", func(t *testing.T) {
		// A four-entry ring driven well past its bound. The retention must hold,
		// and the reader must be TOLD — a truncated log and a container that went
		// quiet look identical otherwise, and they call for opposite actions.
		const cap = 4
		c := NewCapture(cap, 0, 0)
		var b strings.Builder
		for i := 0; i < 100; i++ {
			fmt.Fprintf(&b, "line-%d\n", i)
		}
		writeTo(t, c, "app", StreamStdout, b.String())

		entries := collect(t, c, "app", Selector{})
		if len(entries) != cap+1 {
			t.Fatalf("got %d entries, want %d retained plus one truncation notice: %v", len(entries), cap, lines(entries))
		}
		notice := entries[0]
		if !bytes.Contains(notice.Line, []byte("log truncated")) {
			t.Errorf("first entry = %q, want the in-band truncation notice at the head of the gap", notice.Line)
		}
		if !bytes.Contains(notice.Line, []byte("96")) {
			t.Errorf("notice = %q, want it to name the 96 dropped entries", notice.Line)
		}
		got := lines(entries[1:])
		want := []string{"out:line-96", "out:line-97", "out:line-98", "out:line-99"}
		if !equalStrings(got, want) {
			t.Errorf("retained = %v, want the newest %d (%v) — the ring drops OLDEST first", got, cap, want)
		}
	})

	t.Run("an-endless-line-with-no-newline-is-bounded", func(t *testing.T) {
		// The bound the ring itself cannot enforce: a workload that never emits a
		// newline would otherwise grow an unbounded partial in the pump, which the
		// ring's caps never see and therefore never evict.
		const maxLine = 64
		c := NewCapture(0, 0, maxLine)
		w := c.Writer("app", StreamStdout)
		if _, err := w.Write(bytes.Repeat([]byte("x"), 10*maxLine)); err != nil {
			t.Fatal(err)
		}
		entries := collect(t, c, "app", Selector{})
		if len(entries) == 0 {
			t.Fatal("an unterminated line produced no entries at all")
		}
		for i, e := range entries {
			if len(e.Line) > maxLine {
				t.Errorf("entry %d is %d bytes, over the %d-byte per-entry bound", i, len(e.Line), maxLine)
			}
		}
		_ = w.Close()
	})
}

// TestCaptureServesTheLogsRPC drives the capture through the SHIPPED Logs handler
// over a real gRPC connection, so the seam the RPC actually calls is the one under
// test — not a fake standing in for it.
func TestCaptureServesTheLogsRPC(t *testing.T) {
	c := NewCapture(0, 0, 0)
	writeTo(t, c, "app", StreamStdout, "app-line\n")
	writeTo(t, c, "sidecar", StreamStderr, "sidecar-line\n")

	client := testAgent(t, "pod-1", Deps{
		Runner: &fakeRunner{names: []string{"app", "sidecar"}},
		Logs:   c,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.Logs(ctx, &runtimev1.GetLogsRequest{PodId: "pod-1", Container: "app"})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	var got []string
	for {
		e, rerr := stream.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("recv: %v", rerr)
		}
		got = append(got, string(e.GetLine()))
		if e.GetStream() != runtimev1.LogStream_LOG_STREAM_STDOUT {
			t.Errorf("entry %q stream = %v, want STDOUT", e.GetLine(), e.GetStream())
		}
	}
	if !equalStrings(got, []string{"app-line"}) {
		t.Errorf("Logs(app) = %v, want only app's own output", got)
	}
}

// recvEntry takes one entry or fails the test.
func recvEntry(t *testing.T, ch <-chan LogEntry) LogEntry {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("the stream ended early")
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no entry arrived")
		return LogEntry{}
	}
}

// equalStrings compares two string slices element for element.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
