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
	"strings"
	"sync"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// flatten concatenates a chunk slice's bytes, ignoring the stream labels.
func flatten(chunks []ByteChunk) string {
	var b bytes.Buffer
	for _, c := range chunks {
		b.Write(c.Data)
	}
	return b.String()
}

// TestAttachSourceIsByteGranular is THE defect gate for this slice, and the
// contrast is the whole test.
//
// `kubectl attach` exists to serve a full-screen raw-mode TUI, and the two
// things such a client depends on most — a shell prompt and the echo of the
// key the user just pressed — are written with NO NEWLINE behind them. The
// capture's line writer holds exactly those: it splits on \n and retains a
// trailing partial until a delimiter arrives that an interactive session may
// never send. Attach served from the line ring therefore appears wedged at
// precisely the moment the user is typing, which is not a ceiling to document
// but a feature that does not work.
//
// So the assertion is a CONTRAST, on one write, through both rings at once —
// exactly as the guest's pump tees them. The attach source must deliver a
// newline-less write immediately; the logs source must still be holding it.
// Either half alone would pass on a build where both sources were the same.
func TestAttachSourceIsByteGranular(t *testing.T) {
	const prompt = "blightmud> " // no newline: a prompt, and then a keystroke echo

	t.Run("a-newline-less-write-reaches-attach-while-logs-still-holds-it", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		lineW := c.Writer("app", StreamStdout)
		raw := c.Raw("app")

		sub, err := c.RawStream("app")
		if err != nil {
			t.Fatalf("RawStream: %v", err)
		}
		defer sub.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		lines, stopLines, err := c.Stream(ctx, "app", Selector{Follow: true})
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		defer stopLines()

		// One read by the container's pump, tee'd into both rings.
		if _, err := lineW.Write([]byte(prompt)); err != nil {
			t.Fatalf("write: %v", err)
		}
		raw.Append(StreamStdout, []byte(prompt))

		// ATTACH: the bytes are there now.
		select {
		case chunk := <-sub.C():
			if string(chunk.Data) != prompt {
				t.Fatalf("attach received %q, want %q verbatim", chunk.Data, prompt)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the attach source did not deliver a newline-less write — this is the defect: " +
				"a prompt and every pty keystroke echo arrive with no newline, and a client that " +
				"never receives them cannot be a terminal")
		}

		// LOGS: still holding it, because a line is not a line until it ends.
		select {
		case e := <-lines:
			t.Fatalf("the logs source emitted %q for a write with no newline; if it no longer holds "+
				"partial lines then this contrast is vacuous and --tail no longer counts lines", e.Line)
		case <-time.After(100 * time.Millisecond):
		}

		// And once the newline lands, logs delivers the whole line while attach
		// delivers only the remaining bytes — the two granularities, side by side.
		if _, err := lineW.Write([]byte("\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		raw.Append(StreamStdout, []byte("\n"))
		select {
		case e := <-lines:
			if string(e.Line) != prompt {
				t.Errorf("logs line = %q, want %q (delimiter stripped)", e.Line, prompt)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the logs source never delivered the completed line")
		}
		select {
		case chunk := <-sub.C():
			if string(chunk.Data) != "\n" {
				t.Errorf("attach chunk = %q, want just the newline (it already had the prompt)", chunk.Data)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the attach source never delivered the newline write")
		}
	})

	t.Run("the-attach-handler-serves-the-byte-source-verbatim", func(t *testing.T) {
		// The same fact one level up, through the real Server: a newline-less
		// write must reach an attached CLIENT, with no delimiter invented for it.
		c := NewCapture(0, 0, 0)
		_ = c.Writer("app", StreamStdout)
		raw := c.Raw("app")
		hub := NewAttachHub()
		hub.Register("app", AttachEndpoints{TTY: true})
		client := testAgent(t, "pod-a", Deps{
			Runner: &fakeRunner{names: []string{"app"}}, Logs: c, RawOutput: c, Attach: hub,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream, err := client.Attach(ctx)
		if err != nil {
			t.Fatalf("Attach: %v", err)
		}
		if err := stream.Send(&runtimev1.AttachRequest{
			PodId: "pod-a", Container: "app", Stdout: true, Tty: true}); err != nil {
			t.Fatalf("send: %v", err)
		}

		// An escape sequence and a prompt: not one newline anywhere in it.
		const redraw = "\x1b[2J\x1b[H" + prompt
		raw.Append(StreamStdout, []byte(redraw))

		got := ""
		deadline := time.After(3 * time.Second)
		for len(got) < len(redraw) {
			type recvd struct {
				b   []byte
				err error
			}
			ch := make(chan recvd, 1)
			go func() { r, e := stream.Recv(); ch <- recvd{r.GetStdout(), e} }()
			select {
			case r := <-ch:
				if r.err != nil {
					t.Fatalf("recv: %v", r.err)
				}
				got += string(r.b)
			case <-deadline:
				t.Fatalf("timed out; the client received %q of %q", got, redraw)
			}
		}
		if got != redraw {
			t.Errorf("client received %q, want %q verbatim — an attached terminal's escape "+
				"sequences must not be re-chunked or re-delimited", got, redraw)
		}
	})

	t.Run("kubectl-logs-still-reads-the-line-ring", func(t *testing.T) {
		// The other half of "unchanged": the Logs verb must not have been
		// quietly moved onto the byte source, which would make --tail count
		// reads instead of lines.
		c := NewCapture(0, 0, 0)
		w := c.Writer("app", StreamStdout)
		raw := c.Raw("app")
		// Three lines delivered as five ragged writes, as a real workload does.
		for _, part := range []string{"one\ntw", "o\n", "thr", "ee", "\n"} {
			if _, err := w.Write([]byte(part)); err != nil {
				t.Fatalf("write: %v", err)
			}
			raw.Append(StreamStdout, []byte(part))
		}
		client := testAgent(t, "pod-a", Deps{
			Runner: &fakeRunner{names: []string{"app"}}, Logs: c, RawOutput: c,
		})

		stream, err := client.Logs(context.Background(), &runtimev1.GetLogsRequest{
			PodId: "pod-a", Container: "app", TailLines: 2})
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		var lines []string
		for {
			e, rerr := stream.Recv()
			if rerr != nil {
				break
			}
			lines = append(lines, string(e.GetLine()))
		}
		if len(lines) != 2 || lines[0] != "two" || lines[1] != "three" {
			t.Errorf("logs --tail=2 returned %q, want the last two LINES [two three]; "+
				"a byte-granular logs source would return the last two writes instead", lines)
		}
	})
}

// TestByteRingBoundsAndOrdering pins the raw buffer's own contract.
//
// The ordering half is the line ring's subscribe-then-snapshot property made
// STRICTER: ByteRing takes the snapshot and registers the subscriber in ONE
// critical section, so a chunk is never lost AND never duplicated. That upgrade
// is not cosmetic — a duplicated log line is harmless, while a duplicated
// escape sequence is a corrupted screen.
func TestByteRingBoundsAndOrdering(t *testing.T) {
	t.Run("subscribe-is-atomic-so-nothing-is-lost-or-duplicated", func(t *testing.T) {
		b := NewByteRing(0, 0)
		b.Append(StreamStdout, []byte("before"))

		sub := b.Subscribe(0)
		defer sub.Close()
		b.Append(StreamStdout, []byte("after"))

		if got := flatten(sub.Snapshot()); got != "before" {
			t.Errorf("snapshot = %q, want %q", got, "before")
		}
		select {
		case c := <-sub.C():
			if string(c.Data) != "after" {
				t.Errorf("live chunk = %q, want %q", c.Data, "after")
			}
		default:
			t.Fatal("the chunk appended after the subscribe was not delivered live")
		}
		select {
		case c := <-sub.C():
			t.Fatalf("a second live chunk %q arrived; the snapshot and the live stream must not overlap", c.Data)
		default:
		}
	})

	t.Run("snapshot-then-subscribe-would-lose-it", func(t *testing.T) {
		// The counterfactual, ported from the line ring's gate. Without it the
		// subtest above passes on a ring whose ordering does not matter at all.
		b := NewByteRing(0, 0)
		b.Append(StreamStdout, []byte("before"))

		snapshot := b.Snapshot()
		b.Append(StreamStdout, []byte("during")) // lands between the two calls
		sub := b.Subscribe(0)
		defer sub.Close()

		if strings.Contains(flatten(snapshot), "during") {
			t.Fatal("a snapshot cannot contain a chunk appended after it was taken")
		}
		select {
		case c := <-sub.C():
			t.Fatalf("the live channel delivered %q from before the subscribe", c.Data)
		default:
		}
		// Neither half has it: doing the two steps separately drops it entirely,
		// which is why Subscribe does both under one lock.
	})

	t.Run("the-byte-bound-is-honoured-exactly-by-trimming-the-oldest", func(t *testing.T) {
		b := NewByteRing(10, 0)
		b.Append(StreamStdout, []byte("0123456789"))
		b.Append(StreamStdout, []byte("abcde"))
		// The newest bytes are what a client redraws from, so the oldest are
		// trimmed IN PLACE rather than the whole oldest chunk being discarded.
		if got := flatten(b.Snapshot()); got != "56789abcde" {
			t.Errorf("retained %q, want %q (exactly the last 10 bytes)", got, "56789abcde")
		}
	})

	t.Run("the-chunk-bound-holds-against-single-byte-keystrokes", func(t *testing.T) {
		// A terminal echoes ONE BYTE at a time. The byte cap alone would hold
		// tens of thousands of one-byte chunks whose slice headers cost far more
		// than the bytes; this is the bound that stops it.
		b := NewByteRing(0, 8)
		for _, ch := range "abcdefghijklmnop" {
			b.Append(StreamStdout, []byte(string(ch)))
		}
		snap := b.Snapshot()
		if len(snap) != 8 {
			t.Fatalf("retained %d chunks, want the 8-chunk cap", len(snap))
		}
		if got := flatten(snap); got != "ijklmnop" {
			t.Errorf("retained %q, want the newest 8 keystrokes %q", got, "ijklmnop")
		}
	})

	t.Run("a-trimmed-chunk-keeps-its-stream-label", func(t *testing.T) {
		b := NewByteRing(6, 0)
		b.Append(StreamStderr, []byte("eeeee"))
		b.Append(StreamStdout, []byte("ooo"))
		snap := b.Snapshot()
		if len(snap) != 2 || snap[0].Stream != StreamStderr || snap[1].Stream != StreamStdout {
			t.Fatalf("snapshot = %+v, want a trimmed stderr chunk then a stdout one", snap)
		}
		if string(snap[0].Data) != "eee" {
			t.Errorf("trimmed chunk = %q, want %q", snap[0].Data, "eee")
		}
	})

	t.Run("a-slow-subscriber-loses-bytes-and-is-told-how-many", func(t *testing.T) {
		// The writer is the container's own output pump: blocking it fills the
		// pty and then blocks the workload on its own stdout, so a slow client
		// must lose bytes rather than stop the program it is watching.
		b := NewByteRing(0, 0)
		sub := b.Subscribe(2)
		defer sub.Close()
		for i := 0; i < 10; i++ {
			b.Append(StreamStdout, []byte("xxxx"))
		}
		if got := sub.DroppedBytes(); got != 32 {
			t.Errorf("DroppedBytes = %d, want 32 (8 undeliverable chunks of 4); a gap a reader "+
				"is not told about is a half-drawn screen it cannot know to redraw", got)
		}
	})

	t.Run("close-ends-followers-but-keeps-the-retained-bytes", func(t *testing.T) {
		b := NewByteRing(0, 0)
		b.Append(StreamStdout, []byte("said"))
		sub := b.Subscribe(0)
		defer sub.Close()

		b.Close()
		if _, open := <-sub.C(); open {
			t.Error("Close did not end the follower's channel")
		}
		// A client attaching after the container exited still sees what it said,
		// and then the exit frame.
		late := b.Subscribe(0)
		defer late.Close()
		if got := flatten(late.Snapshot()); got != "said" {
			t.Errorf("post-close snapshot = %q, want %q", got, "said")
		}
	})

	t.Run("concurrent-appends-subscribes-and-closes-are-race-free", func(t *testing.T) {
		b := NewByteRing(0, 0)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 50 {
					b.Append(StreamStdout, []byte("chunk"))
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				sub := b.Subscribe(0)
				_ = sub.Snapshot()
				_ = sub.DroppedBytes()
				sub.Close()
				sub.Close()
			}()
		}
		wg.Wait()
	})

	t.Run("append-copies-the-pumps-buffer", func(t *testing.T) {
		// The caller is a read pump reusing ONE buffer. Retaining the slice
		// would make every stored chunk alias whatever it last held.
		b := NewByteRing(0, 0)
		buf := []byte("first")
		b.Append(StreamStdout, buf)
		copy(buf, []byte("HELLO"))
		if got := flatten(b.Snapshot()); got != "first" {
			t.Errorf("retained %q after the caller reused its buffer, want %q", got, "first")
		}
	})
}
