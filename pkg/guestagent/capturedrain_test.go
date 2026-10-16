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
	"io"
	"testing"
	"time"
)

// TestCaptureDrainWaitsForEverySink pins the exit path's order: Drain returns
// only once every Hold is released and every Writer closed, so the Close that
// follows it cannot drop a line a pump had not yet appended.
func TestCaptureDrainWaitsForEverySink(t *testing.T) {
	t.Run("an-unregistered-container-is-drained", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		if !c.Drain("app", time.Millisecond) {
			t.Error("Drain waited on a container with no sinks")
		}
	})

	t.Run("a-hold-and-a-writer-are-both-waited-for", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		release := c.Hold("app")
		if c.Drain("app", 20*time.Millisecond) {
			t.Fatal("Drain returned with the pre-fork hold still taken; " +
				"a container reaped before its pumps start would lose its output")
		}
		w := c.Writer("app", StreamStdout)
		release()
		release() // idempotent: a second release must not free the writer's count
		if c.Drain("app", 20*time.Millisecond) {
			t.Fatal("Drain returned with a writer still open")
		}
		if _, err := io.WriteString(w, "last line, no newline"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		if !c.Drain("app", time.Second) {
			t.Fatal("Drain did not return once every sink was closed")
		}
		c.Close("app")
		got := c.ring("app").Snapshot(Selector{})
		if len(got) != 1 || string(got[0].Line) != "last line, no newline" {
			t.Fatalf("ring holds %v, want the flushed final line", got)
		}
	})

	t.Run("reset-does-not-carry-the-old-instance's-sinks", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		stale := c.Writer("app", StreamStdout) // a pump a leftover child keeps alive
		c.Reset("app")
		if !c.Drain("app", 20*time.Millisecond) {
			t.Error("the new instance's Drain waited on the replaced instance's writer")
		}
		_ = stale.Close()
	})

	t.Run("a-drain-that-would-wait-forever-is-bounded", func(t *testing.T) {
		c := NewCapture(0, 0, 0)
		_ = c.Writer("app", StreamStdout)
		start := time.Now()
		if c.Drain("app", 30*time.Millisecond) {
			t.Fatal("Drain reported drained with a writer open")
		}
		if waited := time.Since(start); waited > 5*time.Second {
			t.Errorf("Drain waited %v, far past its bound", waited)
		}
	})
}

// TestCaptureFollowLosesNothingBehindAFastWriter: a follower that falls behind
// a writer still receives every entry, in order. Ring.Append never blocks on a
// follower, so its live channel drops what it cannot buffer; the stream fetches
// those from the ring by seq instead of losing them, which for the host meant
// losing them from the pod's log file for good.
func TestCaptureFollowLosesNothingBehindAFastWriter(t *testing.T) {
	const lines = 3000 // under DefaultRingEntries, far over the live buffer
	c := NewCapture(0, 0, 0)
	w := c.Writer("app", StreamStdout)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entries, stop, err := c.Stream(ctx, "app", Selector{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// Nothing reads while the container writes: the follower is as far behind
	// as it can be.
	for i := 0; i < lines; i++ {
		if _, err := fmt.Fprintf(w, "line %d\n", i); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	c.Drain("app", time.Second)
	c.Close("app")

	var got []string
	for e := range entries {
		got = append(got, string(e.Line))
	}
	if len(got) != lines {
		t.Fatalf("the follower received %d entries, want %d", len(got), lines)
	}
	for i, l := range got {
		if want := fmt.Sprintf("line %d", i); l != want {
			t.Fatalf("entry %d = %q, want %q", i, l, want)
		}
	}
}

// TestRingStampsStrictlyIncrease: entries that read the same clock value leave
// the ring with distinct, increasing wall-clock stamps, because the host
// resumes a follow stream by since_time and drops what is at or before it.
func TestRingStampsStrictlyIncrease(t *testing.T) {
	r := NewRing(0, 0)
	at := time.Now() // carries a monotonic reading, which the wire does not
	for i := 0; i < 3; i++ {
		r.Append(LogEntry{At: at, Line: []byte("same instant")})
	}
	got := r.Snapshot(Selector{})
	for i := 1; i < len(got); i++ {
		if !got[i].At.After(got[i-1].At) {
			t.Fatalf("entry %d stamp %v is not after entry %d stamp %v", i, got[i].At, i-1, got[i-1].At)
		}
	}
	if !got[0].At.Equal(at.Round(0)) {
		t.Errorf("the first entry's stamp moved: %v, want %v", got[0].At, at.Round(0))
	}
}
