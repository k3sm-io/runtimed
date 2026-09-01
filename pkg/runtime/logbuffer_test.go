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
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// retained reports the buffer's live payload bytes, its accounted retention cost
// and its line count — read under the buffer's own lock so the helper is safe to
// call while a pump goroutine is still writing (the concurrent subtest does).
func retained(l *logBuffer) (payload, accounted, lines int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range l.lines {
		payload += len(ln.line)
	}
	return payload, l.bytes, len(l.lines)
}

// TestLogBufferIsBounded is the B162 gate. logBuffer's doc comment has always
// called it "an in-memory ring", but write was a bare append with no cap: a
// chatty or long-lived pod grew runtimed's own heap without limit, and runtimed
// supervises every pod on the node, so its OOM is a node-wide outage. The buffer
// is memory-only — nothing rotates or pages it — so the cap in write is the only
// bound that exists.
//
// The test asserts both halves, because either alone is passable by a broken
// implementation: (a) memory stops growing under sustained writes, and (b) the
// surviving lines are the NEWEST ones — a cap that evicted the newest (or that
// simply stopped accepting writes when full) would satisfy any size assertion
// while making `kubectl logs` and the FallbackToLogsOnError termination message
// useless.
func TestLogBufferIsBounded(t *testing.T) {
	t.Run("sustained-writes-stop-growing-and-keep-the-newest", func(t *testing.T) {
		l := newLogBuffer(nil)

		// ~100-byte lines, 8 MiB of output — ~32x the cap, so a buffer that grows
		// by even a fraction of what it is fed fails the bound below.
		const lines = 80_000
		pad := strings.Repeat("x", 80)
		var last string
		for i := range lines {
			last = fmt.Sprintf("line-%06d %s", i, pad)
			l.write([]byte(last))
		}

		payload, accounted, n := retained(l)
		if accounted > logBufferMaxBytes {
			t.Errorf("accounted = %d bytes, want <= %d (the cap must hold)", accounted, logBufferMaxBytes)
		}
		if payload > logBufferMaxBytes {
			t.Errorf("retained payload = %d bytes after %d lines (~%d bytes written), want <= %d — "+
				"the buffer grows without bound", payload, lines, lines*len(last), logBufferMaxBytes)
		}
		if n >= lines {
			t.Errorf("retained %d of %d lines: nothing was ever evicted", n, lines)
		}
		if n == 0 {
			t.Fatal("retained 0 lines: eviction emptied the buffer instead of ringing")
		}

		// (b) The survivors are the newest lines, in order, contiguously.
		snap := l.snapshot(0)
		if len(snap) != n {
			t.Fatalf("snapshot returned %d lines, want the %d retained", len(snap), n)
		}
		if got := string(snap[len(snap)-1]); got != last {
			t.Errorf("newest line = %q, want %q — eviction kept the OLDEST end, which is\n"+
				"exactly the tail `kubectl logs` and the termination message need", got, last)
		}
		firstKept := lines - n
		for i, ln := range snap {
			want := fmt.Sprintf("line-%06d %s", firstKept+i, pad)
			if string(ln) != want {
				t.Fatalf("snapshot[%d] = %q, want %q (survivors must be a contiguous newest-suffix)",
					i, ln, want)
			}
		}
		if string(snap[0]) == fmt.Sprintf("line-%06d %s", 0, pad) {
			t.Error("the very first line survived 8 MiB of newer output")
		}
	})

	// One pathological line can be arbitrarily long (the supervisor's pump admits
	// a token up to 1 MiB), which is why the cap counts bytes rather than lines:
	// a line-count cap would admit it whole and blow the budget on its own.
	t.Run("single-oversized-line-cannot-exceed-the-cap", func(t *testing.T) {
		l := newLogBuffer(nil)
		l.write([]byte(strings.Repeat("y", 4*logBufferMaxBytes)))

		payload, accounted, n := retained(l)
		if accounted > logBufferMaxBytes || payload > logBufferMaxBytes {
			t.Errorf("one line retained %d payload / %d accounted bytes, want <= %d",
				payload, accounted, logBufferMaxBytes)
		}
		if n != 1 {
			t.Fatalf("retained %d lines, want the 1 (truncated) line", n)
		}
		if snap := l.snapshot(0); len(snap) != 1 || len(snap[0]) == 0 {
			t.Fatalf("snapshot = %d lines, want 1 non-empty truncated line", len(snap))
		}
	})

	// The oversized-line cut keeps the tail and rounds to a rune boundary, so a
	// multi-byte payload stays valid UTF-8 (terminationMessageFromLogs renders
	// this straight into ContainerStateTerminated.Message).
	t.Run("oversized-line-truncation-stays-valid-utf8", func(t *testing.T) {
		l := newLogBuffer(nil)
		l.write([]byte(strings.Repeat("世", logBufferMaxBytes))) // 3x the cap in bytes

		snap := l.snapshot(0)
		if len(snap) != 1 {
			t.Fatalf("snapshot = %d lines, want 1", len(snap))
		}
		if !utf8.Valid(snap[0]) {
			t.Error("truncated line is not valid UTF-8 (the cut sliced a rune)")
		}
		if !strings.HasSuffix(string(snap[0]), "世") {
			t.Error("truncated line lost its tail end (the cut should trim the leading partial rune only)")
		}
	})

	// Empty lines carry no payload, so a payload-only budget would retain them
	// without limit — each still costs a slice header plus an allocation. The
	// per-line overhead is what bounds the line count.
	t.Run("empty-line-flood-is-bounded", func(t *testing.T) {
		l := newLogBuffer(nil)
		for range 200_000 {
			l.write(nil)
		}
		_, accounted, n := retained(l)
		if accounted > logBufferMaxBytes {
			t.Errorf("accounted = %d, want <= %d", accounted, logBufferMaxBytes)
		}
		if n > logBufferMaxBytes/logLineOverheadBytes {
			t.Errorf("retained %d empty lines, want <= %d (per-line overhead must bound the count)",
				n, logBufferMaxBytes/logLineOverheadBytes)
		}
	})

	// Regression guard for the property eviction must not cost: write fans out to
	// followers without blocking, so a follower that never drains loses lines
	// rather than stalling the supervisor's log pump.
	t.Run("slow-follower-drops-instead-of-blocking-the-pump", func(t *testing.T) {
		l := newLogBuffer(nil)
		_, cancel := l.subscribe() // subscribed and never drained
		defer cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := range 10_000 { // >> the 256-entry follower channel
				l.write([]byte(fmt.Sprintf("line-%d", i)))
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("write blocked on an undrained follower: the log pump must drop, never stall")
		}
	})

	// A live follower still sees new lines after the buffer has started evicting
	// (eviction touches the retained ring, not the fan-out).
	t.Run("follower-still-receives-after-eviction-begins", func(t *testing.T) {
		l := newLogBuffer(nil)
		big := strings.Repeat("z", 4096)
		for range logBufferMaxBytes/len(big) + 8 { // overflow the cap first
			l.write([]byte(big))
		}
		if _, _, n := retained(l); n == 0 {
			t.Fatal("buffer emptied itself")
		}

		ch, cancel := l.subscribe()
		defer cancel()
		l.write([]byte("after-eviction"))
		select {
		case got := <-ch:
			if string(got.line) != "after-eviction" {
				t.Errorf("follower got %q, want %q", got.line, "after-eviction")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("follower received nothing after eviction started")
		}
	})
}
