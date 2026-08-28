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
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// logsBase is the reference instant the option tests write lines around. Absolute
// (not time.Now-relative) so an assertion on a rendered RFC3339 stamp is exact.
var logsBase = time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)

// stampWrite appends line to l and back-dates the resulting entry to at, under
// the buffer's own lock. Back-dating after the write (rather than injecting a
// clock) keeps the production path clock-free and stays race-free against the
// supervisor's log pump.
func stampWrite(l *logBuffer, at time.Time, line string) {
	l.write([]byte(line))
	l.mu.Lock()
	l.lines[len(l.lines)-1].at = at
	l.mu.Unlock()
}

// newLogPod builds a runtime with one pod ("pod-opt", container "main") and
// returns the runtime plus that container's log buffer.
func newLogPod(t *testing.T, w supervisor.ExitWaiter) (*Runtime, *logBuffer) {
	t.Helper()
	rt := newTestRuntime(t, Deps{Waiter: w})
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-opt")}); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	rt.mu.Lock()
	p := rt.pods["pod-opt"]
	rt.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	return rt, p.containers[0].logs
}

// sentLines renders what the stream received, one string per LogEntry.
func sentLines(s *fakeLogStream) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, string(e.GetLine()))
	}
	return out
}

// TestGetLogsOptions is the runtimed half of the B163 gate. GetLogsRequest has
// carried six options since the apis contract was frozen; M1 deliberately served
// tail_lines alone and scoped `kubectl logs` to the non-follow path. Serving the
// rest means EVALUATING them here, where the buffer and its per-line timestamps
// live — a request that reaches the runtime and is then ignored returns a wrong
// answer that looks right.
func TestGetLogsOptions(t *testing.T) {
	// Five lines, one minute apart, so every option has a distinguishable effect.
	seed := func(l *logBuffer) {
		for i := range 5 {
			stampWrite(l, logsBase.Add(time.Duration(i)*time.Minute), "line-"+string(rune('0'+i)))
		}
	}

	tests := []struct {
		name string
		req  *runtimev1.GetLogsRequest
		want []string
	}{
		{
			name: "no options returns the whole buffer",
			req:  &runtimev1.GetLogsRequest{},
			want: []string{"line-0", "line-1", "line-2", "line-3", "line-4"},
		},
		{
			name: "tail_lines takes the newest n",
			req:  &runtimev1.GetLogsRequest{TailLines: 2},
			want: []string{"line-3", "line-4"},
		},
		{
			name: "since_time drops entries older than the cutoff",
			req:  &runtimev1.GetLogsRequest{SinceTime: timestamppb.New(logsBase.Add(3 * time.Minute))},
			want: []string{"line-3", "line-4"},
		},
		{
			name: "since_time is inclusive of an entry exactly at the cutoff",
			req:  &runtimev1.GetLogsRequest{SinceTime: timestamppb.New(logsBase.Add(4 * time.Minute))},
			want: []string{"line-4"},
		},
		{
			name: "since_time in the future selects nothing",
			req:  &runtimev1.GetLogsRequest{SinceTime: timestamppb.New(logsBase.Add(time.Hour))},
			want: nil,
		},
		{
			// tail is POSITIONAL and applied first (the kubelet seeks back n lines,
			// then drops the ones older than --since), so the two compose to FEWER
			// than n lines rather than to "the newest n that are recent enough".
			name: "tail_lines is applied before since_time, as the kubelet does",
			req: &runtimev1.GetLogsRequest{
				TailLines: 3,
				SinceTime: timestamppb.New(logsBase.Add(4 * time.Minute)),
			},
			want: []string{"line-4"},
		},
		{
			name: "timestamps prefix each line with its RFC3339 instant",
			req:  &runtimev1.GetLogsRequest{TailLines: 1, Timestamps: true},
			want: []string{logsBase.Add(4*time.Minute).Format(time.RFC3339Nano) + " line-4"},
		},
		{
			// 6 payload bytes + the newline the line-delimited format costs = 7 per
			// line, so 14 admits exactly two lines and stops.
			name: "limit_bytes stops after the budget is spent",
			req:  &runtimev1.GetLogsRequest{LimitBytes: 14},
			want: []string{"line-0", "line-1"},
		},
		{
			name: "limit_bytes truncates the line that straddles the budget",
			req:  &runtimev1.GetLogsRequest{LimitBytes: 10},
			want: []string{"line-0", "li"},
		},
		{
			name: "limit_bytes counts the timestamp prefix it made the caller pay for",
			req:  &runtimev1.GetLogsRequest{Timestamps: true, LimitBytes: 5},
			want: []string{logsBase.Format(time.RFC3339Nano)[:4]},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, logs := newLogPod(t, newBlockingWaiter())
			seed(logs)

			req := tt.req
			req.PodId, req.Container = "pod-opt", "main"
			stream := newFakeLogStream(context.Background())
			if err := rt.GetLogs(req, stream); err != nil {
				t.Fatalf("GetLogs: %v", err)
			}
			got := sentLines(stream)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries %q, want %d %q", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("entry[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}

	// Every entry carries its instant on the wire whether or not the caller asked
	// for the rendered prefix: the proto field is the structured form, the prefix
	// is only the kubectl rendering of it.
	t.Run("LogEntry always carries its timestamp", func(t *testing.T) {
		rt, logs := newLogPod(t, newBlockingWaiter())
		seed(logs)

		stream := newFakeLogStream(context.Background())
		if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-opt", Container: "main", TailLines: 1}, stream); err != nil {
			t.Fatalf("GetLogs: %v", err)
		}
		if len(stream.entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(stream.entries))
		}
		got := stream.entries[0].GetTimestamp()
		if got == nil {
			t.Fatal("LogEntry.timestamp is unset")
		}
		if want := logsBase.Add(4 * time.Minute); !got.AsTime().Equal(want) {
			t.Errorf("timestamp = %v, want %v", got.AsTime(), want)
		}
	})

	// The limit_bytes cut is on a rune boundary: a truncated line is rendered
	// straight into a terminal, so a sliced multi-byte rune would print as a
	// replacement character (or corrupt whatever follows it).
	t.Run("limit_bytes truncation stays valid UTF-8", func(t *testing.T) {
		cases := []struct {
			name  string
			limit int64
			want  []string
		}{
			// 4 bytes of budget leave 3 for the line: exactly one 3-byte rune.
			{"budget fits one whole rune", 4, []string{"世"}},
			// 3 leave 2, which cannot hold the first rune, so nothing is sent
			// rather than a half rune or a spurious blank line.
			{"budget shorter than the first rune", 3, nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rt, logs := newLogPod(t, newBlockingWaiter())
				stampWrite(logs, logsBase, "世界")

				stream := newFakeLogStream(context.Background())
				if err := rt.GetLogs(&runtimev1.GetLogsRequest{
					PodId: "pod-opt", Container: "main", LimitBytes: tc.limit,
				}, stream); err != nil {
					t.Fatalf("GetLogs: %v", err)
				}
				got := sentLines(stream)
				if len(got) != len(tc.want) {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
				for i := range got {
					if got[i] != tc.want[i] {
						t.Errorf("entry[%d] = %q, want %q", i, got[i], tc.want[i])
					}
					if !utf8.ValidString(got[i]) {
						t.Errorf("entry[%d] = %q is not valid UTF-8 (the cut sliced a rune)", i, got[i])
					}
				}
			})
		}
	})

	// previous is NOT served: the terminated instance's buffer is not retained.
	// It must be REFUSED, not silently answered from the running instance — the
	// one wrong answer `kubectl logs -p` must never get is the current
	// instance's output presented as the crashed one's.
	t.Run("previous is refused, never answered from the current instance", func(t *testing.T) {
		rt, logs := newLogPod(t, newBlockingWaiter())
		seed(logs)

		stream := newFakeLogStream(context.Background())
		err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-opt", Container: "main", Previous: true}, stream)
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("GetLogs(previous) error = %v, want an Unimplemented status", err)
		}
		if n := len(sentLines(stream)); n != 0 {
			t.Errorf("sent %d entries with the refusal, want none", n)
		}
	})
}

// TestGetLogsFollow covers `kubectl logs -f`: the buffered lines first, then new
// lines as they are written, until the container exits or the client goes away.
// M1 returned the buffer and then blocked on the context, so a follower saw
// nothing that was written after it attached — the one thing follow is for.
func TestGetLogsFollow(t *testing.T) {
	t.Run("delivers lines written after the stream opened", func(t *testing.T) {
		rt, logs := newLogPod(t, newBlockingWaiter())
		stampWrite(logs, logsBase, "buffered")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream := newFakeLogStream(ctx)
		done := make(chan error, 1)
		go func() {
			done <- rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-opt", Container: "main", Follow: true}, stream)
		}()

		waitForLines(t, stream, 1)
		logs.write([]byte("live-1"))
		waitForLines(t, stream, 2)
		logs.write([]byte("live-2"))
		waitForLines(t, stream, 3)

		if got := sentLines(stream); got[0] != "buffered" || got[1] != "live-1" || got[2] != "live-2" {
			t.Errorf("follow delivered %q, want the buffer then the live lines in order", got)
		}

		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("GetLogs did not return after the client context was cancelled")
		}
	})

	t.Run("the options still apply to followed lines", func(t *testing.T) {
		rt, logs := newLogPod(t, newBlockingWaiter())
		stampWrite(logs, logsBase, "old")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream := newFakeLogStream(ctx)
		go func() {
			_ = rt.GetLogs(&runtimev1.GetLogsRequest{
				PodId: "pod-opt", Container: "main", Follow: true,
				SinceTime: timestamppb.New(logsBase.Add(time.Hour)),
			}, stream)
		}()

		// The buffered line predates the cutoff, so nothing is sent for it; a line
		// written now does not, so it is.
		logs.write([]byte("new"))
		waitForLines(t, stream, 1)
		if got := sentLines(stream); len(got) != 1 || got[0] != "new" {
			t.Errorf("follow delivered %q, want only the line at/after since_time", got)
		}
	})

	t.Run("ends when the container exits", func(t *testing.T) {
		w := newBlockingWaiter()
		rt, logs := newLogPod(t, w)
		stampWrite(logs, logsBase, "buffered")

		rt.mu.Lock()
		p := rt.pods["pod-opt"]
		rt.mu.Unlock()
		p.mu.Lock()
		pid := p.containers[0].proc.PID()
		p.mu.Unlock()

		stream := newFakeLogStream(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-opt", Container: "main", Follow: true}, stream)
		}()
		waitForLines(t, stream, 1)

		w.release(pid)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("GetLogs after container exit = %v, want nil (a followed stream ends cleanly)", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("GetLogs kept following after the container exited: `kubectl logs -f` would hang forever")
		}
	})
}

// waitForLines blocks until the stream has received at least n entries.
func waitForLines(t *testing.T, s *fakeLogStream, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := len(s.entries)
		s.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d log entries; got %q", n, sentLines(s))
}
