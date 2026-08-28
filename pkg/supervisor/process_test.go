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

package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// fakeSpawner records the spec and returns a canned pid/err. If it has a logLine
// and the spec carries a LogFD, it writes the line to that fd so the Process log
// pump can be exercised without a real child.
type fakeSpawner struct {
	pid     int
	err     error
	logLine string

	mu      sync.Mutex
	gotSpec SpawnSpec
}

func (f *fakeSpawner) Spawn(_ context.Context, spec SpawnSpec) (int, error) {
	f.mu.Lock()
	f.gotSpec = spec
	f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	if f.logLine != "" && spec.LogFD != 0 {
		w := os.NewFile(spec.LogFD, "logfd")
		_, _ = w.WriteString(f.logLine + "\n")
		_ = w.Close()
	}
	return f.pid, nil
}

// fakeWaiter returns a canned exit after an optional delay, honoring ctx.
type fakeWaiter struct {
	code  int
	sig   int
	err   error
	delay time.Duration
}

func (f fakeWaiter) WaitExit(ctx context.Context, _ int) (int, int, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		}
	}
	return f.code, f.sig, f.err
}

// TestProcessLifecycle exercises the supervisor's Process state machine with
// fakes: Start → Running → reap → Exited, with the recorded exit status.
func TestProcessLifecycle(t *testing.T) {
	cases := []struct {
		name     string
		waiter   fakeWaiter
		wantCode int
		wantSig  int
	}{
		{"clean-exit", fakeWaiter{code: 0}, 0, 0},
		{"nonzero-exit", fakeWaiter{code: 7}, 7, 0},
		{"killed", fakeWaiter{code: 137, sig: 9}, 137, 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := &fakeSpawner{pid: 4242}
			p := NewProcess(sp, tc.waiter, SpawnSpec{Path: "/bin/true", Argv: []string{"/bin/true"}}, nil)

			if p.State() != StateInit {
				t.Fatalf("pre-start state = %v", p.State())
			}
			ctx := context.Background()
			if err := p.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if p.PID() != 4242 {
				t.Errorf("PID = %d", p.PID())
			}
			code, sig, err := p.Wait(ctx)
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
			if code != tc.wantCode || sig != tc.wantSig {
				t.Errorf("exit (code=%d sig=%d), want (code=%d sig=%d)", code, sig, tc.wantCode, tc.wantSig)
			}
			if p.State() != StateExited {
				t.Errorf("post-wait state = %v", p.State())
			}
		})
	}
}

// TestProcessLogCapture checks the combined-log pump delivers the child's output
// to the sink (via a real pipe wired by the fake spawner).
func TestProcessLogCapture(t *testing.T) {
	sp := &fakeSpawner{pid: 1, logLine: "hello-pod"}

	var mu sync.Mutex
	var got []string
	sink := func(line []byte) {
		mu.Lock()
		got = append(got, string(line))
		mu.Unlock()
	}

	p := NewProcess(sp, fakeWaiter{code: 0, delay: 50 * time.Millisecond},
		SpawnSpec{Path: "/bin/echo", Argv: []string{"/bin/echo"}}, sink)
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := p.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// Give the pump goroutine a moment to flush after EOF.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "hello-pod" {
		t.Fatalf("captured logs = %v, want [hello-pod]", got)
	}
}

// TestProcessLogsDrained checks the drain edge: with a sink, LogsDrained closes only
// AFTER the pump has flushed every line to the sink (the B11 "logs fully drained"
// guarantee watchContainerExit relies on); with no sink there is no pump, so it is
// closed at Start.
func TestProcessLogsDrained(t *testing.T) {
	t.Run("closes-after-all-lines-flushed", func(t *testing.T) {
		sp := &fakeSpawner{pid: 1, logLine: "final-diagnostic-line"}
		var mu sync.Mutex
		var got []string
		sink := func(line []byte) {
			mu.Lock()
			got = append(got, string(line))
			mu.Unlock()
		}
		p := NewProcess(sp, fakeWaiter{code: 1, delay: 20 * time.Millisecond},
			SpawnSpec{Path: "/bin/echo", Argv: []string{"/bin/echo"}}, sink)
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		select {
		case <-p.LogsDrained():
		case <-time.After(2 * time.Second):
			t.Fatal("LogsDrained did not close")
		}
		// Once drained, every emitted line is already in the sink.
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 || got[0] != "final-diagnostic-line" {
			t.Fatalf("after drain, sink = %v, want [final-diagnostic-line]", got)
		}
	})

	t.Run("no-sink-drained-at-start", func(t *testing.T) {
		p := NewProcess(&fakeSpawner{pid: 2}, fakeWaiter{code: 0},
			SpawnSpec{Path: "/x", Argv: []string{"/x"}}, nil)
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		select {
		case <-p.LogsDrained():
		case <-time.After(time.Second):
			t.Fatal("LogsDrained must be closed for a sink-less process")
		}
	})
}

// TestSpawnFailure surfaces a spawn error and leaves the process unstarted.
func TestSpawnFailure(t *testing.T) {
	boom := errors.New("posix_spawn boom")
	sp := &fakeSpawner{err: boom}
	p := NewProcess(sp, fakeWaiter{}, SpawnSpec{Path: "/x", Argv: []string{"/x"}}, nil)
	if err := p.Start(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("want wrapped spawn error, got %v", err)
	}
	if p.State() != StateInit {
		t.Errorf("state after failed start = %v, want init", p.State())
	}
}

// TestStartErrorClosesDrained guards the start-error footgun: a Process with a
// sink whose Start fails at spawn must still close the drain edge, so a
// LogsDrained() waiter (watchContainerExit's drain-wait) is never wedged forever
// on a Process that never pumped a byte.
func TestStartErrorClosesDrained(t *testing.T) {
	boom := errors.New("posix_spawn boom")
	// A non-nil sink forces the pipe path, so the spawn-error return is the one
	// that must close drained (the pipe was created, the pump never launched).
	sink := func([]byte) {}
	p := NewProcess(&fakeSpawner{err: boom}, fakeWaiter{},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}}, sink)
	if err := p.Start(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("want wrapped spawn error, got %v", err)
	}
	select {
	case <-p.LogsDrained():
	case <-time.After(2 * time.Second):
		t.Fatal("LogsDrained blocked after a failed Start (drained never closed)")
	}
}

// TestWaitBeforeStart returns ErrNotStarted.
func TestWaitBeforeStart(t *testing.T) {
	p := NewProcess(&fakeSpawner{}, fakeWaiter{}, SpawnSpec{Path: "/x", Argv: []string{"/x"}}, nil)
	if _, _, err := p.Wait(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("want ErrNotStarted, got %v", err)
	}
}

// TestEnvCarriesThrough asserts the spawner receives the env verbatim (the DYLD
// insert pass-through the supervisor guarantees).
func TestEnvCarriesThrough(t *testing.T) {
	sp := &fakeSpawner{pid: 5}
	env := []string{"DYLD_INSERT_LIBRARIES=/opt/k3sm/libdnsshim.dylib", "FOO=bar"}
	p := NewProcess(sp, fakeWaiter{code: 0},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}, Env: env}, nil)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, _ = p.Wait(context.Background())
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if len(sp.gotSpec.Env) != 2 || sp.gotSpec.Env[0] != env[0] {
		t.Fatalf("spawner env = %v, want %v", sp.gotSpec.Env, env)
	}
}

// TestNodeNetwork covers the M1 single-node PodNetwork.
func TestNodeNetwork(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{"default-loopback", "", "127.0.0.1"},
		{"node-ip", "10.0.0.5", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NodeNetwork{IP: tc.ip}.Setup(context.Background(), "pod-1")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Setup() = %q, want %q", got, tc.want)
			}
		})
	}
}

// logPipeSpawner is a Spawner that plays a scripted byte stream into the
// Process's combined-log pipe. Unlike fakeSpawner it writes from a goroutine on
// its OWN dup of the write end — the way a real child does — which is required
// for payloads larger than the pipe buffer: a synchronous in-Spawn write would
// deadlock, because Start only launches the pump after Spawn returns. The dup
// also keeps the write end alive past Start's close of the parent's copy, so EOF
// happens exactly when the script is done.
type logPipeSpawner struct {
	pid   int
	write func(w *os.File)
	wrote chan struct{} // closed once the script has run and the dup is closed
}

func (s *logPipeSpawner) Spawn(_ context.Context, spec SpawnSpec) (int, error) {
	fd, err := unix.Dup(int(spec.LogFD))
	if err != nil {
		return 0, err
	}
	w := os.NewFile(uintptr(fd), "log-dup")
	go func() {
		defer close(s.wrote)
		defer func() { _ = w.Close() }()
		s.write(w)
	}()
	return s.pid, nil
}

// TestPumpLogsSurvivesOversizedLine is the B164 gate. A single line longer than
// the pump's per-line cap must NOT stop the pump: before the fix the pump used a
// bufio.Scanner whose Scan() returns false on an over-cap token and whose Err()
// was never checked, so one oversized line silently ended log delivery for the
// rest of the container's life — taking kubectl logs AND the
// FallbackToLogsOnError termination message with it. The load-bearing assertion
// is that a line written AFTER the oversized one still reaches the sink.
func TestPumpLogsSurvivesOversizedLine(t *testing.T) {
	const (
		head   = "HEAD-MARKER"
		marker = "TAIL-MARKER"
	)
	cases := []struct {
		name string
		fill string // repeated to pad the oversized line past the cap
	}{
		{"ascii", "x"},
		{"multibyte", "é"}, // the tail cut lands mid-rune; output must stay valid UTF-8
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pad := strings.Repeat(tc.fill, 2*maxLogLineBytes/len(tc.fill))
			huge := head + pad + marker
			if len(huge) <= maxLogLineBytes {
				t.Fatalf("test payload %d bytes is not oversized (cap %d)", len(huge), maxLogLineBytes)
			}
			if tc.fill == "é" && utf8.Valid([]byte(huge)[len(huge)-maxLogLineBytes:]) {
				t.Fatalf("naive tail is already valid UTF-8; this case no longer exercises rune rounding")
			}

			var buf bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(old)

			var mu sync.Mutex
			var got []string
			sink := func(line []byte) {
				mu.Lock()
				got = append(got, string(line))
				mu.Unlock()
			}

			sp := &logPipeSpawner{pid: 4242, wrote: make(chan struct{}), write: func(w *os.File) {
				// Two oversized lines, so the operator warning can be asserted
				// to fire once per process rather than once per line.
				_, _ = io.WriteString(w, "before\n"+huge+"\n"+huge+"\nafter\n")
			}}
			p := NewProcess(sp, fakeWaiter{code: 0},
				SpawnSpec{Path: "/x", Argv: []string{"/x"}}, sink)
			if err := p.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-p.LogsDrained():
			case <-time.After(30 * time.Second):
				t.Fatal("log pump never drained")
			}
			<-sp.wrote
			_, _, _ = p.Wait(context.Background())

			mu.Lock()
			defer mu.Unlock()
			if len(got) != 4 {
				t.Fatalf("sink got %d lines %s, want 4 (before, 2 truncated, after): "+
					"the pump stopped at the oversized line", len(got), summarize(got))
			}
			if got[0] != "before" {
				t.Errorf("first line = %q, want %q", got[0], "before")
			}
			// The load-bearing assertion: pumping CONTINUED past the oversized line.
			if got[3] != "after" {
				t.Errorf("last line = %q, want %q (output after an oversized line must still be pumped)", got[3], "after")
			}
			for i, ln := range got[1:3] {
				if len(ln) > maxLogLineBytes {
					t.Errorf("oversized line %d delivered as %d bytes, want <= %d", i, len(ln), maxLogLineBytes)
				}
				if !strings.HasSuffix(ln, marker) {
					t.Errorf("oversized line %d does not end with %q; the retained tail is not the line's tail", i, marker)
				}
				if strings.Contains(ln, head) {
					t.Errorf("oversized line %d still carries the head marker; it was not truncated", i)
				}
				if !utf8.ValidString(ln) {
					t.Errorf("oversized line %d is not valid UTF-8 after tail truncation", i)
				}
			}
			if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
				t.Errorf("got %d WARN records, want exactly 1 (once per process): %s", n, buf.String())
			}
			if w := buf.String(); w != "" && !strings.Contains(w, "truncated") {
				t.Errorf("warning does not name the truncation: %s", w)
			}
		})
	}
}

// summarize renders received log lines compactly (they can be ~1 MiB each).
func summarize(lines []string) string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if len(ln) > 32 {
			out = append(out, fmt.Sprintf("%q...(%d bytes)", ln[:32], len(ln)))
			continue
		}
		out = append(out, fmt.Sprintf("%q", ln))
	}
	return "[" + strings.Join(out, " ") + "]"
}

// TestReadLogLineMatchesScanner pins the line semantics B164 inherited: within
// the truncation bound, the replacement reader must split exactly as the
// bufio.Scanner it replaced did — including the final unterminated line, empty
// lines, and CR-stripping — so the fix changes only the oversized case.
func TestReadLogLineMatchesScanner(t *testing.T) {
	inputs := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"one-line", "a\n"},
		{"unterminated", "a"},
		{"blank-lines", "\n\n\n"},
		{"crlf", "a\r\nb\r\n"},
		{"trailing-cr-at-eof", "a\r"},
		{"two-lines-unterminated-last", "a\nb"},
		{"longer-than-read-buffer", strings.Repeat("z", 100) + "\n"},
		{"long-unterminated", strings.Repeat("z", 100)},
		{"mixed", "a\n" + strings.Repeat("q", 40) + "\n\nb\n"},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			var want []string
			sc := bufio.NewScanner(strings.NewReader(tc.in))
			for sc.Scan() {
				want = append(want, sc.Text())
			}
			if err := sc.Err(); err != nil {
				t.Fatalf("scanner: %v", err)
			}

			var got []string
			// A 16-byte read buffer (bufio's minimum) forces the multi-fragment
			// slow path on the longer inputs.
			br := bufio.NewReaderSize(strings.NewReader(tc.in), 16)
			for {
				line, dropped, ok, err := readLogLine(br, maxLogLineBytes)
				if ok {
					got = append(got, string(line))
				}
				if dropped != 0 {
					t.Errorf("dropped = %d, want 0 (no input here exceeds the bound)", dropped)
				}
				if err != nil {
					if !errors.Is(err, io.EOF) {
						t.Fatalf("read: %v", err)
					}
					break
				}
			}
			if len(got) != len(want) {
				t.Fatalf("got %d lines %q, want %d %q", len(got), got, len(want), want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}

// TestReadLogLineTruncatesToTail covers the truncation arithmetic directly at a
// small bound: the retained bytes are the line's tail, within the bound, and the
// dropped count accounts for every byte not delivered.
func TestReadLogLineTruncatesToTail(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		max     int
		want    string
		dropped int
	}{
		{"exactly-at-bound", "0123456789\n", 10, "0123456789", 0},
		{"one-over", "0123456789a\n", 10, "123456789a", 1},
		{"far-over", strings.Repeat("h", 90) + "TAIL012345", 10, "TAIL012345", 90},
		{"rune-boundary", strings.Repeat("é", 20) + "\n", 9, "éééé", 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReaderSize(strings.NewReader(tc.in), 16)
			line, dropped, ok, _ := readLogLine(br, tc.max)
			if !ok {
				t.Fatal("no line produced")
			}
			if string(line) != tc.want {
				t.Errorf("line = %q, want %q", line, tc.want)
			}
			if len(line) > tc.max {
				t.Errorf("line is %d bytes, want <= %d", len(line), tc.max)
			}
			if dropped != tc.dropped {
				t.Errorf("dropped = %d, want %d", dropped, tc.dropped)
			}
			if !utf8.Valid(line) {
				t.Errorf("line %q is not valid UTF-8", line)
			}
		})
	}
}
