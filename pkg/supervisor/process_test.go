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
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/crilog"
)

// fakeSpawner records the spec and returns a canned pid/err. If it has a logLine
// it writes the line to the spec's stdout fd (and errLine to the stderr fd) so
// the Process log pumps can be exercised without a real child. Both fds are
// closed afterwards, which is what gives each pump its EOF.
type fakeSpawner struct {
	pid     int
	err     error
	logLine string
	errLine string

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
	if err := writeAndClose(spec.StdoutFD, f.logLine); err != nil {
		return 0, err
	}
	if err := writeAndClose(spec.StderrFD, f.errLine); err != nil {
		return 0, err
	}
	return f.pid, nil
}

// writeAndClose writes payload (plus a newline, when non-empty) to a DUP of fd
// and closes the dup — the child's half of one stream, played synchronously
// because the payloads here are far under the pipe buffer.
//
// The dup is not a flourish. Closing the fd the Process still holds frees that
// NUMBER, and the next unix.Dup in the same spawner takes the lowest free one —
// so Start's own closeWriteEnds then closes a descriptor that now belongs to the
// other stream, and both pipes EOF at once. Writing through a dup leaves every
// descriptor's ownership exactly where Start put it.
func writeAndClose(fd uintptr, payload string) error {
	if fd == 0 {
		return nil
	}
	d, err := unix.Dup(int(fd))
	if err != nil {
		return err
	}
	w := os.NewFile(uintptr(d), "streamfd")
	if payload != "" {
		if _, werr := w.WriteString(payload + "\n"); werr != nil {
			_ = w.Close()
			return werr
		}
	}
	return w.Close()
}

// chunkSink collects what the pumps delivered, tagged by stream.
type chunkSink struct {
	mu   sync.Mutex
	got  []string
	errs []error
}

// sink is the LogSink; it renders each chunk as "<stream>:<payload>" (a P chunk
// gets a trailing "…") so a test can assert the label and the tag together.
func (c *chunkSink) sink(stream crilog.Stream, chunk []byte, partial bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rendered := string(stream) + ":" + string(chunk)
	if partial {
		rendered += "…"
	}
	c.got = append(c.got, rendered)
	if len(c.errs) > 0 {
		err := c.errs[0]
		c.errs = c.errs[1:]
		return err
	}
	return nil
}

func (c *chunkSink) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.got...)
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
	sk := &chunkSink{}

	p := NewProcess(sp, fakeWaiter{code: 0, delay: 50 * time.Millisecond},
		SpawnSpec{Path: "/bin/echo", Argv: []string{"/bin/echo"}}, sk.sink)
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, _, err := p.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	select {
	case <-p.LogsDrained():
	case <-time.After(2 * time.Second):
		t.Fatal("LogsDrained did not close")
	}
	got := sk.lines()
	if len(got) != 1 || got[0] != "stdout:hello-pod" {
		t.Fatalf("captured logs = %v, want [stdout:hello-pod]", got)
	}
}

// TestProcessLogsDrained checks the drain edge: with a sink, LogsDrained closes only
// after the pump has flushed every line to the sink (the B11 "logs fully drained"
// guarantee watchContainerExit relies on); with no sink there is no pump, so it is
// closed at Start.
func TestProcessLogsDrained(t *testing.T) {
	t.Run("closes-after-all-lines-flushed", func(t *testing.T) {
		sp := &fakeSpawner{pid: 1, logLine: "final-diagnostic-line"}
		sk := &chunkSink{}
		p := NewProcess(sp, fakeWaiter{code: 1, delay: 20 * time.Millisecond},
			SpawnSpec{Path: "/bin/echo", Argv: []string{"/bin/echo"}}, sk.sink)
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		select {
		case <-p.LogsDrained():
		case <-time.After(2 * time.Second):
			t.Fatal("LogsDrained did not close")
		}
		// Once drained, every emitted chunk is already in the sink.
		if got := sk.lines(); len(got) != 1 || got[0] != "stdout:final-diagnostic-line" {
			t.Fatalf("after drain, sink = %v, want [stdout:final-diagnostic-line]", got)
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
	sink := func(crilog.Stream, []byte, bool) error { return nil }
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
// its own dup of the write end — the way a real child does — which is required
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
	fd, err := unix.Dup(int(spec.StdoutFD))
	if err != nil {
		return 0, err
	}
	w := os.NewFile(uintptr(fd), "log-dup")
	go func() {
		defer close(s.wrote)
		defer func() { _ = w.Close() }()
		s.write(w)
	}()
	// The stderr pipe gets no writer at all: closing the parent's copy in Start
	// is enough for that pump to see EOF immediately, which is exactly the
	// "one stream is silent" shape a real container commonly has.
	return s.pid, nil
}

// TestPumpLogsChunksOversizedLine is the B164 successor. The predecessor
// asserted that an oversized line was TRUNCATED to its tail and that the pump
// kept going; the truncation is gone — crilog splits instead — so what is
// asserted now is stronger: a 2 MiB line arrives COMPLETE, as P chunks followed
// by an F, and output after it still flows. Nothing a container writes is
// dropped by the pump any more.
func TestPumpLogsChunksOversizedLine(t *testing.T) {
	const (
		head   = "HEAD-MARKER"
		marker = "TAIL-MARKER"
	)
	pad := strings.Repeat("x", 2<<20)
	huge := head + pad + marker

	sk := &chunkSink{}
	sp := &logPipeSpawner{pid: 4242, wrote: make(chan struct{}), write: func(w *os.File) {
		_, _ = io.WriteString(w, "before\n"+huge+"\nafter\n")
	}}
	p := NewProcess(sp, fakeWaiter{code: 0},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}}, sk.sink)
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

	got := sk.lines()
	if len(got) < 3 {
		t.Fatalf("sink got %d chunks, want the oversized line split across several", len(got))
	}
	if got[0] != "stdout:before" {
		t.Errorf("first chunk = %q, want %q", got[0], "stdout:before")
	}
	// The load-bearing assertion: pumping CONTINUED past the oversized line.
	if last := got[len(got)-1]; last != "stdout:after" {
		t.Errorf("last chunk = %q, want %q (output after an oversized line must still be pumped)", last, "stdout:after")
	}

	// Reassemble the middle: every P chunk plus the F that ends the run must
	// reproduce the line exactly — nothing dropped, nothing duplicated.
	var rejoined strings.Builder
	for _, c := range got[1 : len(got)-1] {
		payload := strings.TrimPrefix(c, "stdout:")
		payload = strings.TrimSuffix(payload, "…")
		rejoined.WriteString(payload)
	}
	if rejoined.String() != huge {
		t.Errorf("the reassembled line is %d bytes, want %d — the pump lost or duplicated content",
			rejoined.Len(), len(huge))
	}
	for i, c := range got[1 : len(got)-2] {
		if !strings.HasSuffix(c, "…") {
			t.Errorf("middle chunk %d is not tagged partial: %.32q", i, c)
		}
	}
	if c := got[len(got)-2]; strings.HasSuffix(c, "…") {
		t.Error("the chunk ending the oversized line is tagged partial; it must be full")
	}
}

// TestTwoStreamCaptureLabelsStderr pins the split the CRI log format needs: the
// child's fd 1 and fd 2 arrive on separate pipes and reach the sink with
// separate labels. A merged pipe cannot be un-merged downstream, so this is the
// only place the distinction can be established.
func TestTwoStreamCaptureLabelsStderr(t *testing.T) {
	sp := &fakeSpawner{pid: 1, logLine: "to-stdout", errLine: "to-stderr"}
	sk := &chunkSink{}
	p := NewProcess(sp, fakeWaiter{code: 0},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}}, sk.sink)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.LogsDrained():
	case <-time.After(5 * time.Second):
		t.Fatal("LogsDrained did not close")
	}

	got := sk.lines()
	want := map[string]bool{"stdout:to-stdout": true, "stderr:to-stderr": true}
	if len(got) != 2 {
		t.Fatalf("sink got %v, want one chunk per stream", got)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected chunk %q; want exactly %v", c, want)
		}
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("missing chunks: %v — the two streams are not separately labelled", want)
	}

	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.gotSpec.StdoutFD == 0 || sp.gotSpec.StderrFD == 0 {
		t.Errorf("spec carried StdoutFD=%d StderrFD=%d, want both set", sp.gotSpec.StdoutFD, sp.gotSpec.StderrFD)
	}
	if sp.gotSpec.StdoutFD == sp.gotSpec.StderrFD {
		t.Error("both streams were handed the SAME fd; the labels would be a fiction")
	}
}

// TestLogsDrainedWaitsForBothPumps is the two-pump drain gate. With one stream
// finished and the other still open, LogsDrained must stay OPEN: a sync.Once
// closed on the first pump's EOF would report "drained" while the dying child's
// stderr — the panic, the stack trace — was still in flight, which is exactly
// what the drain edge exists to prevent.
func TestLogsDrainedWaitsForBothPumps(t *testing.T) {
	held := make(chan struct{})
	sp := &spawnerHoldingStderr{pid: 7, release: held}
	sk := &chunkSink{}
	p := NewProcess(sp, fakeWaiter{code: 0},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}}, sk.sink)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// stdout has already reached EOF (the spawner closed it). Give the pump
	// time to finish and assert the edge has NOT fired.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(sk.lines()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-p.LogsDrained():
		t.Fatal("LogsDrained closed on the FIRST pump's EOF; the other stream was still open")
	default:
	}

	close(held) // the stderr writer goes away
	select {
	case <-p.LogsDrained():
	case <-time.After(5 * time.Second):
		t.Fatal("LogsDrained never closed after both pumps finished")
	}
	if got := sk.lines(); len(got) != 2 {
		t.Fatalf("sink got %v, want one chunk from each stream", got)
	}
}

// spawnerHoldingStderr writes one line to each stream, closes stdout, and keeps
// its dup of the stderr write end open until release is closed — the two-pump
// analogue of a forked grandchild holding a pipe.
type spawnerHoldingStderr struct {
	pid     int
	release chan struct{}
}

func (s *spawnerHoldingStderr) Spawn(_ context.Context, spec SpawnSpec) (int, error) {
	if err := writeAndClose(spec.StdoutFD, "out-line"); err != nil {
		return 0, err
	}
	fd, err := unix.Dup(int(spec.StderrFD))
	if err != nil {
		return 0, err
	}
	w := os.NewFile(uintptr(fd), "stderr-dup")
	if _, err := w.WriteString("err-line\n"); err != nil {
		_ = w.Close()
		return 0, err
	}
	go func() {
		<-s.release
		_ = w.Close()
	}()
	return s.pid, nil
}

// TestStartUnwindsBothPipesOnFailure pins the partial-failure unwind: a spawn
// that fails after both pipes exist must leave NO descriptor open. A daemon that
// leaked two fds per failed start — and a failed start is the ordinary outcome
// of a bad image on a node running every pod — would run out of descriptors.
func TestStartUnwindsBothPipesOnFailure(t *testing.T) {
	boom := errors.New("posix_spawn boom")
	rec := &fdRecordingSpawner{err: boom}
	p := NewProcess(rec, fakeWaiter{},
		SpawnSpec{Path: "/x", Argv: []string{"/x"}}, (&chunkSink{}).sink)
	if err := p.Start(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("want wrapped spawn error, got %v", err)
	}

	if p.outR != nil || p.outW != nil || p.errR != nil || p.errW != nil {
		t.Error("a pipe end is still held on the Process after a failed Start")
	}
	// The write ends the spawner saw must be closed. (A descriptor number can in
	// principle be reused by another goroutine in this binary between the close
	// and this check; nothing here opens files, so the residual is accepted for
	// the directness of the assertion.)
	for name, fd := range map[string]uintptr{"stdout": rec.outFD, "stderr": rec.errFD} {
		if fd == 0 {
			t.Fatalf("%s fd was never stamped on the spec", name)
		}
		if _, err := unix.FcntlInt(fd, unix.F_GETFD, 0); err == nil {
			t.Errorf("%s write end (fd %d) is still open after a failed Start", name, fd)
		}
	}
}

// fdRecordingSpawner records the two write-end fds it was handed and fails.
type fdRecordingSpawner struct {
	err          error
	outFD, errFD uintptr
}

func (s *fdRecordingSpawner) Spawn(_ context.Context, spec SpawnSpec) (int, error) {
	s.outFD, s.errFD = spec.StdoutFD, spec.StderrFD
	return 0, s.err
}
