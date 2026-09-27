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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/crilog"
)

// appendRaw appends to a raw capture file the way the child does: through an
// O_APPEND descriptor of its own.
func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// eventually polls cond until it holds or 5s pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func offsetIs(path string, want int64) func() bool {
	return func() bool {
		n, err := readOffset(OffsetPath(path))
		return err == nil && n == want
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// startTail runs a rawTail over path in a goroutine and returns its abort and
// stop controls plus a channel that closes when it returns.
func startTail(path string, sk *chunkSink, maxBytes int64) (abort context.CancelFunc, stop chan struct{}, done chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	stop = make(chan struct{})
	done = make(chan struct{})
	tail := &rawTail{path: path, stream: crilog.StreamStdout, sink: sk.sink, maxBytes: maxBytes, poll: 5 * time.Millisecond}
	go func() {
		defer close(done)
		_ = tail.run(ctx, stop)
	}()
	return cancel, stop, done
}

// TestRawTailSurvivesADaemonRestart is the file-capture gate: a child writes
// before, during and after a daemon death (an abort: no final drain, exactly
// what a SIGKILLed daemon does), and every byte reaches the sink exactly once,
// in order, with the offset file tracking what was consumed. An unterminated
// line written across the gap is held until its newline, not split.
func TestRawTailSurvivesADaemonRestart(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "stdout.raw")
	appendRaw(t, raw, "one\ntwo\n")

	first := &chunkSink{}
	abort, _, done := startTail(raw, first, RawCaptureMaxBytes)
	eventually(t, "the first tail to consume the backlog", offsetIs(raw, fileSize(t, raw)))
	appendRaw(t, raw, "three\n")
	eventually(t, "the first tail to consume a live write", offsetIs(raw, fileSize(t, raw)))
	abort() // the daemon dies
	<-done

	// Written while no daemon runs: the child's descriptor is a file, so this
	// neither fails nor is lost.
	appendRaw(t, raw, "four\nfi")

	second := &chunkSink{}
	_, stop, done2 := startTail(raw, second, RawCaptureMaxBytes)
	appendRaw(t, raw, "ve\nsix-unterminated")
	eventually(t, "the second tail to reach the last complete line", func() bool {
		return len(second.lines()) == 2
	})
	close(stop) // the process exits: final drain flushes the partial
	<-done2

	got := append(first.lines(), second.lines()...)
	want := []string{"stdout:one", "stdout:two", "stdout:three", "stdout:four", "stdout:five", "stdout:six-unterminated…"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("delivered %q, want %q (each byte exactly once, in order)", got, want)
	}
	if n, _ := readOffset(OffsetPath(raw)); n != fileSize(t, raw) {
		t.Fatalf("offset = %d, want the whole file %d", n, fileSize(t, raw))
	}
}

// TestRawTailTruncatesAtTheBound pins the disk bound: past maxBytes, once
// consumed to the end, the file is truncated to zero and the offset reset; the
// child's next O_APPEND write lands at the new start and is still delivered.
func TestRawTailTruncatesAtTheBound(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "stdout.raw")
	line := strings.Repeat("x", 30) + "\n"
	appendRaw(t, raw, line+line+line) // 93 bytes > 64

	sk := &chunkSink{}
	_, stop, done := startTail(raw, sk, 64)
	eventually(t, "truncation at the bound", func() bool {
		st, err := os.Stat(raw)
		return err == nil && st.Size() == 0 && offsetIs(raw, 0)()
	})
	appendRaw(t, raw, "after\n")
	eventually(t, "the post-truncate line", offsetIs(raw, int64(len("after\n"))))
	close(stop)
	<-done

	got := sk.lines()
	if len(got) != 4 || got[3] != "stdout:after" {
		t.Fatalf("delivered %q, want three x-lines then stdout:after", got)
	}
}

// TestRawTailSplitsAnUnterminatedLineAtTheBound: a line with no newline that
// reaches crilog.MaxLineBytes is emitted as a partial chunk at the bound, as the
// pipe chunker does, instead of being held forever.
func TestRawTailSplitsAnUnterminatedLineAtTheBound(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "stdout.raw")
	appendRaw(t, raw, strings.Repeat("y", crilog.MaxLineBytes+10))
	sk := &chunkSink{}
	_, stop, done := startTail(raw, sk, RawCaptureMaxBytes)
	eventually(t, "the bound split", func() bool { return len(sk.lines()) == 1 })
	appendRaw(t, raw, "\n")
	eventually(t, "the tail of the long line", func() bool { return len(sk.lines()) == 2 })
	close(stop)
	<-done
	got := sk.lines()
	if len(got[0]) != len("stdout:")+crilog.MaxLineBytes+len("…") || got[1] != "stdout:"+strings.Repeat("y", 10) {
		t.Fatalf("got %d chunks, first %d bytes, second %q", len(got), len(got[0]), got[1])
	}
}

// TestProcessCaptureToFiles runs the Process over capture files: the spec
// carries two DISTINCT file descriptors (not pipes), both streams are delivered
// with their labels, and the drain edge closes after the exit.
func TestProcessCaptureToFiles(t *testing.T) {
	dir := t.TempDir()
	c := FileCapture{Stdout: filepath.Join(dir, "c", "stdout.raw"), Stderr: filepath.Join(dir, "c", "stderr.raw")}
	sp := &fakeSpawner{pid: 1, logLine: "to-stdout", errLine: "to-stderr"}
	sk := &chunkSink{}
	p := NewProcess(sp, fakeWaiter{code: 0, delay: 50 * time.Millisecond}, SpawnSpec{Path: "/x", Argv: []string{"/x"}}, sk.sink)
	p.CaptureToFiles(c)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.LogsDrained():
	case <-time.After(5 * time.Second):
		t.Fatal("LogsDrained did not close after the exit")
	}
	got := sk.lines()
	if len(got) != 2 {
		t.Fatalf("sink got %v, want one line per stream", got)
	}
	if !(got[0] == "stdout:to-stdout" && got[1] == "stderr:to-stderr") && !(got[1] == "stdout:to-stdout" && got[0] == "stderr:to-stderr") {
		t.Fatalf("sink got %v", got)
	}
	sp.mu.Lock()
	out, errFD := sp.gotSpec.StdoutFD, sp.gotSpec.StderrFD
	sp.mu.Unlock()
	if out == 0 || errFD == 0 || out == errFD {
		t.Fatalf("spec fds stdout=%d stderr=%d, want two distinct descriptors", out, errFD)
	}
	for _, raw := range []string{c.Stdout, c.Stderr} {
		st, err := os.Lstat(raw)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			t.Fatalf("capture file %s: %v %v, want a regular 0600 file", raw, st, err)
		}
		if n, _ := readOffset(OffsetPath(raw)); n != st.Size() {
			t.Fatalf("offset of %s = %d, want %d", raw, n, st.Size())
		}
	}
}

// TestCaptureFileRefusesASymlink: the daemon never opens a capture path through
// a link someone else planted.
func TestCaptureFileRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "stdout.raw")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openCaptureFile(link); err == nil {
		_ = f.Close()
		t.Fatal("openCaptureFile followed a symlink")
	}
}
