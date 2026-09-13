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

package crilog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedClock returns a deterministic, advancing clock so the timestamp column
// of a golden file is reproducible.
func fixedClock() func() time.Time {
	base := time.Date(2026, 9, 13, 10, 30, 0, 123456789, time.UTC)
	var n int
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Millisecond)
		n++
		return t
	}
}

// openTestWriter opens a Writer under t.TempDir() with a pinned clock.
func openTestWriter(t *testing.T) *Writer {
	t.Helper()
	w, err := Open(filepath.Join(t.TempDir(), "logs", "0.log"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	w.now = fixedClock()
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// TestWriterRendersCRIFormat pins the on-disk line format against a golden
// file. The format is a cross-project contract — the node's reader parses
// exactly these five fields in exactly this order — so it is asserted
// byte-for-byte rather than by a field-by-field re-derivation that would drift
// with the code it checks.
func TestWriterRendersCRIFormat(t *testing.T) {
	w := openTestWriter(t)

	writes := []struct {
		stream  Stream
		chunk   string
		partial bool
	}{
		{StreamStdout, "hello from the pod", false},
		{StreamStderr, "a diagnostic", false},
		{StreamStdout, "a long line that was", true},
		{StreamStdout, " split in two", false},
		{StreamStdout, "", false},
		{StreamStderr, "trailing unterminated output", true},
	}
	for i, wr := range writes {
		if err := w.Write(wr.stream, []byte(wr.chunk), wr.partial); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	got, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	golden := filepath.Join("testdata", "cri-format.log")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("rendered log does not match %s:\n got:\n%s\nwant:\n%s", golden, got, want)
	}
}

// TestWriterFileMode pins the two modes the privilege model depends on: the log
// tree is the daemon user's alone (0700 dirs, 0600 files), not the 0755/0644 a
// naive copy of upstream's numbers would give on a Mac where the daemon user's
// primary group is staff.
func TestWriterFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "0.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("log file mode = %v, want 0600", got)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("log dir mode = %v, want 0700", got)
	}
}

// TestWriterAppendsRatherThanTruncates asserts a second Open on the same path
// keeps what is there — the daemon-restart case, where the same instance's file
// is reopened and must not lose the output of the run before the restart.
func TestWriterAppendsRatherThanTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0.log")
	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.Write(StreamStdout, []byte("before"), false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := second.Write(StreamStdout, []byte("after"), false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("file holds %d lines, want 2 (the reopen truncated): %q", n, b)
	}
	if !strings.Contains(string(b), "before") {
		t.Errorf("the pre-restart output is gone: %q", b)
	}
}

// TestWriterReopenLosesNothingUnderConcurrentWrites is the rotation gate. Two
// goroutines write while Reopen runs repeatedly (the node rotating the file
// under a live container). Every line must survive, whole, in exactly one of
// the files — a Reopen that raced a Write would either lose a line or leave a
// half-written one. Run with -race.
func TestWriterReopenLosesNothingUnderConcurrentWrites(t *testing.T) {
	const (
		perStream = 300
		rotations = 25
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	var wg sync.WaitGroup
	for _, stream := range []Stream{StreamStdout, StreamStderr} {
		wg.Add(1)
		go func(s Stream) {
			defer wg.Done()
			for i := range perStream {
				if err := w.Write(s, []byte(fmt.Sprintf("%s-%04d", s, i)), false); err != nil {
					t.Errorf("Write(%s, %d): %v", s, i, err)
					return
				}
			}
		}(stream)
	}

	// The rotation loop: rename the live file aside and reopen, exactly as the
	// node's rotation manager does, so lines land across several files and a
	// lost one cannot hide in a still-open handle.
	rotated := make([]string, 0, rotations)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range rotations {
			target := filepath.Join(dir, fmt.Sprintf("0.log.%d", i))
			if err := os.Rename(path, target); err != nil {
				t.Errorf("rotate %d: %v", i, err)
				return
			}
			rotated = append(rotated, target)
			if err := w.Reopen(); err != nil {
				t.Errorf("Reopen %d: %v", i, err)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	<-done

	seen := map[string]int{}
	for _, f := range append(rotated, path) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if line == "" {
				continue
			}
			fields := strings.SplitN(line, " ", 4)
			if len(fields) != 4 {
				t.Fatalf("malformed line %q in %s: a write was interleaved or split", line, f)
			}
			if fields[1] != string(StreamStdout) && fields[1] != string(StreamStderr) {
				t.Fatalf("line %q carries stream %q", line, fields[1])
			}
			if fields[2] != tagFull {
				t.Fatalf("line %q carries tag %q, want %q", line, fields[2], tagFull)
			}
			seen[fields[3]]++
		}
	}
	if len(seen) != 2*perStream {
		t.Fatalf("recovered %d distinct lines across the rotated set, want %d", len(seen), 2*perStream)
	}
	for payload, n := range seen {
		if n != 1 {
			t.Errorf("line %q appears %d times, want 1", payload, n)
		}
	}
}

// failingSink fails every Write after the first, counting the calls that reach
// it. A persistent ENOSPC/EIO is what the sticky-failure policy exists for and
// cannot be provoked with a real file.
type failingSink struct {
	mu     sync.Mutex
	calls  int
	failAt int
	err    error
}

func (f *failingSink) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls >= f.failAt {
		return 0, f.err
	}
	return len(p), nil
}

func (f *failingSink) Close() error { return nil }

func (f *failingSink) seen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestWriterStopsOnPersistentWriteError pins the failure policy: once a write
// fails, the Writer reports ErrWriterFailed and never touches the file again.
// The load-bearing assertion is the call count — a Writer that retried would
// leave the pod's pipe drained and the operator with no signal, which is the
// silent-data-loss shape this policy rejects.
func TestWriterStopsOnPersistentWriteError(t *testing.T) {
	enospc := errors.New("no space left on device")
	f := &failingSink{failAt: 2, err: enospc}
	w := &Writer{path: "/var/log/pods/ns_pod_uid/c/0.log", now: fixedClock(), f: f}

	if err := w.Write(StreamStdout, []byte("first"), false); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	err := w.Write(StreamStdout, []byte("second"), false)
	if !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("second Write err = %v, want ErrWriterFailed", err)
	}
	if !errors.Is(err, enospc) {
		t.Errorf("the errno is not preserved in %v", err)
	}
	if !strings.Contains(err.Error(), w.Path()) {
		t.Errorf("error %v does not name the path %q", err, w.Path())
	}

	for i := range 3 {
		if e := w.Write(StreamStdout, []byte("later"), false); !errors.Is(e, ErrWriterFailed) {
			t.Fatalf("Write %d after failure = %v, want the sticky ErrWriterFailed", i, e)
		}
	}
	if got := f.seen(); got != 2 {
		t.Errorf("the file saw %d writes, want 2 (one success, one failure, then no retries)", got)
	}
	if e := w.Reopen(); !errors.Is(e, ErrWriterFailed) {
		t.Errorf("Reopen on a failed writer = %v, want the sticky failure", e)
	}
}
