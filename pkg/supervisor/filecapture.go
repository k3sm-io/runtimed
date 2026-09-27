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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k3sm.io/runtimed/pkg/crilog"
)

const (
	// RawCaptureMaxBytes is the size past which a raw capture file is truncated
	// to zero, once its tail has consumed it to the end (see rawTail).
	RawCaptureMaxBytes int64 = 16 << 20
	// rawTailPoll is how often a tail looks for new output at end of file.
	rawTailPoll = 100 * time.Millisecond
	// rawReadBytes bounds one read of a raw file, so a burst never becomes one
	// allocation the size of the backlog.
	rawReadBytes = 1 << 20
)

// FileCapture names the two append-only files a process's stdout and stderr are
// written to instead of pipes (see Process.CaptureToFiles). Both must be
// absolute paths in a directory only the daemon can write.
type FileCapture struct {
	// Stdout receives the child's fd 1.
	Stdout string
	// Stderr receives the child's fd 2.
	Stderr string
}

// OffsetPath is where the tail of raw persists how far it has consumed raw:
// raw + ".offset", a decimal byte count replaced by write-then-rename.
func OffsetPath(raw string) string { return raw + ".offset" }

// openCaptureFile opens (creating) a raw capture file for the child to append
// to. O_NOFOLLOW: the daemon never follows a link it did not make.
func openCaptureFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create capture dir for %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open capture file %s: %w", path, err)
	}
	return f, nil
}

// readOffset loads a persisted tail offset. A missing file is offset 0.
func readOffset(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("malformed tail offset %q in %s", b, path)
	}
	return n, nil
}

// writeOffset persists a tail offset atomically (write-then-rename).
func writeOffset(path string, n int64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(n, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// rawTail copies one raw capture file into a LogSink, from a persisted offset,
// so capture survives the daemon: the child's descriptor is a file, not a pipe
// into this process, so a daemon death neither kills the writer (no EPIPE) nor
// loses what it writes meanwhile, and the next daemon resumes from the offset.
//
// Lines are chunked exactly as the pipe pump chunks them (crilog.Chunk over the
// complete lines read), and stamped when they are READ — output written while no
// daemon was running carries the time it was captured, not the time it was
// written.
//
// The offset is persisted after each batch reaches the sink. A daemon that dies
// between the sink write and the rename replays that one batch on resume:
// delivery is at-least-once for the last batch, exactly-once otherwise.
//
// # Disk bound, and its accepted cost
//
// When the file has grown past maxBytes AND the tail has consumed it to the end,
// it is truncated to zero and the offset reset. O_APPEND makes the child's next
// write land at the new end. Bytes the child appends between the size check and
// the truncate are LOST — a window of one stat plus one truncate, taken only at
// a quiet end of file. That loss is the accepted cost of file capture until a
// resident per-container shim (the containerd-shim shape) owns the stdio and can
// rotate without a race. A tail that stops (a sink error) no longer truncates,
// so the file then grows with the child's output until the pod is deleted.
type rawTail struct {
	path     string
	stream   crilog.Stream
	sink     LogSink
	maxBytes int64
	poll     time.Duration
	offset   int64
}

// run tails until stop is closed (the process exited), then drains to the end of
// the file — flushing an unterminated last line as a partial chunk — and returns.
// abort ends it at once WITHOUT the final drain; production never aborts (the
// daemon's own death is the only abort), tests use it to simulate one. It
// returns only a sink error.
func (t *rawTail) run(abort context.Context, stop <-chan struct{}) error {
	f, err := os.OpenFile(t.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open capture file for tailing: %w", err)
	}
	defer func() { _ = f.Close() }()
	off, err := readOffset(OffsetPath(t.path))
	if err != nil {
		slog.Warn("capture tail: unreadable offset, resuming from the start", "path", t.path, "err", err)
		off = 0
	}
	t.offset = off
	// Written at once, even with nothing consumed: an offset file is what tells
	// a later daemon that this container's output is file-captured.
	t.persist()
	for {
		select {
		case <-abort.Done():
			return nil
		default:
		}
		stopped := false
		select {
		case <-stop:
			stopped = true
		default:
		}
		if err := t.drain(f, stopped); err != nil {
			return err
		}
		if stopped {
			return nil
		}
		timer := time.NewTimer(t.poll)
		select {
		case <-abort.Done():
			timer.Stop()
			return nil
		case <-stop:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// drain consumes everything complete in the file past the offset. With final,
// an unterminated last line is emitted too (partial, crilog.Chunk's EOF rule).
func (t *rawTail) drain(f *os.File, final bool) error {
	for {
		st, err := f.Stat()
		if err != nil {
			return nil // transient: retried next poll
		}
		size := st.Size()
		if t.offset > size {
			// Truncated under us (never by this tail, which resets as it
			// truncates): start over from the new beginning.
			t.offset = 0
			t.persist()
		}
		if size == t.offset {
			if size > t.maxBytes {
				if err := os.Truncate(t.path, 0); err == nil {
					t.offset = 0
					t.persist()
				} else {
					slog.Warn("capture tail: truncate at the size bound failed", "path", t.path, "err", err)
				}
			}
			return nil
		}
		n := min(size-t.offset, rawReadBytes)
		buf := make([]byte, n)
		got, err := f.ReadAt(buf, t.offset)
		buf = buf[:got]
		if got == 0 {
			if err != nil {
				return nil
			}
			continue
		}
		var consumed int
		switch complete := bytes.LastIndexByte(buf, '\n') + 1; {
		case complete > 0:
			if err := crilog.Chunk(bytes.NewReader(buf[:complete]), func(chunk []byte, partial bool) error {
				return t.sink(t.stream, chunk, partial)
			}); err != nil {
				return err
			}
			consumed = complete
		case len(buf) >= crilog.MaxLineBytes:
			// An unterminated line already at the bound: split it here, exactly
			// where the pipe chunker would.
			if err := t.sink(t.stream, buf[:crilog.MaxLineBytes], true); err != nil {
				return err
			}
			consumed = crilog.MaxLineBytes
		case final:
			if err := t.sink(t.stream, buf, true); err != nil {
				return err
			}
			consumed = len(buf)
		default:
			return nil // an incomplete line: wait for its newline
		}
		t.offset += int64(consumed)
		t.persist()
	}
}

func (t *rawTail) persist() {
	if err := writeOffset(OffsetPath(t.path), t.offset); err != nil {
		slog.Warn("capture tail: persist offset", "path", t.path, "err", err)
	}
}
