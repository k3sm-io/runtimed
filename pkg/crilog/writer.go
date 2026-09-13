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
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Stream is the CRI log-line stream label. The two values are WIRE: they are
// written verbatim into every line of every container log file and parsed back
// by the reader, so they are the lowercase spellings CRI defines
// (k8s.io/cri-api runtime/v1: Stdout, Stderr) and never anything else.
type Stream string

// The two streams a container writes.
const (
	// StreamStdout labels a chunk that came from the container's fd 1.
	StreamStdout Stream = "stdout"
	// StreamStderr labels a chunk that came from the container's fd 2. It is
	// kept distinct all the way to disk: `kubectl logs` presents the two
	// together, but a reader that asked for the split cannot recover it from a
	// merged file.
	StreamStderr Stream = "stderr"
)

// The CRI log tags. A chunk is P when it is part of a longer logical line and F
// when it ends one; a reader concatenates a P run and stops at the F.
const (
	tagPartial = "P"
	tagFull    = "F"
)

// MaxLineBytes is the most content one rendered line carries. A logical line
// longer than this is emitted as P chunks of exactly MaxLineBytes followed by a
// final chunk — so it is SPLIT, never truncated, and a reader reassembles it
// byte for byte.
//
// 16 KiB is containerd's value and therefore the one every kubelet-side reader
// has been exercised against. It is deliberately not a tunable: the number is
// only meaningful because both ends agree on it.
const MaxLineBytes = 16 << 10

// timestampFormat is RFC3339 with a FIXED nine-digit nanosecond field
// (k8s.io/apimachinery's RFC3339NanoFixed). time.RFC3339Nano drops trailing
// zeros, which makes the timestamp column ragged and breaks the reader's
// fixed-width fast path, so the padded form is written instead.
const timestampFormat = "2006-01-02T15:04:05.000000000Z07:00"

// ErrWriterFailed reports that a Writer has taken a write error and will not
// write again. It is STICKY by design: see Writer for the failure policy and
// why retrying a container log write is the wrong answer.
var ErrWriterFailed = errors.New("crilog: log writer failed")

// sink is the Writer's file seam: the subset of *os.File it uses. It exists so
// a test can inject a writer that fails deterministically — a persistent ENOSPC
// is the failure the policy below is written for and is not reproducible with a
// real file.
type sink interface {
	io.Writer
	io.Closer
}

// Writer appends a container's output to one CRI-format log file.
//
// # Concurrency
//
// mu guards the file handle and the sticky error, and it is held across the
// whole of one Write. That is what makes a line ATOMIC with respect to the
// other stream: both of a container's pumps share one Writer, so without the
// lock a stdout chunk and a stderr chunk could interleave mid-line and produce
// a file no reader can parse. Reopen swaps the handle under the same lock, so a
// rotation can never land between a line's bytes.
//
// # Failure policy (deliberate, and the opposite of best-effort)
//
// A Write error is recorded and STICKY: every later Write returns it without
// touching the file. The caller — the supervisor's log pump — stops consuming
// that stream and closes its read end, so the container's own write(2) gets
// EPIPE/SIGPIPE. That is containerd's behaviour and it is the honest one on
// this platform: a pump that kept retrying a full or broken disk would leave
// the pod's pipe undrained, and an undrained pipe on XNU blocks the pod's
// write(2) forever with nothing anywhere saying why. A container that is told
// its output is gone can decide what to do; a container blocked on a full pipe
// cannot.
//
// The zero value is not usable; construct one with Open.
type Writer struct {
	path string
	// now is the clock. It is a field only so the golden tests can pin the
	// timestamp column; production never sets it.
	now func() time.Time

	mu  sync.Mutex
	f   sink
	err error
}

// Open opens (creating, appending to) the CRI log file at path and returns a
// Writer over it.
//
// The parent directory is created 0700 defensively. The node owns the log tree
// and creates it before it ever sends a PodBox — but a runtime that refused to
// start a container because a directory the node promised was missing would
// turn a node-side bug into a pod failure, and MkdirAll on a directory that
// already exists is free.
//
// The file is opened O_CREATE|O_APPEND|O_WRONLY at 0600 — append because the
// file may already hold this instance's earlier output (a daemon restart
// re-opens the same path), write-only because nothing in this process ever
// reads it, and 0600 because a pod's output is the pod's, readable through
// `kubectl logs` or as the daemon user, not by every local account.
func Open(path string) (*Writer, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("crilog: log path %q must be absolute", path)
	}
	w := &Writer{path: path, now: time.Now}
	f, err := w.openFile()
	if err != nil {
		return nil, err
	}
	w.f = f
	return w, nil
}

// openFile opens the writer's path fresh. It is the one place the flags and
// modes live, so Open and Reopen cannot come to disagree about them.
func (w *Writer) openFile() (sink, error) {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return nil, fmt.Errorf("create container log dir for %s: %w", w.path, err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open container log %s: %w", w.path, err)
	}
	return f, nil
}

// Path returns the file the Writer appends to. It is what
// ContainerStatus.log_path publishes, so the runtime reads it from here rather
// than re-deriving the name.
func (w *Writer) Path() string { return w.path }

// Write renders one chunk as a CRI log line and appends it.
//
// partial chooses the tag: true is P (this chunk continues a logical line),
// false is F (this chunk ends one). chunk must not contain a newline — the
// chunker guarantees that, and a caller that broke it would write a line the
// reader splits at the wrong place.
//
// It returns an ErrWriterFailed-wrapping error once the Writer has failed, and
// keeps returning it; see Writer for why the failure is sticky.
func (w *Writer) Write(stream Stream, chunk []byte, partial bool) error {
	tag := tagFull
	if partial {
		tag = tagPartial
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}

	// One buffer, one Write: the line must reach the file in a single syscall
	// so a concurrent write on the other stream cannot interleave with it.
	line := make([]byte, 0, len(chunk)+len(timestampFormat)+16)
	line = w.now().UTC().AppendFormat(line, timestampFormat)
	line = append(line, ' ')
	line = append(line, stream...)
	line = append(line, ' ')
	line = append(line, tag...)
	line = append(line, ' ')
	line = append(line, chunk...)
	line = append(line, '\n')

	if _, err := w.f.Write(line); err != nil {
		w.err = fmt.Errorf("%w: %s: %w", ErrWriterFailed, w.path, err)
		return w.err
	}
	return nil
}

// Reopen closes the current handle and opens the same path again — the runtime
// half of log rotation, served by ReopenContainerLog.
//
// The node renames the file out from under this Writer and then calls it. The
// open fd keeps writing into the RENAMED inode until this runs, so nothing is
// lost in the window; the new handle is created with O_CREATE|O_APPEND and
// never O_TRUNC, so a path that was not in fact rotated keeps its content.
// The swap happens under the same lock Write holds, so it can never land
// between a line's bytes.
//
// A Writer that has already failed is NOT resurrected: the error is returned
// and the handle left alone. The pump that fed it has closed its read end (see
// Writer), so a fresh fd would have nothing to write; reporting the failure is
// what tells the node why rotation is pointless for this container.
func (w *Writer) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	f, err := w.openFile()
	if err != nil {
		return err
	}
	old := w.f
	w.f = f
	if old != nil {
		_ = old.Close() // the new handle is already installed; a close error changes nothing
	}
	return nil
}

// Close releases the file. Later Writes fail (the handle is closed), which is
// the correct answer for a container that is gone.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	// A closed Writer must not be silently re-usable: pin the terminal state so
	// a stray Write returns the typed failure rather than a nil-deref.
	if w.err == nil {
		w.err = fmt.Errorf("%w: %s: closed", ErrWriterFailed, w.path)
	}
	return err
}
