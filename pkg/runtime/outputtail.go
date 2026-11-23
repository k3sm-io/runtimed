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
	"bytes"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// The bounds of a failed init container's output tail: at most this many
// lines and this many bytes once rendered. The tail is appended to the error
// that rejects the pod, which the provider puts into an Event and the pod
// status, so it must stay short.
const (
	initTailMaxLines = 8
	initTailMaxBytes = 2048
	// initTailWindowBytes is the raw output retained before sanitising. It is
	// twice the rendered bound so stripped control bytes and a cut first line
	// still leave a full tail to render.
	initTailWindowBytes = 2 * initTailMaxBytes
	// shimLogTailBytes is how much of a resident-shim init container's CRI
	// log file is read back, from its end, when no in-daemon tail exists.
	shimLogTailBytes = 4096
)

// outputTail keeps the last few KiB of one plain init container's output in
// memory.
//
// It exists for one case: an init container that exits non-zero rejects the
// whole pod, a rejected pod is never registered and keeps no log directory,
// so the CRI log file is not there to read afterwards. The tail is what lets
// the rejection say why ("init container X exited 74: <its last lines>").
// It is NOT a log. On the in-daemon pump path it is filled alongside the file
// write (containerLogSink), and only a plain init container gets one, so a
// pod's memory cost is initTailWindowBytes per init container while it runs.
// On the resident-shim path the daemon never sees the output, so the tail is
// built after the exit from the end of the CRI log file the shim wrote
// (readCRILogTail), through the same record/render rules.
//
// Concurrency: record is called from both of a container's pump goroutines
// (stdout and stderr) with no serialisation between them, so mu guards buf.
// The two streams are interleaved chunk by chunk, in the order the pumps
// deliver them.
type outputTail struct {
	mu  sync.Mutex
	buf []byte
	// cut records that bytes were dropped from the front of buf, so its first
	// line may be the end of a longer one.
	cut bool
}

// record appends one CRI chunk to the tail, terminating the line when the
// chunk is not partial, and keeps only the last initTailWindowBytes.
func (t *outputTail) record(chunk []byte, partial bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(chunk) >= initTailWindowBytes {
		t.buf = append(t.buf[:0], chunk[len(chunk)-initTailWindowBytes:]...)
		t.cut = true
	} else {
		t.buf = append(t.buf, chunk...)
	}
	if !partial {
		t.buf = append(t.buf, '\n')
	}
	if over := len(t.buf) - initTailWindowBytes; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
		t.cut = true
	}
}

// render returns the tail as at most initTailMaxLines non-empty lines joined
// by newlines, at most initTailMaxBytes long, with invalid UTF-8 and control
// characters removed (a tab becomes a space). It returns "" when the
// container printed nothing printable.
func (t *outputTail) render() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	text := sanitizeTail(t.buf)
	cut := t.cut
	t.mu.Unlock()

	lines := strings.Split(text, "\n")
	if cut && len(lines) > 1 {
		lines = lines[1:] // the end of a line whose start was dropped
	}
	kept := make([]string, 0, initTailMaxLines)
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			kept = append(kept, l)
		}
	}
	if len(kept) > initTailMaxLines {
		kept = kept[len(kept)-initTailMaxLines:]
	}
	out := strings.Join(kept, "\n")
	for len(out) > initTailMaxBytes && len(kept) > 1 {
		kept = kept[1:]
		out = strings.Join(kept, "\n")
	}
	if len(out) > initTailMaxBytes {
		// One line longer than the bound: keep its end, which is where a
		// failing program usually says what went wrong.
		const ellipsis = "..."
		start := len(out) - (initTailMaxBytes - len(ellipsis))
		for start < len(out) && !utf8.RuneStart(out[start]) {
			start++
		}
		out = ellipsis + out[start:]
	}
	return out
}

// sanitizeTail drops invalid UTF-8 and every control character except the
// newline, and turns a tab into a space, so the tail cannot carry terminal
// escapes, NULs or broken encodings into an Event or a log line.
func sanitizeTail(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		switch {
		case r == utf8.RuneError && size <= 1:
			// invalid byte: dropped
		case r == '\n':
			sb.WriteByte('\n')
		case r == '\t':
			sb.WriteByte(' ')
		case unicode.IsControl(r), r == ' ', r == ' ', unicode.Is(unicode.Bidi_Control, r):
			// control, line-separator and bidi-override runes: dropped
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// readCRILogTail builds a tail from the last shimLogTailBytes of the CRI log
// file at path, which must be the path runtimed itself configured for the
// container (its status log_path), never one taken from the pod.
//
// The file's content is pod-written, so it is opened O_NOFOLLOW (a symlink in
// the final component is refused) and O_NONBLOCK (a FIFO planted there cannot
// hang the open), checked by fstat to be a regular file, and read with one
// bounded pread from its end. The bytes are parsed by parseCRILine and fed to
// an outputTail, so the message rules are those of the in-daemon path.
func readCRILogTail(path string) (*outputTail, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open container log %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat container log %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("container log %s is not a regular file", path)
	}
	off := st.Size - shimLogTailBytes
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size-off)
	n, err := unix.Pread(fd, buf, off)
	if err != nil {
		return nil, fmt.Errorf("read container log %s: %w", path, err)
	}
	return criTail(buf[:max(n, 0)], off > 0), nil
}

// criTail feeds the CRI log lines in b to a fresh outputTail. cut says b
// starts mid-file, so its first line is a fragment and is skipped. A line
// that is not a well-formed CRI frame is skipped, never fed raw.
func criTail(b []byte, cut bool) *outputTail {
	t := &outputTail{}
	for i := 0; len(b) > 0; i++ {
		line := b
		if j := bytes.IndexByte(b, '\n'); j >= 0 {
			line, b = b[:j], b[j+1:]
		} else {
			b = nil
		}
		if i == 0 && cut {
			continue
		}
		if msg, partial, ok := parseCRILine(line); ok {
			t.record(msg, partial)
		}
	}
	return t
}

// parseCRILine splits one CRI log line, without its newline, of the form
// "<timestamp> <stdout|stderr> <F|P> <message>" and returns the message bytes
// (a sub-slice of line) and whether the P (partial) tag was set. ok is false
// for anything that is not exactly that framing.
func parseCRILine(line []byte) (msg []byte, partial bool, ok bool) {
	ts, rest, found := bytes.Cut(line, []byte{' '})
	if !found || len(ts) == 0 {
		return nil, false, false
	}
	stream, rest, found := bytes.Cut(rest, []byte{' '})
	if !found || (string(stream) != "stdout" && string(stream) != "stderr") {
		return nil, false, false
	}
	tag, msg, found := bytes.Cut(rest, []byte{' '})
	if !found {
		// An empty F line may be written without the separator before the
		// (empty) message.
		tag, msg = rest, nil
	}
	switch string(tag) {
	case "F":
		return msg, false, true
	case "P":
		return msg, true, true
	default:
		return nil, false, false
	}
}
