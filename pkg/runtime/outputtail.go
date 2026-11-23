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
	"os"
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

// render returns the tail as ONE line: at most initTailMaxLines non-empty
// output lines joined by " | ", at most initTailMaxBytes long, with invalid
// UTF-8 and control, format and private-use characters removed (a tab
// becomes a space). It returns "" when the container printed nothing
// printable. The caller quotes it (strconv.Quote) before it goes into an
// error or a log line.
func (t *outputTail) render() string {
	kept := t.renderLines()
	out := strings.Join(kept, tailLineSep)
	for len(out) > initTailMaxBytes && len(kept) > 1 {
		kept = kept[1:]
		out = strings.Join(kept, tailLineSep)
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

// tailLineSep joins a rendered tail's lines into one line.
const tailLineSep = " | "

// renderLines returns the last initTailMaxLines non-empty sanitised lines of
// the tail, each trimmed, before render bounds their joined length.
func (t *outputTail) renderLines() []string {
	if t == nil {
		return nil
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
	return kept
}

// sanitizeTail drops invalid UTF-8, every control character (Cc) except the
// newline, every format character (Cf: zero-width characters, the BOM, bidi
// overrides, tag characters), every private-use character (Co) and the
// Unicode line and paragraph separators, and turns a tab into a space, so the
// tail cannot carry terminal escapes, NULs, hidden or reordered text or broken
// encodings into an Event or a log line.
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
		case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co), r == '\u2028', r == '\u2029':
			// control, format, private-use and separator runes: dropped
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// logFileIdent names one file by device and inode. ok is false for the zero
// value, which matches no file.
type logFileIdent struct {
	dev, ino uint64
	ok       bool
}

// fileIdentOf returns the device and inode of the open file f.
func fileIdentOf(f *os.File) (logFileIdent, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return logFileIdent{}, err
	}
	return logFileIdent{dev: uint64(st.Dev), ino: st.Ino, ok: true}, nil
}

// readCRILogTail builds a tail from the last shimLogTailBytes of the CRI log
// file at path, provided it is still the very file runtimed created there
// (want, recorded by spawnBesideShim from the descriptor it opened).
//
// The path is derived from PodBox fields (log_directory and the container
// name), not chosen by runtimed alone, and the file's content is pod-written,
// so the path is not trusted to name the right file: the dev/ino binding is
// what makes the read safe. After an O_NOFOLLOW|O_NONBLOCK open (a symlink in
// the final component is refused, a FIFO cannot hang the open) the descriptor
// is fstat'ed and the read goes ahead only for a regular file with the
// recorded device and inode, exactly one link, owned by this daemon's euid. A
// file swapped in at the path, a symlinked parent directory leading elsewhere,
// or a hard link to some other file all fail that check, and the caller then
// renders no tail. The read is one bounded pread from the end; the bytes are
// parsed by parseCRILine and fed to an outputTail, so the message rules are
// those of the in-daemon path.
func readCRILogTail(path string, want logFileIdent) (*outputTail, error) {
	if !want.ok {
		return nil, fmt.Errorf("container log %s: no recorded identity", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open container log %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat container log %s: %w", path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("container log %s is not a regular file", path)
	case uint64(st.Dev) != want.dev || st.Ino != want.ino:
		return nil, fmt.Errorf("container log %s is not the file runtimed created", path)
	case st.Nlink != 1:
		return nil, fmt.Errorf("container log %s has %d links, want 1", path, st.Nlink)
	case int64(st.Uid) != int64(os.Geteuid()):
		return nil, fmt.Errorf("container log %s is owned by uid %d, not this daemon", path, st.Uid)
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
