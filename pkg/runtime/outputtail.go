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
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
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
)

// outputTail keeps the last few KiB of one plain init container's output in
// memory.
//
// It exists for one case: an init container that exits non-zero rejects the
// whole pod, a rejected pod is never registered and keeps no log directory,
// so the CRI log file is not there to read afterwards. The tail is what lets
// the rejection say why ("init container X exited 74: <its last lines>").
// It is NOT a log: it is filled from the log pump alongside the file write
// (containerLogSink), never read back from disk, and only a plain init
// container gets one, so a pod's memory cost is initTailWindowBytes per init
// container while it runs.
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
