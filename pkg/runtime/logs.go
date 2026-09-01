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
	"errors"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errLogLimitReached ends a GetLogs response because the request's limit_bytes
// budget is spent. It is a normal end of stream, not a failure: the caller asked
// for at most N bytes and got them, so GetLogs returns nil.
var errLogLimitReached = errors.New("log limit_bytes budget spent")

// logEmitter renders retained lines onto a GetLogs stream under the request's
// PRESENTATION options — timestamps (the RFC3339 prefix) and limit_bytes (the
// budget). The SELECTION options (tail_lines, since_time) are applied by the
// caller, because they decide which lines reach the emitter at all.
//
// The budget is denominated in the bytes the client receives, which for a
// line-delimited stream is the rendered line plus its newline delimiter — the
// same unit `kubectl logs --limit-bytes` means and the same unit the buffer's own
// cap uses. The prefix counts against it too: a caller that asked for timestamps
// asked for those bytes.
type logEmitter struct {
	stream     grpc.ServerStreamingServer[runtimev1.LogEntry]
	timestamps bool
	// limit is the remaining byte budget, or -1 for unlimited.
	limit int64
}

// newLogEmitter returns an emitter for req's presentation options.
func newLogEmitter(stream grpc.ServerStreamingServer[runtimev1.LogEntry], req *runtimev1.GetLogsRequest) *logEmitter {
	limit := int64(-1)
	if req.GetLimitBytes() > 0 {
		limit = req.GetLimitBytes()
	}
	return &logEmitter{stream: stream, timestamps: req.GetTimestamps(), limit: limit}
}

// send renders and sends one entry, returning errLogLimitReached once the budget
// can no longer carry a line. A line that only partly fits is TRUNCATED rather
// than dropped (matching the kubelet, whose limit is a byte reader over the
// formatted output — "may not display a complete final line"), on a rune boundary
// so the emitted bytes stay valid UTF-8.
//
// The structured LogEntry.timestamp is set on every entry regardless of the
// timestamps option: the option governs the kubectl rendering, while the field is
// the entry's instant, which a non-kubectl consumer of the stream should not have
// to parse back out of the line.
func (e *logEmitter) send(ent logLine) error {
	return e.sendEntry(ent, runtimev1.LogStream_LOG_STREAM_STDOUT)
}

// sendEntry is send with an explicit stream label. The host-process path has
// only a COMBINED buffer, so send fixes the label at stdout; the vm route
// (getLogsGuest) is told stdout vs stderr by the guest agent and must not lose
// that distinction on the way through, so it supplies the label per entry.
func (e *logEmitter) sendEntry(ent logLine, kind runtimev1.LogStream) error {
	line := ent.line
	if e.timestamps {
		line = append([]byte(ent.at.UTC().Format(time.RFC3339Nano)+" "), line...)
	}
	if e.limit >= 0 {
		cost := int64(len(line)) + 1 // + the newline delimiter
		switch {
		case cost <= e.limit:
			e.limit -= cost
		case e.limit < 2:
			// Not even one byte plus its delimiter fits.
			return errLogLimitReached
		default:
			line = utf8HeadBytes(line, int(e.limit-1))
			e.limit = 0
			if len(line) == 0 {
				// The cut landed inside the first rune; an empty entry would
				// render as a spurious blank line.
				return errLogLimitReached
			}
		}
	}
	return e.stream.Send(&runtimev1.LogEntry{
		Line:      line,
		Timestamp: timestamppb.New(ent.at),
		Stream:    kind,
	})
}

// utf8HeadBytes returns the first n bytes of b, trimmed back so the result never
// ends in a partial rune. It is the head-side counterpart of utf8TailBytes (which
// the buffer's oversized-line cut uses), and it only ever trims, so the n-byte
// bound still holds.
func utf8HeadBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	b = b[:n]
	for i := len(b) - 1; i >= 0 && len(b)-i < utf8.UTFMax; i-- {
		if !utf8.RuneStart(b[i]) {
			continue
		}
		if r, size := utf8.DecodeRune(b[i:]); r == utf8.RuneError && size <= 1 {
			return b[:i] // an incomplete rune at the cut
		}
		break
	}
	return b
}
