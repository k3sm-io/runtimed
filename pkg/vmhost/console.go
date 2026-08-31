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

package vmhost

import (
	"io"
	"sync"
)

// consoleTruncationNotice is written once, at the cap, so a reader of a truncated
// console log can tell truncation from a guest that simply went quiet. Those two
// look identical without it, and they call for opposite operator actions.
const consoleTruncationNotice = "\n[k3sm-vmhost] console log truncated: the size cap was reached; further guest console output is discarded\n"

// CappedWriter relays a guest's console output to w until Max bytes have been
// written, then discards the rest after appending a one-line truncation notice.
//
// IT NEVER REPORTS SHORT WRITES OR ERRORS FOR DISCARDED BYTES. Write returns
// len(p), nil once capped, because the caller is an io.Copy pump draining the
// console pipe: a short write there is an error that stops the pump, the pipe then
// fills, and a guest blocked writing to its console is a guest that has stopped
// booting. Discarding is the whole point; propagating the discard as a failure
// would convert a log-size policy into a guest hang.
//
// It is safe for concurrent use — the console pump is one goroutine, but the
// truncation state is also read by Truncated from another.
//
// The zero value is not usable; construct one with NewCappedWriter.
type CappedWriter struct {
	w   io.Writer
	max int64

	mu        sync.Mutex
	written   int64
	truncated bool
}

// NewCappedWriter wraps w with a cap of max bytes. A max of zero or less means
// DefaultConsoleMaxBytes; a nil w discards everything (the "no console log
// configured" case), which keeps the pump's code path identical either way.
func NewCappedWriter(w io.Writer, max int64) *CappedWriter {
	if max <= 0 {
		max = DefaultConsoleMaxBytes
	}
	if w == nil {
		w = io.Discard
	}
	return &CappedWriter{w: w, max: max}
}

// Write relays p subject to the cap. See the type doc for why the return value is
// always len(p) once the cap is reached.
func (c *CappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.truncated {
		return len(p), nil
	}
	room := c.max - c.written
	if room > 0 {
		chunk := p
		if int64(len(chunk)) > room {
			chunk = chunk[:room]
		}
		n, err := c.w.Write(chunk)
		c.written += int64(n)
		if err != nil {
			return n, err
		}
	}
	if c.written < c.max {
		return len(p), nil
	}
	// At the cap: mark once, note it once, and swallow everything after.
	c.truncated = true
	if _, err := io.WriteString(c.w, consoleTruncationNotice); err != nil {
		return len(p), err
	}
	return len(p), nil
}

// Truncated reports whether the cap has been reached and output is being
// discarded. It is what lets the helper say so in its own log rather than leaving
// an operator to infer it from a file that stops mid-line.
func (c *CappedWriter) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// Written reports how many guest bytes reached w, excluding the truncation notice.
func (c *CappedWriter) Written() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}
