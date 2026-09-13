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
	"bufio"
	"bytes"
	"io"
)

// readBufBytes is the chunker's read-buffer size. It sizes the syscall, not the
// line: a longer line is assembled from several reads. containerd uses the same
// 4 KiB.
const readBufBytes = 4096

// ChunkSink receives one chunk of a container's output. partial is true while
// the chunk continues a logical line (the P tag) and false on the chunk that
// ends one (F). A non-nil return STOPS the chunker, which returns that error to
// its caller — see Chunk for the policy that makes stopping the right answer.
type ChunkSink func(chunk []byte, partial bool) error

// Chunk reads r to EOF, handing sink one chunk per logical line, splitting any
// line longer than MaxLineBytes.
//
// The emitted sequence for a 40 KiB line at the shipped bound is
// P(16 KiB), P(16 KiB), F(8 KiB): nothing is dropped and a reader that
// concatenates the P run recovers the line exactly. A stream that ends without
// a trailing newline emits its final chunk as P, because that is what the tag
// means — the line is incomplete, and the reader must not present it as a whole
// one.
//
// The line terminator is stripped (and a CR immediately before it with it): the
// rendered CRI line supplies its own newline, so a chunk that carried one would
// be double-delimited and would split into two lines on the way back.
//
// # Memory
//
// The chunker holds at most MaxLineBytes + readBufBytes of an in-flight line,
// however long the line runs: the split at the bound is what empties the
// buffer. That is the whole reason a bound exists — an unbounded line from a
// pod must not be an unbounded allocation in the daemon that supervises every
// pod on the node.
//
// # Sink errors
//
// A sink error ends the chunker immediately and is returned unwrapped-by-value
// to the caller. It does NOT retry and does NOT skip the chunk: the supervisor
// pump above it then closes its read end so the container's write(2) takes
// EPIPE. See Writer for why that fail-fast is preferred to a silently
// undrained pipe.
//
// # Provenance
//
// This is a port of containerd's redirectLogs (internal/cri/io/logger.go,
// Apache-2.0), including its readLine helper, whose contract — err != nil if
// and only if the line does not end in a newline — is what makes the
// EOF-without-newline case distinguishable at all (bufio.Reader.ReadLine and
// bufio.Scanner both erase it).
func Chunk(r io.Reader, sink ChunkSink) error {
	br := bufio.NewReaderSize(r, readBufBytes)
	var (
		buf    [][]byte
		length int
	)
	emit := func(partial bool) error {
		return sink(bytes.Join(buf, nil), partial)
	}
	for {
		var stop bool
		line, isPrefix, err := readLine(br)
		if len(line) > 0 {
			// The slice ReadSlice returned aliases the read buffer and is
			// invalidated by the next read, so it is copied before it is held.
			c := bytes.Clone(line)
			buf = append(buf, c)
			length += len(c)
		}
		if err != nil {
			if length == 0 {
				// Nothing held: a clean end of stream (io.EOF) or an unreadable
				// pipe. Either way there is nothing left to chunk. The error is
				// not returned — only a SINK error is this function's caller's
				// problem; a read error is the ordinary end of a container's
				// output and is reported by the pump above.
				return nil
			}
			stop = true
		}
		if length > MaxLineBytes {
			// Cut exactly at the bound: the overflow stays held and becomes the
			// head of the next chunk, so the split is lossless.
			exceed := length - MaxLineBytes
			last := buf[len(buf)-1]
			buf[len(buf)-1] = last[:len(last)-exceed]
			if serr := emit(true); serr != nil {
				return serr
			}
			buf = [][]byte{last[len(last)-exceed:]}
			length = exceed
		}
		if isPrefix {
			continue
		}
		// readLine reports an error only when the line did not end in a
		// newline, so a stopping line is by definition an incomplete one: P.
		if serr := emit(stop); serr != nil {
			return serr
		}
		buf, length = nil, 0
		if stop {
			return nil
		}
	}
}

// readLine reads one line from br, returning it WITHOUT its terminator.
//
// It exists because bufio eats the distinction this package needs:
// bufio.Reader.ReadLine and bufio.Scanner both return "CONTENT" for "CONTENT\n"
// and for "CONTENT", so a caller cannot tell a finished line from a stream that
// ended mid-line — which is exactly the F/P decision. So, per containerd's
// note: err != nil if and only if the line does not end with a newline.
//
// isPrefix reports that the line is longer than the read buffer and continues
// on the next call, matching bufio.Reader.ReadLine.
func readLine(b *bufio.Reader) (line []byte, isPrefix bool, err error) {
	line, err = b.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// A "\r\n" straddling the buffer boundary: hold the CR back so the
		// terminator is stripped as one unit on the next call.
		if len(line) > 0 && line[len(line)-1] == '\r' {
			if uerr := b.UnreadByte(); uerr != nil {
				// UnreadByte can only fail when the last operation was not a
				// read, which cannot happen here. Rather than panic in library
				// code, keep the CR: at worst one chunk ends with a stray CR.
				return line, true, nil
			}
			line = line[:len(line)-1]
		}
		return line, true, nil
	}
	if len(line) == 0 {
		if err != nil {
			line = nil
		}
		return line, false, err
	}
	if line[len(line)-1] == '\n' {
		drop := 1
		if len(line) > 1 && line[len(line)-2] == '\r' {
			drop = 2
		}
		line = line[:len(line)-drop]
		// ReadSlice returns a non-nil error only when the line does not end in
		// the delimiter, so this arm always has err == nil.
		return line, false, nil
	}
	return line, false, err
}
