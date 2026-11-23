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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// TestReadCRILogTailRefusesNonRegularFiles: the log path's final component is
// pod-reachable content, so a symlink or a FIFO there is refused, never
// followed or blocked on.
func TestReadCRILogTailRefusesNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("2026-01-01T00:00:00Z stderr F secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCRILogTail(link); err == nil {
		t.Error("read a tail through a symlink")
	}
	fifo := filepath.Join(dir, "fifo.log")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCRILogTail(fifo); err == nil {
		t.Error("read a tail from a FIFO")
	}
}

// TestCRITailSkipsTheCutFragmentAndBadFrames: a mid-file read drops its first
// (partial) line, malformed frames are skipped, and P chunks join their line.
func TestCRITailSkipsTheCutFragmentAndBadFrames(t *testing.T) {
	in := "ent F half a line\n" +
		"2026-01-01T00:00:00Z stdout F one\n" +
		"garbage without framing\n" +
		"2026-01-01T00:00:00Z stdin F not a stream\n" +
		"2026-01-01T00:00:00Z stderr X bad tag\n" +
		"2026-01-01T00:00:00Z stderr P two-\n" +
		"2026-01-01T00:00:00Z stderr F joined\n"
	if got, want := criTail([]byte(in), true).render(), "one\ntwo-joined"; got != want {
		t.Errorf("tail = %q, want %q", got, want)
	}
}

// FuzzParseCRILine fuzzes the CRI-frame parser and the tail built from it:
// the file is pod-written, so neither may panic, a parsed message is always
// the end of its line, and the rendered tail always keeps the message rules.
func FuzzParseCRILine(f *testing.F) {
	for _, s := range []string{
		"2026-11-22T10:00:00.000000000Z stderr F yurei-agentd install-tree: refused io-error",
		"2026-11-22T10:00:00.000000000Z stdout P partial",
		"2026-11-22T10:00:00.000000000Z stdout F",
		"2026-11-22T10:00:00.000000000Z stdout F ",
		"ts stderr F \x1b[31mred\x00\xff",
		" stderr F empty timestamp",
		"ts stdin F x",
		"ts stderr Q x",
		"",
		"\n\n\n",
		"ts stderr F a\nts stderr P b\nts stderr F c\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if msg, _, ok := parseCRILine(b); ok && !bytes.HasSuffix(b, msg) {
			t.Fatalf("message %q is not the end of line %q", msg, b)
		}
		for _, cut := range []bool{false, true} {
			out := criTail(b, cut).render()
			if len(out) > initTailMaxBytes {
				t.Fatalf("tail is %d bytes", len(out))
			}
			if out != "" && strings.Count(out, "\n")+1 > initTailMaxLines {
				t.Fatalf("tail has too many lines: %q", out)
			}
			if !utf8.ValidString(out) {
				t.Fatalf("tail is not valid UTF-8: %q", out)
			}
			for _, r := range out {
				if r != '\n' && (r < 0x20 || r == 0x7f) {
					t.Fatalf("tail carries control byte %q", r)
				}
			}
		}
	})
}
