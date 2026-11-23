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
	"testing"

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
	if _, err := readCRILogTail(link, identOfPath(t, target)); err == nil {
		t.Error("read a tail through a symlink")
	}
	fifo := filepath.Join(dir, "fifo.log")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCRILogTail(fifo, identOfPath(t, target)); err == nil {
		t.Error("read a tail from a FIFO")
	}
}

// TestReadCRILogTailIsBoundToTheCreatedFile: the shim-path read goes ahead
// only for the very file runtimed created at the path. Every way of making
// the path name some other file yields no tail.
func TestReadCRILogTailIsBoundToTheCreatedFile(t *testing.T) {
	const frame = "2026-01-01T00:00:00Z stderr F the real line\n"
	setup := func(t *testing.T) (dir, path string, id logFileIdent) {
		dir = t.TempDir()
		path = filepath.Join(dir, "init", "0.log")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(frame), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, path, identOfPath(t, path)
	}

	t.Run("the created file is read", func(t *testing.T) {
		_, path, id := setup(t)
		tail, err := readCRILogTail(path, id)
		if err != nil {
			t.Fatal(err)
		}
		if got := tail.render(); got != "the real line" {
			t.Errorf("tail = %q", got)
		}
	})
	t.Run("a file swapped in at the path", func(t *testing.T) {
		_, path, id := setup(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(frame), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCRILogTail(path, id); err == nil {
			t.Error("read a tail from a different inode")
		}
	})
	t.Run("a hard link to another file", func(t *testing.T) {
		dir, path, id := setup(t)
		other := filepath.Join(dir, "other")
		if err := os.WriteFile(other, []byte(frame), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(other, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readCRILogTail(path, id); err == nil {
			t.Error("read a tail through a hard link to another file")
		}
	})
	t.Run("an extra hard link to the created file", func(t *testing.T) {
		dir, path, id := setup(t)
		if err := os.Link(path, filepath.Join(dir, "extra")); err != nil {
			t.Fatal(err)
		}
		if _, err := readCRILogTail(path, id); err == nil {
			t.Error("read a tail from a file with two links")
		}
	})
	t.Run("a symlinked parent directory", func(t *testing.T) {
		dir, path, id := setup(t)
		elsewhere := filepath.Join(dir, "elsewhere")
		if err := os.MkdirAll(elsewhere, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(elsewhere, "0.log"), []byte(frame), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		if _, err := readCRILogTail(path, id); err == nil {
			t.Error("read a tail through a symlinked parent directory")
		}
	})
	t.Run("no recorded identity", func(t *testing.T) {
		_, path, _ := setup(t)
		if _, err := readCRILogTail(path, logFileIdent{}); err == nil {
			t.Error("read a tail with no recorded identity")
		}
	})
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
	if got, want := criTail([]byte(in), true).render(), "one | two-joined"; got != want {
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
			checkTailInvariants(t, criTail(b, cut))
		}
	})
}

// FuzzOutputTailRecord fuzzes the in-daemon ring: data is cut into chunks
// whose lengths and partial flags come from shape, as the two pumps would
// deliver them, and the rendered tail must keep the message rules.
func FuzzOutputTailRecord(f *testing.F) {
	f.Add([]byte("yurei-agentd install-tree: refused io-error"), []byte{0x40})
	f.Add([]byte("a\x1b[31mb\x00c\xff\xfe\u200b\ufeff\U000e0041\ue000d"), []byte{3, 5, 7, 2})
	f.Add(bytes.Repeat([]byte("noise line xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"), 200), []byte{0xff, 0x80, 0x01})
	f.Add([]byte("\xe2\x80\xae\xe2\x80"), []byte{1, 1, 1, 1, 1})
	f.Add(bytes.Repeat([]byte{'z'}, 9000), []byte{0xfe, 0xfe, 0xfe})
	f.Fuzz(func(t *testing.T, data, shape []byte) {
		tail := &outputTail{}
		for i := 0; len(data) > 0; i++ {
			n := len(data)
			partial := false
			if len(shape) > 0 {
				s := shape[i%len(shape)]
				n = min(n, int(s)*37+1)
				partial = s&1 == 1
			}
			tail.record(data[:n], partial)
			data = data[n:]
		}
		checkTailInvariants(t, tail)
	})
}

// checkTailInvariants asserts the message rules on a tail: at most
// initTailMaxLines lines, a rendered line within initTailMaxBytes, valid
// UTF-8, and no Cc, Cf or Co rune.
func checkTailInvariants(t *testing.T, tail *outputTail) {
	t.Helper()
	if n := len(tail.renderLines()); n > initTailMaxLines {
		t.Fatalf("tail has %d lines", n)
	}
	out := tail.render()
	if len(out) > initTailMaxBytes {
		t.Fatalf("tail is %d bytes", len(out))
	}
	assertTailRunes(t, out)
}
