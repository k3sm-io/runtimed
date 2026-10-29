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

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// VMBootFailureSubdir is the directory under the runtime work-dir
// (<stateRoot>/vmboot-failures) where the guest console of a failed vm boot is
// kept.
//
// It exists because the console the helper writes lives in the POD dir, and a
// failed boot is a failed pod: the pod dir is removed with the pod, so the one
// file that explains why the guest never answered was gone by the time anyone
// looked. A copy under the work-dir outlives the pod and sits beside the other
// runtime-private stores (vmreap, podreap).
const VMBootFailureSubdir = "vmboot-failures"

// vmBootFailureKeep is how many retained failed-boot consoles are kept; older
// ones are pruned whenever a new one is written. Twenty is several failing
// pods' worth of attempts, enough to compare a flake with its neighbours,
// while bounding the directory at vmBootFailureKeep*vmBootConsoleRetainBytes.
const vmBootFailureKeep = 20

// vmBootConsoleRetainBytes bounds one retained console: its LAST 256 KiB. The
// end of the console is where a stall or a panic shows; the kernel's driver
// inventory at the start is the same on every boot.
const vmBootConsoleRetainBytes = 256 << 10

// vmBootConsoleTailLines and vmBootConsoleTailBytes bound the console excerpt a
// boot failure's MESSAGE carries, which reaches the pod's status and events.
// The excerpt is guest output and therefore untrusted: it is sanitised to
// printable text and capped so it cannot crowd out the rest of the message.
const (
	vmBootConsoleTailLines = 20
	vmBootConsoleTailBytes = 1024
)

// vmBootConsoleSuffix names a retained console file; pruning considers only
// files carrying it.
const vmBootConsoleSuffix = ".console.log"

// readFileTail returns at most the last max bytes of the regular file at path.
// The final component is opened with O_NOFOLLOW, so a symlink planted where
// the console belongs is refused rather than followed.
func readFileTail(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	off := st.Size() - max
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// retainBootConsole copies the tail of a failed boot's console into
// <stateRoot>/vmboot-failures and prunes the directory to vmBootFailureKeep
// files. It returns the retained path and the bytes it read, so the caller
// can build the message excerpt from the same snapshot.
//
// A console that cannot be read still returns no error: an absent console is
// itself evidence (the guest never started), and the caller states it. An
// empty stateRoot keeps nothing and returns an empty path.
func retainBootConsole(stateRoot, podID, consolePath string, attempt int, now time.Time) (string, []byte, error) {
	data, rerr := readFileTail(consolePath, vmBootConsoleRetainBytes)
	if rerr != nil {
		data = nil
	}
	if stateRoot == "" {
		return "", data, nil
	}
	dir := filepath.Join(stateRoot, VMBootFailureSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", data, fmt.Errorf("create the failed-boot console dir: %w", err)
	}
	// The directory must be a real directory, never a symlink out of the
	// work-dir: the copy below runs as the daemon.
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return "", data, fmt.Errorf("refusing the failed-boot console dir %s: not a directory", dir)
	}
	name := fmt.Sprintf("%s-%s-attempt%d%s", filepath.Base(podID), now.UTC().Format("20060102T150405.000000000Z"), attempt, vmBootConsoleSuffix)
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", data, fmt.Errorf("create the retained console %s: %w", path, err)
	}
	if rerr != nil {
		data = nil
		_, _ = fmt.Fprintf(f, "[k3sm-runtimed] the guest console %s could not be read: %v\n", consolePath, rerr)
	} else {
		_, _ = f.Write(data)
	}
	if err := f.Close(); err != nil {
		return "", data, fmt.Errorf("write the retained console %s: %w", path, err)
	}
	return path, data, pruneBootConsoles(dir, vmBootFailureKeep)
}

// pruneBootConsoles removes all but the newest keep retained consoles in dir,
// newest by modification time, ties broken by name (which embeds the time).
func pruneBootConsoles(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type kept struct {
		name string
		mod  time.Time
	}
	var files []kept
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), vmBootConsoleSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, kept{name: e.Name(), mod: info.ModTime()})
	}
	if len(files) <= keep {
		return nil
	}
	sort.Slice(files, func(i, j int) bool {
		if !files[i].mod.Equal(files[j].mod) {
			return files[i].mod.After(files[j].mod)
		}
		return files[i].name > files[j].name
	})
	var errs []error
	for _, f := range files[keep:] {
		if err := os.Remove(filepath.Join(dir, f.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// consoleExcerpt renders the last lines of a console as one bounded,
// printable string for an error message: at most vmBootConsoleTailLines lines,
// at most vmBootConsoleTailBytes bytes in total, joined with " | " the way the
// helper's output tail is. The newest lines win when the budget is short.
func consoleExcerpt(data []byte) string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var picked []string
	total := 0
	for i := len(lines) - 1; i >= 0 && len(picked) < vmBootConsoleTailLines; i-- {
		l := sanitizeConsoleLine(lines[i])
		if l == "" {
			continue
		}
		sep := 0
		if len(picked) > 0 {
			sep = len(" | ")
		}
		if total+sep+len(l) > vmBootConsoleTailBytes {
			if len(picked) == 0 {
				// One line longer than the whole budget: keep its end.
				picked = append(picked, "…"+keepUTF8Suffix(l, vmBootConsoleTailBytes-len("…")))
			}
			break
		}
		picked = append(picked, l)
		total += sep + len(l)
	}
	for i, j := 0, len(picked)-1; i < j; i, j = i+1, j-1 {
		picked[i], picked[j] = picked[j], picked[i]
	}
	return strings.Join(picked, " | ")
}

// sanitizeConsoleLine strips ANSI escape sequences, replaces every other
// control character and invalid UTF-8 with a space, and collapses each run of
// white space to one space.
// The console is written by the guest, so nothing in it may reach a log line
// or a Kubernetes event as a terminal control sequence.
func sanitizeConsoleLine(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			i = skipANSI(s, i)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			b.WriteByte(' ')
		case unicode.IsControl(r) || r == ' ' || r == ' ':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// skipANSI returns the index just past the escape sequence starting at s[i]
// (an ESC byte): a CSI sequence runs to its final byte in 0x40-0x7e, any other
// escape is ESC plus one byte.
func skipANSI(s string, i int) int {
	i++
	if i >= len(s) {
		return i
	}
	if s[i] != '[' {
		return i + 1
	}
	for i++; i < len(s); i++ {
		if s[i] >= 0x40 && s[i] <= 0x7e {
			return i + 1
		}
	}
	return i
}

// keepUTF8Suffix returns the longest suffix of s of at most n bytes that
// starts on a rune boundary.
func keepUTF8Suffix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}
