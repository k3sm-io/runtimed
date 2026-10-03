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

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeRestricted accepts exactly the names in set, standing in for the
// SF_RESTRICTED stat so the table runs without depending on the host's /bin.
func fakeRestricted(set ...string) func(string) bool {
	return func(p string) bool {
		for _, s := range set {
			if s == p {
				return true
			}
		}
		return false
	}
}

const reportName = ".k3sm-shim-report-app"

func TestChildReportName(t *testing.T) {
	for _, tc := range []struct {
		container string
		want      string
		ok        bool
	}{
		{"app", ".k3sm-shim-report-app", true},
		{"a-1", ".k3sm-shim-report-a-1", true},
		{"", "", false},
		{"App", "", false},
		{"../x", "", false},
		{"a/b", "", false},
		{"-a", "", false},
		{strings.Repeat("a", 64), "", false},
	} {
		t.Run(fmt.Sprintf("%q", tc.container), func(t *testing.T) {
			got, err := ChildReportName(tc.container)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("ChildReportName(%q) = %q, %v; want %q ok=%v", tc.container, got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestValidReportedName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"/bin/cat", true},
		{"/usr/bin/python3", true},
		{"/sbin/ping", true},
		{"/System/Library/Frameworks/x.framework/Versions/A/Resources/tool", true},
		{"/usr/libexec/c++filt", true},
		{"", false},
		{"bin/cat", false},
		{"cat", false},
		{"/tmp/cat", false},
		{"/opt/homebrew/bin/cat", false},
		{"/Users/x/bin/cat", false},
		{"/bin/../tmp/cat", false},
		{"/bin//cat", false},
		{"/bin/cat/", false},
		{"/bin/c at", false},
		{"/bin/cat,/bin/ls", false},
		{"/bin/cat\r", false},
		{"/bin/c\x00at", false},
		{"/bin/c\x1bat", false},
		{"/bin/" + strings.Repeat("a", 1100), false},
		{"/binx/cat", false},
	} {
		t.Run(fmt.Sprintf("%q", tc.name), func(t *testing.T) {
			if got := validReportedName(tc.name); got != tc.ok {
				t.Fatalf("validReportedName(%q) = %v, want %v", tc.name, got, tc.ok)
			}
		})
	}
}

func TestParseChildReport(t *testing.T) {
	r := fakeRestricted("/bin/cat", "/bin/ls", "/usr/bin/grep")
	for _, tc := range []struct {
		name     string
		buf      string
		full     bool
		seen     []string
		room     int
		consumed int
		want     []string
	}{
		{"one", "/bin/cat\n", false, nil, 8, 9, []string{"/bin/cat"}},
		{"partial trailing line not consumed", "/bin/cat\n/bin/l", false, nil, 8, 9, []string{"/bin/cat"}},
		{"only a partial line", "/bin/ca", false, nil, 8, 0, nil},
		{"full read without newline is skipped", "xxxx", true, nil, 8, 4, nil},
		{"dedup in buffer", "/bin/cat\n/bin/cat\n", false, nil, 8, 18, []string{"/bin/cat"}},
		{"dedup against seen", "/bin/cat\n/bin/ls\n", false, []string{"/bin/cat"}, 7, 17, []string{"/bin/ls"}},
		{"garbage, NUL and CR lines dropped", "junk\n/bin/c\x00at\n/bin/cat\r\n\n/usr/bin/grep\n", false, nil, 8, 40, []string{"/usr/bin/grep"}},
		{"relative path dropped", "bin/cat\n", false, nil, 8, 8, nil},
		{"non-allowlisted prefix dropped", "/tmp/cat\n", false, nil, 8, 9, nil},
		{"lookalike without the flag dropped", "/usr/bin/fake\n", false, nil, 8, 14, nil},
		{"room caps the names", "/bin/cat\n/bin/ls\n", false, nil, 1, 17, []string{"/bin/cat"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consumed, got := parseChildReport([]byte(tc.buf), tc.full, tc.seen, tc.room, r)
			if consumed != tc.consumed || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseChildReport = %d, %q; want %d, %q", consumed, got, tc.consumed, tc.want)
			}
		})
	}
}

// newReportDir returns a data volume dir and the report path inside it.
func newReportDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return dir, filepath.Join(dir, reportName)
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustPoll(t *testing.T, c *ChildReport) []string {
	t.Helper()
	got, err := c.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return got
}

func TestChildReportPollHardening(t *testing.T) {
	r := fakeRestricted("/bin/cat", "/bin/ls")

	t.Run("missing file is no report", func(t *testing.T) {
		dir, _ := newReportDir(t)
		if got := mustPoll(t, NewChildReport(dir, reportName, r)); got != nil {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("missing dir is no report", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "gone")
		if got := mustPoll(t, NewChildReport(dir, reportName, r)); got != nil {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("incremental with partial trailing line", func(t *testing.T) {
		dir, path := newReportDir(t)
		c := NewChildReport(dir, reportName, r)
		appendFile(t, path, "/bin/cat\n/bin/l")
		if got := mustPoll(t, c); !reflect.DeepEqual(got, []string{"/bin/cat"}) {
			t.Fatalf("first poll %q", got)
		}
		appendFile(t, path, "s\n/bin/cat\n")
		if got := mustPoll(t, c); !reflect.DeepEqual(got, []string{"/bin/ls"}) {
			t.Fatalf("second poll %q", got)
		}
		if got := mustPoll(t, c); got != nil {
			t.Fatalf("third poll %q", got)
		}
	})

	t.Run("FIFO does not block", func(t *testing.T) {
		dir, path := newReportDir(t)
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := NewChildReport(dir, reportName, r).Poll()
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, errChildReportNotRegular) {
				t.Fatalf("FIFO poll err = %v, want errChildReportNotRegular", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Poll blocked on a FIFO")
		}
	})

	t.Run("symlink is refused", func(t *testing.T) {
		dir, path := newReportDir(t)
		target := filepath.Join(t.TempDir(), "elsewhere")
		appendFile(t, target, "/bin/cat\n")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		got, err := NewChildReport(dir, reportName, r).Poll()
		if err == nil || got != nil {
			t.Fatalf("symlink poll = %q, %v; want refused", got, err)
		}
	})

	t.Run("symlinked data volume is refused", func(t *testing.T) {
		real, _ := newReportDir(t)
		appendFile(t, filepath.Join(real, reportName), "/bin/cat\n")
		link := filepath.Join(t.TempDir(), "vol")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		got, err := NewChildReport(link, reportName, r).Poll()
		if err == nil || got != nil {
			t.Fatalf("symlinked dir poll = %q, %v; want refused", got, err)
		}
	})

	t.Run("hard link is refused", func(t *testing.T) {
		dir, path := newReportDir(t)
		other := filepath.Join(dir, "other")
		appendFile(t, other, "/bin/cat\n")
		if err := os.Link(other, path); err != nil {
			t.Fatal(err)
		}
		got, err := NewChildReport(dir, reportName, r).Poll()
		if !errors.Is(err, errChildReportNotRegular) || got != nil {
			t.Fatalf("hard link poll = %q, %v; want errChildReportNotRegular", got, err)
		}
	})

	t.Run("directory is refused", func(t *testing.T) {
		dir, path := newReportDir(t)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewChildReport(dir, reportName, r).Poll(); !errors.Is(err, errChildReportNotRegular) {
			t.Fatalf("dir poll err = %v", err)
		}
	})

	t.Run("over-cap file is read a cap at a time", func(t *testing.T) {
		dir, path := newReportDir(t)
		junk := strings.Repeat("x", childReportReadCap+100) + "\n/bin/cat\n"
		appendFile(t, path, junk)
		c := NewChildReport(dir, reportName, r)
		if got := mustPoll(t, c); got != nil {
			t.Fatalf("first poll %q (a newline-free full read must be skipped)", got)
		}
		if c.off != childReportReadCap {
			t.Fatalf("offset after the first poll = %d, want %d", c.off, childReportReadCap)
		}
		if got := mustPoll(t, c); !reflect.DeepEqual(got, []string{"/bin/cat"}) {
			t.Fatalf("second poll %q", got)
		}
	})

	t.Run("truncated file is re-read from the start", func(t *testing.T) {
		dir, path := newReportDir(t)
		c := NewChildReport(dir, reportName, r)
		appendFile(t, path, "/usr/bin/nothing-here-long-enough\n")
		if got := mustPoll(t, c); got != nil {
			t.Fatalf("first poll %q", got)
		}
		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
		appendFile(t, path, "/bin/cat\n")
		if got := mustPoll(t, c); !reflect.DeepEqual(got, []string{"/bin/cat"}) {
			t.Fatalf("after truncate %q", got)
		}
	})

	t.Run("replaced file is re-read from the start", func(t *testing.T) {
		dir, path := newReportDir(t)
		c := NewChildReport(dir, reportName, r)
		appendFile(t, path, "/bin/cat\n")
		if got := mustPoll(t, c); !reflect.DeepEqual(got, []string{"/bin/cat"}) {
			t.Fatalf("first poll %q", got)
		}
		repl := filepath.Join(dir, "repl")
		appendFile(t, repl, "/bin/ls\n/bin/cat\n")
		if err := os.Rename(repl, path); err != nil {
			t.Fatal(err)
		}
		if got := mustPoll(t, c); !reflect.DeepEqual(got, []string{"/bin/ls"}) {
			t.Fatalf("after replace %q", got)
		}
	})

	t.Run("more than the cap of names", func(t *testing.T) {
		var set []string
		var b strings.Builder
		for i := 0; i < ChildReportMaxNames+4; i++ {
			n := fmt.Sprintf("/bin/t%d", i)
			set = append(set, n)
			b.WriteString(n + "\n")
		}
		dir, path := newReportDir(t)
		appendFile(t, path, b.String())
		c := NewChildReport(dir, reportName, fakeRestricted(set...))
		if got := mustPoll(t, c); len(got) != ChildReportMaxNames {
			t.Fatalf("got %d names, want %d", len(got), ChildReportMaxNames)
		}
		appendFile(t, path, "/bin/t20\n")
		if got := mustPoll(t, c); got != nil {
			t.Fatalf("after the cap: %q", got)
		}
	})
}

func TestRemoveChildReport(t *testing.T) {
	dir, path := newReportDir(t)
	appendFile(t, path, "/bin/cat\n")
	if err := RemoveChildReport(dir, reportName); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("report still present: %v", err)
	}
	if err := RemoveChildReport(dir, reportName); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	// A symlink at the path is removed, never followed.
	target := filepath.Join(t.TempDir(), "keep")
	appendFile(t, target, "x")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := RemoveChildReport(dir, reportName); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was touched: %v", err)
	}
}

// TestRestrictedPlatformFileRejectsLookalike pins that a file the test (like a
// pod) creates never carries SF_RESTRICTED.
func TestRestrictedPlatformFileRejectsLookalike(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cat")
	appendFile(t, p, "x")
	if RestrictedPlatformFile(p) {
		t.Fatalf("a freshly created file reads as SF_RESTRICTED")
	}
	if RestrictedPlatformFile(filepath.Join(t.TempDir(), "missing")) {
		t.Fatalf("a missing file reads as SF_RESTRICTED")
	}
}

func TestMemorySamplerWithTick(t *testing.T) {
	n := 0
	s := NewMemorySampler(&fakeFootprinter{}, func() []int { return nil }, 0, nil, WithTick(func() { n++ }))
	s.sampleOnce()
	s.sampleOnce()
	if n != 2 {
		t.Fatalf("tick ran %d times, want 2", n)
	}
}
