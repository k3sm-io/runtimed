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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPruneBootConsolesKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for i := range 25 {
		p := filepath.Join(dir, fmt.Sprintf("pod-%02d%s", i, vmBootConsoleSuffix))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(dir, "not-a-console.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pruneBootConsoles(dir, vmBootFailureKeep); err != nil {
		t.Fatalf("prune: %v", err)
	}
	for i := range 25 {
		_, err := os.Stat(filepath.Join(dir, fmt.Sprintf("pod-%02d%s", i, vmBootConsoleSuffix)))
		if kept := err == nil; kept != (i >= 25-vmBootFailureKeep) {
			t.Errorf("pod-%02d kept=%v, want only the newest %d kept", i, kept, vmBootFailureKeep)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("prune removed a file that is not a retained console: %v", err)
	}
}

func TestRetainBootConsoleBoundsAndPrunes(t *testing.T) {
	root := t.TempDir()
	console := filepath.Join(t.TempDir(), "console.log")
	big := strings.Repeat("a", vmBootConsoleRetainBytes) + "END\n"
	if err := os.WriteFile(console, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 3, 28, 0, 0, time.UTC)
	var last string
	for i := range vmBootFailureKeep + 3 {
		p, data, err := retainBootConsole(root, "7c76fe1f", console, 1, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("retain: %v", err)
		}
		if len(data) != vmBootConsoleRetainBytes || !strings.HasSuffix(string(data), "END\n") {
			t.Fatalf("retained %d bytes ending %q, want the last %d", len(data), data[len(data)-4:], vmBootConsoleRetainBytes)
		}
		last = p
	}
	got, _ := filepath.Glob(filepath.Join(root, VMBootFailureSubdir, "*"+vmBootConsoleSuffix))
	if len(got) != vmBootFailureKeep {
		t.Errorf("%d retained consoles, want %d", len(got), vmBootFailureKeep)
	}
	if _, err := os.Stat(last); err != nil {
		t.Errorf("the newest retained console was pruned: %v", err)
	}
}

func TestRetainBootConsoleRecordsAMissingConsole(t *testing.T) {
	root := t.TempDir()
	p, data, err := retainBootConsole(root, "p1", filepath.Join(root, "absent.log"), 2, time.Now())
	if err != nil || p == "" || data != nil {
		t.Fatalf("retain = %q, %d bytes, %v; want a kept note and no data", p, len(data), err)
	}
	note, _ := os.ReadFile(p)
	if !strings.Contains(string(note), "could not be read") {
		t.Errorf("the kept file does not say the console was missing: %q", note)
	}
}

func TestRetainBootConsoleRefusesASymlinkedConsole(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("do not copy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "console.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	_, data, err := retainBootConsole(root, "p1", link, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do not copy") {
		t.Error("a symlinked console was followed")
	}
}

func TestConsoleExcerpt(t *testing.T) {
	cases := []struct {
		name, in string
		want     string
		check    func(t *testing.T, got string)
	}{
		{name: "empty", in: "", want: ""},
		{name: "joins the last lines", in: "a\nb\n\nc\n", want: "a | b | c"},
		{name: "strips escapes and controls", in: "\x1b[1;31mred\x1b[0m\tx\x07y\r\n", want: "red x y"},
		{name: "invalid utf-8 becomes a space", in: "a\xffb\n", want: "a b"},
		{name: "line cap", in: strings.Repeat("l\n", 5) + func() string {
			var b strings.Builder
			for i := range 30 {
				fmt.Fprintf(&b, "n%d\n", i)
			}
			return b.String()
		}(), check: func(t *testing.T, got string) {
			parts := strings.Split(got, " | ")
			if len(parts) != vmBootConsoleTailLines || parts[0] != "n10" || parts[len(parts)-1] != "n29" {
				t.Errorf("got %q, want n10..n29", got)
			}
		}},
		{name: "byte cap keeps the newest", in: strings.Repeat(strings.Repeat("x", 200)+"\n", 10) + "last\n", check: func(t *testing.T, got string) {
			if len(got) > vmBootConsoleTailBytes || !strings.HasSuffix(got, "last") {
				t.Errorf("got %d bytes ending %q", len(got), got[max(0, len(got)-8):])
			}
		}},
		{name: "one huge line keeps its end", in: strings.Repeat("é", 2000) + "tail\n", check: func(t *testing.T, got string) {
			if len(got) > vmBootConsoleTailBytes || !strings.HasSuffix(got, "tail") || !strings.HasPrefix(got, "…") {
				t.Errorf("got %d bytes", len(got))
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := consoleExcerpt([]byte(tc.in))
			if tc.check != nil {
				tc.check(t, got)
				return
			}
			if got != tc.want {
				t.Errorf("consoleExcerpt(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
