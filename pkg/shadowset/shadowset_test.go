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

package shadowset

import (
	"path"
	"strings"
	"testing"
)

// TestEntriesAreWellFormed pins the invariants every consumer relies on: a
// copy name is a plain file name, unique; every path is absolute and clean;
// an exec path maps to exactly one copy.
func TestEntriesAreWellFormed(t *testing.T) {
	copies := map[string]bool{}
	hosts := map[string]string{}
	for _, e := range Entries() {
		if e.Copy == "" || strings.ContainsAny(e.Copy, "/\x00") || e.Copy == "." || e.Copy == ".." {
			t.Errorf("copy name %q is not a plain file name", e.Copy)
		}
		if copies[e.Copy] {
			t.Errorf("copy name %q declared twice", e.Copy)
		}
		copies[e.Copy] = true
		for _, s := range append([]string{e.Copy, e.Source}, e.Hosts...) {
			// The generator emits these as C string literals verbatim.
			for _, r := range s {
				if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
					t.Errorf("%q holds %q, which the generated C table cannot carry as-is", s, r)
				}
			}
		}
		if !path.IsAbs(e.Source) || path.Clean(e.Source) != e.Source {
			t.Errorf("%s: source %q is not an absolute clean path", e.Copy, e.Source)
		}
		if len(e.Hosts) == 0 {
			t.Errorf("%s: no exec paths", e.Copy)
		}
		for _, h := range e.Hosts {
			if !path.IsAbs(h) || path.Clean(h) != h {
				t.Errorf("%s: exec path %q is not an absolute clean path", e.Copy, h)
			}
			if prev, dup := hosts[h]; dup {
				t.Errorf("exec path %q maps to both %s and %s", h, prev, e.Copy)
			}
			hosts[h] = e.Copy
		}
	}
}

// TestLookups pins CopyFor and IsShell against the declared shape, including
// the argv[0]-dispatch aliases and the shell/non-shell split.
func TestLookups(t *testing.T) {
	cases := []struct {
		host  string
		copy  string
		shell bool
	}{
		{"/bin/sh", "bash", true},
		{"/bin/bash", "bash", true},
		{"/bin/zsh", "zsh", true},
		{"/bin/dash", "dash", true},
		{"/usr/bin/env", "env", true},
		{"/usr/bin/tar", "tar", false},
		{"/usr/bin/bsdtar", "tar", false},
		{"/usr/bin/egrep", "grep", false},
		{"/usr/bin/zgrep", "grep", false},
		{"/usr/bin/fgrep", "fgrep", false},
		{"/usr/bin/zcat", "gunzip", false},
		{"/usr/bin/gzip", "gzip", false},
		{"/bin/[", "test", false},
		{"/usr/bin/readlink", "readlink", false},
		{"/usr/bin/awk", "awk", false},
		{"/usr/bin/python3", "", false},
		{"/bin/sh/", "", false},
		{"bash", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got, ok := CopyFor(tc.host)
			if got != tc.copy || ok != (tc.copy != "") {
				t.Errorf("CopyFor(%q) = %q, %v; want %q", tc.host, got, ok, tc.copy)
			}
			if IsShell(tc.host) != tc.shell {
				t.Errorf("IsShell(%q) = %v, want %v", tc.host, !tc.shell, tc.shell)
			}
		})
	}
}

// TestEntriesReturnsACopy proves a caller cannot edit the list through the
// returned slice.
func TestEntriesReturnsACopy(t *testing.T) {
	a := Entries()
	a[0].Copy = "x"
	a[0].Hosts[0] = "/x"
	b := Entries()
	if b[0].Copy == "x" || b[0].Hosts[0] == "/x" {
		t.Fatal("Entries exposes the package's own list")
	}
	if got, _ := CopyFor("/bin/sh"); got != "bash" {
		t.Fatalf("CopyFor(/bin/sh) = %q after editing a returned slice", got)
	}
}
