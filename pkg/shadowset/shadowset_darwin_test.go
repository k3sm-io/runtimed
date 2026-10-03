//go:build darwin

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
	"os"
	"syscall"
	"testing"
)

// sfRestricted is the SIP SF_RESTRICTED file flag (sys/stat.h).
const sfRestricted = 0x00080000

// TestEntriesMatchTheDisk pins the list against this host's disk, not only
// against its own generated twin: every Source exists, is a regular file and
// not a symlink, and carries SF_RESTRICTED (a binary without it keeps the
// interposers anyway and needs no copy); every exec path resolves to a
// restricted regular file; and for a non-shell entry every exec path is the
// SAME file as the Source, so the copy really is what that name runs (the
// shells differ by design: /bin/sh is the dispatcher, served by bash).
//
// A host that lacks one of the binaries skips that entry with the reason
// logged; the rest are still checked.
func TestEntriesMatchTheDisk(t *testing.T) {
	for _, e := range Entries() {
		t.Run(e.Copy, func(t *testing.T) {
			lfi, err := os.Lstat(e.Source)
			if err != nil {
				t.Skipf("SKIP: this host has no %s: %v", e.Source, err)
			}
			if lfi.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("source %s is a symlink; the installer must copy the real file", e.Source)
			}
			if !lfi.Mode().IsRegular() {
				t.Fatalf("source %s is not a regular file (%v)", e.Source, lfi.Mode())
			}
			if !restricted(t, e.Source) {
				t.Errorf("source %s is not SF_RESTRICTED: it keeps the interposers without a copy", e.Source)
			}
			for _, h := range e.Hosts {
				fi, err := os.Stat(h)
				if err != nil {
					t.Logf("SKIP %s: this host has no %s: %v", e.Copy, h, err)
					continue
				}
				if !fi.Mode().IsRegular() {
					t.Errorf("exec path %s does not resolve to a regular file (%v)", h, fi.Mode())
				}
				if !restricted(t, h) {
					t.Errorf("exec path %s is not SF_RESTRICTED", h)
				}
				if !e.Shell && !os.SameFile(fi, lfi) {
					t.Errorf("exec path %s is not the same file as the source %s", h, e.Source)
				}
			}
		})
	}
}

// restricted stats p (following a symlink, as exec does) and reports its
// SF_RESTRICTED flag.
func restricted(t *testing.T, p string) bool {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return st.Flags&sfRestricted != 0
}
