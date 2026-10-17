//go:build darwin && cgo

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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelperLogRotatesAtTheCap pins the helper's own bound on its output file:
// a write that would cross the cap moves the file to path.1 and continues in a
// fresh file on the same descriptor, nothing is lost, and the file is never
// truncated in place. A descriptor that is no longer the file at path is not
// rotated.
func TestHelperLogRotatesAtTheCap(t *testing.T) {
	cases := []struct {
		name       string
		writes     []string
		divert     bool // path no longer names the file the descriptor writes
		wantCur    string
		wantRotate string
	}{
		{name: "under the cap no rotation", writes: []string{"aaaa\n", "bbbb\n"}, wantCur: "aaaa\nbbbb\n"},
		{name: "a write past the cap rotates first", writes: []string{"aaaaaaa\n", "bbbbbbb\n"}, wantCur: "bbbbbbb\n", wantRotate: "aaaaaaa\n"},
		{name: "a second rotation replaces the first", writes: []string{"aaaaaaa\n", "bbbbbbb\n", "ccccccc\n"}, wantCur: "ccccccc\n", wantRotate: "bbbbbbb\n"},
		{name: "an empty file takes an oversized line whole", writes: []string{strings.Repeat("x", 20) + "\n"}, wantCur: strings.Repeat("x", 20) + "\n"},
		{name: "a diverted descriptor is never rotated", writes: []string{"aaaaaaa\n", "bbbbbbb\n"}, divert: true, wantCur: "aaaaaaa\nbbbbbbb\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "vmhost.log")
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			read := path
			if tc.divert {
				read = filepath.Join(dir, "moved.log")
				if err := os.Rename(path, read); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			h := newHelperLog(path, 12, f, []int{int(f.Fd())})
			for _, w := range tc.writes {
				if _, err := h.Write([]byte(w)); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			cur, err := os.ReadFile(read)
			if err != nil {
				t.Fatal(err)
			}
			if string(cur) != tc.wantCur {
				t.Errorf("current file = %q, want %q", cur, tc.wantCur)
			}
			rot, err := os.ReadFile(path + ".1")
			if tc.wantRotate == "" {
				if err == nil {
					t.Errorf("rotation = %q, want none", rot)
				}
				return
			}
			if string(rot) != tc.wantRotate {
				t.Errorf("rotation = %q, want %q", rot, tc.wantRotate)
			}
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("fresh file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
			}
		})
	}
}
