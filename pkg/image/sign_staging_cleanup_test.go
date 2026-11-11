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

package image

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// cstempSign is a signFunc that behaves like a codesign killed mid-write: it
// leaves codesign's own temp beside the staged copy, then runs the stubbed tool
// through the real deadline wrapper (codesignAs), which hangs until it is killed.
// started is closed once the temp exists, so a test can cancel mid-sign.
func cstempSign(t *testing.T, started chan<- struct{}) signFunc {
	return func(ctx context.Context, path, ident string) error {
		if err := os.WriteFile(path+codesignTempSuffix, []byte("partial"), 0o600); err != nil {
			t.Errorf("write codesign temp: %v", err)
		}
		close(started)
		return codesignAs(ctx, path, ident)
	}
}

// TestSignByReplaceHungSignLeavesNoStagedFile pins the staged-copy cleanup on
// the two ways a hung sign ends: killed at the sign deadline, and stopped by a
// cancelled caller. Either way the call reports that outcome (never success),
// the staging directory is left empty (the staged copy and codesign's temp are
// both removed), and the original is byte-identical and still the same inode at
// its name.
func TestSignByReplaceHungSignLeavesNoStagedFile(t *testing.T) {
	cases := []struct {
		name   string
		cancel bool
		want   error
	}{
		{"sign-deadline", false, ErrSignatureCheckTimeout},
		{"parent-cancel", true, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubTools(t, sleeper)
			checkTimeout, signTimeout = testLongTimeout, testSignTimeout
			if tc.cancel {
				signTimeout = testLongTimeout
			}
			r := newSignReplaceRig(t)
			before, err := os.ReadFile(r.bin)
			if err != nil {
				t.Fatal(err)
			}
			beforeIno := inode(t, r.bin)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			if tc.cancel {
				go func() {
					<-started
					cancel()
				}()
			}
			start := time.Now()
			err = signByReplace(ctx, r.staging, r.root, r.bin, cstempSign(t, started), nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if time.Since(start) > testSignTimeout+slack {
				t.Errorf("returned after %s, want within %s", time.Since(start), testSignTimeout+slack)
			}

			ents, err := os.ReadDir(r.staging)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				t.Errorf("staging holds %q after a hung sign", e.Name())
			}
			ents, err = os.ReadDir(filepath.Dir(r.bin))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if e.Name() != filepath.Base(r.bin) {
					t.Errorf("%s holds %q after a hung sign", filepath.Dir(r.bin), e.Name())
				}
			}
			after, err := os.ReadFile(r.bin)
			if err != nil {
				t.Fatalf("original is gone: %v", err)
			}
			if !bytes.Equal(after, before) {
				t.Errorf("original = %q, want byte-identical %q", after, before)
			}
			if got := inode(t, r.bin); got != beforeIno {
				t.Errorf("original inode = %d, want %d (still in place)", got, beforeIno)
			}
		})
	}
}

// inode returns the inode number of the file at p.
func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}
