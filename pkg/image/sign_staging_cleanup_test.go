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
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// cstempSign is a signFunc that behaves like a codesign killed mid-write: it
// appends a marker to the staged copy (as a real sign rewrites it), leaves
// codesign's own temp beside it, then runs the stubbed tool through the real
// deadline wrapper (codesignAs), which hangs until it is killed. The append
// means a staged copy that leaked into place would change the original's bytes.
func cstempSign(t *testing.T) signFunc {
	return func(ctx context.Context, path, ident string) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Errorf("open staged copy: %v", err)
		} else {
			if _, err := f.WriteString("+signed"); err != nil {
				t.Errorf("append to staged copy: %v", err)
			}
			if err := f.Close(); err != nil {
				t.Errorf("close staged copy: %v", err)
			}
		}
		if err := os.WriteFile(path+codesignTempSuffix, []byte("partial"), 0o600); err != nil {
			t.Errorf("write codesign temp: %v", err)
		}
		return codesignAs(ctx, path, ident)
	}
}

// markedSleeper returns a stub tool that writes the file marker once its own
// process is running and then sleeps past every test deadline, so a test can
// tell a tool that really started from one that was only constructed.
func markedSleeper(t *testing.T) (stub func(ctx context.Context) *exec.Cmd, marker string) {
	t.Helper()
	marker = filepath.Join(t.TempDir(), "started")
	return func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", `printf started > "$1"; exec /bin/sleep 30`, "sh", marker)
	}, marker
}

// fileExists reports whether p exists.
func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// TestSignByReplaceHungSignLeavesNoStagedFile pins the staged-copy cleanup on
// the two ways a hung sign ends: killed at the sign deadline, and stopped by a
// cancelled caller (cancelled only once the stubbed tool's process is running).
// Either way the call reports that outcome (never success), the staging
// directory is left empty (the staged copy, which the sign appended to, and
// codesign's temp are both removed), and the original is byte-identical and
// still the same inode at its name.
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
			stub, marker := markedSleeper(t)
			rec := stubTools(t, stub)
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
			// cancelledAt receives the time of the cancel, made only once the
			// stubbed tool's own process has written its marker.
			cancelledAt := make(chan time.Time, 1)
			if tc.cancel {
				go func() {
					for ctx.Err() == nil {
						if fileExists(marker) {
							cancelledAt <- time.Now()
							cancel()
							return
						}
						time.Sleep(5 * time.Millisecond)
					}
				}()
			}
			start := time.Now()
			err = signByReplace(ctx, r.staging, r.root, r.bin, cstempSign(t), nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			from := start
			if tc.cancel {
				select {
				case from = <-cancelledAt:
				default:
					t.Fatal("call ended without the cancel: the stubbed tool never started")
				}
			}
			// Half the long deadline: a call bounded by the long deadline fails.
			if bound := testLongTimeout / 2; time.Since(from) > bound {
				t.Errorf("returned %s after the deadline clock started, want within %s", time.Since(from), bound)
			}
			if got := rec.names(); len(got) == 0 {
				t.Error("no tool invocation recorded: the sign never ran the tool")
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
