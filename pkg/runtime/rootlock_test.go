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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// lockTestWait is the shrunken RootLockWait these tests run under, so the
// refusal arm costs a fraction of a second instead of DefaultRootLockWait.
const lockTestWait = 300 * time.Millisecond

// lockTestSlack is the tolerance on either side of the wait: the poll cadence
// plus scheduler noise on a loaded machine.
const lockTestSlack = 2 * time.Second

// TestSecondRuntimeOnOneRootRefused is the gate: while one Runtime holds a root,
// a second New on that root waits its bound and then fails with ErrRootInUse,
// naming this process's pid as the holder.
func TestSecondRuntimeOnOneRootRefused(t *testing.T) {
	root := t.TempDir()
	newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})

	start := time.Now()
	_, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")},
		testDeps(t, Deps{RootLockWait: lockTestWait}))
	elapsed := time.Since(start)

	if !errors.Is(err, ErrRootInUse) {
		t.Fatalf("second New on a held root: err = %v, want ErrRootInUse", err)
	}
	if want := "pid " + strconv.Itoa(os.Getpid()); !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %q does not name the holder (%q)", err, want)
	}
	if elapsed < lockTestWait-rootLockPoll || elapsed > lockTestWait+lockTestSlack {
		t.Errorf("refused after %s, want %s within %s", elapsed, lockTestWait, lockTestSlack)
	}
}

// TestRootLockReleasedByClose: once the holder closes, a new Runtime on the same
// root comes up without waiting.
func TestRootLockReleasedByClose(t *testing.T) {
	root := t.TempDir()
	first := newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})
	if err := first.Close(); err != nil {
		t.Fatalf("close first runtime: %v", err)
	}
	start := time.Now()
	newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})
	if elapsed := time.Since(start); elapsed >= lockTestWait {
		t.Errorf("New after Close took %s, want no wait for a released lock", elapsed)
	}
	// A second Close of the first runtime must not release the successor's lock.
	if err := first.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	_, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")},
		testDeps(t, Deps{RootLockWait: lockTestWait}))
	if !errors.Is(err, ErrRootInUse) {
		t.Fatalf("New while the successor holds the root: err = %v, want ErrRootInUse", err)
	}
}

// TestRootLockWaiterAcquiresOnRelease is the kickstart order: the old holder lets
// go partway through the new one's wait, and the new New succeeds.
func TestRootLockWaiterAcquiresOnRelease(t *testing.T) {
	root := t.TempDir()
	first := newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})
	wait := 5 * time.Second
	hold := 200 * time.Millisecond
	go func() {
		time.Sleep(hold)
		_ = first.Close() // the waiter's outcome is the assertion
	}()
	start := time.Now()
	rt, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")},
		testDeps(t, Deps{RootLockWait: wait}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New waiting on a releasing holder: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	// No upper check: a New that outwaited its bound failed above with
	// ErrRootInUse, and the rest of New's construction time is not the lock's.
	if elapsed < hold-rootLockPoll {
		t.Errorf("acquired after %s, before the holder's %s hold ended", elapsed, hold)
	}
	got, err := os.ReadFile(filepath.Join(root, RootLockName))
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(os.Getpid()); strings.TrimSpace(string(got)) != want {
		t.Errorf("lock file records %q, want pid %s", got, want)
	}
}

// TestRootLockFile pins the lock file's own hardening: created 0600, and a
// symlink planted at its name is refused rather than followed.
func TestRootLockFile(t *testing.T) {
	t.Run("created-0600", func(t *testing.T) {
		root := t.TempDir()
		l, err := acquireRootLock(root, lockTestWait)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.release() }()
		fi, err := os.Lstat(filepath.Join(root, RootLockName))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Errorf("lock file mode = %v, want a regular 0600 file", fi.Mode())
		}
	})
	t.Run("symlink-refused", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Symlink(target, filepath.Join(root, RootLockName)); err != nil {
			t.Fatal(err)
		}
		l, err := acquireRootLock(root, lockTestWait)
		if err == nil {
			_ = l.release()
			t.Fatal("acquireRootLock followed a symlink")
		}
		if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
			t.Errorf("symlink target was created (stat err %v)", statErr)
		}
	})
	t.Run("directory-refused", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, RootLockName), 0o700); err != nil {
			t.Fatal(err)
		}
		l, err := acquireRootLock(root, lockTestWait)
		if err == nil {
			_ = l.release()
			t.Fatal("acquireRootLock accepted a directory")
		}
	})
}

// TestDefaultRootLockWait pins the production bound, so a shrunken test value
// can never leak into the daemon.
func TestDefaultRootLockWait(t *testing.T) {
	if DefaultRootLockWait != 15*time.Second {
		t.Errorf("DefaultRootLockWait = %s, want 15s", DefaultRootLockWait)
	}
}
