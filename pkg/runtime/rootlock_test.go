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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// lockTestWait is the shrunken RootLockWait these tests run under, so the
// refusal arm costs a fraction of a second instead of DefaultRootLockWait.
const lockTestWait = 300 * time.Millisecond

// busyCounter returns a rootLockBusy seam and the count of refused attempts it
// has seen. The tests assert on that count rather than on elapsed wall time: a
// count of zero proves New never waited, whatever the machine's load.
func busyCounter() (func(), *atomic.Int32) {
	n := new(atomic.Int32)
	return func() { n.Add(1) }, n
}

// maxBusy is the most refused attempts a wait can report: each one is followed
// by a full rootLockPoll sleep and is made only before the deadline.
func maxBusy(wait time.Duration) int32 {
	return int32((wait + rootLockPoll - 1) / rootLockPoll)
}

// TestSecondRuntimeOnOneRootRefused is the gate: while one Runtime holds a root,
// a second New on that root waits its bound and then fails with ErrRootInUse,
// naming this process's pid as the holder.
func TestSecondRuntimeOnOneRootRefused(t *testing.T) {
	root := t.TempDir()
	newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})

	d := testDeps(t, Deps{RootLockWait: lockTestWait})
	onBusy, busy := busyCounter()
	d.rootLockBusy = onBusy
	_, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")}, d)

	if !errors.Is(err, ErrRootInUse) {
		t.Fatalf("second New on a held root: err = %v, want ErrRootInUse", err)
	}
	if want := "pid " + strconv.Itoa(os.Getpid()); !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %q does not name the holder (%q)", err, want)
	}
	if n := busy.Load(); n < 1 || n > maxBusy(lockTestWait) {
		t.Errorf("refused after %d waits, want 1..%d (it must wait, and no longer than its bound)", n, maxBusy(lockTestWait))
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
	onBusy, busy := busyCounter()
	newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait, rootLockBusy: onBusy})
	if n := busy.Load(); n != 0 {
		t.Errorf("New after Close waited %d times, want no wait for a released lock", n)
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

// TestNewFailureReleasesRootLock: a New that fails after it took the root's
// lock lets go of it, so the next New on that root starts without waiting. The
// failure is a regular file where the image cache's blob dir belongs, which
// fails image.NewCache, the first step after the lock.
func TestNewFailureReleasesRootLock(t *testing.T) {
	root := t.TempDir()
	blobs := filepath.Join(root, "blobs")
	if err := os.WriteFile(blobs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")},
		testDeps(t, Deps{RootLockWait: lockTestWait}))
	if err == nil || errors.Is(err, ErrRootInUse) || !strings.Contains(err.Error(), "init image cache") {
		t.Fatalf("New over a blocked cache dir: err = %v, want the image cache failure", err)
	}
	if err := os.Remove(blobs); err != nil {
		t.Fatal(err)
	}
	onBusy, busy := busyCounter()
	newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait, rootLockBusy: onBusy})
	if n := busy.Load(); n != 0 {
		t.Errorf("New after a failed New waited %d times, want the failed New to have released the root", n)
	}
}

// TestRootLockWaiterAcquiresOnRelease is the kickstart order: the old holder lets
// go partway through the new one's wait, and the new New succeeds. The release
// is ordered by an event, not a sleep: the holder closes only once the waiter
// has reported a refused attempt, so the waiter is provably mid-wait when the
// lock is let go.
func TestRootLockWaiterAcquiresOnRelease(t *testing.T) {
	root := t.TempDir()
	first := newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})
	busy := make(chan struct{}, 1)
	var refused atomic.Int32
	onBusy := func() {
		refused.Add(1)
		select {
		case busy <- struct{}{}:
		default:
		}
	}
	done := make(chan struct{})
	defer close(done)
	released := make(chan struct{})
	go func() {
		defer close(released)
		select {
		case <-busy:
			_ = first.Close() // the waiter's outcome is the assertion
		case <-done:
		}
	}()
	d := testDeps(t, Deps{RootLockWait: 5 * time.Second})
	d.rootLockBusy = onBusy
	rt, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")}, d)
	if err != nil {
		t.Fatalf("New waiting on a releasing holder: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	// The waiter must have been refused at least once before it acquired: a
	// New that took the lock on its first attempt never waited on the holder.
	if n := refused.Load(); n < 1 {
		t.Fatalf("New acquired after %d refused attempts, want it to wait on the holder", n)
	}
	<-released
	got, err := os.ReadFile(filepath.Join(root, RootLockName))
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(os.Getpid()); strings.TrimSpace(string(got)) != want {
		t.Errorf("lock file records %q, want pid %s", got, want)
	}
}

// rootLockHelperEnv names the root the re-executed test binary holds when it
// runs TestRootLockHelperProcess; unset, that test skips.
const rootLockHelperEnv = "K3SM_TEST_ROOTLOCK_HELPER_ROOT"

// rootLockHelperReady is the line the helper prints once its Runtime holds the
// root, so the parent proceeds on an event rather than a sleep.
const rootLockHelperReady = "rootlock-helper-ready"

// rootLockHelperReadyBound bounds the wait for that line. It is a ceiling for a
// helper wedged before it prints, far above a healthy start on a loaded machine,
// and it fails with the helper's stderr long before the package timeout would.
const rootLockHelperReadyBound = 30 * time.Second

// TestRootLockHelperProcess is not a test of its own: TestRootLockCrossProcess
// re-executes the test binary to run it, as a second process that takes the
// root through New and then holds it until it is killed or its stdin closes.
func TestRootLockHelperProcess(t *testing.T) {
	root := os.Getenv(rootLockHelperEnv)
	if root == "" {
		t.Skip("helper process for TestRootLockCrossProcess")
	}
	newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait})
	fmt.Println(rootLockHelperReady)
	_, _ = io.Copy(io.Discard, os.Stdin) // hold the root until the parent lets go of us
}

// startRootLockHolder re-executes the test binary as a process holding root and
// returns once it reports the root is held.
func startRootLockHolder(t *testing.T, root string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestRootLockHelperProcess$")
	cmd.Env = append(os.Environ(), rootLockHelperEnv+"="+root)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second // a descendant holding stderr cannot hang the failure path's Wait
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the root holder: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()         // a holder still alive exits on its own
		_ = cmd.Process.Kill()    // and is killed if it does not
		_, _ = cmd.Process.Wait() // reaped either way; a test that already waited gets an error here
	})
	if err := awaitReadyLine(stdout, rootLockHelperReady, rootLockHelperReadyBound); err != nil {
		_ = cmd.Process.Kill() // a wedged holder would otherwise keep Wait from returning
		_ = cmd.Wait()         // collects stderr for the message below
		t.Fatalf("root holder did not report the root held: %v: %s", err, stderr.String())
	}
	return cmd
}

// awaitReadyLine scans r for a line equal to want, giving up after bound. The scan
// runs in its own goroutine, because a read from a wedged writer does not return
// on its own; it ends when r is closed or reaches EOF, which for a child's stdout
// happens when the child is killed and waited for.
func awaitReadyLine(r io.Reader, want string, bound time.Duration) error {
	result := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if sc.Text() == want {
				result <- nil
				return
			}
		}
		if err := sc.Err(); err != nil {
			result <- fmt.Errorf("read before line %q: %w", want, err)
			return
		}
		result <- fmt.Errorf("end of output before line %q", want)
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		return fmt.Errorf("no line %q within %s", want, bound)
	}
}

// TestAwaitReadyLine pins the readiness scan's three outcomes, the third being why it
// is bounded: a writer that stays silent fails the scan instead of blocking until
// the package timeout.
func TestAwaitReadyLine(t *testing.T) {
	t.Run("line-found", func(t *testing.T) {
		if err := awaitReadyLine(strings.NewReader("noise\nready\n"), "ready", time.Minute); err != nil {
			t.Errorf("awaitReadyLine: %v", err)
		}
	})
	t.Run("output-ends-first", func(t *testing.T) {
		err := awaitReadyLine(strings.NewReader("noise\n"), "ready", time.Minute)
		if err == nil || !strings.Contains(err.Error(), "end of output") {
			t.Errorf("awaitReadyLine = %v, want the end of output reported", err)
		}
	})
	t.Run("silent-writer-hits-the-bound", func(t *testing.T) {
		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() }) // ends the scan goroutine
		err := awaitReadyLine(pr, "ready", 10*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "within") {
			t.Errorf("awaitReadyLine = %v, want the bound reported", err)
		}
	})
}

// TestRootLockCrossProcess pins the lock across processes, which is the case it
// exists for (a daemon restart, a hand-started second daemon): another process
// holding the root refuses New with that process's pid, and the root is free the
// moment that process dies, with no Close and no wait. A lock file left behind
// by a dead process, with no flock on it, does not hold the root at all.
func TestRootLockCrossProcess(t *testing.T) {
	t.Run("released-at-process-death", func(t *testing.T) {
		root := t.TempDir()
		holder := startRootLockHolder(t, root)

		d := testDeps(t, Deps{RootLockWait: lockTestWait})
		onBusy, busy := busyCounter()
		d.rootLockBusy = onBusy
		_, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")}, d)
		if !errors.Is(err, ErrRootInUse) {
			t.Fatalf("New on a root another process holds: err = %v, want ErrRootInUse", err)
		}
		if want := "pid " + strconv.Itoa(holder.Process.Pid) + " "; !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name the holder process (%q)", err, want)
		}
		if n := busy.Load(); n < 1 {
			t.Errorf("refused after %d waits, want it to wait on the holder", n)
		}

		if err := holder.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatalf("kill the holder: %v", err)
		}
		_ = holder.Wait() // the SIGKILL exit status is expected; the process is gone once Wait returns

		onBusy, busy = busyCounter()
		newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait, rootLockBusy: onBusy})
		if n := busy.Load(); n != 0 {
			t.Errorf("New after the holder died waited %d times, want the kernel to have released its flock", n)
		}
		assertLockRecordsPid(t, root, os.Getpid())
	})
	t.Run("stale-file-dead-pid", func(t *testing.T) {
		root := t.TempDir()
		dead := exec.Command(os.Args[0], "-test.run", "^$")
		if err := dead.Run(); err != nil {
			t.Fatalf("run a short-lived process for its pid: %v", err)
		}
		stale := []byte(strconv.Itoa(dead.Process.Pid) + "\n")
		if err := os.WriteFile(filepath.Join(root, RootLockName), stale, 0o600); err != nil {
			t.Fatal(err)
		}
		onBusy, busy := busyCounter()
		newTestRuntimeCfg(t, Config{Root: root}, Deps{RootLockWait: lockTestWait, rootLockBusy: onBusy})
		if n := busy.Load(); n != 0 {
			t.Errorf("New over a stale lock file waited %d times, want the file's content ignored", n)
		}
		assertLockRecordsPid(t, root, os.Getpid())
	})
}

// assertLockRecordsPid checks the pid the root's lock file records.
func assertLockRecordsPid(t *testing.T, root string, pid int) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(root, RootLockName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strconv.Itoa(pid) {
		t.Errorf("lock file records %q, want pid %d", got, pid)
	}
}

// TestRootLockSpellings: the lock is on the file, not on the path that named
// it, so every spelling of one root (a symlink to it, its symlink-resolved
// path, the path as given) contends for one lock.
func TestRootLockSpellings(t *testing.T) {
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	spellings := map[string]string{"as-given": root, "symlink": link}
	if resolved != root {
		spellings["resolved"] = resolved
	}
	for holderName, holderPath := range spellings {
		for waiterName, waiterPath := range spellings {
			if holderName == waiterName {
				continue
			}
			t.Run(holderName+"-holds-"+waiterName+"-refused", func(t *testing.T) {
				held, err := acquireRootLock(holderPath, lockTestWait, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = held.release() }()
				l, err := acquireRootLock(waiterPath, rootLockPoll, nil, nil)
				if err == nil {
					_ = l.release()
					t.Fatalf("%s acquired while %s held the root", waiterPath, holderPath)
				}
				if !errors.Is(err, ErrRootInUse) {
					t.Fatalf("err = %v, want ErrRootInUse", err)
				}
			})
		}
	}
}

// TestRootLockHolder pins how the refusal names a holder: the recorded pid
// when the file holds one, and "unknown" for anything else, so a corrupt or
// half-written file never puts garbage in the message.
func TestRootLockHolder(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"pid", "4242\n", "4242"},
		{"padded-pid", "  4242 \n", "4242"},
		{"empty", "", "unknown"},
		{"not-an-integer", "not-a-pid\n", "unknown"},
		{"trailing-garbage", "42abc\n", "unknown"},
		{"binary", "\x00\x01\x02", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, RootLockName)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			// Hold the flock without recording a pid, as a holder between its
			// flock and its write would, so the refusal reads the content above.
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			if got := lockHolder(int(f.Fd())); got != tc.want {
				t.Errorf("lockHolder = %q, want %q", got, tc.want)
			}
			_, err = acquireRootLock(root, rootLockPoll, nil, nil)
			if !errors.Is(err, ErrRootInUse) {
				t.Fatalf("err = %v, want ErrRootInUse", err)
			}
			if want := "held by pid " + tc.want + " "; !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not carry %q", err, want)
			}
		})
	}
}

// TestRootLockFlockError: a flock error other than "held" (ENOTSUP from a
// volume without flock support) fails at once with the errno in the chain and
// the lock path in the message, never as ErrRootInUse and never after a wait.
func TestRootLockFlockError(t *testing.T) {
	root := t.TempDir()
	onBusy, busy := busyCounter()
	enotsup := func(int, int) error { return unix.ENOTSUP }
	l, err := acquireRootLock(root, lockTestWait, onBusy, enotsup)
	if err == nil {
		_ = l.release()
		t.Fatal("acquireRootLock succeeded on a flock that returns ENOTSUP")
	}
	if !errors.Is(err, unix.ENOTSUP) {
		t.Errorf("err = %v, want unix.ENOTSUP in the chain", err)
	}
	if errors.Is(err, ErrRootInUse) {
		t.Errorf("err = %v reads as ErrRootInUse; an unsupported lock is not a held one", err)
	}
	if want := filepath.Join(root, RootLockName); !strings.Contains(err.Error(), want) {
		t.Errorf("err %q does not name the lock file %s", err, want)
	}
	if n := busy.Load(); n != 0 {
		t.Errorf("an ENOTSUP flock was retried %d times, want an immediate failure", n)
	}
	// The failed attempt closed its descriptor: a real lock on the root works.
	l, err = acquireRootLock(root, lockTestWait, nil, nil)
	if err != nil {
		t.Fatalf("acquire after the ENOTSUP attempt: %v", err)
	}
	_ = l.release()
}

// TestRootLockFile pins the lock file's own hardening: created 0600, and a
// symlink planted at its name is refused rather than followed.
func TestRootLockFile(t *testing.T) {
	t.Run("created-0600", func(t *testing.T) {
		root := t.TempDir()
		l, err := acquireRootLock(root, lockTestWait, nil, nil)
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
		l, err := acquireRootLock(root, lockTestWait, nil, nil)
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
		l, err := acquireRootLock(root, lockTestWait, nil, nil)
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
