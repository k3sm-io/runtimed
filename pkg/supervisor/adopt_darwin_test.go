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

package supervisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// startOrphan starts /bin/sleep through a shell that backgrounds it and exits
// at once (a double fork), so the sleeper reparents to launchd: this test
// process is its grandparent, not its parent — the position a restarted daemon
// is in toward a pod process its predecessor spawned. It returns the pid.
func startOrphan(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", "/bin/sleep 300 </dev/null >/dev/null 2>&1 & echo $!").Output()
	if err != nil {
		t.Fatalf("double fork: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 1 {
		t.Fatalf("double fork printed %q", out)
	}
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
	// The precondition the whole test rests on: the kernel says it is not ours.
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("wait4 on the orphan = %v, want ECHILD (it must not be this process's child)", err)
	}
	return pid
}

// TestNonChildExitIsReportedUnknown is the B124 supervisor gate. An adopted
// process's exit is observed through NOTE_EXIT and reported as ErrExitUnknown,
// never as a fabricated exit code 0 — which is what KqueueReaper's ECHILD branch
// reports, and why the adopted path needs its own waiter. The child path is
// unchanged: a process this daemon spawned still reports its real status through
// either waiter.
func TestNonChildExitIsReportedUnknown(t *testing.T) {
	t.Run("adopted non-child exit is unknown", func(t *testing.T) {
		pid := startOrphan(t)
		p, err := AdoptProcess(context.Background(), AdoptedExitWaiter{}, pid, nil, nil)
		if err != nil {
			t.Fatalf("AdoptProcess: %v", err)
		}
		if p.State() != StateRunning || p.PID() != pid {
			t.Fatalf("adopted process state %v pid %d, want running %d", p.State(), p.PID(), pid)
		}
		select {
		case <-p.Done():
			t.Fatal("the adopted process was reported exited while it was alive")
		case <-time.After(100 * time.Millisecond):
		}
		if err := unix.Kill(pid, unix.SIGKILL); err != nil {
			t.Fatalf("kill orphan: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		code, sig, err := p.Wait(ctx)
		if !errors.Is(err, ErrExitUnknown) {
			t.Fatalf("Wait = (%d, %d, %v), want ErrExitUnknown", code, sig, err)
		}
	})

	t.Run("KqueueReaper would fabricate a success for the same process", func(t *testing.T) {
		pid := startOrphan(t)
		done := make(chan [3]any, 1)
		go func() {
			code, sig, err := KqueueReaper{}.WaitExit(context.Background(), pid)
			done <- [3]any{code, sig, err}
		}()
		time.Sleep(50 * time.Millisecond)
		_ = unix.Kill(pid, unix.SIGKILL)
		select {
		case got := <-done:
			if got[0] != 0 || got[1] != 0 || got[2] != nil {
				t.Fatalf("KqueueReaper on a non-child = %v; the contrast this gate rests on changed", got)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("KqueueReaper never observed the non-child exit")
		}
	})

	t.Run("already-gone adopted pid is unknown", func(t *testing.T) {
		pid := startOrphan(t)
		_ = unix.Kill(pid, unix.SIGKILL)
		deadline := time.Now().Add(5 * time.Second)
		for unix.Kill(pid, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, err := (AdoptedExitWaiter{}).WaitExit(ctx, pid); !errors.Is(err, ErrExitUnknown) {
			t.Fatalf("WaitExit on a vanished pid = %v, want ErrExitUnknown", err)
		}
	})

	for _, tc := range []struct {
		name   string
		waiter ExitWaiter
	}{
		{"child path through KqueueReaper reports the real code", KqueueReaper{}},
		{"child path through AdoptedExitWaiter reports the real code", AdoptedExitWaiter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProcess(PosixSpawner{}, tc.waiter,
				SpawnSpec{Path: "/bin/sh", Argv: []string{"/bin/sh", "-c", "exit 7"}, Env: []string{}}, nil)
			if err := p.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			code, sig, err := p.Wait(ctx)
			if err != nil || code != 7 || sig != 0 {
				t.Fatalf("Wait = (%d, %d, %v), want (7, 0, nil)", code, sig, err)
			}
		})
	}

	t.Run("adopt refuses a wildcard or launchd pid", func(t *testing.T) {
		for _, pid := range []int{-1, 0, 1} {
			if _, err := AdoptProcess(context.Background(), AdoptedExitWaiter{}, pid, nil, nil); err == nil {
				t.Fatalf("AdoptProcess(%d) accepted", pid)
			}
		}
	})
}

// TestCodeDirectoryHashOfSelf pins the build-fingerprint source: the running
// (linker-signed) test binary has a 20-byte code-directory hash, stable across
// calls, and a pid that does not exist has none.
func TestCodeDirectoryHashOfSelf(t *testing.T) {
	h, err := CodeDirectoryHash(os.Getpid())
	if err != nil {
		t.Fatalf("CodeDirectoryHash(self): %v", err)
	}
	if len(h) != 2*cdHashLen {
		t.Fatalf("cdhash %q: want %d hex chars", h, 2*cdHashLen)
	}
	if again, _ := CodeDirectoryHash(os.Getpid()); again != h {
		t.Fatalf("cdhash not stable: %q then %q", h, again)
	}
	if _, err := CodeDirectoryHash(1 << 30); err == nil {
		t.Fatal("CodeDirectoryHash of a nonexistent pid succeeded")
	}
}
