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
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestObserveExecSeesThePostExecImage proves the exec-sync ordering the
// restricted-main-process detection depends on: the observer runs after the
// spawned launcher has exec'd its target, so csops describes the TARGET, not
// the launcher; it runs before the reap (Wait cannot return first); and Start
// does not wait for it.
//
// The launcher is a stand-in for the exec-shim built at test time: it marks
// fd ExecSyncChildFD close-on-exec (what the shim does on ExecSyncFDEnv),
// sleeps so an observer that did not wait would certainly see it, and execs
// /bin/sleep, a platform binary. The launcher itself is ad-hoc (not platform),
// so the platform bit in the observed flags can only come from after the exec.
func TestObserveExecSeesThePostExecImage(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH, cannot build the launcher: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "launcher.c")
	const prog = `#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
	fcntl(3, F_SETFD, FD_CLOEXEC);
	usleep(100000);
	execv(argv[1], argv + 1);
	return 127;
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "launcher")
	if out, err := exec.Command("clang", "-o", launcher, src).CombinedOutput(); err != nil {
		t.Fatalf("build launcher: %v\n%s", err, out)
	}

	var observed []uint32
	var observedPid int
	p := NewProcess(PosixSpawner{}, KqueueReaper{}, SpawnSpec{
		Path: launcher,
		Argv: []string{launcher, "/bin/sleep", "0.3"},
	}, nil)
	p.ObserveExec(func(pid int, seen bool) {
		observedPid = pid
		if !seen {
			t.Errorf("observer told the exec of pid %d was not observed", pid)
			return
		}
		flags, err := CodeSignStatus(pid)
		if err != nil {
			t.Errorf("csops(%d) in the observer: %v", pid, err)
			return
		}
		observed = append(observed, flags)
	}, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// The launcher sleeps 100ms before its exec; a Start that waited for the
	// observation could not return before that.
	if d := time.Since(start); d >= 100*time.Millisecond {
		t.Errorf("Start took %v: it waited for the exec observation", d)
	}
	// Wait returns only after the reaper goroutine reaped, which it does only
	// after the observer returned, so reading observed here is ordered.
	if _, _, err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 {
		t.Fatalf("observer ran %d times, want exactly once before the reap", len(observed))
	}
	if observedPid != p.PID() {
		t.Errorf("observer saw pid %d, want the spawned pid %d", observedPid, p.PID())
	}
	if observed[0]&CSPlatformBinary == 0 {
		t.Errorf("observed csflags %#x lack CS_PLATFORM_BINARY: the observer read the launcher, not the exec'd /bin/sleep", observed[0])
	}
}

// TestObserveExecSkipsOnTimeout proves the timeout arm: a child that never
// execs (it holds the sync descriptor open) is reported NOT observed once the
// bound passes, so the caller cannot mistake it for silence; Start never waits
// for it, and the child is still reaped.
func TestObserveExecSkipsOnTimeout(t *testing.T) {
	var mu sync.Mutex
	calls, observedFlag := 0, true
	p := NewProcess(PosixSpawner{}, KqueueReaper{}, SpawnSpec{
		Path: "/bin/sleep",
		Argv: []string{"/bin/sleep", "1"},
	}, nil)
	p.ObserveExec(func(_ int, seen bool) { mu.Lock(); calls++; observedFlag = seen; mu.Unlock() }, 200*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= 200*time.Millisecond {
		t.Errorf("Start took %v, want it not to wait for the 200ms observe bound", d)
	}
	if _, _, err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || observedFlag {
		t.Errorf("observer ran %d times with observed=%v, want once with observed=false: the child never exec'd past the sync descriptor", calls, observedFlag)
	}
}
