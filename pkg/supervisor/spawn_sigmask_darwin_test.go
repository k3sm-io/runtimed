//go:build integration && darwin

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
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestIntegrationSpawnResetsSignalMask proves PosixSpawner resets the child's
// signal mask so a pod honors SIGTERM (k8s graceful termination) even though the
// Go runtime blocks signals on its worker threads. It BLOCKS SIGTERM on the
// spawning OS thread and pins the goroutine to it, so the cgo posix_spawn inherits
// the block UNLESS POSIX_SPAWN_SETSIGMASK clears it (the fix). Fails-before: with
// SETSID alone the child inherits the blocked SIGTERM, ignores it, and Wait hits
// its deadline (the wasted-grace bug on hardware); passes-after: it terminates.
func TestIntegrationSpawnResetsSignalMask(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	blockSIGTERMForTest()

	// /bin/sleep never touches its own signal mask, so it faithfully reflects the
	// mask it inherited from the spawn (a shell might reset signals and mask this).
	spec := SpawnSpec{Path: "/bin/sleep", Argv: []string{"/bin/sleep", "60"}, Env: os.Environ()}
	p := NewProcess(PosixSpawner{}, KqueueReaper{}, spec, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Graceful SIGTERM to the pod's process group (pid == pgid for a SETSID leader).
	if err := SignalGroup(p.PID(), os.Signal(unix.SIGTERM)); err != nil {
		t.Fatalf("SignalGroup: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	code, sig, err := p.Wait(waitCtx)
	if err != nil {
		t.Fatalf("child did not terminate on SIGTERM (inherited a blocked mask?): %v", err)
	}
	// Terminated by SIGTERM → signal 15, code 128+15.
	if sig != 15 || code != 143 {
		t.Errorf("after SIGTERM got (code=%d sig=%d), want (143,15)", code, sig)
	}
}
