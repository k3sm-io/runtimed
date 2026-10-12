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
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSpawnChildKeepsOnlyDeclaredDescriptors pins POSIX_SPAWN_CLOEXEC_DEFAULT
// in the cgo spawner. Go marks a new pipe close-on-exec with a separate fcntl
// after pipe(2), under syscall.ForkLock, which the cgo posix_spawn does not
// take, so a spawn racing that window would inherit another spawn's pipe end
// (its launch payload above all). The window is not reproducible on demand,
// so the test opens its state deliberately: a descriptor WITHOUT
// close-on-exec, standing in for a payload pipe's write end caught between
// pipe(2) and the fcntl. The child must not hold it, and must hold exactly the
// descriptors the spawn declares: 0-2, the exec-sync fd 3 and the payload fd 4.
func TestSpawnChildKeepsOnlyDeclaredDescriptors(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pr.Close(), pw.Close() }()
	// F_DUPFD (not F_DUPFD_CLOEXEC): the copy is inheritable, as a freshly
	// made pipe end is until Go's fcntl runs.
	leaked, err := unix.FcntlInt(pw.Fd(), unix.F_DUPFD, 40)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(leaked) }()
	if flags, err := unix.FcntlInt(uintptr(leaked), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("the stand-in descriptor is close-on-exec (flags %#x, %v); the test would prove nothing", flags, err)
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outR.Close() }()
	syncR, syncW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syncR.Close() }()

	probe := []int{0, 1, 2, 3, 4, leaked}
	var script strings.Builder
	for _, fd := range probe {
		n := strconv.Itoa(fd)
		script.WriteString("[ -e /dev/fd/" + n + " ] && echo " + n + "; ")
	}
	script.WriteString("true")
	pid, err := PosixSpawner{}.Spawn(context.Background(), SpawnSpec{
		Path:       "/bin/sh",
		Argv:       []string{"/bin/sh", "-c", script.String()},
		Launch:     &LaunchPayload{Env: []string{"A=b"}},
		StdoutFD:   outW.Fd(),
		ExecSyncFD: syncW.Fd(),
	})
	_, _ = outW.Close(), syncW.Close()
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := io.ReadAll(outR)
	_, _, _ = KqueueReaper{}.WaitExit(ctx, pid)

	var held []int
	for _, f := range strings.Fields(string(out)) {
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("child output %q", out)
		}
		held = append(held, n)
	}
	if slices.Contains(held, leaked) {
		t.Errorf("the child holds the parent's inheritable descriptor %d: CLOEXEC_DEFAULT is not in force", leaked)
	}
	for _, want := range []int{1, 3, 4} {
		if !slices.Contains(held, want) {
			t.Errorf("the child lacks declared descriptor %d (holds %v)", want, held)
		}
	}
	if isOpen(0) && !slices.Contains(held, 0) {
		t.Errorf("the child lost this process's stdin (holds %v)", held)
	}
	if isOpen(2) && !slices.Contains(held, 2) {
		t.Errorf("the child lost this process's stderr (holds %v)", held)
	}
}

// isOpen reports whether descriptor fd is open in this process.
func isOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}
