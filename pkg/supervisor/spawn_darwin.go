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

/*
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>

extern char **environ;

// k3sm_posix_spawn spawns argv[0] with argv/envp in its OWN session (and thus
// its own process group, since the session leader's pgid == its pid), dup2'ing
// logFD onto the child's stdout(1) and stderr(2) when logFD >= 0. Returns 0 and
// writes the pid to *outPid on success, or an errno.
//
// POSIX_SPAWN_SETSID alone is used (NOT also POSIX_SPAWN_SETPGROUP): on macOS the
// two together return EPERM, because a freshly-created session leader cannot also
// be setpgid'd. SETSID already gives the pod a fresh process group led by the
// child (pgid == child pid), which is what DeletePod signals, and detaches it
// from the daemon's controlling tty.
//
// SETSIGMASK + SETSIGDEF reset the child's signal STATE, which is
// SECURITY/CORRECTNESS-CRITICAL for graceful termination. The supervisor is a Go
// process, and the Go runtime BLOCKS most signals on its worker threads; a raw
// posix_spawn (unlike os/exec, which resets it) leaves the child with the CALLING
// THREAD's signal mask, and execve PRESERVES a blocked mask. Without SETSIGMASK a
// pod inherits a BLOCKED SIGTERM, silently ignores k8s graceful termination, and
// runs to the SIGKILL deadline (terminationGracePeriodSeconds wasted every time).
// SETSIGDEF additionally restores the default disposition for every signal so an
// inherited SIG_IGN (e.g. Go's default-ignored SIGPIPE) does not leak into the
// pod. Probe-verified on macOS 26.5.1: a blocked-SIGTERM parent + SETSID-only →
// child survives SIGTERM; adding SETSIGMASK(empty) → child terminates on SIGTERM.
//
// Raw posix_spawn (not os/exec) is deliberate: the supervisor owns a single
// reaper (kqueue), and posix_spawn_file_actions gives precise fd control for the
// combined-log pipe without a fork+exec dance in Go.
static int k3sm_posix_spawn(const char *path, char *const argv[], char *const envp[], int logFD, pid_t *outPid) {
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t fa;
	int rc;

	if ((rc = posix_spawnattr_init(&attr)) != 0) return rc;
	if ((rc = posix_spawn_file_actions_init(&fa)) != 0) {
		posix_spawnattr_destroy(&attr);
		return rc;
	}

	// Reset the child's signal mask (unblock everything) and dispositions (all
	// default) so a pod does not inherit the Go runtime's blocked/ignored signals
	// — otherwise a blocked SIGTERM makes graceful termination a no-op.
	sigset_t emptyMask, allSignals;
	sigemptyset(&emptyMask);
	sigfillset(&allSignals);
	posix_spawnattr_setsigmask(&attr, &emptyMask);
	posix_spawnattr_setsigdefault(&attr, &allSignals);

	short flags = POSIX_SPAWN_SETSID | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
	posix_spawnattr_setflags(&attr, flags);

	if (logFD >= 0) {
		// Combined log: child's fd 1 and fd 2 both go to logFD.
		if ((rc = posix_spawn_file_actions_adddup2(&fa, logFD, 1)) != 0) goto done;
		if ((rc = posix_spawn_file_actions_adddup2(&fa, logFD, 2)) != 0) goto done;
		// Close the original logFD in the child after the dups.
		if ((rc = posix_spawn_file_actions_addclose(&fa, logFD)) != 0) goto done;
	}

	rc = posix_spawn(outPid, path, &fa, &attr, argv, envp ? envp : environ);

done:
	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&attr);
	return rc;
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// syscallErrno converts a C errno (returned by posix_spawn) to a Go error.
func syscallErrno(rc C.int) error {
	return unix.Errno(int(rc))
}

// PosixSpawner is the production Spawner: raw posix_spawn into a new session +
// process group, with the combined-log fd dup2'd onto the child's stdout/stderr.
// The zero value is usable.
type PosixSpawner struct{}

// Spawn posix_spawns spec into its own process group and returns the child pid.
// It passes spec.Env verbatim (so DYLD_INSERT_LIBRARIES flows through to the
// pod) and wires spec.LogFD as the child's combined stdout+stderr.
func (PosixSpawner) Spawn(ctx context.Context, spec SpawnSpec) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if spec.Path == "" || len(spec.Argv) == 0 {
		return 0, fmt.Errorf("supervisor: spawn needs path and argv")
	}

	cPath := C.CString(spec.Path)
	defer C.free(unsafe.Pointer(cPath))

	argvArr := newCStringArray(spec.Argv)
	defer argvArr.free()

	var envp **C.char
	if spec.Env != nil {
		envArr := newCStringArray(spec.Env)
		defer envArr.free()
		envp = envArr.ptr
	}

	logFD := C.int(-1)
	if spec.LogFD != 0 {
		logFD = C.int(spec.LogFD)
	}

	var pid C.pid_t
	rc := C.k3sm_posix_spawn(cPath, argvArr.ptr, envp, logFD, &pid)
	if rc != 0 {
		return 0, fmt.Errorf("posix_spawn %s: %w", spec.Path, syscallErrno(rc))
	}
	return int(pid), nil
}

// cStringArray is a NULL-terminated C string vector (char **) plus the element
// count, so it can be freed without unsafe pointer walking.
type cStringArray struct {
	ptr **C.char
	n   int // number of non-NULL elements (the slot at index n is the NULL term)
}

// newCStringArray builds a NULL-terminated char ** from ss.
func newCStringArray(ss []string) cStringArray {
	// +1 for the NULL terminator.
	block := C.calloc(C.size_t(len(ss)+1), C.size_t(unsafe.Sizeof(uintptr(0))))
	view := unsafe.Slice((**C.char)(block), len(ss)+1)
	for i, s := range ss {
		view[i] = C.CString(s)
	}
	view[len(ss)] = nil
	return cStringArray{ptr: (**C.char)(block), n: len(ss)}
}

// free releases the vector and every string in it.
func (a cStringArray) free() {
	if a.ptr == nil {
		return
	}
	view := unsafe.Slice(a.ptr, a.n+1)
	for i := 0; i < a.n; i++ {
		C.free(unsafe.Pointer(view[i]))
	}
	C.free(unsafe.Pointer(a.ptr))
}
