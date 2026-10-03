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
#include <Availability.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>

extern char **environ;

// posix_spawnattr_setpcontrol_np records the child's resource-starvation
// policy. PRIVATE SPI (XNU libsyscall spawn_private.h; no SDK prototype), per
// docs/GO-STANDARDS.md §Darwin/cgo, so only the function is declared here; its
// POSIX_SPAWN_PCONTROL_KILL argument comes from the public SDK <sys/spawn.h>.
// The symbol is canaried in internal/spicanary.
extern int posix_spawnattr_setpcontrol_np(posix_spawnattr_t *, const int);

// k3sm_spawn_addchdir is the posix_spawn file-action that gives the child its
// own working directory before exec. DARWIN SPI DISCIPLINE, per
// docs/GO-STANDARDS.md Â§Darwin/cgo: there is NO golang.org/x/sys/unix binding
// for a posix_spawn file action (unix exposes no posix_spawn at all), and the
// Go-level alternative — fork+chdir+exec via os/exec — is exactly what this
// supervisor rejected for pod spawns, because it gives up the single-kqueue
// reaper and the precise file-action fd control the two output pipes need. So
// cgo it is, isolated in this file behind the Spawner interface.
//
// two SPELLINGS, one MEANING, chosen by DEPLOYMENT TARGET so the build is
// warning-free on either:
//
//   - posix_spawn_file_actions_addchdir     â the POSIX-standard name, new in
//     macOS 26.0. Not declared at all by an older SDK.
//   - posix_spawn_file_actions_addchdir_np  â the Darwin/BSD extension it
//     replaced (macOS 10.15+), DEPRECATED as of macOS 26.0.
//
// The _np arm is the deprecated-SPI use the standards require documenting: it is
// a published, headered, non-private extension (unlike libsandbox or
// memorystatus), it is the only spelling that exists below macOS 26, and clang
// only warns about it when the deployment target is >= 26.0 — which is exactly
// when this macro selects the other one instead. Neither arm needs a symbol
// canary: both are declared in <spawn.h> and a missing one is a compile error,
// not a runtime surprise.
#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED >= 260000
#define k3sm_spawn_addchdir posix_spawn_file_actions_addchdir
#else
#define k3sm_spawn_addchdir posix_spawn_file_actions_addchdir_np
#endif

// k3sm_posix_spawn spawns argv[0] with argv/envp in its own session (and thus
// its own process group, since the session leader's pgid == its pid), chdir'ing
// into dir when dir is non-NULL and dup2'ing outFD onto the child's stdout(1)
// and errFD onto its stderr(2), each when the respective fd is >= 0. Returns 0
// and writes the pid to *outPid on success, or an errno.
//
// TWO fds, not one: the CRI log format labels every line stdout or stderr, and
// that label has to be established at the descriptor, because nothing
// downstream can recover it from a merged pipe.
//
// A dir that cannot be chdir'd into FAILS the SPAWN with that chdir's errno
// (ENOENT / ENOTDIR / EACCES) and no child survives it â posix_spawn evaluates
// file actions in the kernel and reports the first failure to the caller. There
// is no arm in which the child runs with the caller's cwd instead; the Go side
// (planSpawn) refuses an unusable dir before it gets here, and this is the
// TOCTOU backstop behind that refusal.
//
// POSIX_SPAWN_SETSID alone is used (not also POSIX_SPAWN_SETPGROUP): on macOS the
// two together return EPERM, because a freshly-created session leader cannot also
// be setpgid'd. SETSID already gives the pod a fresh process group led by the
// child (pgid == child pid), which is what DeletePod signals, and detaches it
// from the daemon's controlling tty.
//
// SETSIGMASK + SETSIGDEF reset the child's signal state, which is
// SECURITY/CORRECTNESS-critical for graceful termination. The supervisor is a Go
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
// output pipes without a fork+exec dance in Go.
//
// syncFD, when >= 0, is the exec-sync pipe's write end: it lands on the child's
// fd 3 (ExecSyncChildFD) AFTER the stdout/stderr dups and closes, so a stream fd
// that happened to be 3 has already been retired. When syncFD already IS 3 a
// dup2(3, 3) would be a no-op that leaves close-on-exec set (Go opens every
// descriptor O_CLOEXEC), so posix_spawn_file_actions_addinherit_np, the
// published Darwin extension that clears it for the child, is used instead.
//
// pcKill, when non-zero, marks the child POSIX_SPAWN_PCONTROL_KILL; what
// posix_spawnattr_setpcontrol_np returned is written to *setRC (0 when not
// called). A non-zero *setRC leaves the attribute unset and the spawn proceeds
// unmarked: this function executes the plan it is handed and decides nothing,
// the Go side owns the fail-soft policy (pcontrolRetry).
static int k3sm_posix_spawn(const char *path, char *const argv[], char *const envp[], const char *dir, int outFD, int errFD, int syncFD, int pcKill, int *setRC, pid_t *outPid) {
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

	// The pressure-kill mark. Private SPI (see the declaration above), canaried
	// in internal/spicanary. Why this lever and not the jetsam band:
	//   - memorystatus_control is EPERM for the unprivileged daemon user;
	//   - macOS (no CONFIG_JETSAM) never picks a victim by jetsam band 30-210;
	//   - the no-paging-space path picks the process with the most compressed
	//     pages among pcontrol-marked processes, and this attribute needs no
	//     root and no entitlement.
	// fork zeroes the mark (a pod's own children are unmarked), and so does a
	// plain execve (measured on macOS 26): the exec-shim therefore re-applies
	// it when it execs the pod binary (posix_spawn POSIX_SPAWN_SETEXEC with
	// this same attribute), and a process that execs further drops it.
	*setRC = 0;
	if (pcKill) {
		*setRC = posix_spawnattr_setpcontrol_np(&attr, POSIX_SPAWN_PCONTROL_KILL);
	}

	// The child's working directory. File actions run in order, and this one
	// touches no descriptor, so it is independent of the dup2s below; it is added
	// first only so the child is in its own directory for everything that follows.
	if (dir != NULL) {
		if ((rc = k3sm_spawn_addchdir(&fa, dir)) != 0) goto done;
	}

	// Each stream onto its own pipe, and the raw descriptor closed in the child
	// after its dup. The close is not housekeeping: without it the pod holds a
	// second, un-dup'd fd onto the pipe, so the parent's read never sees EOF
	// when the pod closes fd 1/2 — the log pump would hang for the life of the
	// process group instead of draining.
	if (outFD >= 0) {
		if ((rc = posix_spawn_file_actions_adddup2(&fa, outFD, 1)) != 0) goto done;
	}
	if (errFD >= 0) {
		if ((rc = posix_spawn_file_actions_adddup2(&fa, errFD, 2)) != 0) goto done;
	}
	if (outFD >= 0) {
		if ((rc = posix_spawn_file_actions_addclose(&fa, outFD)) != 0) goto done;
	}
	// Guard the aliased case: when both streams were handed the same fd (a
	// caller that wants them merged), the close above already retired it and a
	// second addclose would fail the spawn with EBADF.
	if (errFD >= 0 && errFD != outFD) {
		if ((rc = posix_spawn_file_actions_addclose(&fa, errFD)) != 0) goto done;
	}

	if (syncFD == 3) {
		if ((rc = posix_spawn_file_actions_addinherit_np(&fa, 3)) != 0) goto done;
	} else if (syncFD >= 0) {
		if ((rc = posix_spawn_file_actions_adddup2(&fa, syncFD, 3)) != 0) goto done;
		if ((rc = posix_spawn_file_actions_addclose(&fa, syncFD)) != 0) goto done;
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
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// syscallErrno converts a C errno (returned by posix_spawn) to a Go error.
func syscallErrno(rc C.int) error {
	return unix.Errno(int(rc))
}

// PosixSpawner is the production Spawner: raw posix_spawn into a new session +
// process group, with one pipe dup2'd onto each of the child's stdout/stderr.
// The zero value is usable.
type PosixSpawner struct {
	// PressureKill marks every child pcontrol-KILL (POSIX_SPAWN_PCONTROL_KILL):
	// when the system runs out of paging space the kernel kills the largest
	// marked process before it considers an unmarked one. Pod spawners set it
	// so a pod, not a control-plane process, is the memory-exhaustion victim.
	// The mark is fail-soft: a spawn that cannot carry it runs unmarked (one
	// Warn, UnmarkedSpawns increments) rather than failing the pod.
	// It orders victims under paging-space exhaustion; it is NOT an isolation
	// control — a pod can clear its own mark, re-exec, or fork unmarked
	// children. VerifyPressureKill proves this spawn attribute only; a child
	// that execs (the exec-shim) keeps the mark only because the shim re-applies
	// it at its exec, which the startup self-check does not cover.
	PressureKill bool
}

// Spawn posix_spawns spec into its own process group and returns the child pid.
// It passes spec.Env verbatim (so DYLD_INSERT_LIBRARIES flows through to the
// pod), gives the child spec.Dir as its working directory, and wires
// spec.StdoutFD and spec.StderrFD as the child's fd 1 and fd 2.
//
// spec.Dir is honored through a posix_spawn chdir file action, never by chdir'ing
// the daemon: this process is shared by every pod, so a parent-side chdir would
// be a data race with every other spawn in flight. An unusable Dir fails the
// spawn with ErrWorkingDir (planSpawn) and starts nothing.
//
// With PressureKill the child is marked pcontrol-KILL. A kernel that rejects the
// attribute fails the spawn with EINVAL; that spawn is retried once unmarked
// (pcontrolRetry), and when the retry fails too the first error is returned.
func (s PosixSpawner) Spawn(ctx context.Context, spec SpawnSpec) (int, error) {
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

	// Resolve (and refuse) the working directory before any allocation: an
	// unusable Dir must fail typed, never fall back to the daemon's cwd.
	plan, err := planSpawn(spec, s.PressureKill)
	if err != nil {
		return 0, err
	}
	var cDir *C.char
	if plan.ChangeDir != "" {
		cDir = C.CString(plan.ChangeDir)
		defer C.free(unsafe.Pointer(cDir))
	}

	outFD, errFD := C.int(-1), C.int(-1)
	if spec.StdoutFD != 0 {
		outFD = C.int(spec.StdoutFD)
	}
	if spec.StderrFD != 0 {
		errFD = C.int(spec.StderrFD)
	}

	syncFD := C.int(-1)
	if spec.ExecSyncFD != 0 {
		syncFD = C.int(spec.ExecSyncFD)
	}

	spawn := func(p spawnPlan) (int, int, error) {
		pcKill := C.int(0)
		if p.PControl == pcontrolKill {
			pcKill = 1
		}
		var pid C.pid_t
		var setRC C.int
		rc := C.k3sm_posix_spawn(cPath, argvArr.ptr, envp, cDir, outFD, errFD, syncFD, pcKill, &setRC, &pid)
		if rc != 0 {
			return 0, int(setRC), syscallErrno(rc)
		}
		return int(pid), int(setRC), nil
	}

	pid, setRC, spawnErr := spawn(plan)
	if spawnErr != nil {
		retry, ok := pcontrolRetry(plan, setRC, spawnErr)
		if !ok {
			return 0, fmt.Errorf("posix_spawn %s: %w", spec.Path, spawnErr)
		}
		pid, _, retryErr := spawn(retry)
		if retryErr != nil {
			// The first error is the one that names why the marked spawn failed;
			// the retry only proves the mark was not the whole story.
			return 0, fmt.Errorf("posix_spawn %s: %w", spec.Path, spawnErr)
		}
		var errno unix.Errno
		_ = errors.As(spawnErr, &errno)
		noteUnmarkedSpawn(spec.Path, "posix_spawn rejected the pcontrol attribute; retried unmarked", int(errno))
		return pid, nil
	}
	if plan.PControl == pcontrolKill && setRC != 0 {
		noteUnmarkedSpawn(spec.Path, "posix_spawnattr_setpcontrol_np failed", setRC)
	}
	return pid, nil
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
