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

package execshim

/*
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>

// posix_spawnattr_setpcontrol_np: PRIVATE spawn SPI (XNU spawn_private.h, no
// SDK prototype), per docs/GO-STANDARDS.md §Darwin/cgo; the same declaration as
// pkg/supervisor/spawn_darwin.go, canaried in internal/spicanary. Its
// POSIX_SPAWN_PCONTROL_KILL argument is the public SDK <sys/spawn.h> value.
extern int posix_spawnattr_setpcontrol_np(posix_spawnattr_t *, const int);

// k3smExecMarked replaces this process image with path, like execve, but
// through posix_spawn(POSIX_SPAWN_SETEXEC) so the new image can carry
// POSIX_SPAWN_PCONTROL_KILL. A plain execve CLEARS the pcontrol mark (measured
// on macOS 26: a process marked at spawn, or by proc_setpcontrol on itself, is
// unmarked after execve), while a SETEXEC spawn applies its attribute to the
// image it activates. SETSIGMASK with an empty set gives the pod the same
// unblocked mask k3smUnblockSignals gives a plain execve.
//
// It returns only on failure, with the errno. *setRC reports what
// posix_spawnattr_setpcontrol_np returned; a non-zero value means the attribute
// was not set and nothing was exec'd.
static int k3smExecMarked(const char *path, char *const argv[], char *const envp[], int *setRC) {
	posix_spawnattr_t attr;
	int rc;
	*setRC = 0;
	if ((rc = posix_spawnattr_init(&attr)) != 0) return rc;
	sigset_t empty;
	sigemptyset(&empty);
	if ((rc = posix_spawnattr_setsigmask(&attr, &empty)) != 0) goto out;
	if ((rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_SETSIGMASK)) != 0) goto out;
	if ((*setRC = posix_spawnattr_setpcontrol_np(&attr, POSIX_SPAWN_PCONTROL_KILL)) != 0) {
		rc = *setRC;
		goto out;
	}
	rc = posix_spawn(NULL, path, NULL, &attr, argv, envp);
out:
	posix_spawnattr_destroy(&attr);
	return rc;
}

// k3smUnblockSignals clears the CALLING thread's signal mask (unblocks every
// signal) and reports whether SIGTERM had been blocked. execve preserves the
// thread's mask, and this Go process (the exec-shim) runs after cgo/syscall work
// during which the Go runtime blocks signals on the worker thread — so without
// this a workload inherits a BLOCKED SIGTERM and cannot honor graceful
// termination (a trap never fires; the default terminate action never runs).
static int k3smUnblockSignals(void) {
	sigset_t cur, empty;
	int wasBlocked = 0;
	if (pthread_sigmask(SIG_SETMASK, (const sigset_t *)0, &cur) == 0) {
		wasBlocked = sigismember(&cur, SIGTERM);
	}
	sigemptyset(&empty);
	pthread_sigmask(SIG_SETMASK, &empty, (sigset_t *)0);
	return wasBlocked;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"
)

// podLaunchSeam is the production supervisor.LaunchSeam. It embeds the supervisor
// UnixDropper for the three drop steps (setgid / initgroups / setuid via
// golang.org/x/sys/unix) and adds the two exec-shim-local steps: SandboxApply
// (apply the SBPL via libsandbox, irreversible) and Exec (execve the pod binary,
// preserving the environment). supervisor.RunLaunchSequence drives them in the
// mandated order.
type podLaunchSeam struct {
	supervisor.UnixDropper
	profile string
	// path is the file execve'd; argv is what the pod sees. They differ only
	// when the daemon handed an argv[0] override (supervisor.ExecArgv0Env).
	path string
	argv []string
}

// SandboxApply confines the current process to the per-pod SBPL profile. After it
// returns nil the process is irreversibly sandboxed.
func (s *podLaunchSeam) SandboxApply() error { return confine(s.profile) }

// Exec replaces the process image with the pod binary, preserving the inherited
// environment (so DYLD_INSERT_LIBRARIES survives into the pod). It returns only
// on error.
//
// It first clears the thread's signal mask so the pod does not inherit a BLOCKED
// signal (esp. SIGTERM): execve preserves the calling thread's mask, and by this
// point the Go runtime has blocked signals on the worker thread the exec runs on
// (a pod could not honor terminationGracePeriodSeconds — its SIGTERM trap never
// fired, and it ran to the SIGKILL deadline). LockOSThread pins the goroutine so
// the mask we clear is the one execve inherits. os/exec does this reset for a
// fork+exec; a raw execve must do it explicitly.
//
// The exec also marks the pod pcontrol-KILL, so that when the system runs out of
// paging space the kernel kills a pod before it considers an unmarked
// control-plane process. A plain execve clears that mark, whatever the shim
// carried in from its own spawn, so the image is activated by
// posix_spawn(POSIX_SPAWN_SETEXEC) with the attribute (k3smExecMarked). This
// covers both ways a pod process starts: a container (the shim was spawned
// marked, and the mark would not survive execve) and an exec session (the shim
// was started by fork+exec, which clears it anyway).
//
// The mark orders victims under paging-space exhaustion; it is NOT an isolation
// control — a pod can clear its own mark, re-exec, or fork unmarked children.
//
// It is a preference, never a gate: when the marked exec fails, the plain execve
// below runs and the pod starts unmarked, or fails with the error execve
// reports. That fallback is not reported per pod (the shim's stderr is the
// pod's log, so nothing is printed). The daemon's startup self-check proves only
// the spawn-attribute path, not this exec-time mark; the exec-time mark is
// proven by the integration test of the real shim chain.
//
// A path, argv or env element holding a NUL byte skips the marked exec: C
// strings would silently truncate it, while unix.Exec refuses it with EINVAL
// exactly as before.
func (s *podLaunchSeam) Exec() error {
	runtime.LockOSThread()
	if wasBlocked := C.k3smUnblockSignals(); wasBlocked != 0 {
		// Diagnostic: confirms the inherited-blocked-SIGTERM mechanism on hardware.
		fmt.Fprintln(os.Stderr, "k3sm-execshim: cleared a blocked signal mask before exec (SIGTERM was blocked)")
	}
	env := os.Environ()
	if !hasNUL(s.path, s.argv, env) {
		_ = execMarked(s.path, s.argv, env) // returns only on failure; fall back below
	}
	if err := unix.Exec(s.path, s.argv, env); err != nil {
		return fmt.Errorf("execve %s: %w", s.path, err)
	}
	return nil // unreachable on success
}

// execMarked is the Go side of k3smExecMarked: it returns only when the marked
// exec did not happen.
func execMarked(path string, argv, env []string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cArgv := cStrings(argv)
	defer freeCStrings(cArgv)
	cEnv := cStrings(env)
	defer freeCStrings(cEnv)
	var setRC C.int
	rc := C.k3smExecMarked(cPath, &cArgv[0], &cEnv[0], &setRC)
	if setRC != 0 {
		return fmt.Errorf("posix_spawnattr_setpcontrol_np: %w", unix.Errno(setRC))
	}
	return fmt.Errorf("posix_spawn SETEXEC %s: %w", path, unix.Errno(rc))
}

// cStrings returns ss as a NULL-terminated vector of C strings allocated in C
// memory (cgo forbids passing Go memory that holds Go pointers).
func cStrings(ss []string) []*C.char {
	out := make([]*C.char, len(ss)+1)
	for i, s := range ss {
		out[i] = C.CString(s)
	}
	return out
}

// freeCStrings frees every string cStrings allocated.
func freeCStrings(v []*C.char) {
	for _, p := range v {
		if p != nil {
			C.free(unsafe.Pointer(p))
		}
	}
}

// RunPodLaunch becomes a confined, privilege-dropped pod process: it applies
// spec's decoded rlimit plan, drops to spec.Cred (when Drop), backgrounds itself
// (when spec.BgQoS), applies the SBPL profile, and execve's argv — in the
// SECURITY-critical order supervisor.RunLaunchSequence enforces (setrlimit →
// setgid→initgroups→setuid → setpriority → sandbox_apply → exec). The exec
// marks the pod pcontrol-KILL (see podLaunchSeam.Exec). spec is the
// launch spec main() decoded from the shim argv (supervisor.ParseCredential /
// ParseRlimits / ParseQoS — a decode failure is fatal before this is reached, so
// the plan handed here is exactly what the daemon resolved). It returns only on
// error; a successful exec never returns. The ordering rationale lives at
// supervisor.RunLaunchSequence (the single source of truth, also unit-tested
// there with a recording seam).
func RunPodLaunch(profile string, argv []string, spec supervisor.LaunchSpec) error {
	if len(argv) == 0 {
		return errors.New("execshim: empty argv")
	}
	path, execArgv := takeExecHandoff(argv)
	seam := &podLaunchSeam{profile: profile, path: path, argv: execArgv}
	// euid is the shim's own effective uid (== the daemon's). RunLaunchSequence
	// refuses a drop when it is non-root, so an unprivileged _k3sm daemon fails
	// closed rather than attempting a doomed setuid.
	_, err := supervisor.RunLaunchSequence(seam, spec, os.Geteuid())
	return err
}

// takeExecHandoff consumes the two daemon-to-shim environment hand-offs and
// removes both variables, so the pod's environment never carries them. It
// returns the file to exec (always argv[0], as the daemon resolved it) and the
// argv the pod sees.
//
//   - supervisor.ExecSyncFDEnv names the inherited exec-sync descriptor; it is
//     marked close-on-exec so the daemon's read end sees EOF exactly when the
//     pod binary replaces this process (supervisor.Process.ObserveExec). Only
//     the agreed descriptor number is honoured: a mismatched value is ignored
//     rather than closing some other inherited descriptor.
//   - supervisor.ExecArgv0Env replaces argv[0] (a re-signed shell copy run as
//     "sh"). An empty value is ignored.
func takeExecHandoff(argv []string) (string, []string) {
	if v, ok := os.LookupEnv(supervisor.ExecSyncFDEnv); ok {
		_ = os.Unsetenv(supervisor.ExecSyncFDEnv)
		if fd, err := strconv.Atoi(v); err == nil && fd == supervisor.ExecSyncChildFD {
			unix.CloseOnExec(fd)
		}
	}
	execArgv := argv
	if v, ok := os.LookupEnv(supervisor.ExecArgv0Env); ok {
		_ = os.Unsetenv(supervisor.ExecArgv0Env)
		if v != "" {
			execArgv = append([]string{v}, argv[1:]...)
		}
	}
	return argv[0], execArgv
}
