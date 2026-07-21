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
	argv    []string
}

// SandboxApply confines the current process to the per-pod SBPL profile. After it
// returns nil the process is irreversibly sandboxed.
func (s *podLaunchSeam) SandboxApply() error { return confine(s.profile) }

// Exec replaces the process image with the pod binary, PRESERVING the inherited
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
func (s *podLaunchSeam) Exec() error {
	runtime.LockOSThread()
	if wasBlocked := C.k3smUnblockSignals(); wasBlocked != 0 {
		// Diagnostic: confirms the inherited-blocked-SIGTERM mechanism on hardware.
		fmt.Fprintln(os.Stderr, "k3sm-execshim: cleared a blocked signal mask before exec (SIGTERM was blocked)")
	}
	if err := unix.Exec(s.argv[0], s.argv, os.Environ()); err != nil {
		return fmt.Errorf("execve %s: %w", s.argv[0], err)
	}
	return nil // unreachable on success
}

// RunPodLaunch becomes a confined, privilege-dropped pod process: it applies
// spec's decoded rlimit plan, drops to spec.Cred (when Drop), backgrounds itself
// (when spec.BgQoS), applies the SBPL profile, and execve's argv — in the
// SECURITY-CRITICAL order supervisor.RunLaunchSequence enforces (setrlimit →
// setgid→initgroups→setuid → setpriority → sandbox_apply → exec). spec is the
// launch spec main() decoded from the shim argv (supervisor.ParseCredential /
// ParseRlimits / ParseQoS — a decode failure is fatal BEFORE this is reached, so
// the plan handed here is exactly what the daemon resolved). It returns only on
// error; a successful exec never returns. The ordering rationale lives at
// supervisor.RunLaunchSequence (the single source of truth, also unit-tested
// there with a recording seam).
func RunPodLaunch(profile string, argv []string, spec supervisor.LaunchSpec) error {
	if len(argv) == 0 {
		return errors.New("execshim: empty argv")
	}
	seam := &podLaunchSeam{profile: profile, argv: argv}
	// euid is the shim's own effective uid (== the daemon's). RunLaunchSequence
	// refuses a drop when it is non-root, so an unprivileged _k3sm daemon fails
	// closed rather than attempting a doomed setuid.
	_, err := supervisor.RunLaunchSequence(seam, spec, os.Geteuid())
	return err
}
