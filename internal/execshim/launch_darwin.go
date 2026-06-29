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

import (
	"errors"
	"fmt"
	"os"

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
func (s *podLaunchSeam) Exec() error {
	if err := unix.Exec(s.argv[0], s.argv, os.Environ()); err != nil {
		return fmt.Errorf("execve %s: %w", s.argv[0], err)
	}
	return nil // unreachable on success
}

// RunPodLaunch becomes a confined, privilege-dropped pod process: it drops to
// cred (when cred.Drop), applies the SBPL profile, and execve's argv — in the
// SECURITY-CRITICAL order supervisor.RunLaunchSequence enforces
// (setgid→initgroups→setuid → sandbox_apply → exec). It returns only on error;
// a successful exec never returns. The ordering rationale lives at
// supervisor.RunLaunchSequence (the single source of truth, also unit-tested
// there with a recording seam).
func RunPodLaunch(profile string, argv []string, cred supervisor.Credential) error {
	if len(argv) == 0 {
		return errors.New("execshim: empty argv")
	}
	seam := &podLaunchSeam{profile: profile, argv: argv}
	// euid is the shim's own effective uid (== the daemon's). RunLaunchSequence
	// refuses a drop when it is non-root, so an unprivileged _k3sm daemon fails
	// closed rather than attempting a doomed setuid.
	_, err := supervisor.RunLaunchSequence(seam, cred, os.Geteuid())
	return err
}
