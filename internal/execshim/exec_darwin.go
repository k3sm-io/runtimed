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

	"k3sm.io/runtimed/pkg/supervisor"
)

// sessionSeam is the launch seam of an exec session a resident shim spawned: the
// container's seam with SandboxApply a no-op, because the session was forked by
// the confined shim and already runs under the shim profile — a second
// sandbox_apply fails on macOS, and the first cannot be undone.
type sessionSeam struct{ *podLaunchSeam }

// SandboxApply does nothing: the confinement is inherited (see sessionSeam).
func (sessionSeam) SandboxApply() error { return nil }

// RunExecSession is exec mode (supervisor.ShimModeExec): it applies the pod's
// rlimit plan and QoS band (the two launch-spec tokens) and execs argv marked
// pcontrol-KILL, preserving the environment. A bare command name is resolved
// on the session's own PATH (supervisor.ResolveExecPath) — the container's
// environment, which is also what an adopted shim holds — while argv[0] stays
// the name the caller sent, as execvp does. It never drops privilege — the
// resident shim already runs as the pod's credential — and applies no profile.
// Unlike the container's launch child, it sets the band from INSIDE the
// confinement, so the shim profile's self-only system-sched grant
// (sandbox.ShimProfile) is what admits the call; a refusal is the session's
// error. It returns only on error.
//
// It is reachable only as a confined exec session: it refuses to run unless
// this process is already sandboxed (requireConfined), because it keeps the
// environment it was started with, and outside a resident shim's confinement
// a library that environment names would load unconfined.
func RunExecSession(rlimits, qos string, argv []string) error {
	if err := requireConfined(selfSandboxed); err != nil {
		return err
	}
	if len(argv) == 0 {
		return errors.New("execshim: empty argv")
	}
	plan, err := supervisor.ParseRlimits(rlimits)
	if err != nil {
		return err
	}
	bg, err := supervisor.ParseQoS(qos)
	if err != nil {
		return err
	}
	// No daemon hand-off reaches an exec session: the session runs its
	// command as sent, with this process's environment (see the resident
	// shim's Exec for why exec mode, unlike launch mode, keeps one).
	path, execArgv, env := argv[0], argv, os.Environ()
	// A bare name (`kubectl cp` sends `tar`) is searched on the session's own
	// PATH; argv is untouched, so the program still sees the name it was given.
	path, err = supervisor.ResolveExecPath(path, os.Getenv("PATH"), os.Stat)
	if err != nil {
		return err
	}
	seam := sessionSeam{&podLaunchSeam{path: path, argv: execArgv, env: env}}
	_, err = supervisor.RunLaunchSequence(seam, supervisor.LaunchSpec{Rlimits: plan, BgQoS: bg}, os.Geteuid())
	return err
}

// errExecUnconfined refuses an exec session in a process no sandbox confines.
var errExecUnconfined = errors.New("execshim: exec mode runs only inside a resident shim's sandbox; this process is not sandboxed")

// requireConfined fails closed unless sandboxed reports this process already
// sandboxed: exec mode is forked by a resident shim after its sandbox_apply,
// and that is the only state in which its inherited environment is safe. A
// non-root uid is not accepted instead: in the shipped unprivileged posture
// the daemon itself is non-root, so the uid says nothing about confinement.
func requireConfined(sandboxed func() (bool, error)) error {
	ok, err := sandboxed()
	if err != nil {
		return fmt.Errorf("execshim: check the exec session's confinement: %w", err)
	}
	if !ok {
		return errExecUnconfined
	}
	return nil
}
