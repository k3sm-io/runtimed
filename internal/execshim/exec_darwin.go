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
// It is reachable as a confined exec session only through a resident shim; a
// caller that runs it directly gets an unconfined process, which that caller
// could have started without it.
func RunExecSession(rlimits, qos string, argv []string) error {
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
	path, execArgv := takeExecHandoff(argv)
	// A bare name (`kubectl cp` sends `tar`) is searched on the session's own
	// PATH; argv is untouched, so the program still sees the name it was given.
	path, err = supervisor.ResolveExecPath(path, os.Getenv("PATH"), os.Stat)
	if err != nil {
		return err
	}
	seam := sessionSeam{&podLaunchSeam{path: path, argv: execArgv}}
	_, err = supervisor.RunLaunchSequence(seam, supervisor.LaunchSpec{Rlimits: plan, BgQoS: bg}, os.Geteuid())
	return err
}
