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

package sandbox

import (
	"context"

	"k3sm.io/runtimed/pkg/supervisor"
)

// Backend is the swappable pod-isolation seam: it turns a desired pod command
// (the pod binary + args) into a wrapped command that, when spawned, applies the
// pod's Seatbelt profile to itself and then becomes the pod process. The
// supervisor consumes this interface and is otherwise backend-agnostic — it
// posix_spawns whatever path/argv WrapCommand returns.
//
// Implementations MUST preserve the caller's environment when they exec the pod
// (notably DYLD_INSERT_LIBRARIES, the cross-repo DNS-shim enabler): the
// supervisor passes envp to posix_spawn, and the backend's exec must not strip
// it. This is why M1 uses an ad-hoc-signed exec-shim and NOT Apple's
// /usr/bin/sandbox-exec (a platform binary that strips DYLD_*).
//
// Backends are OS-version-gated and FAIL CLOSED: Available reports false when
// the host cannot support the backend, and the supervisor must then refuse to
// start the pod rather than running it unconfined.
type Backend interface {
	// Available reports whether this backend can confine pods on the host. A
	// false return means the runtime must refuse the pod (never fall through to
	// no isolation).
	Available() bool

	// WrapCommand validates profile (it must be fail-closed — see Validate),
	// persists it as needed, and returns the path + argv to spawn so that the
	// spawned process applies spec (the resolved supervisor.LaunchSpec: the
	// explicit rlimit plan, the securityContext identity drop, and the darwin
	// background-QoS decision), confines itself to profile, and then execs
	// argv[0]+argv[1:] as the pod process — in that irreversible order (see
	// supervisor.RunLaunchSequence). WrapCommand is the single spawn choke-point:
	// container starts AND exec sessions both come through it, so both carry the
	// pod's full launch posture. cleanup releases any backing resources (e.g. the
	// profile temp file) and must be called after the pod process has exited.
	WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (path string, args []string, cleanup func() error, err error)

	// Name identifies the backend for logging/diagnostics.
	Name() string
}
