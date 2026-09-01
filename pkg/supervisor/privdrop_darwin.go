//go:build darwin

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
	"golang.org/x/sys/unix"
)

// UnixDropper performs the privilege-drop syscalls via golang.org/x/sys/unix
// (setgid / setgroups / setuid). These are not private SPI — they are standard
// POSIX calls — but they are process-wide and irreversible on Darwin, so
// UnixDropper is only ever used from the single-purpose exec-shim process (never
// the daemon). It is the production half of the supervisor.LaunchSeam drop steps;
// internal/execshim embeds it and adds SandboxApply (libsandbox) + Exec (execve).
//
// The zero value is usable.
type UnixDropper struct{}

// Setgid sets the process primary group id. Called while still root, before
// Setuid (after a setuid to non-root the gid can no longer be changed).
func (UnixDropper) Setgid(gid int) error { return unix.Setgid(gid) }

// Initgroups sets the supplemental group list. Darwin's x/sys/unix has no
// initgroups(3) binding, and k3sm pod uids are synthetic (no /etc/passwd entry,
// so initgroups-by-name would resolve nothing), so the group list — the primary
// gid plus the pod-level fsGroup — is set explicitly via setgroups while still
// privileged. An empty list is a no-op (the pod inherits no supplemental groups).
func (UnixDropper) Initgroups(groups []int) error {
	if len(groups) == 0 {
		return nil
	}
	return unix.Setgroups(groups)
}

// Setuid sets the process user id. Called last in the drop (after Setgid /
// Initgroups), since dropping the uid first would forfeit the privilege the group
// changes require.
func (UnixDropper) Setuid(uid int) error { return unix.Setuid(uid) }

// Setpriority applies one setpriority(2) call via golang.org/x/sys/unix. The
// launch sequence uses it only as Setpriority(PRIO_DARWIN_PROCESS, 0,
// PRIO_DARWIN_BG) — placing the calling (exec-shim) process in the darwin
// background band pre-exec so the pod image inherits it. setpriority(2) with the
// PRIO_DARWIN_* selectors is public API (<sys/resource.h>, see qos_darwin.go) —
// not private SPI — and lowering one's own priority needs no privilege, so it is
// safe after the uid drop.
func (UnixDropper) Setpriority(which, who, prio int) error {
	return unix.Setpriority(which, who, prio)
}

// Setrlimit applies one POSIX resource limit via setrlimit(2). Called from the
// exec-shim before the uid drop, while euid is still 0, so a hard-limit raise is
// permitted. setrlimit(2) is a standard POSIX call (not private SPI) but, like the
// drop, is process-global, so UnixDropper is only ever used from the exec-shim.
func (UnixDropper) Setrlimit(resource int, lim unix.Rlimit) error {
	return unix.Setrlimit(resource, &lim)
}

// Getrlimit reads the current limit for resource via getrlimit(2) — the inherited
// ceiling RunLaunchSequence clamps a denied hard-limit raise down to.
func (UnixDropper) Getrlimit(resource int) (unix.Rlimit, error) {
	var lim unix.Rlimit
	err := unix.Getrlimit(resource, &lim)
	return lim, err
}
