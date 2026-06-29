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
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Credential is the POSIX identity a pod process drops to before its Seatbelt
// profile is applied and the pod binary is exec'd (M2.3 securityContext).
//
// The drop is performed in the exec-shim — a fresh, single-purpose process the
// supervisor posix_spawns — and NEVER in the multi-threaded daemon: setgid /
// setuid are process-wide and irreversible, so they must run in a process that
// does nothing afterwards except apply the sandbox and execve the pod.
//
// Drop reports whether a drop is requested at all. It is a separate bool because
// the proto's int64 run_as_* fields cannot distinguish "unset" from 0 (0 == root,
// which is also a no-op for a root daemon); the provider resolves the effective
// identity and sets Drop only for a non-root target. A drop REQUIRES root —
// setuid/setgid to another identity is privileged — so on the unprivileged _k3sm
// daemon Drop MUST be false (Validate enforces this). When Drop is false the pod
// runs at the daemon's OWN uid confined by Seatbelt: on today's user-space daemon
// that is _k3sm-in-Seatbelt, NOT root. There is no per-pod uid isolation in this
// posture (the documented residual limitation — untrusted tenancy routes to the
// vm backend).
type Credential struct {
	// UID is the target user id (effective uid after the drop).
	UID int
	// GID is the target primary group id (effective gid after the drop).
	GID int
	// Groups is the supplemental group set (the "initgroups" list), including the
	// pod-level fsGroup, applied while still privileged so a dropped pod retains
	// group access to its fsGroup-owned volumes.
	Groups []int
	// Drop requests the privilege drop. When false, UID/GID/Groups are ignored
	// and the pod keeps the daemon's own (unprivileged _k3sm) identity. A true
	// Drop requires the daemon to be root (Validate); the default posture is
	// false.
	Drop bool
}

// ErrDropRequiresRoot reports a requested privilege drop (Credential.Drop) on a
// non-root process. setuid/setgid to another identity is privileged, so a drop
// is only possible as root (euid 0). On the unprivileged _k3sm daemon Drop MUST
// be false — the supervisor runs pods at its own uid, confined by Seatbelt —
// rather than silently leaving a pod at the wrong identity or attempting a
// setuid that can only fail.
var ErrDropRequiresRoot = errors.New("supervisor: credential drop requires root")

// Validate checks c against euid, the effective uid the drop would run under
// (the exec-shim's euid, == the daemon's). A drop (Drop=true) requires root
// (euid 0); on a non-root process it returns ErrDropRequiresRoot rather than
// attempting a doomed setuid. A non-drop credential (Drop=false) is always valid:
// the pod keeps the daemon's own (unprivileged _k3sm) identity, confined by
// Seatbelt. RunLaunchSequence calls this first, so the invariant is enforced
// fail-closed before any irreversible step.
func (c Credential) Validate(euid int) error {
	if c.Drop && euid != 0 {
		return fmt.Errorf("%w: euid=%d", ErrDropRequiresRoot, euid)
	}
	return nil
}

// noDropSentinel is the uid/gid argv token meaning "no privilege drop". It is
// distinct from any real id (ids are non-negative), so it round-trips a Drop
// decision through the exec-shim argv without an extra flag.
const noDropSentinel = "-1"

// emptyGroupsSentinel is the groups argv token meaning "no supplemental groups".
const emptyGroupsSentinel = "-"

// ShimArgs encodes the credential as the three leading positional arguments the
// k3sm-execshim helper expects: <uid> <gid> <groups-csv>. A non-Drop credential
// encodes as the sentinels ("-1" "-1" "-"). ParseCredential is the inverse.
func (c Credential) ShimArgs() []string {
	if !c.Drop {
		return []string{noDropSentinel, noDropSentinel, emptyGroupsSentinel}
	}
	groups := emptyGroupsSentinel
	if len(c.Groups) > 0 {
		parts := make([]string, len(c.Groups))
		for i, g := range c.Groups {
			parts[i] = strconv.Itoa(g)
		}
		groups = strings.Join(parts, ",")
	}
	return []string{strconv.Itoa(c.UID), strconv.Itoa(c.GID), groups}
}

// ParseCredential decodes the three leading exec-shim arguments produced by
// ShimArgs back into a Credential. The sentinel pair ("-1","-1") decodes to a
// non-Drop credential; otherwise uid/gid are parsed and groupsArg is a CSV of
// supplemental gids ("-" / "" means none).
func ParseCredential(uidArg, gidArg, groupsArg string) (Credential, error) {
	if uidArg == noDropSentinel && gidArg == noDropSentinel {
		return Credential{Drop: false}, nil
	}
	uid, err := strconv.Atoi(uidArg)
	if err != nil {
		return Credential{}, fmt.Errorf("parse uid %q: %w", uidArg, err)
	}
	gid, err := strconv.Atoi(gidArg)
	if err != nil {
		return Credential{}, fmt.Errorf("parse gid %q: %w", gidArg, err)
	}
	var groups []int
	if groupsArg != "" && groupsArg != emptyGroupsSentinel {
		for _, part := range strings.Split(groupsArg, ",") {
			g, err := strconv.Atoi(part)
			if err != nil {
				return Credential{}, fmt.Errorf("parse supplemental group %q: %w", part, err)
			}
			groups = append(groups, g)
		}
	}
	return Credential{UID: uid, GID: gid, Groups: groups, Drop: true}, nil
}

// LaunchStep names one step of the privilege-drop → confine → exec sequence
// RunLaunchSequence performs, in the mandated order. It exists so the ordering is
// assertable by a recording LaunchSeam in a unit test (no real privilege change).
type LaunchStep int

const (
	// StepSetgid sets the primary gid (must precede StepSetuid).
	StepSetgid LaunchStep = iota
	// StepInitgroups sets the supplemental group list (incl. fsGroup).
	StepInitgroups
	// StepSetuid sets the uid (must follow StepSetgid/StepInitgroups).
	StepSetuid
	// StepSandboxApply applies the irreversible Seatbelt profile.
	StepSandboxApply
	// StepExec execve's the pod binary (replaces the process image).
	StepExec
)

// String renders the LaunchStep for diagnostics/tests.
func (s LaunchStep) String() string {
	switch s {
	case StepSetgid:
		return "setgid"
	case StepInitgroups:
		return "initgroups"
	case StepSetuid:
		return "setuid"
	case StepSandboxApply:
		return "sandbox_apply"
	case StepExec:
		return "exec"
	default:
		return "unknown"
	}
}

// LaunchSeam is the ordered set of irreversible operations the exec-shim performs
// to become a confined, privilege-dropped pod process. It is a seam (consumer-
// side interface) so RunLaunchSequence's ordering can be unit-tested with a fake
// that records calls and performs no real syscall; the production implementation
// lives in internal/execshim (drop via golang.org/x/sys/unix, SandboxApply via
// libsandbox cgo, Exec via execve).
type LaunchSeam interface {
	// Setgid sets the process primary group id.
	Setgid(gid int) error
	// Initgroups sets the supplemental group list (the initgroups equivalent).
	Initgroups(groups []int) error
	// Setuid sets the process user id.
	Setuid(uid int) error
	// SandboxApply applies the per-pod Seatbelt profile to the current process,
	// irreversibly.
	SandboxApply() error
	// Exec replaces the process image with the pod binary; it returns only on
	// error (a successful exec never returns).
	Exec() error
}

// RunLaunchSequence drives seam through the SECURITY-CRITICAL, irreversible pod
// launch order (M2.3). euid is the effective uid the sequence runs under (the
// exec-shim's, == the daemon's); it gates the drop. The ordering is load-bearing
// — getting it wrong silently runs the pod with the wrong identity or unconfined:
//
//		when cred.Drop:  Setgid(gid) → Initgroups(groups) → Setuid(uid)
//		always:          SandboxApply → Exec
//
//	  - a drop is refused up front when euid != 0 (cred.Validate): setuid/setgid
//	    to another identity needs root, so on the unprivileged _k3sm daemon Drop
//	    must be false and the pod runs at the daemon's own uid in Seatbelt;
//	  - setgid BEFORE setuid: after setuid drops to a non-root uid the process can
//	    no longer change its gid, so the gid must be set while still privileged;
//	  - initgroups (supplemental groups, incl. fsGroup) BETWEEN them — also a
//	    privileged operation;
//	  - the whole drop BEFORE SandboxApply: the Seatbelt sandbox is IRREVERSIBLE
//	    and a sandboxed (and uid-dropped) process can neither setuid nor chown, so
//	    the drop and any root-side setup must complete first;
//	  - SandboxApply BEFORE Exec: the pod binary must start already confined.
//
// It returns the steps executed (for assertions) and stops at the FIRST error —
// fail-closed: a refused/failed drop or failed sandbox apply means Exec is never
// reached, so the pod never runs with the wrong credential or outside the
// sandbox.
func RunLaunchSequence(seam LaunchSeam, cred Credential, euid int) ([]LaunchStep, error) {
	var done []LaunchStep
	if err := cred.Validate(euid); err != nil {
		return done, err
	}
	if cred.Drop {
		if err := seam.Setgid(cred.GID); err != nil {
			return done, fmt.Errorf("setgid(%d): %w", cred.GID, err)
		}
		done = append(done, StepSetgid)
		if err := seam.Initgroups(cred.Groups); err != nil {
			return done, fmt.Errorf("initgroups %v: %w", cred.Groups, err)
		}
		done = append(done, StepInitgroups)
		if err := seam.Setuid(cred.UID); err != nil {
			return done, fmt.Errorf("setuid(%d): %w", cred.UID, err)
		}
		done = append(done, StepSetuid)
	}
	if err := seam.SandboxApply(); err != nil {
		return done, fmt.Errorf("sandbox apply: %w", err)
	}
	done = append(done, StepSandboxApply)
	if err := seam.Exec(); err != nil {
		return done, fmt.Errorf("exec pod: %w", err)
	}
	done = append(done, StepExec) // unreachable on success: exec replaced the image
	return done, nil
}
