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
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Credential is the POSIX identity a pod process drops to before its Seatbelt
// profile is applied and the pod binary is exec'd (securityContext).
//
// The drop is performed in the exec-shim — a fresh, single-purpose process the
// supervisor posix_spawns — and never in the multi-threaded daemon: setgid /
// setuid are process-wide and irreversible, so they must run in a process that
// does nothing afterwards except apply the sandbox and execve the pod.
//
// Drop reports whether a drop is requested at all. It is a separate bool because
// the proto's int64 run_as_* fields cannot distinguish "unset" from 0 (0 == root,
// which is also a no-op for a root daemon); the provider resolves the effective
// identity and sets Drop only for a non-root target. A drop requires root —
// setuid/setgid to another identity is privileged — so on the unprivileged _k3sm
// daemon Drop must be false (Validate enforces this). When Drop is false the pod
// runs at the daemon's own uid confined by Seatbelt: on today's user-space daemon
// that is _k3sm-in-Seatbelt, not root. There is no per-pod uid isolation in this
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
// is only possible as root (euid 0). On the unprivileged _k3sm daemon Drop must
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
	// StepSetrlimit applies the pod's explicit POSIX resource limits
	// (setrlimit(2)). It is FIRST — before the privilege drop — because raising a
	// hard limit requires euid 0, and the limits must hold whether or not a uid
	// drop is requested.
	StepSetrlimit LaunchStep = iota
	// StepSetgid sets the primary gid (must precede StepSetuid).
	StepSetgid
	// StepInitgroups sets the supplemental group list (incl. fsGroup).
	StepInitgroups
	// StepSetuid sets the uid (must follow StepSetgid/StepInitgroups).
	StepSetuid
	// StepSetpriority places the process in the darwin BACKGROUND band
	// (setpriority(2) with PRIO_DARWIN_PROCESS/PRIO_DARWIN_BG) when the pod's
	// QoS class maps to background. It runs before StepSandboxApply — a
	// default-deny SBPL may deny setpriority afterward — and pre-exec, so the
	// band is inherited by the exec'd image and all its descendants, race-free.
	StepSetpriority
	// StepSandboxApply applies the irreversible Seatbelt profile.
	StepSandboxApply
	// StepExec execve's the pod binary (replaces the process image).
	StepExec
)

// String renders the LaunchStep for diagnostics/tests.
func (s LaunchStep) String() string {
	switch s {
	case StepSetrlimit:
		return "setrlimit"
	case StepSetgid:
		return "setgid"
	case StepInitgroups:
		return "initgroups"
	case StepSetuid:
		return "setuid"
	case StepSetpriority:
		return "setpriority"
	case StepSandboxApply:
		return "sandbox_apply"
	case StepExec:
		return "exec"
	default:
		return "unknown"
	}
}

// PlannedRlimit is one resolved POSIX resource limit ready for setrlimit(2): the
// darwin RLIMIT_* resource selector plus the soft (Cur) / hard (Max) pair as a
// unix.Rlimit. The daemon resolves a []PlannedRlimit from a pod's explicit
// PodBox.rlimits[] (runtime.resolveRlimitPlan) and RunLaunchSequence applies the
// slice — before the privilege drop — through the LaunchSeam. It is the resolved,
// proto-free plan, so the supervisor stays decoupled from apis (mirroring how
// Credential is the resolved form of a pod's securityContext).
type PlannedRlimit struct {
	// Resource is the darwin RLIMIT_* selector (e.g. unix.RLIMIT_NOFILE).
	Resource int
	// Lim is the soft (Cur) and hard (Max) limit pair applied via setrlimit(2).
	Lim unix.Rlimit
}

// LaunchSeam is the ordered set of irreversible operations the exec-shim performs
// to become a confined, privilege-dropped pod process. It is a seam (consumer-
// side interface) so RunLaunchSequence's ordering can be unit-tested with a fake
// that records calls and performs no real syscall; the production implementation
// lives in internal/execshim (drop + rlimits via golang.org/x/sys/unix,
// SandboxApply via libsandbox cgo, Exec via execve).
type LaunchSeam interface {
	// Setrlimit applies one POSIX resource limit (setrlimit(2)) to the current
	// process. Called before the uid drop, while euid is still privileged, so a
	// hard-limit raise is permitted.
	Setrlimit(resource int, lim unix.Rlimit) error
	// Getrlimit reads the current/inherited limit for resource (getrlimit(2)) — the
	// ceiling a denied hard-limit raise is clamped down to in the unprivileged
	// posture.
	Getrlimit(resource int) (unix.Rlimit, error)
	// Setgid sets the process primary group id.
	Setgid(gid int) error
	// Initgroups sets the supplemental group list (the initgroups equivalent).
	Initgroups(groups []int) error
	// Setuid sets the process user id.
	Setuid(uid int) error
	// Setpriority applies one setpriority(2) call. The launch sequence uses it
	// only with the (PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) triple to place a
	// background-QoS pod in the darwin background band, before SandboxApply.
	Setpriority(which, who, prio int) error
	// SandboxApply applies the per-pod Seatbelt profile to the current process,
	// irreversibly.
	SandboxApply() error
	// Exec replaces the process image with the pod binary; it returns only on
	// error (a successful exec never returns).
	Exec() error
}

// RunLaunchSequence drives seam through the SECURITY-critical, irreversible pod
// launch order. spec is the resolved LaunchSpec (identity + rlimit
// plan + qos); euid is the effective uid the sequence runs under (the
// exec-shim's, == the daemon's); it gates the drop. The ordering is load-bearing
// — getting it wrong silently runs the pod with the wrong identity or unconfined:
//
//		when len(spec.Rlimits)>0: Setrlimit(plan...)  [before the drop]
//		when spec.Cred.Drop:      Setgid(gid) → Initgroups(groups) → Setuid(uid)
//		when spec.BgQoS:          Setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG)
//		always:                   SandboxApply → Exec
//
//	  - a drop is refused up front when euid != 0 (cred.Validate): setuid/setgid
//	    to another identity needs root, so on the unprivileged _k3sm daemon Drop
//	    must be false and the pod runs at the daemon's own uid in Seatbelt;
//	  - rlimits FIRST, before the drop — and pod limits may only TIGHTEN, never
//	    widen: setrlimitClamped clamps every entry to the shim's inherited hard
//	    ceiling UNCONDITIONALLY (root included — a euid-0 hard raise would
//	    succeed, turning a pod annotation into a node-wide escalation lever),
//	    with the non-root EPERM retry-clamp kept as defense-in-depth; the plan
//	    applies even when Drop is false (the unprivileged posture still gets
//	    its explicit limits);
//	  - setgid before setuid: after setuid drops to a non-root uid the process can
//	    no longer change its gid, so the gid must be set while still privileged;
//	  - initgroups (supplemental groups, incl. fsGroup) BETWEEN them — also a
//	    privileged operation;
//	  - the whole drop before SandboxApply: the Seatbelt sandbox is IRREVERSIBLE
//	    and a sandboxed (and uid-dropped) process can neither setuid nor chown, so
//	    the drop and any root-side setup must complete first;
//	  - the qos step before SandboxApply: a default-deny SBPL may deny the
//	    setpriority syscall after confinement; and pre-exec, so the background
//	    band is inherited by the exec'd image and all descendants, race-free
//	    (lowering one's own priority needs no privilege, so it runs after the
//	    drop). BgQoS=false means NO call at all (downward-only — the default
//	    band is the absence of the call, never an explicit reset-to-0);
//	  - SandboxApply before Exec: the pod binary must start already confined.
//
// It returns the steps executed (for assertions) and stops at the FIRST error —
// fail-closed: a refused/failed drop or failed sandbox apply means Exec is never
// reached, so the pod never runs with the wrong credential or outside the
// sandbox.
func RunLaunchSequence(seam LaunchSeam, spec LaunchSpec, euid int) ([]LaunchStep, error) {
	var done []LaunchStep
	cred := spec.Cred
	if err := cred.Validate(euid); err != nil {
		return done, err
	}
	// rlimits FIRST — before the drop. Raising a hard limit needs euid 0, and the
	// limits apply whether or not a uid drop is requested (the unprivileged posture
	// gets them too, clamped to the inherited ceiling). An empty plan adds no step.
	if len(spec.Rlimits) > 0 {
		for _, pr := range spec.Rlimits {
			if err := setrlimitClamped(seam, pr); err != nil {
				return done, fmt.Errorf("setrlimit resource=%d: %w", pr.Resource, err)
			}
		}
		done = append(done, StepSetrlimit)
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
	if spec.BgQoS {
		if err := seam.Setpriority(prioDarwinProcess, 0, prioDarwinBG); err != nil {
			return done, fmt.Errorf("setpriority darwin background: %w", err)
		}
		done = append(done, StepSetpriority)
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

// nofileOpenMax is the darwin OPEN_MAX-equivalent ceiling (<sys/syslimits.h>
// OPEN_MAX = 10240) an infinite/oversized soft RLIMIT_NOFILE is clamped down to
// before setrlimit(2). Darwin's setrlimit(2) man page COMPATIBILITY section is
// explicit that, unlike other resources, RLIMIT_NOFILE does not accept
// rlim_cur = RLIM_INFINITY: "setrlimit() now returns with errno set to EINVAL
// in places that historically succeeded. It no longer accepts
// 'rlim_cur = RLIM_INFINITY' for RLIM_NOFILE. Use 'rlim_cur = min(OPEN_MAX,
// rlim_max)'." Without this pre-clamp an unlimited-soft-NOFILE pod would abort
// its launch on EINVAL rather than getting the kernel maximum.
const nofileOpenMax = 10240

// minNOFILESoft is the minimum soft RLIMIT_NOFILE the launch sequence enforces
// (clamping a tighter request UP, with a warning). A too-tight soft NOFILE does
// not fail the launch cleanly — it starves sandbox_compile's profile read and
// the exec'd image's dyld (plus the DYLD-inserted darwin-net DNS shim) of
// descriptors after confinement, producing a misleading in-sandbox error far
// from the cause. 256 is a conservative pick (the historical darwin default
// soft limit); a lab measurement (the dyld-vs-tight-NOFILE floor) confirms
// sufficiency on hardware.
const minNOFILESoft = 256

// normalizeNOFILE applies the darwin RLIMIT_NOFILE taxonomy to one requested
// soft/hard pair, pure-arithmetically (unit-tested with exact values):
//
//  1. ceiling: an infinite or oversized Cur is clamped down to
//     min(nofileOpenMax, Max) — the darwin man-page formula — so the syscall is
//     not EINVAL-aborted (see nofileOpenMax);
//  2. FLOOR: Cur (and, if needed, Max) is then raised UP to minNOFILESoft so the
//     confined process cannot be descriptor-starved before it even execs. A
//     floored HARD raise may still be EPERM-denied in the unprivileged posture;
//     the setrlimitClamped retry-clamp then applies as for any hard raise.
func normalizeNOFILE(lim unix.Rlimit) unix.Rlimit {
	ceil := uint64(nofileOpenMax)
	if lim.Max < ceil {
		ceil = lim.Max // RLIM_INFINITY's bit pattern compares large, never lowers ceil
	}
	if lim.Cur > ceil {
		lim.Cur = ceil
	}
	if lim.Cur < minNOFILESoft {
		lim.Cur = minNOFILESoft
	}
	if lim.Max < minNOFILESoft {
		lim.Max = minNOFILESoft
	}
	return lim
}

// setrlimitClamped applies one planned rlimit, never letting a POD-SOURCED plan
// raise the process's limits above its inherited posture:
//
//  1. RLIMIT_NOFILE first goes through normalizeNOFILE: the darwin EINVAL
//     ceiling (infinite soft is not clamped by the kernel — the launch would
//     abort) and the minNOFILESoft floor;
//  2. the requested hard (and, transitively, soft) limit is then clamped down
//     to the shim's own inherited hard limit (getrlimit(2)) UNCONDITIONALLY —
//     regardless of euid. This is a SECURITY clamp, not just EPERM avoidance:
//     in the root-daemon posture a euid-0 setrlimit may legally raise hard
//     limits, so without it a pod's rlimits[] annotation would be a node-wide
//     escalation lever (e.g. raising RLIMIT_NPROC on the shared _k3sm uid — a
//     per-uid limit — above the operator's configured posture). Pod limits may
//     only ever TIGHTEN, never widen, what the daemon inherited;
//  3. the EPERM retry-clamp is kept as defense-in-depth for the unprivileged
//     posture: if the kernel still denies a raise (e.g. an inherited-ceiling
//     read that disagrees with the kernel's), the limit is reduced to the
//     inherited hard limit and retried, with a warning, rather than failing
//     the pod. A non-EPERM error is a genuine failure and is returned.
func setrlimitClamped(seam LaunchSeam, pr PlannedRlimit) error {
	if pr.Resource == unix.RLIMIT_NOFILE {
		if norm := normalizeNOFILE(pr.Lim); norm != pr.Lim {
			slog.Warn("normalized RLIMIT_NOFILE before setrlimit (darwin EINVAL ceiling / soft floor)",
				"requested_cur", pr.Lim.Cur,
				"requested_max", pr.Lim.Max,
				"applied_cur", norm.Cur,
				"applied_max", norm.Max)
			pr.Lim = norm
		}
	}
	// Unconditional inherited-ceiling clamp (the security clamp — see the doc
	// comment). Fail closed on an unreadable ceiling: without it we cannot prove
	// the pod plan does not widen the node posture.
	inherited, gerr := seam.Getrlimit(pr.Resource)
	if gerr != nil {
		return fmt.Errorf("read inherited rlimit ceiling: %w", gerr)
	}
	if pr.Lim.Max > inherited.Max {
		slog.Warn("pod rlimit hard limit exceeds the shim's inherited posture; clamped to inherited ceiling",
			"resource", pr.Resource,
			"requested_hard", pr.Lim.Max,
			"inherited_hard", inherited.Max)
		pr.Lim.Max = inherited.Max
	}
	if pr.Lim.Cur > pr.Lim.Max {
		pr.Lim.Cur = pr.Lim.Max
	}
	err := seam.Setrlimit(pr.Resource, pr.Lim)
	if err == nil || !errors.Is(err, unix.EPERM) {
		return err
	}
	clamped := pr.Lim
	if clamped.Max > inherited.Max {
		clamped.Max = inherited.Max
	}
	if clamped.Cur > clamped.Max {
		clamped.Cur = clamped.Max
	}
	slog.Warn("rlimit hard-limit raise denied by kernel; clamped to inherited ceiling",
		"resource", pr.Resource,
		"requested_hard", pr.Lim.Max,
		"inherited_hard", inherited.Max)
	return seam.Setrlimit(pr.Resource, clamped)
}
