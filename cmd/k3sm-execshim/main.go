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

// Command k3sm-execshim is the ad-hoc-signed Seatbelt exec-shim: the
// sandbox.Backend helper. Its first argument is a mode token
// (supervisor.ShimModeLaunch, ShimModeServe, ShimModeExec); a missing or unknown
// token is a usage error (exit 2), so an argv of the pre-mode shape fails closed.
//
//	k3sm-execshim launch <uid> <gid> <groups-csv> <rlimits> <qos> <profile.sb> <pod-binary> [args...]
//	k3sm-execshim serve            (launch spec on stdin; see supervisor.ShimSpec)
//	k3sm-execshim exec <rlimits> <qos> <command> [args...]
//
// # serve: the resident shim
//
// The runtime daemon spawns the shim in serve mode as the leader of a new pod
// process group. It stays resident as the container's parent: it holds the
// container's stdout and stderr, writes the CRI log itself, reaps the container
// for its real wait status, persists that status (supervisor.ShimExitFile), and
// serves shimv1.ContainerShim on a unix socket in its shim dir, so a restarted
// daemon reconnects instead of losing the container's output, exit code and
// exec. See internal/execshim.Serve for the confinement order: the shim starts
// unconfined, spawns the container (launch mode, in its own group), and only
// then confines itself to the pod profile plus its shim grant.
//
// # launch: the container's launch sequence
//
// The three leading tokens are the pod's securityContext identity
// (supervisor.Credential, encoded by Credential.ShimArgs); "-1 -1 -" means "no
// drop" — run at the daemon's own uid, confined by Seatbelt (the unprivileged
// _k3sm posture, not root). A drop is refused unless the shim is root
// (RunLaunchSequence → Credential.Validate).
//
// The next two tokens are the pod's launch spec, each a single
// fixed-position token placed before the profile path:
//
//   - <rlimits>: the resolved numeric setrlimit(2) plan,
//     "r=RESOURCE:cur:max[,RESOURCE:cur:max...]" or "-" for none
//     (supervisor.EncodeRlimits/ParseRlimits; the RLIMIT_* name table stays
//     daemon-side — the shim only ever sees numeric selectors);
//   - <qos>: "q=bg" to place the pod in the darwin background band
//     (setpriority(2) PRIO_DARWIN_PROCESS/PRIO_DARWIN_BG), or "-" for no call
//     (supervisor.EncodeQoS/ParseQoS).
//
// A malformed/truncated launch-spec token is fatal (exit 5): the shim never
// skips a limit with a warning and never execs the pod without the limits it
// was handed.
//
// Exit codes: 2 usage/credential, 3 profile read, 4 launch-sequence failure,
// 5 launch-spec token decode failure; serve adds supervisor.ShimExitSpec,
// ShimExitSunPath and ShimExitSetup for a failure before it serves.
//
// The launch mode then, in the SECURITY-critical order
// supervisor.RunLaunchSequence enforces:
//
//	(1) applies the rlimit plan (before the drop — a hard raise needs euid 0);
//	(2) drops privilege: setgid → initgroups → setuid   (setgid before setuid;
//	    after setuid to non-root the gid can no longer change);
//	(3) backgrounds itself when <qos> requests it (before the sandbox — a
//	    default-deny SBPL may deny setpriority; pre-exec so descendants inherit);
//	(4) applies the SBPL profile to itself via libsandbox (irreversible — a
//	    sandboxed/uid-dropped process can neither setuid nor chown, so the drop
//	    must precede this);
//	(5) execve's the pod binary, preserving the inherited environment — so
//	    DYLD_INSERT_LIBRARIES (the darwin-net DNS-shim enabler) survives into the
//	    pod. This is deliberately not /usr/bin/sandbox-exec: that platform binary
//	    strips DYLD_* (Wave-0 confirmed this live), which would break the shim.
//	    The exec is posix_spawn(POSIX_SPAWN_SETEXEC) carrying the pcontrol-KILL
//	    attribute (a plain execve clears that mark), falling back to execve.
//
// # exec: a session inside the shim's confinement
//
// An exec session a resident shim serves runs as exec mode: it applies the
// pod's rlimit plan and QoS band and execs the command marked pcontrol-KILL. It
// drops nothing and applies no profile: it was forked by the confined shim and
// inherits its confinement (a second sandbox_apply fails on macOS), and the
// shim already runs as the pod's credential.
//
// The fsGroup chown of the writable volumes happens ROOT-side in the daemon
// before this shim is spawned (a dropped process can no longer chown).
//
// Privilege-model note (runtimed): the daemon runs unprivileged as _k3sm and the
// only root component is a separate k3sm-netd networking helper. A pod with no
// securityContext drop runs at the daemon's own (_k3sm) uid, confined by Seatbelt
// — there is NO per-pod uid isolation (pods share the runtime uid), which is why
// the SBPL must explicitly deny the helper socket and why untrusted tenancy
// routes to the vm backend (a Virtualization.framework micro-VM), not this path.
//
// The shim must be ad-hoc signed with hardened-runtime and library-validation
// STRIPPED (codesign -s - -f, no -o runtime/library) so a later DYLD insert can
// load. It fails closed: any error dropping privilege, compiling/applying the
// profile, or before exec aborts — the pod never runs unconfined or with the
// wrong identity.
package main

import (
	"fmt"
	"os"

	"k3sm.io/runtimed/internal/execshim"
	"k3sm.io/runtimed/pkg/supervisor"
)

func main() {
	mode, rest, ok := parseMode(os.Args[1:])
	if !ok {
		fmt.Fprintf(os.Stderr, "usage: %s launch|serve|exec ... (see the package documentation)\n", os.Args[0])
		os.Exit(2)
	}
	switch mode {
	case supervisor.ShimModeServe:
		os.Exit(execshim.Serve())
	case supervisor.ShimModeExec:
		if len(rest) < 3 {
			fmt.Fprintf(os.Stderr, "usage: %s exec <rlimits> <qos> <command> [args...]\n", os.Args[0])
			os.Exit(2)
		}
		if err := execshim.RunExecSession(rest[0], rest[1], rest[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "k3sm-execshim: %v\n", err)
			os.Exit(4)
		}
	default:
		os.Exit(launch(rest))
	}
}

// launch is the container launch sequence (launch mode); it returns only on
// failure, with the exit code.
func launch(args []string) int {
	// args: <uid> <gid> <groups-csv> <rlimits> <qos> <profile.sb> <pod-binary> [args...]
	if len(args) < 7 {
		fmt.Fprintf(os.Stderr, "usage: %s launch <uid> <gid> <groups-csv> <rlimits> <qos> <profile.sb> <pod-binary> [args...]\n", os.Args[0])
		return 2
	}
	cred, err := supervisor.ParseCredential(args[0], args[1], args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: parse credential: %v\n", err)
		return 2
	}
	// The launch-spec tokens are fatal on any decode error (exit 5): the pod must
	// never exec without the limits/qos it was handed (fail-closed).
	plan, err := supervisor.ParseRlimits(args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: parse rlimits: %v\n", err)
		return 5
	}
	bgQoS, err := supervisor.ParseQoS(args[4])
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: parse qos: %v\n", err)
		return 5
	}
	profilePath := args[5]
	argv := args[6:]

	profile, err := os.ReadFile(profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: read profile %s: %v\n", profilePath, err)
		return 3
	}

	// RunPodLaunch applies the launch spec (rlimits → drop → qos), applies the
	// profile, and execs argv (in that irreversible order); it returns only on
	// error.
	spec := supervisor.LaunchSpec{Cred: cred, Rlimits: plan, BgQoS: bgQoS}
	if err := execshim.RunPodLaunch(string(profile), argv, spec); err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: %v\n", err)
		return 4
	}
	return 4 // unreachable: a successful launch execs
}
