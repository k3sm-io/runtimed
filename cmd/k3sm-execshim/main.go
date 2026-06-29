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
// sandbox.Backend helper. The runtime supervisor posix_spawns it as:
//
//	k3sm-execshim <uid> <gid> <groups-csv> <profile.sb> <pod-binary> [args...]
//
// The three leading tokens are the pod's securityContext identity
// (supervisor.Credential, encoded by Credential.ShimArgs); "-1 -1 -" means "no
// drop" — run at the daemon's OWN uid, confined by Seatbelt (the unprivileged
// _k3sm posture, not root). A drop is refused unless the shim is root
// (RunLaunchSequence → Credential.Validate). The shim then, in the
// SECURITY-CRITICAL order supervisor.RunLaunchSequence enforces:
//
//	(1) drops privilege: setgid → initgroups → setuid   (setgid BEFORE setuid;
//	    after setuid to non-root the gid can no longer change);
//	(2) applies the SBPL profile to ITSELF via libsandbox (irreversible — a
//	    sandboxed/uid-dropped process can neither setuid nor chown, so the drop
//	    MUST precede this);
//	(3) execve's the pod binary, PRESERVING the inherited environment — so
//	    DYLD_INSERT_LIBRARIES (the darwin-net DNS-shim enabler) survives into the
//	    pod. This is deliberately NOT /usr/bin/sandbox-exec: that platform binary
//	    strips DYLD_* (Wave-0 confirmed this live), which would break the shim.
//
// The fsGroup chown of the writable volumes happens ROOT-SIDE in the daemon
// BEFORE this shim is spawned (a dropped process can no longer chown).
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
	// argv: <uid> <gid> <groups-csv> <profile.sb> <pod-binary> [args...]
	if len(os.Args) < 6 {
		fmt.Fprintf(os.Stderr, "usage: %s <uid> <gid> <groups-csv> <profile.sb> <pod-binary> [args...]\n", os.Args[0])
		os.Exit(2)
	}
	cred, err := supervisor.ParseCredential(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: parse credential: %v\n", err)
		os.Exit(2)
	}
	profilePath := os.Args[4]
	argv := os.Args[5:]

	profile, err := os.ReadFile(profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: read profile %s: %v\n", profilePath, err)
		os.Exit(3)
	}

	// RunPodLaunch drops privilege, applies the profile, and execs argv (in that
	// irreversible order); it returns only on error.
	if err := execshim.RunPodLaunch(string(profile), argv, cred); err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: %v\n", err)
		os.Exit(4)
	}
}
