// Command k3sm-execshim is the ad-hoc-signed Seatbelt exec-shim: the M1
// sandbox.Backend helper. The runtime supervisor posix_spawns it as:
//
//	k3sm-execshim <profile.sb> <pod-binary> [args...]
//
// It reads the SBPL profile, applies it to ITSELF in-process via libsandbox, and
// then execve's the pod binary with args, PRESERVING the inherited environment —
// so DYLD_INSERT_LIBRARIES (the darwin-net DNS-shim enabler) survives into the
// pod. This is deliberately NOT /usr/bin/sandbox-exec: that platform binary
// strips DYLD_* (Wave-0 confirmed this live), which would break the shim.
//
// The shim must be ad-hoc signed with hardened-runtime and library-validation
// STRIPPED (codesign -s - -f, no -o runtime/library) so a later DYLD insert can
// load. It fails closed: any error compiling/applying the profile aborts before
// exec — the pod never runs unconfined.
package main

import (
	"fmt"
	"os"

	"k3sm.io/runtimed/internal/execshim"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <profile.sb> <pod-binary> [args...]\n", os.Args[0])
		os.Exit(2)
	}
	profilePath := os.Args[1]
	argv := os.Args[2:]

	profile, err := os.ReadFile(profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: read profile %s: %v\n", profilePath, err)
		os.Exit(3)
	}

	// ConfineAndExec applies the profile and execs argv; it returns only on error.
	if err := execshim.ConfineAndExec(string(profile), argv); err != nil {
		fmt.Fprintf(os.Stderr, "k3sm-execshim: %v\n", err)
		os.Exit(4)
	}
}
