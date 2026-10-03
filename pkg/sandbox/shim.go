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
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ShimSubdir is the parent of every container's resident-shim dir:
// <WorkDir>/run/shim/<id>/ holds a shim's sockets and its exit record. It is a
// CHILD of RunSubdir, so the run tree's protected file deny already covers it
// for every pod (TestShimSubdirIsInsideTheDeniedRunTree) and it needs no entry
// of its own in DaemonTreeSubdirs. What a file deny cannot stop is connect(2) on
// a socket, so every pod profile also carries one static
// (deny network-outbound (remote unix-socket (subpath <WorkDir>/run/shim)))
// in both firmlink forms (Generate): a confined pod can reach neither its own
// shim nor a sibling pod's.
//
// The deny is derived from the posture alone, so it is identical for every pod
// on the node and the pod profile's digest (the record AttachPod verifies)
// keeps its meaning: the per-container shim dirs never enter the pod profile.
const ShimSubdir = RunSubdir + "/shim"

// ShimRoot returns <workDir>/run/shim for a posture work-dir ("" means
// DefaultWorkDir), the root the daemon allocates shim dirs under.
func ShimRoot(workDir string) string {
	if workDir == "" {
		workDir = DefaultWorkDir
	}
	return filepath.Join(workDir, ShimSubdir)
}

// ErrInvalidShimGrant reports a ShimGrant whose paths are not absolute and
// clean, or a pod profile that is not one Generate rendered.
var ErrInvalidShimGrant = errors.New("sandbox: invalid shim grant")

// ShimGrant is what a resident shim needs beyond its container's pod profile:
// its own shim dir and its container's CRI log, both this container's own
// artifacts.
type ShimGrant struct {
	// Dir is the container's shim dir (under ShimRoot).
	Dir string
	// LogPath is the container's CRI log file, which the daemon creates.
	LogPath string
}

// ShimProfile renders the resident shim's profile: podProfile, unchanged, plus
// one tier emitted AFTER everything in it, so the protected denies the grant
// re-opens (the run tree, the pod-logs tree) are outranked only for these
// literals (SBPL is last-match-wins). The shim applies it to itself after it
// spawned the container, which runs under podProfile alone; an exec session
// the shim forks inherits it.
//
// The grant is, exactly:
//
//   - file-read* on the shim dir (subpath): the shim reads nothing else there,
//     and reading is all a subpath gets;
//   - file-write* on the two literals <dir>/exit.json and <dir>/exit.json.tmp,
//     the exit record's tmp + rename — never the dir, so nothing under this
//     profile can create, unlink or replace a socket;
//   - file-write-data on the log literal: append to the file the daemon
//     created, and reopen it after a rotation (an open of an existing file);
//     no create, no unlink, no other log;
//   - file-ioctl on tty nodes: a tty exec session's controlling-terminal
//     ioctls on the slave the daemon handed over. No file-read or file-write
//     is granted on any tty, so no process under this profile can OPEN a
//     terminal, its own or another session's;
//   - signal to its own children and its own process group: the shim forwards
//     a TERM to its container, delivers the Signal RPC to the pod group it
//     leads, and kills an exec session whose stream ended. The container runs
//     under another sandbox instance, and without this a confined process may
//     signal nothing but itself (measured: EPERM). Neither target reaches a
//     process outside this pod's group or the shim's own children.
//
// No network rule is added: the shim's sockets are bound before it confines
// itself, and accept(2) on a pre-bound socket needs no grant (measured), so the
// shim profile's network scope is the pod profile's.
func ShimProfile(podProfile string, g ShimGrant) (string, error) {
	if err := Validate(podProfile); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidShimGrant, err)
	}
	for _, p := range []string{g.Dir, g.LogPath} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return "", fmt.Errorf("%w: %q is not an absolute clean path", ErrInvalidShimGrant, p)
		}
	}
	var b strings.Builder
	b.WriteString(podProfile)
	if !strings.HasSuffix(podProfile, "\n") {
		b.WriteString("\n")
	}
	b.WriteString(";; SHIM GRANT — the resident shim's own artifacts, emitted LAST so\n")
	b.WriteString(";; it outranks the protected denies for these literals only.\n")
	b.WriteString("(allow file-read*\n")
	writeFirmlinkSubpaths(&b, []string{g.Dir})
	b.WriteString("  )\n")
	b.WriteString("(allow file-write*\n")
	for _, f := range shimWriteLiterals(g.Dir) {
		for _, form := range firmlinkForms(f) {
			b.WriteString(fmt.Sprintf("  (literal %q)\n", form))
		}
	}
	b.WriteString("  )\n")
	b.WriteString("(allow file-write-data\n")
	for _, form := range firmlinkForms(g.LogPath) {
		b.WriteString(fmt.Sprintf("  (literal %q)\n", form))
	}
	b.WriteString("  )\n")
	b.WriteString(shimTTYIoctl)
	b.WriteString(shimSignal)
	return b.String(), nil
}

// shimTTYIoctl is the grant's tty tier (see ShimProfile).
const shimTTYIoctl = "(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))\n"

// shimSignal is the grant's signal tier (see ShimProfile).
const shimSignal = "(allow signal (target children))\n(allow signal (target pgrp))\n"

// shimWriteLiterals are the only files the shim profile may write in its dir.
func shimWriteLiterals(dir string) []string {
	exit := filepath.Join(dir, "exit.json")
	return []string{exit, exit + ".tmp"}
}
