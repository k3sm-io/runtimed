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
	"regexp"
	"slices"
	"sort"
	"strings"
)

// HostShare is one node-admitted host path a pod mounts at its own path: a
// directory (read-write or read-only) or a single Unix socket. It is plain data
// so this package does not import the allowlist that decides it
// (pkg/hostshare).
type HostShare struct {
	// Path is the absolute host path.
	Path string
	// ReadOnly grants read access only (directories).
	ReadOnly bool
	// Socket grants connect(2) to the one socket at Path and its metadata,
	// and nothing else.
	Socket bool
}

// ErrInvalidHostShare reports a HostShare the generator will not render: not
// absolute and clean, the filesystem root, a whole home or /Users itself, or a
// path that overlaps the protected deny-set other than /Users. It is its own
// sentinel, not ErrProtectedPath, for the reason ErrXcodeToolchainDir gives.
var ErrInvalidHostShare = errors.New("sbpl: invalid host share")

// usersRoot is the one protected prefix a host share may sit under.
const usersRoot = "/Users"

// shareRefusedRoots are refused for a share on top of the posture's
// protected prefixes: /System also spells every data-volume path
// (/System/Volumes/Data/Users/...), so a share there would reach /Users
// around the checks below.
var shareRefusedRoots = []string{"/System"}

// validateHostShares checks every share against the posture and returns them
// sorted and de-duplicated. The allowlist (pkg/hostshare) already refused
// these shapes; this is the sink-tier copy, because Generate is exported and
// the re-allow tier it renders into outranks every protected deny.
//
// A share must not be at, under, or an ancestor of any protected prefix other
// than /Users (the work-dir trees, the pods root, the secrets store, the log
// trees), and must not touch the pod's own data volume. Under /Users it must
// be strictly below a home directory (/Users/<name>/<something>), never
// /Users or a home itself.
func validateHostShares(shares []HostShare, protectedPrefixes []string, dataVol string) ([]HostShare, error) {
	out := make([]HostShare, 0, len(shares))
	seen := map[HostShare]bool{}
	for _, sh := range shares {
		p := sh.Path
		bad := func(why string) error { return fmt.Errorf("%w: %q: %s", ErrInvalidHostShare, p, why) }
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return nil, bad("not an absolute, clean path other than /")
		}
		for _, r := range p {
			// ASCII only, as the allowlist requires: Seatbelt matches paths
			// case- and normalization-insensitively, and the checks below
			// fold ASCII case only.
			if r < 0x20 || r >= 0x7f || r == '"' || r == '\\' {
				return nil, bad("contains a character the profile cannot carry")
			}
		}
		if sh.Socket && sh.ReadOnly {
			return nil, bad("a socket share has no read-only form")
		}
		if underAnyForm(p, dataVol) || underAnyForm(dataVol, p) {
			return nil, bad("overlaps the pod's own data volume")
		}
		// Every comparison folds ASCII case, the way Seatbelt and APFS match.
		lp := strings.ToLower(p)
		for _, pre := range append(slices.Clone(protectedPrefixes), shareRefusedRoots...) {
			if pre == usersRoot {
				continue
			}
			lpre := strings.ToLower(pre)
			if underAnyForm(lp, lpre) || underAnyForm(lpre, lp) {
				return nil, bad("overlaps the protected tree " + pre)
			}
		}
		lusers := strings.ToLower(usersRoot)
		if underAnyForm(lp, lusers) {
			parts := strings.Split(strings.TrimPrefix(lp, "/"), "/")
			if len(parts) < 3 {
				return nil, bad("a share under /Users must be below a home directory")
			}
			if parts[2] == "library" {
				return nil, bad("a share may not be a home's Library or under it")
			}
			for _, c := range parts[2:] {
				if strings.HasPrefix(c, ".") {
					return nil, bad("a share may not name a dot directory under a home")
				}
			}
		} else if underAnyForm(lusers, lp) {
			return nil, bad("covers /Users")
		}
		if !seen[sh] {
			seen[sh] = true
			out = append(out, sh)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return !out[i].ReadOnly && out[j].ReadOnly
	})
	return out, nil
}

// hostShareStanza renders the validated shares. Generate emits it in the
// re-allow tier, right after the pod's own data volume, so it outranks the
// protected /Users deny (last-match-wins). Nothing it emits can reach a
// protected tree other than /Users: validateHostShares refused any overlap.
//
//   - A read-write directory gets file-read* and file-write* on its subtree.
//   - A read-only directory gets file-read* on its subtree, then an explicit
//     file-write* deny on it, so a broader grant elsewhere cannot make it
//     writable.
//   - A socket gets connect(2) to that one path (remote unix-socket literal)
//     and file-read-metadata on it, nothing else: the directory around it
//     stays denied.
//
// The strict ancestors of every share get file-read-metadata only, from the
// shared ancestor tier, so a process can stat its way down to the share
// without listing /Users or the home.
func hostShareStanza(shares []HostShare) (files, sockets string) {
	if len(shares) == 0 {
		return "", ""
	}
	var b strings.Builder
	b.WriteString(";; host shares: the node admin's allowlist, admitted for this pod's\n")
	b.WriteString(";; hostPath volumes; after the protected denies so a share under /Users\n")
	b.WriteString(";; is reachable, and only the named paths are.\n")
	var rw, ro, socks []string
	for _, sh := range shares {
		switch {
		case sh.Socket:
			socks = append(socks, sh.Path)
		case sh.ReadOnly:
			ro = append(ro, sh.Path)
		default:
			rw = append(rw, sh.Path)
		}
	}
	if len(rw) > 0 {
		b.WriteString("(allow file-read* file-write*\n")
		writeFirmlinkSubpaths(&b, rw)
		b.WriteString("  )\n")
	}
	if len(ro) > 0 {
		b.WriteString("(allow file-read*\n")
		writeFirmlinkSubpaths(&b, ro)
		b.WriteString("  )\n")
		b.WriteString("(deny file-write*\n")
		writeFirmlinkSubpaths(&b, ro)
		b.WriteString("  )\n")
	}
	if len(socks) > 0 {
		b.WriteString("(allow file-read-metadata\n")
		for _, p := range socks {
			for _, form := range firmlinkForms(p) {
				b.WriteString(fmt.Sprintf("  (literal %q)\n", form))
			}
		}
		b.WriteString("  )\n")
	}
	files = b.String()
	if len(socks) == 0 {
		return files, ""
	}
	var sb strings.Builder
	sb.WriteString(";; host share sockets: connect(2) to these exact paths only.\n")
	sb.WriteString("(allow network-outbound\n")
	for _, p := range socks {
		for _, form := range firmlinkForms(p) {
			sb.WriteString(fmt.Sprintf("  (remote unix-socket (literal %q))\n", form))
		}
	}
	sb.WriteString("  )\n")
	return files, sb.String()
}

// hostShareSocketLine is the one filter shape the socket stanza may carry.
var hostShareSocketLine = regexp.MustCompile(`^  \(remote unix-socket \(literal "[^"\\]+"\)\)$`)

// checkHostShareSocketStanza proves the socket stanza grants AF_UNIX connects
// to literal paths and nothing else. Generate removes this stanza before it
// runs ValidateNetworkScope, which governs IP networking and would otherwise
// read a socket grant as an unrequested network allow; this check is what
// keeps that removal from hiding anything wider.
func checkHostShareSocketStanza(stanza string) error {
	if stanza == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(stanza, "\n"), "\n")
	if len(lines) < 4 || lines[1] != "(allow network-outbound" || lines[len(lines)-1] != "  )" {
		return fmt.Errorf("%w: the socket stanza is malformed", ErrInvalidHostShare)
	}
	for _, l := range lines[2 : len(lines)-1] {
		if !hostShareSocketLine.MatchString(l) {
			return fmt.Errorf("%w: the socket stanza carries %q", ErrInvalidHostShare, l)
		}
	}
	return nil
}
