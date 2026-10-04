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

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The fts gate's mount and escape name. ftsMount sits directly under "/", on
// the sealed read-only system volume (requireSealedMountParents), so a rebase
// that does not happen can never create it on the host.
const (
	ftsMount      = "/k3sm-b434-mnt"
	ftsEscapeName = "k3sm-b434-escape"
)

// ftsTree plants a depth-3 tree with a sibling directory under
// <rootfs><ftsMount>/<top>: u/v/f and sib/g.
func ftsTree(top string) func(*testing.T, string) {
	return func(t *testing.T, rootfs string) {
		t.Helper()
		writeUnder(t, rootfs, ftsMount+"/"+top+"/u/v/f", "nested\n")
		writeUnder(t, rootfs, ftsMount+"/"+top+"/sib/g", "sibling\n")
	}
}

// TestShadowCopiesRebaseFtsWalks is the B434 gate: an fts(3) walk of a
// mounted directory (rm -r, ls, ls -R, chmod -R, find, cp -R, du) lands under
// the rootfs, because the shim now rebases libc's own open$NOCANCEL and
// openat$NOCANCEL, the opens fts makes. Each positive row runs a re-signed
// clone of the real utility with the BUILT shim inserted and asserts the
// effect under <rootfs><mount>, the host mount never created, and a no-shim
// contrast that does not produce the effect (the listing rows assert the
// missing output, not only the exit code).
//
// The walkers print fts_path, which stays in the pod's mount namespace: ls -R
// headers and find output name the MOUNT path, never the rootfs path. That
// is why the opens are rebased and fts_open is not.
//
// Ceilings pinned here: chown -R (the walk is rebased, the fchownat on the
// absolute fts path is not), and du as a pod runs it (/usr/bin/du is not in
// the shadow set, so dyld strips the shim from the platform binary).
func TestShadowCopiesRebaseFtsWalks(t *testing.T) {
	requireSealedMountParents(t)
	shim := buildPathShim(t)
	helper := buildDirMetaHelper(t)
	bin := t.TempDir()
	tools := map[string]string{
		"rm": "/bin/rm", "ls": "/bin/ls", "chmod": "/bin/chmod", "find": "/usr/bin/find",
		"cp": "/bin/cp", "du": "/usr/bin/du", "chown": "/usr/sbin/chown",
	}
	for name, src := range tools {
		cloneSigned(t, src, filepath.Join(bin, name))
	}

	const M = ftsMount
	// noRootfs checks the output never names the rootfs: fts_path must stay
	// in the mount namespace.
	noRootfs := func(rootfs, out string) error {
		if strings.Contains(out, rootfs) {
			return fmt.Errorf("output leaks the rootfs path %s:\n%s", rootfs, out)
		}
		return nil
	}
	outAll := func(want ...string) func(string, string) error {
		return func(rootfs, out string) error {
			for _, w := range want {
				if err := rowOutHas(w)(rootfs, out); err != nil {
					return err
				}
			}
			return nil
		}
	}
	modesAre := func(want os.FileMode, rels ...string) func(string, string) error {
		return func(rootfs, out string) error {
			for _, rel := range rels {
				if err := rowModeIs(rel, want)(rootfs, out); err != nil {
					return err
				}
			}
			return nil
		}
	}
	// duSizes checks du printed a non-zero size for each mounted path.
	duSizes := func(paths ...string) func(string, string) error {
		return func(_, out string) error {
			sizes := map[string]int{}
			for _, line := range strings.Split(out, "\n") {
				n, p, ok := strings.Cut(line, "\t")
				if !ok {
					continue
				}
				if v, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					sizes[p] = v
				}
			}
			for _, p := range paths {
				if sizes[p] <= 0 {
					return fmt.Errorf("du size of %s = %d, want > 0:\n%s", p, sizes[p], out)
				}
			}
			return nil
		}
	}
	// present checks <rootfs>/rel still exists (rm -r of a child must not
	// take the mount directory with it).
	present := func(rel string) func(string, string) error {
		return func(rootfs, _ string) error {
			_, err := os.Lstat(filepath.Join(rootfs, rel))
			return err
		}
	}
	silent := func(_, out string) error {
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("output %q, want none", out)
		}
		return nil
	}
	uidgid := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())

	rows := []dirMetaRow{
		{name: "rm -r", tool: "rm", args: []string{"-r", M + "/t"}, setup: ftsTree("t"),
			check: rowBoth(rowGone(M+"/t"), present(M))},
		{name: "ls", tool: "ls", args: []string{M + "/t"}, setup: ftsTree("t"),
			check: outAll("sib\n", "u\n")},
		{name: "ls -R shows mount paths", tool: "ls", args: []string{"-R", M + "/t"}, setup: ftsTree("t"),
			check: rowBoth(outAll(M+"/t/u:", M+"/t/u/v:", M+"/t/sib:", "f\n", "g\n"), noRootfs)},
		{name: "chmod -R", tool: "chmod", args: []string{"-R", "700", M + "/t"}, setup: ftsTree("t"),
			check: modesAre(0o700, M+"/t", M+"/t/u", M+"/t/u/v", M+"/t/u/v/f", M+"/t/sib", M+"/t/sib/g")},
		{name: "find prints mount paths", tool: "find", args: []string{M + "/t"}, setup: ftsTree("t"),
			check: rowBoth(outAll(M+"/t/u/v/f\n", M+"/t/sib/g\n", M+"/t/u/v\n"), noRootfs)},
		{name: "cp -R", tool: "cp", args: []string{"-R", M + "/t", M + "/c"}, setup: ftsTree("t"),
			check: rowBoth(rowHasBody(M+"/c/u/v/f", "nested\n"), rowHasBody(M+"/c/sib/g", "sibling\n"))},
		{name: "du (re-signed clone)", tool: "du", args: []string{M + "/t"}, setup: ftsTree("t"),
			check: rowBoth(duSizes(M+"/t/u/v", M+"/t/u", M+"/t/sib", M+"/t"), noRootfs)},

		// Boundary: a root that climbs out of the mount with ".." names a host
		// path ("/k3sm-b434-escape", sealed volume, cannot exist). It is not
		// rebased: the tree a wrong rebase WOULD reach survives.
		{name: "boundary dotdot root is not rebased", tool: "rm", args: []string{"-r", M + "/../" + ftsEscapeName},
			setup: func(t *testing.T, rootfs string) {
				t.Helper()
				ftsTree("t")(t, rootfs)
				rowFile("/"+ftsEscapeName+"/u/f", "keep")(t, rootfs)
			},
			boundary: true, refused: true,
			check: rowBoth(rowOutHas("No such file or directory"), rowHasBody("/"+ftsEscapeName+"/u/f", "keep"))},

		// Double-rebase guard. The rootfs's parent is configured as a mount
		// too, so the rootfs sits under a mount prefix.
		//   - opendir rebases the mounted path, then libc re-enters
		//     open$NOCANCEL with "<rootfs>/k3sm-b434-mnt/t", which is under
		//     the covering mount: without the guard it is rebased again to
		//     "<rootfs><rootfs>/..." and the listing fails.
		{name: "double-rebase guard: opendir re-entry", args: []string{"opendir", M + "/t"}, setup: ftsTree("t"),
			coverRootfs: true, check: outAll("sib\n", "u\n")},
		//   - a path already under the rootfs, handed straight to the shim,
		//     is left alone (the shim behaves as if absent: boundary).
		{name: "double-rebase guard: rootfs path passed in", tool: "ls", setup: ftsTree("t"),
			argsFor:     func(rootfs string) []string { return []string{"-R", rootfs + M + "/t"} },
			coverRootfs: true, boundary: true,
			check: func(rootfs, out string) error {
				return outAll(rootfs+M+"/t/u/v:", "f\n", "g\n")(rootfs, out)
			}},

		// Ceilings (documented in the shim header).
		{name: "ceiling chown -R", tool: "chown", args: []string{"-R", uidgid, M + "/t"}, setup: ftsTree("t"),
			check: silent, ceilingErr: "chown: " + M + "/t: No such file or directory"},
		{name: "ceiling du as a pod runs it (not in the shadow set)", tool: "/usr/bin/du", args: []string{M + "/t"}, setup: ftsTree("t"),
			check: duSizes(M + "/t"), ceilingErr: "du: " + M + "/t: No such file or directory"},
	}
	pathShimRowHarness{
		shim: shim, helper: helper, bin: bin,
		mounts:    []string{ftsMount},
		hostPaths: []string{ftsMount, "/" + ftsEscapeName},
	}.run(t, rows)
}
