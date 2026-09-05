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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrFSGroupRootUnbounded is returned when the requested root is not strictly
// inside bound. It is a caller-programming/hostile-input failure, never retried.
var ErrFSGroupRootUnbounded = errors.New("fsGroup chown root is outside the permitted tree")

// ChownForFSGroup recursively sets group ownership of root to gid and makes it
// group-accessible, so a pod that drops to a non-root uid (with fsGroup in its
// supplemental groups — see Credential.Groups) can still read and write its
// volumes (securityContext.fsGroup). It mirrors the kubelet fsGroup
// volume-ownership pass.
//
// It must run ROOT-side in the daemon, before the privilege drop in the exec-shim
// (RunLaunchSequence): once a pod process has dropped its uid it can no longer
// chown, and once it is sandboxed it cannot either. The supervisor performs it
// synchronously before posix_spawn, which is strictly before the exec-shim drops
// — so the "before the drop" ordering is guaranteed by the process flow.
//
// bound is the tree this walk may touch (the daemon's pods root); root must be a
// proper descendant of it or the call is refused with ErrFSGroupRootUnbounded
// before a single Lchown runs. This is DEFENCE AT the SINK, deliberately
// independent of whoever computed root: the walk grants the group the owner's
// full rwx and sets setgid on every directory it reaches, which is a privilege
// grant, and the runtime's pod-dir delete already carries exactly this bound on
// its RemoveAll — the asymmetry was the defect this bound closes. The bound is a PARAMETER
// rather than a package constant because this package deliberately imports
// nothing from k3sm.io: it is the low-level process layer, and reaching into
// pkg/image or pkg/mount for the layout (or the containment predicate) would
// invert that layering.
//
// Directories additionally get the setgid bit so files created later inherit the
// group. Symlinks are chowned (lchown) but not chmod'd (a symlink mode is
// meaningless and Chmod would follow the link); WalkDir does not descend through
// them, so a symlink planted inside the tree cannot redirect the walk. A gid <= 0
// is rejected: 0 (wheel) is never a valid fsGroup target and a negative gid is a
// programming error.
func ChownForFSGroup(bound, root string, gid int) error {
	if gid <= 0 {
		return fmt.Errorf("fsGroup chown: invalid gid %d", gid)
	}
	if !strictlyUnder(root, bound) {
		return fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, root, bound)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// lchown keeps uid (-1) and sets the group; it does not follow symlinks.
		if err := os.Lchown(path, -1, gid); err != nil {
			return fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // do not chmod a symlink
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		// Grant the group the same rwx the owner has (so an fsGroup member can use
		// the volume); dirs also get the setgid bit for group inheritance.
		mode |= (mode & 0o700) >> 3
		newMode := info.Mode()&^fs.FileMode(0o777) | mode
		if d.IsDir() {
			newMode |= os.ModeSetgid
		}
		if err := os.Chmod(path, newMode); err != nil {
			return fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return nil
	})
}

// strictlyUnder reports whether path is a proper descendant of base (both
// cleaned). Equality is false — a caller may chown a pod's data volume, never
// the shared pods root itself — and the check is separator-aware, so /a/b is
// under /a while the sibling /a/bc is not under /a/b. A relative or empty base
// admits nothing: both operands are required absolute.
//
// It is a local predicate rather than an import of pkg/mount.IsStrictlyUnder,
// for the layering reason given on ChownForFSGroup. It is deliberately STRICTER
// than that one and the asymmetry is the point, not drift: mount's variant
// admits relative operands (IsStrictlyUnder("a/b", "a") is true), which is
// harmless for a share-plan check whose inputs are already absolute by
// construction, but is a fail-OPEN shape for a privilege-granting sink reached
// from a wire field — a relative base would make containment depend on the
// process working directory. Here both operands are required absolute, so a
// non-absolute operand admits nothing. TestStrictlyUnder pins the asymmetry
// explicitly; do not "reconcile" the two by loosening this one.
func strictlyUnder(path, base string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(base) {
		return false
	}
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	if base == string(filepath.Separator) {
		return path != base
	}
	return strings.HasPrefix(path, base+string(filepath.Separator))
}
