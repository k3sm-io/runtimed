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
	"log/slog"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
// before a single chown runs. This is DEFENCE AT the SINK, deliberately
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
// them, so a symlink planted inside the tree cannot redirect the walk. A
// non-directory whose link count is above one is skipped (counted, logged at
// Debug, not an error): a hard link can share its inode with a file outside the
// tree, and the bound above is a path bound that cannot see that. Every change
// is made through a no-follow handle; see fsGroupEntry. A gid <= 0
// is rejected: 0 (wheel) is never a valid fsGroup target and a negative gid is a
// programming error.
func ChownForFSGroup(bound, root string, gid int) error {
	if gid <= 0 {
		return fmt.Errorf("fsGroup chown: invalid gid %d", gid)
	}
	if !strictlyUnder(root, bound) {
		return fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, root, bound)
	}
	skipped := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		done, err := fsGroupEntry(path, d, gid)
		if err != nil {
			return err
		}
		if !done {
			skipped++
		}
		return nil
	})
	if skipped > 0 {
		slog.Debug("fsGroup pass skipped entries it could not prove belong to the tree",
			"root", root, "skipped", skipped)
	}
	return err
}

// fsGroupEntry applies the fsGroup group and mode to one walked entry. It
// reports done=false (and no error) for an entry it deliberately leaves alone:
// a non-directory whose link count is above one (its inode may be shared with
// a file outside the tree, and changing it would change that file too), or an
// entry whose type changed between the walk's read and this call.
//
// Every change goes through a no-follow handle, never a re-resolvable path:
// directories and regular files are opened O_NOFOLLOW and changed with
// fchown/fchmod on that descriptor, after the link count and type are read
// from the same descriptor (fstat), so the inode checked is the inode changed.
// Symlinks get only the group (fchownat AT_SYMLINK_NOFOLLOW, the lchown
// equivalent; a symlink mode is meaningless). Other types (fifo, socket,
// device) are not opened — opening one can block or have side effects — and
// are changed with fchownat/fchmodat AT_SYMLINK_NOFOLLOW after an lstat
// link-count check.
func fsGroupEntry(path string, d fs.DirEntry, gid int) (bool, error) {
	typ := d.Type()
	switch {
	case typ&fs.ModeSymlink != 0:
		if err := unix.Fchownat(unix.AT_FDCWD, path, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		return true, nil
	case typ.IsDir() || typ.IsRegular():
		return fsGroupByFD(path, typ.IsDir(), gid)
	default:
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return false, fmt.Errorf("fsGroup lstat %s: %w", path, err)
		}
		if st.Nlink > 1 {
			return false, nil
		}
		if err := unix.Fchownat(unix.AT_FDCWD, path, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		if err := unix.Fchmodat(unix.AT_FDCWD, path, fsGroupMode(uint32(st.Mode), false), unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return true, nil
	}
}

// fsGroupByFD changes a directory or regular file through an O_NOFOLLOW
// descriptor. O_NONBLOCK keeps the open from blocking should the path have been
// replaced by a fifo; the fstat type check then refuses it.
func fsGroupByFD(path string, isDir bool, gid int) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return false, nil // replaced by a symlink since the walk read it
		}
		return false, fmt.Errorf("fsGroup open %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, fmt.Errorf("fsGroup fstat %s: %w", path, err)
	}
	fmtBits := uint32(st.Mode) & unix.S_IFMT
	if isDir && fmtBits != unix.S_IFDIR || !isDir && fmtBits != unix.S_IFREG {
		return false, nil // type changed since the walk read it
	}
	if !isDir && st.Nlink > 1 {
		return false, nil
	}
	if err := unix.Fchown(fd, -1, gid); err != nil {
		return false, fmt.Errorf("fsGroup chown %s: %w", path, err)
	}
	if err := unix.Fchmod(fd, fsGroupMode(uint32(st.Mode), isDir)); err != nil {
		return false, fmt.Errorf("fsGroup chmod %s: %w", path, err)
	}
	return true, nil
}

// fsGroupMode grants the group the same rwx the owner has (so an fsGroup member
// can use the volume), keeps the setuid/setgid/sticky bits already present, and
// adds setgid on directories for group inheritance.
func fsGroupMode(mode uint32, isDir bool) uint32 {
	perm := mode & 0o777
	perm |= (perm & 0o700) >> 3
	out := mode&0o7000 | perm
	if isDir {
		out |= unix.S_ISGID
	}
	return out
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
