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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrFSGroupRootUnbounded is returned when the requested root is not strictly
// inside bound. It is a caller-programming/hostile-input failure, never retried.
var ErrFSGroupRootUnbounded = errors.New("fsGroup chown root is outside the permitted tree")

// ErrFSGroupTreeTooDeep is returned when the tree under root nests deeper than
// maxFSGroupDepth directories.
var ErrFSGroupTreeTooDeep = errors.New("fsGroup chown tree is too deep")

// ErrFSGroupEntryChanged is returned when an entry stopped being the kind of
// file the walk listed it as before the walk had finished with it: something
// is rearranging the tree under the walk, and the walk stops.
var ErrFSGroupEntryChanged = errors.New("fsGroup chown entry changed under the walk")

// maxFSGroupDepth bounds how many directories deep the walk goes below root.
// The by-path walk this replaced stopped at PATH_MAX, about half as deep; the
// bound keeps a pod-authored chain of directories from costing the daemon
// unbounded work. A var so a test can lower it.
var maxFSGroupDepth = 1024

// fsGroupDirFlags opens a directory for the walk: never through a symlink.
const fsGroupDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// fsGroupBeforeApply, when set, is called with an entry's path after the walk
// has read what the entry is and before it changes the entry. It is the seam a
// test uses to swap an entry in that window, as a pod process can; production
// leaves it nil.
var fsGroupBeforeApply func(path string)

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
// bound is the tree this walk may touch (the pod's own dir); root must be a
// proper descendant of it or the call is refused with ErrFSGroupRootUnbounded
// before anything is changed. This is DEFENCE AT the SINK, deliberately
// independent of whoever computed root: the walk grants the group the owner's
// full rwx and sets setgid on every directory it reaches, which is a privilege
// grant, and the runtime's pod-dir delete already carries exactly this bound on
// its RemoveAll — the asymmetry was the defect this bound closes. The bound is a PARAMETER
// rather than a package constant because this package deliberately imports
// nothing from k3sm.io: it is the low-level process layer, and reaching into
// pkg/image or pkg/mount for the layout (or the containment predicate) would
// invert that layering.
//
// Nothing below bound is resolved by path. The tree is the pod's: a pod can
// replace its rootfs, or any directory or file under it, with a symlink, and a
// process of an earlier instance of the pod can still be running while the
// next one is created. A walk by path would then chown and chmod whatever the
// link names, as root. So bound is opened without following a link, and every
// directory from there down is opened with O_NOFOLLOW relative to the open
// directory above it. A directory is changed through its own descriptor
// (fchown, fchmod); any other entry is changed by name relative to its open
// parent with AT_SYMLINK_NOFOLLOW (fchownat, fchmodat), so an entry swapped for
// a link is changed as a link, never through it. A directory that turned into
// a link between being listed and being opened fails the walk (ELOOP), and so
// does any other entry that changed kind before its mode was set
// (ErrFSGroupEntryChanged): each is a refusal, and the caller fails the pod's
// create. bound itself is the
// caller's to vouch for: it must be a directory the pod cannot replace.
//
// What each kind of entry gets, which is what the by-path walk gave a tree
// nobody was rearranging:
//
//   - a directory: group gid, the owner's rwx copied to the group, and setgid,
//     so files created later inherit the group;
//   - a regular file, FIFO, socket or device node: group gid and the owner's
//     rwx copied to the group. They are never opened (opening a FIFO blocks,
//     opening a device can act on it);
//   - a symlink: group gid on the link itself and no mode change (a symlink
//     mode is meaningless), and the walk does not descend through it. A root
//     that is itself a symlink is handled the same way and nothing below its
//     target is touched;
//   - the special bits an entry has once its group is set are kept: the
//     sticky bit always, and setuid and setgid unless the chown cleared them,
//     which it does for a caller that is not root.
//
// fchmodat with AT_SYMLINK_NOFOLLOW is what Darwin provides and this runtime
// targets (TestFchmodatNoFollowLeavesTheTarget measures it: the link's own
// mode changes, its target's does not). A system that rejects the flag fails
// the walk on the first non-directory rather than following a link.
//
// The first error stops the walk and is returned. A gid <= 0 is rejected: 0
// (wheel) is never a valid fsGroup target and a negative gid is a programming
// error.
func ChownForFSGroup(bound, root string, gid int) error {
	if gid <= 0 {
		return fmt.Errorf("fsGroup chown: invalid gid %d", gid)
	}
	if !strictlyUnder(root, bound) {
		return fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, root, bound)
	}
	bound, root = filepath.Clean(bound), filepath.Clean(root)
	rel, err := filepath.Rel(bound, root)
	if err != nil {
		return fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, root, bound)
	}
	comps := strings.Split(rel, string(filepath.Separator))

	// The directory holding root, reached from bound one component at a time.
	parent, err := unix.Open(bound, fsGroupDirFlags, 0)
	if err != nil {
		return fmt.Errorf("fsGroup chown: open %s: %w", bound, err)
	}
	defer func() { unix.Close(parent) }()
	at := bound
	for _, c := range comps[:len(comps)-1] {
		at = filepath.Join(at, c)
		next, err := unix.Openat(parent, c, fsGroupDirFlags, 0)
		if err != nil {
			return fmt.Errorf("fsGroup chown: open %s: %w", at, err)
		}
		unix.Close(parent)
		parent = next
	}

	rootFd, isDir, err := fsGroupApply(parent, comps[len(comps)-1], root, gid)
	if err != nil || !isDir {
		return err
	}
	defer unix.Close(rootFd)

	// Depth first, with an explicit stack of directories still to list, each
	// named by its components below root. A directory is re-opened from the
	// pinned root when its turn comes, so the walk holds a fixed handful of
	// descriptors however deep the tree is, and every re-open is again made
	// without following a link.
	pending := [][]string{nil}
	for len(pending) > 0 {
		dir := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		subdirs, err := fsGroupListAndApply(rootFd, root, dir, gid)
		if err != nil {
			return err
		}
		if len(subdirs) > 0 && len(dir)+1 > maxFSGroupDepth {
			return fmt.Errorf("%w: %s nests more than %d directories below %s",
				ErrFSGroupTreeTooDeep, filepath.Join(append([]string{root}, dir...)...), maxFSGroupDepth, root)
		}
		// Pushed in reverse so the walk visits names in lexical order.
		for i := len(subdirs) - 1; i >= 0; i-- {
			child := make([]string, len(dir)+1)
			copy(child, dir)
			child[len(dir)] = subdirs[i]
			pending = append(pending, child)
		}
	}
	return nil
}

// fsGroupListAndApply opens the directory dir (components below the open root
// directory rootFd), applies the fsGroup change to each of its entries, and
// returns the names of the entries that are directories, sorted. The directory
// itself was changed when its parent was listed.
func fsGroupListAndApply(rootFd int, root string, dir []string, gid int) ([]string, error) {
	path := root
	fd, err := unix.Openat(rootFd, ".", fsGroupDirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("fsGroup chown: open %s: %w", path, err)
	}
	for _, c := range dir {
		path = filepath.Join(path, c)
		next, err := unix.Openat(fd, c, fsGroupDirFlags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("fsGroup chown: open %s: %w", path, err)
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("fsGroup chown: read %s: %w", path, err)
	}
	sort.Strings(names)
	var subdirs []string
	for _, name := range names {
		child, isDir, err := fsGroupApply(fd, name, filepath.Join(path, name), gid)
		if err != nil {
			return nil, err
		}
		if isDir {
			unix.Close(child)
			subdirs = append(subdirs, name)
		}
	}
	return subdirs, nil
}

// fsGroupApply applies the fsGroup change to the entry name of the open
// directory parent; path is only for messages. For a directory it returns the
// directory's own open descriptor, which the caller closes, and isDir true.
func fsGroupApply(parent int, name, path string, gid int) (fd int, isDir bool, err error) {
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, false, fmt.Errorf("fsGroup chown %s: %w", path, err)
	}
	if fsGroupBeforeApply != nil {
		fsGroupBeforeApply(path)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		// The link itself, never its target, and no mode change.
		if err := unix.Fchownat(parent, name, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return -1, false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		return -1, false, nil
	case unix.S_IFDIR:
		// Opened first, then changed through the descriptor: what is changed
		// is the directory that was opened, whatever the name means by now. A
		// name that became a link fails the open.
		fd, err := unix.Openat(parent, name, fsGroupDirFlags, 0)
		if err != nil {
			return -1, false, fmt.Errorf("fsGroup chown: open %s: %w", path, err)
		}
		if err := unix.Fchown(fd, -1, gid); err != nil {
			unix.Close(fd)
			return -1, false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		// The mode is read after the chown, as the by-path walk read it: a
		// chown by an unprivileged caller clears setuid and setgid, and the
		// walk must not put them back.
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return -1, false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		if err := unix.Fchmod(fd, fsGroupMode(uint32(st.Mode), true)); err != nil {
			unix.Close(fd)
			return -1, false, fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return fd, true, nil
	default:
		// A file, FIFO, socket or device: changed by name relative to the open
		// parent and without following a link, and never opened. If the name
		// was swapped for a link after the stat above, the chown changes the
		// link, and the second stat sees that the entry is no longer what was
		// listed and stops the walk before any mode is changed.
		kind := st.Mode & unix.S_IFMT
		if err := unix.Fchownat(parent, name, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return -1, false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		// The mode is read after the chown: see the directory case.
		if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return -1, false, fmt.Errorf("fsGroup chown %s: %w", path, err)
		}
		if st.Mode&unix.S_IFMT != kind {
			return -1, false, fmt.Errorf("%w: %s changed kind while it was being walked", ErrFSGroupEntryChanged, path)
		}
		if err := unix.Fchmodat(parent, name, fsGroupMode(uint32(st.Mode), false), unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return -1, false, fmt.Errorf("fsGroup chmod %s: %w", path, err)
		}
		return -1, false, nil
	}
}

// fsGroupMode is the mode an entry with mode st gets: its permission and
// special bits, with the owner's rwx copied to the group, and setgid on a
// directory.
func fsGroupMode(st uint32, isDir bool) uint32 {
	mode := st & 0o7777
	mode |= (mode & 0o700) >> 3
	if isDir {
		mode |= unix.S_ISGID
	}
	return mode
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
