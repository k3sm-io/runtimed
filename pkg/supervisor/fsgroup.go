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
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrFSGroupRootUnbounded is returned when the requested root is not strictly
// inside bound. It is a caller-programming/hostile-input failure, never retried.
var ErrFSGroupRootUnbounded = errors.New("fsGroup chown root is outside the permitted tree")

// ErrFSGroupTreeTooDeep is returned when the tree under root nests deeper than
// maxFSGroupDepth directories.
var ErrFSGroupTreeTooDeep = errors.New("fsGroup chown tree is too deep")

// ErrFSGroupTreeTooLarge is returned when the tree under root holds more
// entries than maxFSGroupEntries, or more directories waiting to be listed
// than maxFSGroupPendingBytes pays for.
var ErrFSGroupTreeTooLarge = errors.New("fsGroup chown tree is too large")

// ErrFSGroupEntryChanged is returned when an entry stopped being what the walk
// listed it as before the walk had finished with it: something is rearranging
// the tree under the walk, and the walk stops.
var ErrFSGroupEntryChanged = errors.New("fsGroup chown entry changed under the walk")

// The walk's bounds. The tree is written by the pod, so each bounds what a pod
// can make the daemon spend, and each fails closed: the walk stops with an
// error before it changes anything past the bound. They are vars so a test can
// lower them.
var (
	// maxFSGroupDepth is how many directories deep the walk goes below root.
	// The by-path walk this replaced stopped at PATH_MAX, about half as deep.
	maxFSGroupDepth = 1024
	// maxFSGroupEntries is how many entries the walk examines in all.
	maxFSGroupEntries = 8 << 20
	// maxFSGroupPendingBytes bounds the memory held for directories that have
	// been changed and are waiting to be listed: each is charged
	// fsGroupNodeCost plus the length of its name. 128 MB is about 1.3 million
	// waiting directories with short names, or half a million with names of
	// the maximum length.
	maxFSGroupPendingBytes = 128 << 20
	// maxFSGroupHeldDirs is how many directory descriptors the walk keeps
	// open: the directories on the way to the one being listed, the deepest
	// ones when the tree is deeper than this.
	maxFSGroupHeldDirs = 32
)

// fsGroupNodeCost is what a waiting directory is charged against
// maxFSGroupPendingBytes besides its name: the node, its allocation and its
// slot in the pending list, rounded up.
const fsGroupNodeCost = 96

// fsGroupContextEvery is how many entries of one directory the walk changes
// between two looks at its context.
const fsGroupContextEvery = 1024

// fsGroupDirFlags opens a directory for the walk: never through a symlink, and
// never blocking, in case the name has become a FIFO or a device by the time
// it is opened.
const fsGroupDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC

// fsGroupFileFlags opens a regular file or a FIFO for the walk. O_NONBLOCK
// makes the open of a FIFO return at once whether or not it has a writer, and
// O_NOCTTY keeps a name that has become a terminal from becoming the daemon's.
const fsGroupFileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC

// fsGroupReportExamples is how many skipped paths a report names, and
// fsGroupExampleMax how long each may be: the report is logged, and the paths
// are the pod's to choose.
const (
	fsGroupReportExamples = 8
	fsGroupExampleMax     = 256
)

// The walk's test seams: each, when set, is called with an entry's path at a
// point where a pod process could rearrange the tree. Production leaves them
// nil.
var (
	// fsGroupBeforeApply runs after the walk has read what an entry is and
	// before it opens or changes it.
	fsGroupBeforeApply func(path string)
	// fsGroupBeforeChmod runs after an entry's group is set and before its
	// mode is.
	fsGroupBeforeChmod func(path string)
	// fsGroupOnPathBuild runs each time the walk builds a directory's path
	// from its nodes, which costs time in proportion to its depth.
	fsGroupOnPathBuild func()
)

// FSGroupReport says what a walk did not change, and why. A skipped entry is
// not an error: the pod starts, and the entry keeps the group and mode it had.
type FSGroupReport struct {
	// Changed counts the entries whose group (and, unless a symlink, mode)
	// the walk set.
	Changed int
	// MultiLink counts regular files, FIFOs and symlinks with more than one
	// hard link.
	MultiLink int
	// Special counts sockets, device nodes and anything else the walk does
	// not open.
	Special int
	// OtherDevice counts directories on a different device from root: a
	// mount point, which the walk does not cross.
	OtherDevice int
	// Unopenable counts regular files and FIFOs the daemon could not open
	// (it has no read permission on them, which cannot happen to root).
	Unopenable int
	// Vanished counts entries that were gone when the walk reached them,
	// and directories that were gone when their turn to be listed came. What
	// lay below such a directory was not changed.
	Vanished int
	// SetID counts files with the setuid or setgid bit. They get the group
	// and the owner's read and execute bits, and are not made group-writable:
	// whoever can write such a file can run code as its owner or group. They
	// are counted in Changed, not in Skipped.
	SetID int
	// Examples names up to fsGroupReportExamples of the entries counted in
	// the fields after Changed, each as "<reason>: <path>", cut to
	// fsGroupExampleMax bytes.
	Examples []string
}

// Skipped is the number of entries the walk left as they were.
func (r FSGroupReport) Skipped() int {
	return r.MultiLink + r.Special + r.OtherDevice + r.Unopenable + r.Vanished
}

// note counts one entry under counter and, while there is room, names it. The
// path is built only when it is kept: building one costs time in proportion to
// the entry's depth, and a pod chooses both the depth and how many entries are
// noted.
func (r *FSGroupReport) note(counter *int, reason string, path func() string) {
	*counter++
	if len(r.Examples) >= fsGroupReportExamples {
		return
	}
	ex := reason + ": " + path()
	if len(ex) > fsGroupExampleMax {
		ex = ex[:fsGroupExampleMax-3] + "..."
	}
	r.Examples = append(r.Examples, ex)
}

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
// invert that layering. bound itself is the caller's to vouch for: it must be
// a directory the pod cannot replace.
//
// The tree is the pod's, and the walk trusts nothing in it. A pod can replace
// its rootfs, or any directory or file under it, with a symlink or with a hard
// link to a file elsewhere, and a process of an earlier instance of the pod can
// still be running while the next one is created. So:
//
//   - Nothing below bound is resolved by path. bound is opened without
//     following a link, and every directory from there down is opened with
//     O_NOFOLLOW relative to the open directory above it.
//   - Every entry is changed through a descriptor opened on it, never by name:
//     the entry is opened, what was opened is examined (fstat), and the group
//     and mode are set on that same descriptor (fchown, fchmod), with the mode
//     read from it. What a name means after the open cannot matter.
//   - An entry with more than one hard link is skipped. A second link may lie
//     outside the tree, where the file is somebody else's, and the walk cannot
//     tell: counting the links it meets is no proof against a process that
//     moves one while the walk runs. The check covers the links that exist
//     when the entry is opened and examined. It does not cover a link made
//     between that fstat and the fchown, which needs no second layer: the
//     file had one link, inside the tree, so it was the pod's own, and a link
//     the pod adds to its own file gives it nothing. Nor does it cover a file
//     MOVED into the tree, which keeps one link. The profile denies a pod a
//     link to a file outside its rootfs (pkg/sandbox
//     TestPodHardLinkIntoItsRootfsUnderSandboxExec measures that for the
//     cases it lists); the skip is a second layer behind that.
//   - A directory on another device than root is a mount point; it is skipped
//     and not entered.
//   - Sockets and device nodes are skipped: a socket cannot be opened, and
//     opening a device can act on it.
//   - An entry that is no longer the kind of file it was listed as stops the
//     walk (ErrFSGroupEntryChanged), and so does a listed directory that
//     cannot be opened as one, or that is a different directory when its turn
//     to be listed comes. An entry or a waiting directory that is gone by
//     then is passed over and counted (FSGroupReport.Vanished): nothing is
//     changed by not changing it, and the report says a subtree may have been
//     left as it was.
//
// What the walk gives each kind of entry it does change is what the by-path
// walk gave a tree nobody was rearranging:
//
//   - a directory: group gid, the owner's rwx copied to the group, and setgid,
//     so files created later inherit the group;
//   - a regular file or FIFO: group gid and the owner's rwx copied to the
//     group. A FIFO is opened non-blocking, which returns at once. A file
//     that still has the setuid or setgid bit once its group is set (it does
//     when the caller is root) gets the owner's read and execute bits and
//     not write: a group that could write it could run code as its owner;
//   - a symlink: group gid on the link itself (it is opened as a link) and no
//     mode change, and the walk does not go through it. A root that is itself
//     a symlink is handled the same way and nothing below its target is
//     touched. On a system that cannot open a symlink as itself, links are
//     left alone;
//   - the special bits an entry has once its group is set are kept: the
//     sticky bit always, and setuid and setgid unless the chown cleared them,
//     which it does for a caller that is not root.
//
// It differs from that walk in what it skips (above), in not making a setuid
// or setgid file group-writable, and in refusing a symlinked directory between
// bound and root, which the by-path walk followed. The report says what was
// skipped; the caller logs it.
//
// The walk is bounded (see maxFSGroupDepth and the bounds beside it), keeps at
// most maxFSGroupHeldDirs directories open however deep the tree is, and
// looks at ctx at every directory and every fsGroupContextEvery entries. It
// has no time bound of its own; the context is the caller's. The first error
// stops it. A gid <= 0 is
// rejected: 0 (wheel) is never a valid fsGroup target and a negative gid is a
// programming error.
func ChownForFSGroup(ctx context.Context, bound, root string, gid int) (FSGroupReport, error) {
	var rep FSGroupReport
	if gid <= 0 {
		return rep, fmt.Errorf("fsGroup chown: invalid gid %d", gid)
	}
	if !strictlyUnder(root, bound) {
		return rep, fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, root, bound)
	}
	bound, root = filepath.Clean(bound), filepath.Clean(root)
	rel, err := filepath.Rel(bound, root)
	if err != nil {
		return rep, fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, root, bound)
	}
	comps := strings.Split(rel, string(filepath.Separator))

	// The directory holding root, reached from bound one component at a time.
	parent, err := unix.Open(bound, fsGroupDirFlags, 0)
	if err != nil {
		return rep, fmt.Errorf("fsGroup chown: open %s: %w", bound, err)
	}
	defer func() { unix.Close(parent) }()
	at := bound
	for _, c := range comps[:len(comps)-1] {
		at = filepath.Join(at, c)
		next, err := unix.Openat(parent, c, fsGroupDirFlags, 0)
		if err != nil {
			return rep, fmt.Errorf("fsGroup chown: open %s: %w", at, err)
		}
		unix.Close(parent)
		parent = next
	}

	w := &fsGroupWalk{ctx: ctx, gid: gid, root: root, rep: &rep}
	defer w.closeHeld()
	rootNode, err := w.apply(parent, comps[len(comps)-1], nil, func() string { return root })
	if err != nil || rootNode == nil {
		return rep, err
	}
	return rep, w.walk(parent, comps[len(comps)-1], rootNode)
}

// fsGroupNode is a directory the walk has changed and has still to list: its
// name in its parent, and the device and inode it had when it was changed, so
// that what is opened under that name later is known to be the same directory.
type fsGroupNode struct {
	parent   *fsGroupNode
	name     string
	dev, ino uint64
	depth    int // 0 for root
}

// cost is what the node is charged against maxFSGroupPendingBytes.
func (n *fsGroupNode) cost() int { return fsGroupNodeCost + len(n.name) }

// path is the node's path, for messages. It costs time in proportion to the
// node's depth, so the walk builds one only for an error it is about to
// return, a kept example or a test seam, and at most once per directory
// listing.
func (n *fsGroupNode) path(root string) string {
	if fsGroupOnPathBuild != nil {
		fsGroupOnPathBuild()
	}
	if n == nil || n.parent == nil {
		return root
	}
	names := make([]string, n.depth+1)
	names[0] = root
	for m := n; m.parent != nil; m = m.parent {
		names[m.depth] = m.name
	}
	return strings.Join(names, string(filepath.Separator))
}

// fsGroupHeld is one directory the walk keeps open.
type fsGroupHeld struct {
	node *fsGroupNode
	fd   int
}

// fsGroupWalk is the state of one walk.
type fsGroupWalk struct {
	ctx     context.Context
	gid     int
	root    string
	rep     *FSGroupReport
	rootDev uint64
	rootSet bool
	// entries counts every entry examined, against maxFSGroupEntries.
	entries int
	// pending is the directories changed and waiting to be listed, the next
	// one last, and pendingBytes what they are charged in all.
	pending      []*fsGroupNode
	pendingBytes int
	// held is the chain of open directories from root (held[0], always
	// kept) towards the directory being listed, shallowest first. When the
	// chain is longer than maxFSGroupHeldDirs the shallowest below root are
	// closed, and re-opened from root if the walk comes back to them.
	held []fsGroupHeld
}

func (w *fsGroupWalk) closeHeld() {
	for _, h := range w.held {
		unix.Close(h.fd)
	}
	w.held = nil
}

func (w *fsGroupWalk) ctxErr() error {
	if err := w.ctx.Err(); err != nil {
		return fmt.Errorf("fsGroup chown %s: %w", w.root, err)
	}
	return nil
}

// walk lists root and everything below it, depth first. rootParent and
// rootName are where root was opened from.
func (w *fsGroupWalk) walk(rootParent int, rootName string, rootNode *fsGroupNode) error {
	fd, err := w.openNode(rootParent, rootName, rootNode)
	if err != nil {
		return err
	}
	if fd < 0 {
		// Root went away between being changed and being listed.
		w.rep.note(&w.rep.Vanished, "gone before it was listed", func() string { return w.root })
		return nil
	}
	w.held = append(w.held, fsGroupHeld{node: rootNode, fd: fd})

	w.pending = []*fsGroupNode{rootNode}
	w.pendingBytes = rootNode.cost()
	for len(w.pending) > 0 {
		if err := w.ctxErr(); err != nil {
			return err
		}
		dir := w.pending[len(w.pending)-1]
		w.pending = w.pending[:len(w.pending)-1]
		w.pendingBytes -= dir.cost()
		fd, err := w.hold(dir)
		if err != nil {
			return err
		}
		listed := fd >= 0
		if listed {
			if listed, err = w.list(fd, dir); err != nil {
				return err
			}
		}
		if !listed {
			// The directory, or one above it that had to be re-opened, is
			// gone: whatever was below it stays as it was.
			w.rep.note(&w.rep.Vanished, "gone before it was listed", func() string { return dir.path(w.root) })
		}
	}
	return nil
}

// list changes every entry of the open directory dir and adds the directories
// among them to the pending list. It reports false when the directory was
// removed before it could be read.
func (w *fsGroupWalk) list(fd int, dir *fsGroupNode) (bool, error) {
	// The directory's path is built at most once however many of its entries
	// need one.
	var dirPath string
	var havePath bool
	pathOfDir := func() string {
		if !havePath {
			dirPath, havePath = dir.path(w.root), true
		}
		return dirPath
	}
	// A descriptor of its own for reading, so that the held one keeps no read
	// position.
	rd, err := unix.Openat(fd, ".", fsGroupDirFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("fsGroup chown: open %s: %w", pathOfDir(), err)
	}
	defer unix.Close(rd)
	buf := make([]byte, 32<<10)
	names := make([]string, 0, 256)
	sinceCtx := 0
	for {
		n, err := unix.ReadDirent(rd, buf)
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("fsGroup chown: read %s: %w", pathOfDir(), err)
		}
		if n <= 0 {
			return true, nil
		}
		names = names[:0]
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
		for _, name := range names {
			if sinceCtx++; sinceCtx >= fsGroupContextEvery {
				sinceCtx = 0
				if err := w.ctxErr(); err != nil {
					return false, err
				}
			}
			child, err := w.apply(fd, name, dir, func() string {
				return pathOfDir() + string(filepath.Separator) + name
			})
			if err != nil {
				return false, err
			}
			if child != nil {
				w.pending = append(w.pending, child)
				w.pendingBytes += child.cost()
			}
		}
	}
}

// hold returns an open descriptor for dir, which stays owned by the walk. It
// keeps the directories on the way to dir open and closes the ones that are
// not on that way. A directory that has to be re-opened is checked against the
// device and inode recorded when it was changed. It returns -1 when dir, or a
// directory above it that had to be re-opened, is gone.
func (w *fsGroupWalk) hold(dir *fsGroupNode) (int, error) {
	// chain[d] is dir's ancestor at depth d; chain[dir.depth] is dir.
	chain := make([]*fsGroupNode, dir.depth+1)
	for n := dir; n != nil; n = n.parent {
		chain[n.depth] = n
	}
	// Keep the held directories that are on the chain; they are a prefix of
	// held, because held is itself a chain.
	keep := 0
	for keep < len(w.held) && w.held[keep].node.depth <= dir.depth && chain[w.held[keep].node.depth] == w.held[keep].node {
		keep++
	}
	for _, h := range w.held[keep:] {
		unix.Close(h.fd)
	}
	w.held = w.held[:keep]
	last := w.held[len(w.held)-1]
	for d := last.node.depth + 1; d <= dir.depth; d++ {
		fd, err := w.openNode(last.fd, chain[d].name, chain[d])
		if err != nil {
			return -1, err
		}
		if fd < 0 {
			return -1, nil
		}
		if len(w.held) >= maxFSGroupHeldDirs {
			// Close the shallowest below root; the open of chain[d] above was
			// made relative to the deepest, which stays.
			unix.Close(w.held[1].fd)
			w.held = append(w.held[:1], w.held[2:]...)
		}
		last = fsGroupHeld{node: chain[d], fd: fd}
		w.held = append(w.held, last)
	}
	return last.fd, nil
}

// openNode opens the directory node by its name under the open directory
// parent, and checks it is the directory that was changed under that name. It
// returns -1 when the name is gone.
func (w *fsGroupWalk) openNode(parent int, name string, node *fsGroupNode) (int, error) {
	fd, err := unix.Openat(parent, name, fsGroupDirFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, nil
	}
	if err != nil {
		return -1, fmt.Errorf("%w: open %s: %v", ErrFSGroupEntryChanged, node.path(w.root), err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("fsGroup chown %s: %w", node.path(w.root), err)
	}
	if uint64(st.Dev) != node.dev || uint64(st.Ino) != node.ino {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: %s is not the directory the walk changed", ErrFSGroupEntryChanged, node.path(w.root))
	}
	return fd, nil
}

// apply changes the entry name of the open directory parent, which is the
// directory dir (nil when the entry is root itself). path builds the entry's
// path and is called only for an error, a kept example or a test seam. For a
// directory apply returns the node to list later; for anything else, and for
// an entry it skipped, nil.
func (w *fsGroupWalk) apply(parent int, name string, dir *fsGroupNode, path func() string) (*fsGroupNode, error) {
	node := &fsGroupNode{parent: dir, name: name}
	if dir != nil {
		node.depth = dir.depth + 1
	}
	w.entries++
	if w.entries > maxFSGroupEntries {
		return nil, fmt.Errorf("%w: more than %d entries under %s", ErrFSGroupTreeTooLarge, maxFSGroupEntries, w.root)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if dir != nil && errors.Is(err, unix.ENOENT) {
			w.rep.note(&w.rep.Vanished, "gone before it was changed", path)
			return nil, nil
		}
		return nil, fmt.Errorf("fsGroup chown %s: %w", path(), err)
	}
	kind := uint32(st.Mode) & unix.S_IFMT
	if kind == unix.S_IFDIR {
		// Both bounds are checked before the directory is opened, so a
		// directory past either is not changed.
		if node.depth > maxFSGroupDepth {
			return nil, fmt.Errorf("%w: %s nests more than %d directories below %s",
				ErrFSGroupTreeTooDeep, path(), maxFSGroupDepth, w.root)
		}
		if w.pendingBytes+node.cost() > maxFSGroupPendingBytes {
			return nil, fmt.Errorf("%w: the directories waiting to be listed under %s need more than %d bytes",
				ErrFSGroupTreeTooLarge, w.root, maxFSGroupPendingBytes)
		}
	}
	if fsGroupBeforeApply != nil {
		fsGroupBeforeApply(path())
	}

	var flags int
	switch kind {
	case unix.S_IFDIR:
		flags = fsGroupDirFlags
	case unix.S_IFREG, unix.S_IFIFO:
		flags = fsGroupFileFlags
	case unix.S_IFLNK:
		if !fsGroupCanOpenLinks {
			return nil, nil
		}
		flags = fsGroupLinkFlags
	default:
		w.rep.note(&w.rep.Special, "a socket or device", path)
		return nil, nil
	}
	fd, err := unix.Openat(parent, name, flags, 0)
	switch {
	case err == nil:
	case dir != nil && errors.Is(err, unix.ENOENT):
		w.rep.note(&w.rep.Vanished, "gone before it was changed", path)
		return nil, nil
	case kind != unix.S_IFDIR && errors.Is(err, unix.EACCES):
		w.rep.note(&w.rep.Unopenable, "not readable by the daemon", path)
		return nil, nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return nil, fmt.Errorf("%w: open %s: %v", ErrFSGroupEntryChanged, path(), err)
	default:
		return nil, fmt.Errorf("fsGroup chown: open %s: %w", path(), err)
	}
	defer unix.Close(fd)

	// From here on only the descriptor is used: what was opened is what is
	// examined and what is changed.
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fsGroup chown %s: %w", path(), err)
	}
	if uint32(st.Mode)&unix.S_IFMT != kind {
		return nil, fmt.Errorf("%w: %s changed kind while it was being walked", ErrFSGroupEntryChanged, path())
	}
	if kind == unix.S_IFDIR {
		if !w.rootSet {
			w.rootDev, w.rootSet = uint64(st.Dev), true
		} else if uint64(st.Dev) != w.rootDev {
			w.rep.note(&w.rep.OtherDevice, "a directory on another device", path)
			return nil, nil
		}
	} else if st.Nlink > 1 {
		w.rep.note(&w.rep.MultiLink, "more than one hard link", path)
		return nil, nil
	}
	if err := unix.Fchown(fd, -1, w.gid); err != nil {
		return nil, fmt.Errorf("fsGroup chown %s: %w", path(), err)
	}
	w.rep.Changed++
	if kind == unix.S_IFLNK {
		return nil, nil // a symlink's mode is meaningless
	}
	if fsGroupBeforeChmod != nil {
		fsGroupBeforeChmod(path())
	}
	// The mode is read after the chown, as the by-path walk read it: a chown
	// by an unprivileged caller clears setuid and setgid, and the walk must
	// not put them back.
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fsGroup chown %s: %w", path(), err)
	}
	mode, withheld := fsGroupMode(uint32(st.Mode), kind == unix.S_IFDIR)
	if withheld {
		w.rep.note(&w.rep.SetID, "setuid or setgid, not made group-writable", path)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return nil, fmt.Errorf("fsGroup chmod %s: %w", path(), err)
	}
	if kind != unix.S_IFDIR {
		return nil, nil
	}
	node.dev, node.ino = uint64(st.Dev), uint64(st.Ino)
	return node, nil
}

// fsGroupMode is the mode an entry with mode st gets: its permission and
// special bits with the owner's rwx copied to the group, and setgid on a
// directory. A file that is setuid or setgid does not get the owner's write
// bit copied (a group that can write such a file can run code as its owner or
// group); withheld reports that this left the group without a write bit the
// owner has. A group write bit the file already had is not taken away.
func fsGroupMode(st uint32, isDir bool) (mode uint32, withheld bool) {
	mode = st & 0o7777
	grant := (mode & 0o700) >> 3
	if isDir {
		return mode | grant | unix.S_ISGID, false
	}
	if mode&(unix.S_ISUID|unix.S_ISGID) != 0 && grant&0o020 != 0 {
		grant &^= 0o020
		withheld = mode&0o020 == 0
	}
	return mode | grant, withheld
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
