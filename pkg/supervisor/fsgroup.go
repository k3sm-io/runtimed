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
	"math"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/pathsafe"
)

// ErrFSGroupRootUnbounded is returned when the requested root is not strictly
// inside bound. It is a caller-programming/hostile-input failure, never retried.
var ErrFSGroupRootUnbounded = errors.New("fsGroup chown root is outside the permitted tree")

// ErrFSGroupTreeTooDeep is returned when the tree under root nests deeper than
// maxFSGroupDepth directories.
var ErrFSGroupTreeTooDeep = errors.New("fsGroup chown tree is too deep")

// ErrFSGroupTreeTooLarge is returned when the tree under root holds more
// entries than maxFSGroupEntries (with the directories the walk re-opens
// charged against the same budget), or more directories waiting to be listed
// than maxFSGroupPendingBytes pays for.
var ErrFSGroupTreeTooLarge = errors.New("fsGroup chown tree is too large")

// ErrFSGroupEntryChanged is returned when an entry stopped being what the walk
// listed it as before the walk had finished with it, or when root itself is
// gone before it is listed: something is rearranging the tree under the walk,
// and the walk stops.
var ErrFSGroupEntryChanged = errors.New("fsGroup chown entry changed under the walk")

// ErrFSGroupForeignOwner is returned when root itself is owned by a uid outside
// the owners the caller names: the tree is not the pod's to regroup.
var ErrFSGroupForeignOwner = errors.New("fsGroup chown root is owned by a uid the pod does not run as")

// ErrFSGroupGidRefused is returned for a gid the walk will not hand a pod's
// tree to (FSGroupGidAllowed).
var ErrFSGroupGidRefused = errors.New("fsGroup gid is not one a pod may be given")

// fsGroupMinGid is the lowest gid the allow-list admits by default. macOS
// assigns its own groups below 500 (staff, admin, everyone, certusers,
// _developer, _analyticsusers, the com.apple.access_ groups and the rest),
// and the groups an administrator or an installer makes start at 501; 1000
// leaves a margin above both, and is where Kubernetes fsGroup values start
// in practice.
const fsGroupMinGid = 1000

// fsGroupNeverGids are refused even when the caller admits them: the groups
// whose membership is a privilege on any macOS host (wheel is refused with
// every gid <= 0).
var fsGroupNeverGids = map[int]string{
	1:   "daemon",
	2:   "kmem",
	3:   "sys",
	4:   "tty",
	5:   "operator",
	8:   "procview",
	9:   "procmod",
	20:  "staff",
	80:  "admin",
	204: "_developer",
}

// GroupLookup reports the name of the group the host assigns to gid, with
// ok false when the host assigns it none. An error is any failure but "no
// such group", and a caller refuses on it. LookupGroupID is the production
// one; a nil GroupLookup means it.
type GroupLookup func(gid int) (name string, ok bool, err error)

// LookupGroupID is the production GroupLookup. It asks the system's directory
// services (getgrgid, through user.LookupGroupId), so groups that live only
// there, not in /etc/group, count too. "No such group" answers ok false and
// no error.
func LookupGroupID(gid int) (string, bool, error) {
	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err == nil {
		return g.Name, true, nil
	}
	var unknown user.UnknownGroupIdError
	if errors.As(err, &unknown) {
		return "", false, nil
	}
	return "", false, err
}

// or returns lookup, or LookupGroupID when lookup is nil.
func (lookup GroupLookup) or() GroupLookup {
	if lookup == nil {
		return LookupGroupID
	}
	return lookup
}

// FSGroupGidAllowed says whether a pod may be given gid as its fsGroup: it
// becomes a supplementary group of every process of the pod, and the walk
// gives it the owner's access to the pod's tree. It is an allow-list. A gid
// is allowed when it is in 1..MaxInt32 (a gid_t is 32 bits, and a larger
// value would be cut short in the chown), is not one of fsGroupNeverGids, and
// either the caller admits it (admitted: the node's own list of gids it means
// pods to have) or it is at least fsGroupMinGid and names no group on this
// host. A gid with no group gives its members access to nothing but the
// files given to it, so membership grants a pod no more than its own tree;
// an existing group may own files elsewhere, so it is allowed only when the
// node names it. The group lookup is LookupGroupID, and a lookup that fails
// for any reason but "no such group" refuses.
func FSGroupGidAllowed(gid int, admitted []int) error {
	return FSGroupGidAllowedWith(gid, admitted, nil)
}

// FSGroupGidAllowedWith is FSGroupGidAllowed with the group lookup it asks
// (LookupGroupID when nil).
func FSGroupGidAllowedWith(gid int, admitted []int, lookup GroupLookup) error {
	if gid <= 0 || gid > math.MaxInt32 {
		return fmt.Errorf("%w: gid %d is outside 1..%d", ErrFSGroupGidRefused, gid, math.MaxInt32)
	}
	if name, ok := fsGroupNeverGids[gid]; ok {
		return fmt.Errorf("%w: gid %d (%s) is a system group", ErrFSGroupGidRefused, gid, name)
	}
	if slices.Contains(admitted, gid) {
		return nil
	}
	if gid < fsGroupMinGid {
		return fmt.Errorf("%w: gid %d is below %d, where macOS and installers assign groups, and the node does not admit it", ErrFSGroupGidRefused, gid, fsGroupMinGid)
	}
	name, assigned, err := lookup.or()(gid)
	if err != nil {
		return fmt.Errorf("%w: gid %d: look up the group: %v", ErrFSGroupGidRefused, gid, err)
	}
	if assigned {
		return fmt.Errorf("%w: gid %d is the group %q on this host, and the node does not admit it", ErrFSGroupGidRefused, gid, name)
	}
	return nil
}

// FSGroupOwners says whose entries the walk changes. UIDs are the uids whose
// entries it regroups. InGroup are uids whose entries it changes only when
// they already carry the walk's gid, and then only their mode (the group is
// already the one asked for): it is for a daemon running as root whose pods
// drop to other uids, where an entry root owns and the daemon did not make
// for the pod must keep its group (see ChownForFSGroup and
// PrepareFSGroupRoot). A uid in both is in UIDs.
type FSGroupOwners struct {
	UIDs, InGroup []int
}

// The walk's bounds. The tree is written by the pod, so each bounds what a pod
// can make the daemon spend, and each fails closed: the walk stops with an
// error at the bound. The entries it changed before the bound stay changed, a
// partial state the caller's failed create discards; nothing at or past the
// bound is changed. A walk runs under them through fsGroupTuning, which only
// this package's tests set to anything else.
const (
	// maxFSGroupDepth is how many directories deep the walk goes below root.
	// The by-path walk this replaced stopped at PATH_MAX, about half as deep.
	maxFSGroupDepth = 1024
	// maxFSGroupEntries is how many entries the walk examines in all, plus
	// how many directory levels it re-opens to get back to a directory whose
	// ancestors it had to close (see maxFSGroupHeldDirs). Each of either costs
	// a bounded number of system calls, so the walk makes at most a few times
	// this many, whatever the tree's shape.
	maxFSGroupEntries = 8 << 20
	// maxFSGroupPendingBytes bounds the memory held for directories that have
	// been changed and are waiting to be listed: each is charged
	// fsGroupNodeCost plus the length of its name. 128 MiB is about 1.38
	// million waiting directories with one-byte names (128 MiB / 97), or about
	// 382 thousand with names of the maximum length (128 MiB / (96 + 255)).
	maxFSGroupPendingBytes = 128 << 20
	// maxFSGroupHeldDirs is how many directory descriptors the walk keeps
	// open: the directories on the way to the one being listed, the deepest
	// ones when the tree is deeper than this. A directory closed this way is
	// re-opened, level by level from the deepest held ancestor, when the walk
	// comes back below it, and each level is charged to maxFSGroupEntries.
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
// It is pathsafe.DirFlags.
const fsGroupDirFlags = pathsafe.DirFlags

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

// fsGroupTuning is what one walk runs under besides its arguments: its bounds
// and its test seams. ChownForFSGroup always walks under fsGroupDefaults (the
// constants above and no seams); only this package's tests build another and
// call chownForFSGroup with it, so nothing in a production binary can lower a
// bound or install a seam.
type fsGroupTuning struct {
	depth, entries, pendingBytes, heldDirs int

	// The seams, each called, when set, at a point where a pod process could
	// rearrange the tree. beforeApply runs after the walk has read what an
	// entry is and before it opens or changes it; beforeChmod after an
	// entry's group is set and before its mode is.
	beforeApply, beforeChmod func(path string)
	// onPathBuild runs each time the walk builds a directory's path from its
	// nodes, which costs time in proportion to its depth; onReopen each time
	// it re-opens a directory level it had closed, before the open.
	onPathBuild, onReopen func()
	// ownerOf replaces the owner the walk read from an opened entry: an
	// unprivileged test cannot make a file another uid owns.
	ownerOf func(path string, uid uint32) uint32
}

// fsGroupDefaults is the tuning every production walk runs under.
func fsGroupDefaults() fsGroupTuning {
	return fsGroupTuning{
		depth:        maxFSGroupDepth,
		entries:      maxFSGroupEntries,
		pendingBytes: maxFSGroupPendingBytes,
		heldDirs:     maxFSGroupHeldDirs,
	}
}

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
	// not open, which includes symlinks on a system that cannot open a link
	// as itself.
	Special int
	// OtherDevice counts directories on a different device from root: a
	// mount point, which the walk does not cross.
	OtherDevice int
	// Unopenable counts regular files and FIFOs the daemon could not open
	// (it has no read permission on them, which cannot happen to root).
	Unopenable int
	// Vanished counts entries that were gone when the walk reached them,
	// and directories below root that were gone when their turn to be listed
	// came. What lay below such a directory was not changed. Root itself
	// being gone is an error, not a count.
	Vanished int
	// ForeignOwner counts entries owned by a uid outside the owners the
	// caller named: something put there from outside the pod's own content,
	// such as an entry renamed in from a writable share. A directory counted
	// here is not entered.
	ForeignOwner int
	// SetID counts files whose setuid or setgid bit the walk cleared before
	// setting their group, as a chown on Linux does: a file the pod wrote
	// must not become setgid to the fsGroup, or setuid to its owner with a
	// group that can write it. They are counted in Changed, not in Skipped.
	SetID int
	// Examples names up to fsGroupReportExamples of the entries counted in
	// the fields after Changed, each as "<reason>: <path>", cut to
	// fsGroupExampleMax bytes.
	Examples []string
}

// Skipped is the number of entries the walk left as they were.
func (r FSGroupReport) Skipped() int {
	return r.MultiLink + r.Special + r.OtherDevice + r.Unopenable + r.Vanished + r.ForeignOwner
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
	r.Examples = append(r.Examples, fsGroupClip(reason+": "+path()))
}

// fsGroupClip cuts s to fsGroupExampleMax bytes, on a UTF-8 boundary. Every
// path the walk puts in an example or an error goes through it: the paths are
// the pod's to choose, and both end up in the daemon's log.
func fsGroupClip(s string) string {
	if len(s) <= fsGroupExampleMax {
		return s
	}
	n := fsGroupExampleMax - 3
	// Back off to the start of a rune, at most utf8.UTFMax-1 bytes: a name
	// that is not UTF-8 at all is still cut near the limit.
	for i := 0; i < utf8.UTFMax-1 && n > 0 && !utf8.RuneStart(s[n]); i++ {
		n--
	}
	return s[:n] + "..."
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
// still be running while the next one is created. What the walk guarantees is
// that everything it changes is an inode that had a name in the tree when the
// walk opened it (and, for a file, no other name) and is owned by one of the
// uids in owners.UIDs, or by one in owners.InGroup and in gid already. The
// caller names those: the uids the pod's processes run as and the uid that
// owns the content the daemon put in the tree. A daemon running as root whose
// pod drops to other uids does not put root in owners.UIDs, since every file
// root owns anywhere on the volume would then be the walk's to regroup: it
// gives the pod's root (PrepareFSGroupRoot) the group before it puts anything
// there, so what it puts there carries the group, and names root in
// owners.InGroup. An inode
// renamed into the tree from outside it keeps its one link, and the sandbox
// does not stop that from a location the pod may write: pkg/sandbox
// TestPodRenameIntoItsRootfsUnderSandboxExec measures a file and a directory
// moved in from a read-write host share (the same holds for any writable
// volume on the same file system). The owner check is what keeps such an
// entry, when another tenant owns it, from being regrouped; one owned by a uid
// in owners is not told apart from the pod's own. So pods that run as the
// same uid are one trust domain to the walk: the owner check cannot keep one
// from having the walk regroup an entry another made (on the shipped posture
// every pod runs as the service user, so every pod is in one such domain),
// and only the sandbox keeps a pod from reaching another's tree. A subtree the walk holds
// open that is renamed out of the tree while it is held is not covered: the
// walk goes on inside it, still changing only entries owned by owners. So:
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
//     between that fstat and the fchown: a link the pod adds then, to a file
//     in owners' hands, gives it nothing it could not do to that file
//     already. Nor does it cover a file MOVED into the tree, which keeps one
//     link (the owner check below covers that). The profile denies a pod a
//     link to a file outside its rootfs except in a location it may write
//     (pkg/sandbox TestPodHardLinkIntoItsRootfsUnderSandboxExec measures the
//     cases it lists, a read-write share among them).
//   - An entry owned by a uid outside owners is skipped and counted
//     (FSGroupReport.ForeignOwner), and a directory so owned is not entered.
//     A root so owned is an error (ErrFSGroupForeignOwner).
//   - A directory on another device than root is a mount point; it is skipped
//     and not entered.
//   - Sockets and device nodes are skipped: a socket cannot be opened, and
//     opening a device can act on it. The kind is read with fstatat before
//     the open, so a name swapped for a device node between the two is opened
//     once (non-blocking, never as a controlling terminal) before the fstat
//     of the descriptor sees the change and stops the walk. That one open is
//     the residual. Only a pod process running as root can make a device node
//     (mknod), and none can rename or link one in from /dev, which is another
//     file system.
//   - An entry that is no longer the kind of file it was listed as stops the
//     walk (ErrFSGroupEntryChanged), and so does a listed directory that
//     cannot be opened as one, or that is a different directory when its turn
//     to be listed comes, and so does root being gone before it is listed. An
//     entry or a waiting directory below root that is gone by then is passed
//     over and counted (FSGroupReport.Vanished): nothing is changed by not
//     changing it, and the report says a subtree may have been left as it
//     was.
//
// What the walk gives each kind of entry it does change is what the by-path
// walk gave a tree nobody was rearranging:
//
//   - a directory: group gid, the owner's rwx copied to the group, and setgid,
//     so files created later inherit the group;
//   - a regular file or FIFO: group gid and the owner's rwx copied to the
//     group. A FIFO is opened non-blocking, which returns at once. Its setuid
//     and setgid bits are cleared before its group is set, as a chown on
//     Linux clears them, and the walk counts that (FSGroupReport.SetID): on
//     Darwin a chown by root keeps them, and a file the pod wrote would come
//     out setgid to the fsGroup;
//   - a symlink: group gid on the link itself (it is opened as a link) and no
//     mode change, and the walk does not go through it. A root that is itself
//     a symlink is handled the same way and nothing below its target is
//     touched. On a system that cannot open a symlink as itself, links are
//     left alone and counted in FSGroupReport.Special;
//   - the sticky bit is kept, and a directory's setuid bit.
//
// It differs from that walk in what it skips (above), in clearing setuid and
// setgid on what is not a directory (the by-path walk kept them when it ran as
// root), and in refusing a symlinked directory between bound and root, which
// the by-path walk followed. The report says what was
// skipped; the caller logs it.
//
// The walk is bounded (see maxFSGroupDepth and the bounds beside it), keeps at
// most maxFSGroupHeldDirs directories open however deep the tree is, and
// looks at ctx at every directory, every fsGroupContextEvery entries and every
// directory level it re-opens. It has no time bound of its own; the context is
// the caller's. The first error stops it, and the paths in errors are cut to
// fsGroupExampleMax bytes. A gid FSGroupGidAllowed refuses (admitted is the
// node's own list of gids it admits) is refused with ErrFSGroupGidRefused
// before anything is opened, and an empty owners.UIDs, or a uid outside
// 0..MaxInt32 in either list, is a programming error.
func ChownForFSGroup(ctx context.Context, bound, root string, gid int, owners FSGroupOwners, admitted []int) (FSGroupReport, error) {
	if err := FSGroupGidAllowed(gid, admitted); err != nil {
		return FSGroupReport{}, err
	}
	return chownForFSGroup(ctx, bound, root, gid, owners, fsGroupDefaults())
}

// fsGroupUIDs is uids as a set, refusing an empty list where need is set and
// any uid outside 0..MaxInt32 (a uid_t is 32 bits).
func fsGroupUIDs(uids []int, need bool, what string) (map[uint32]bool, error) {
	if need && len(uids) == 0 {
		return nil, fmt.Errorf("fsGroup chown: no %s named", what)
	}
	set := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		if u < 0 || u > math.MaxInt32 {
			return nil, fmt.Errorf("fsGroup chown: invalid %s uid %d", what, u)
		}
		set[uint32(u)] = true
	}
	return set, nil
}

// chownForFSGroup is ChownForFSGroup after the gid policy, under tune.
func chownForFSGroup(ctx context.Context, bound, root string, gid int, owners FSGroupOwners, tune fsGroupTuning) (FSGroupReport, error) {
	var rep FSGroupReport
	if gid <= 0 || gid > math.MaxInt32 {
		return rep, fmt.Errorf("fsGroup chown: invalid gid %d", gid)
	}
	owned, err := fsGroupUIDs(owners.UIDs, true, "owner")
	if err != nil {
		return rep, err
	}
	inGroup, err := fsGroupUIDs(owners.InGroup, false, "in-group owner")
	if err != nil {
		return rep, err
	}
	parent, last, err := openFSGroupParent(bound, root)
	if err != nil {
		return rep, err
	}
	defer func() { unix.Close(parent) }()

	w := &fsGroupWalk{ctx: ctx, gid: gid, owned: owned, inGroup: inGroup, root: filepath.Clean(root), rootMsg: fsGroupClip(root), rep: &rep, tune: tune}
	defer w.closeHeld()
	rootNode, err := w.apply(parent, last, nil, func() string { return w.root })
	if err != nil || rootNode == nil {
		return rep, err
	}
	return rep, w.walk(parent, last, rootNode)
}

// openFSGroupParent checks root is strictly inside bound and opens the
// directory holding root, reached from bound one component at a time without
// following a link (pathsafe.OpenDirFrom). It returns that descriptor and
// root's last name.
func openFSGroupParent(bound, root string) (int, string, error) {
	if !strictlyUnder(root, bound) {
		return -1, "", fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, fsGroupClip(root), fsGroupClip(bound))
	}
	bound, root = filepath.Clean(bound), filepath.Clean(root)
	rel, err := filepath.Rel(bound, root)
	if err != nil {
		return -1, "", fmt.Errorf("%w: %q is not inside %q", ErrFSGroupRootUnbounded, fsGroupClip(root), fsGroupClip(bound))
	}
	bfd, err := unix.Open(bound, fsGroupDirFlags, 0)
	if err != nil {
		return -1, "", fmt.Errorf("fsGroup chown: open %s: %w", fsGroupClip(bound), err)
	}
	defer unix.Close(bfd)
	parent, err := pathsafe.OpenDirFrom(bfd, bound, filepath.Dir(rel), false, 0)
	if err != nil {
		return -1, "", fmt.Errorf("fsGroup chown: open the directory holding %s: %w", fsGroupClip(root), err)
	}
	return parent, filepath.Base(rel), nil
}

// PrepareFSGroupRoot gives root, a directory strictly inside bound owned by
// uid, the group gid, through a descriptor opened from bound without
// following a link, and changes nothing else. A daemon running as root whose
// pod drops to another uid calls it right after it makes root, before it puts
// anything in it: every entry it then creates there takes root's group (on
// Darwin a new entry always takes its directory's group; see
// TestDarwinNewEntriesTakeTheParentsGroup), so the walk can tell the daemon's
// root-owned entries (in the group already, FSGroupOwners.InGroup) from one
// renamed in from elsewhere (which keeps its own group). gid is checked
// against the allow-list as ChownForFSGroup checks it.
func PrepareFSGroupRoot(bound, root string, gid, uid int, admitted []int) error {
	if err := FSGroupGidAllowed(gid, admitted); err != nil {
		return err
	}
	parent, last, err := openFSGroupParent(bound, root)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, last, fsGroupDirFlags, 0)
	if err != nil {
		return fmt.Errorf("fsGroup: open %s: %w", fsGroupClip(root), err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fsGroup: stat %s: %w", fsGroupClip(root), err)
	}
	if uid < 0 || st.Uid != uint32(uid) {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrFSGroupForeignOwner, fsGroupClip(root), st.Uid)
	}
	if err := unix.Fchown(fd, -1, gid); err != nil {
		return fmt.Errorf("fsGroup: chown %s: %w", fsGroupClip(root), err)
	}
	return nil
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

// path is the node's path, for messages, cut to fsGroupExampleMax bytes. It
// costs time in proportion to the node's depth, so the walk builds one only
// for an error it is about to return, a kept example or a test seam, and at
// most once per directory listing.
func (n *fsGroupNode) path(root string, onBuild func()) string {
	if onBuild != nil {
		onBuild()
	}
	if n == nil || n.parent == nil {
		return fsGroupClip(root)
	}
	names := make([]string, n.depth+1)
	names[0] = root
	for m := n; m.parent != nil; m = m.parent {
		names[m.depth] = m.name
	}
	return fsGroupClip(strings.Join(names, string(filepath.Separator)))
}

// fsGroupHeld is one directory the walk keeps open.
type fsGroupHeld struct {
	node *fsGroupNode
	fd   int
}

// fsGroupWalk is the state of one walk.
type fsGroupWalk struct {
	ctx context.Context
	gid int
	// owned is the uids whose entries the walk may change, and inGroup the
	// uids whose entries it may change only when they carry gid already.
	owned, inGroup map[uint32]bool
	tune           fsGroupTuning
	root           string
	// rootMsg is root cut for messages.
	rootMsg string
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
	// closed, and re-opened from the deepest held ancestor if the walk comes
	// back below them.
	held []fsGroupHeld
	// chain is hold's buffer, reused for every directory: chain[d] is the
	// ancestor at depth d of the directory being held. It grows to the
	// deepest directory listed, at most maxFSGroupDepth+1 entries.
	chain []*fsGroupNode
}

func (w *fsGroupWalk) closeHeld() {
	for _, h := range w.held {
		unix.Close(h.fd)
	}
	w.held = nil
}

func (w *fsGroupWalk) ctxErr() error {
	if err := w.ctx.Err(); err != nil {
		return fmt.Errorf("fsGroup chown %s: %w", w.rootMsg, err)
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
		// Root went away between being changed and being listed: nothing
		// below it was changed, and the caller must not take the tree as done.
		return fmt.Errorf("%w: %s is gone before it was listed", ErrFSGroupEntryChanged, w.rootMsg)
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
			w.rep.note(&w.rep.Vanished, "gone before it was listed", func() string { return dir.path(w.root, w.tune.onPathBuild) })
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
			dirPath, havePath = dir.path(w.root, w.tune.onPathBuild), true
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
// not on that way. The levels between the deepest held ancestor and dir are
// opened one at a time from that ancestor; every one of them but dir itself
// was open before and is a re-open, charged against maxFSGroupEntries, with
// ctx looked at before it. A directory opened here is checked against the
// device and inode recorded when it was changed. It returns -1 when dir, or a
// directory above it that had to be re-opened, is gone.
func (w *fsGroupWalk) hold(dir *fsGroupNode) (int, error) {
	if cap(w.chain) < dir.depth+1 {
		w.chain = make([]*fsGroupNode, dir.depth+1, 2*dir.depth+2)
	}
	chain := w.chain[:dir.depth+1]
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
		if d < dir.depth {
			w.entries++
			if w.entries > w.tune.entries {
				return -1, fmt.Errorf("%w: more than %d entries and re-opened directories under %s",
					ErrFSGroupTreeTooLarge, w.tune.entries, w.rootMsg)
			}
			if w.tune.onReopen != nil {
				w.tune.onReopen()
			}
			if err := w.ctxErr(); err != nil {
				return -1, err
			}
		}
		fd, err := w.openNode(last.fd, chain[d].name, chain[d])
		if err != nil {
			return -1, err
		}
		if fd < 0 {
			return -1, nil
		}
		if len(w.held) >= w.tune.heldDirs {
			// Close the shallowest below root; the open of chain[d] above was
			// made relative to the deepest, which stays.
			unix.Close(w.held[1].fd)
			w.held = append(w.held[:1], w.held[2:]...)
		}
		last = fsGroupHeld{node: chain[d], fd: fd}
		w.held = append(w.held, last)
	}
	clear(chain)
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
		return -1, fmt.Errorf("%w: open %s: %v", ErrFSGroupEntryChanged, node.path(w.root, w.tune.onPathBuild), err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("fsGroup chown %s: %w", node.path(w.root, w.tune.onPathBuild), err)
	}
	if uint64(st.Dev) != node.dev || uint64(st.Ino) != node.ino {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: %s is not the directory the walk changed", ErrFSGroupEntryChanged, node.path(w.root, w.tune.onPathBuild))
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
	if w.entries > w.tune.entries {
		return nil, fmt.Errorf("%w: more than %d entries and re-opened directories under %s",
			ErrFSGroupTreeTooLarge, w.tune.entries, w.rootMsg)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if dir != nil && errors.Is(err, unix.ENOENT) {
			w.rep.note(&w.rep.Vanished, "gone before it was changed", path)
			return nil, nil
		}
		return nil, fmt.Errorf("fsGroup chown %s: %w", fsGroupClip(path()), err)
	}
	kind := uint32(st.Mode) & unix.S_IFMT
	if kind == unix.S_IFDIR {
		// Both bounds are checked before the directory is opened, so a
		// directory past either is not changed.
		if node.depth > w.tune.depth {
			return nil, fmt.Errorf("%w: %s nests more than %d directories below %s",
				ErrFSGroupTreeTooDeep, fsGroupClip(path()), w.tune.depth, w.rootMsg)
		}
		if w.pendingBytes+node.cost() > w.tune.pendingBytes {
			return nil, fmt.Errorf("%w: the directories waiting to be listed under %s need more than %d bytes",
				ErrFSGroupTreeTooLarge, w.rootMsg, w.tune.pendingBytes)
		}
	}
	if w.tune.beforeApply != nil {
		w.tune.beforeApply(path())
	}

	var flags int
	switch kind {
	case unix.S_IFDIR:
		flags = fsGroupDirFlags
	case unix.S_IFREG, unix.S_IFIFO:
		flags = fsGroupFileFlags
	case unix.S_IFLNK:
		if !fsGroupCanOpenLinks {
			w.rep.note(&w.rep.Special, "a symlink, which this system cannot open as itself", path)
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
		return nil, fmt.Errorf("%w: open %s: %v", ErrFSGroupEntryChanged, fsGroupClip(path()), err)
	default:
		return nil, fmt.Errorf("fsGroup chown: open %s: %w", fsGroupClip(path()), err)
	}
	defer unix.Close(fd)

	// From here on only the descriptor is used: what was opened is what is
	// examined and what is changed.
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fsGroup chown %s: %w", fsGroupClip(path()), err)
	}
	if uint32(st.Mode)&unix.S_IFMT != kind {
		return nil, fmt.Errorf("%w: %s changed kind while it was being walked", ErrFSGroupEntryChanged, fsGroupClip(path()))
	}
	uid := st.Uid
	if w.tune.ownerOf != nil {
		uid = w.tune.ownerOf(path(), uid)
	}
	if !w.owned[uid] && !(w.inGroup[uid] && st.Gid == uint32(w.gid)) {
		if dir == nil {
			return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrFSGroupForeignOwner, w.rootMsg, uid)
		}
		w.rep.note(&w.rep.ForeignOwner, "owned by a uid the pod does not run as", path)
		return nil, nil
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
	if kind != unix.S_IFDIR && kind != unix.S_IFLNK && uint32(st.Mode)&(unix.S_ISUID|unix.S_ISGID) != 0 {
		// Cleared before the group is set, so the file is never setgid to
		// the fsGroup, not even between the two calls.
		if err := unix.Fchmod(fd, uint32(st.Mode)&0o7777&^(unix.S_ISUID|unix.S_ISGID)); err != nil {
			return nil, fmt.Errorf("fsGroup chmod %s: %w", fsGroupClip(path()), err)
		}
		w.rep.note(&w.rep.SetID, "setuid or setgid, cleared", path)
	}
	if err := unix.Fchown(fd, -1, w.gid); err != nil {
		return nil, fmt.Errorf("fsGroup chown %s: %w", fsGroupClip(path()), err)
	}
	if kind == unix.S_IFLNK {
		w.rep.Changed++
		return nil, nil // a symlink's mode is meaningless
	}
	if w.tune.beforeChmod != nil {
		w.tune.beforeChmod(path())
	}
	// The mode is read after the chown, from the descriptor.
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fsGroup chown %s: %w", fsGroupClip(path()), err)
	}
	mode := fsGroupMode(uint32(st.Mode), kind == unix.S_IFDIR)
	if err := unix.Fchmod(fd, mode); err != nil {
		return nil, fmt.Errorf("fsGroup chmod %s: %w", fsGroupClip(path()), err)
	}
	w.rep.Changed++
	if kind != unix.S_IFDIR {
		return nil, nil
	}
	node.dev, node.ino = uint64(st.Dev), uint64(st.Ino)
	return node, nil
}

// fsGroupMode is the mode an entry with mode st gets: its permission bits with
// the owner's rwx copied to the group, the sticky bit kept, setgid added on a
// directory, and setuid and setgid cleared on anything else.
func fsGroupMode(st uint32, isDir bool) uint32 {
	mode := st & 0o7777
	grant := (mode & 0o700) >> 3
	if isDir {
		return mode | grant | unix.S_ISGID
	}
	return (mode &^ (unix.S_ISUID | unix.S_ISGID)) | grant
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
