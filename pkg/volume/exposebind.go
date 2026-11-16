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

package volume

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
)

// Modes of the exposure tree below <data root>/expose, which k3sm install owns
// and runtimed never creates or re-modes. A parent is 0711 so the receiving
// account can traverse to the one name it knows without listing who exposes
// what; the leaf is 0700 so only its ACL lets anyone else in.
const (
	exposeParentMode = 0o711
	exposeLeafMode   = 0o700
)

// openDirFlags opens a directory and never follows a symlink in the last
// component: every exposure walk goes one level at a time from a descriptor,
// so a symlink anywhere below the exposures root is refused, never followed.
const openDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// ErrNoExposeACL reports a runtime with no ExposeACL asked to bind an
// exposure. It is refused: the runtime never exposes data it cannot scope.
var ErrNoExposeACL = errors.New("volume: no exposure ACL is wired on this node")

// ExposeBinding is one exposure volume bound for a pod.
type ExposeBinding struct {
	// Volume is the pod's volume name.
	Volume string
	// Dir is the leaf directory (hostshare.ExposeDir) the pod writes and the
	// account was granted. It is the path the caller adds to the pod's
	// read/write profile scope.
	Dir string
	// UID is the account the ACL names.
	UID uint32
	// ReadWrite is the access the account was granted.
	ReadWrite bool
	// Links are the symlinks created in the pod rootfs, one per mount path.
	Links []string
}

// exposeMount is one container mount of a pod volume, for the overlap check.
type exposeMount struct {
	volume string
	path   string
}

// PlanExposures returns the leaf directory of every exposure volume a
// container of box mounts, in volume order, without touching the filesystem.
// It is the one derivation a pod's create (after authorization, before
// BindExposures) and its re-attach (which recompiles the profile and must not
// do I/O) both use, so the read/write scope they compile is the same by
// construction. A box with no mounted exposure returns nil.
//
// It refuses (ErrInvalid, naming the volumes) an exposure mount path that
// equals, lies under or contains any other volume mount's path in the pod:
// volumes are linked into the rootfs with symlinks, so a nested mount would
// land inside another volume's tree, or put another volume inside the
// exposure. Invalid pod or volume names are ErrInvalid wrapping
// hostshare.ErrNotExposed.
func PlanExposures(box *runtimev1.PodBox, dataRoot string) ([]string, error) {
	expose := map[string]bool{}
	for _, v := range box.GetVolumes() {
		if v.GetExpose() != nil {
			expose[v.GetName()] = true
		}
	}
	if len(expose) == 0 {
		return nil, nil
	}
	var mounts []exposeMount
	mounted := map[string]bool{}
	for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
		for _, c := range cs {
			for _, m := range c.GetVolumeMounts() {
				if strings.TrimSpace(m.GetMountPath()) == "" {
					if expose[m.GetName()] {
						return nil, fmt.Errorf("%w: exposure volume %q has an empty mount path", ErrInvalid, m.GetName())
					}
					continue
				}
				mounts = append(mounts, exposeMount{volume: m.GetName(), path: filepath.Clean("/" + m.GetMountPath())})
				if expose[m.GetName()] {
					mounted[m.GetName()] = true
				}
			}
		}
	}
	for _, m := range mounts {
		if !expose[m.volume] {
			continue
		}
		for _, o := range mounts {
			if o == m {
				continue // the same volume at the same path in another container
			}
			if pathsOverlap(m.path, o.path) {
				return nil, fmt.Errorf("%w: exposure volume %q at %q overlaps volume %q at %q; an exposure's mount path may not equal, lie under or contain another mount's",
					ErrInvalid, m.volume, m.path, o.volume, o.path)
			}
		}
	}
	var dirs []string
	for _, v := range box.GetVolumes() {
		if v.GetExpose() == nil || !mounted[v.GetName()] {
			continue
		}
		dir, err := hostshare.ExposeDir(dataRoot, box.GetNamespace(), box.GetName(), v.GetName())
		if err != nil {
			return nil, fmt.Errorf("%w: volume %q: %w", ErrInvalid, v.GetName(), err)
		}
		dirs = append(dirs, dir)
	}
	return dirs, nil
}

// pathsOverlap reports whether a is b, under b, or above b, comparing path
// segments without regard to case: the default APFS volume is
// case-insensitive, so /Run and /run are one link target there. Both are clean
// absolute paths.
func pathsOverlap(a, b string) bool {
	return underFold(a, b) || underFold(b, a)
}

// underFold reports whether path is prefix or below it, segment by segment
// and case-insensitively.
func underFold(path, prefix string) bool {
	if prefix == "/" || path == "/" {
		return true
	}
	ps, pres := strings.Split(path, "/"), strings.Split(prefix, "/")
	if len(ps) < len(pres) {
		return false
	}
	for i, seg := range pres {
		if !strings.EqualFold(ps[i], seg) {
			return false
		}
	}
	return true
}

// BindExposures materializes each authorized exposure of box and links it
// into rootfs. exps is hostshare.AuthorizeExposures' result for box; it must
// name exactly the leaves PlanExposures derives, or the pod is refused. For
// each exposure it:
//
//   - opens <dataRoot>/expose, which must already be a real directory (k3sm
//     install owns it; it is never created or re-moded here);
//   - creates or reuses <namespace> and <pod> below it as real directories,
//     mode 0711, refusing a symlink or anything that is not a directory owned
//     by this process's uid;
//   - removes a leaf left by an earlier pod of the same name without following
//     any symlink in it, clearing modes and user flags the pod set and
//     retrying once when the first removal fails;
//   - creates the leaf empty, mode 0700, and grants the account through acl;
//   - links the leaf at each of the volume's mount paths in rootfs, as Bind
//     links a claim.
//
// A nil acl refuses every exposure (ErrNoExposeACL, wrapping
// hostshare.ErrNotExposed). A box with no mounted exposure returns nil.
func BindExposures(ctx context.Context, acl ExposeACL, box *runtimev1.PodBox, rootfs, dataRoot string, exps []hostshare.Exposure) ([]ExposeBinding, error) {
	dirs, err := PlanExposures(box, dataRoot)
	if err != nil {
		return nil, err
	}
	if len(dirs) == 0 && len(exps) == 0 {
		return nil, nil
	}
	if acl == nil {
		return nil, fmt.Errorf("%w: %w", hostshare.ErrNotExposed, ErrNoExposeACL)
	}
	if len(exps) != len(dirs) {
		return nil, fmt.Errorf("%w: %d exposures were authorized for %d exposure volumes", ErrInvalid, len(exps), len(dirs))
	}
	for i, x := range exps {
		if x.Dir != dirs[i] {
			return nil, fmt.Errorf("%w: authorized exposure %q is not the volume's directory %q", ErrInvalid, x.Dir, dirs[i])
		}
	}
	rootfs = filepath.Clean(rootfs)
	out := make([]ExposeBinding, 0, len(exps))
	for _, x := range exps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := prepareLeaf(dataRoot, box.GetNamespace(), box.GetName(), x.Volume); err != nil {
			return nil, fmt.Errorf("exposure volume %q: %w", x.Volume, err)
		}
		if err := acl.Grant(x.Dir, x.UID, x.ReadWrite); err != nil {
			return nil, fmt.Errorf("exposure volume %q: grant uid %d: %w", x.Volume, x.UID, err)
		}
		b := ExposeBinding{Volume: x.Volume, Dir: x.Dir, UID: x.UID, ReadWrite: x.ReadWrite}
		seen := map[string]bool{}
		for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
			for _, c := range cs {
				for _, m := range c.GetVolumeMounts() {
					if m.GetName() != x.Volume || seen[m.GetMountPath()] {
						continue
					}
					seen[m.GetMountPath()] = true
					link, err := linkInto(rootfs, m.GetMountPath(), "", x.Dir)
					if err != nil {
						return nil, fmt.Errorf("link exposure %q into pod: %w", x.Volume, err)
					}
					b.Links = append(b.Links, link)
				}
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// prepareLeaf leaves <dataRoot>/expose/<ns>/<pod>/<volume> an empty 0700
// directory under 0711 parents, walking from descriptors so no symlink below
// the exposures root is followed.
func prepareLeaf(dataRoot, ns, pod, volume string) error {
	root := hostshare.ExposeRoot(dataRoot)
	rootFD, err := openExposeRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	nsFD, err := ensureDirAt(rootFD, ns, filepath.Join(root, ns))
	if err != nil {
		return err
	}
	defer unix.Close(nsFD)
	podPath := filepath.Join(root, ns, pod)
	podFD, err := ensureDirAt(nsFD, pod, podPath)
	if err != nil {
		return err
	}
	defer unix.Close(podFD)

	leaf := filepath.Join(podPath, volume)
	var st unix.Stat_t
	switch err := unix.Fstatat(podFD, volume, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		if err := removeTreeAt(podFD, volume); err != nil {
			return fmt.Errorf("remove the stale exposure %s: %w", leaf, err)
		}
	case !errors.Is(err, unix.ENOENT):
		return fmt.Errorf("lstat %s: %w", leaf, err)
	}
	if err := unix.Mkdirat(podFD, volume, exposeLeafMode); err != nil {
		return fmt.Errorf("create %s: %w", leaf, err)
	}
	leafFD, err := unix.Openat(podFD, volume, openDirFlags, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", leaf, err)
	}
	defer unix.Close(leafFD)
	if err := unix.Fchmod(leafFD, exposeLeafMode); err != nil {
		return fmt.Errorf("chmod %s: %w", leaf, err)
	}
	return nil
}

// openExposeRoot opens <dataRoot>/expose, which must be a real directory. It
// is never created here: k3sm install owns its owner and mode.
func openExposeRoot(root string) (int, error) {
	fd, err := unix.Open(root, openDirFlags, 0)
	switch {
	case err == nil:
		return fd, nil
	case errors.Is(err, unix.ENOENT):
		return -1, fmt.Errorf("%w: the exposures root %s does not exist; `k3sm install` creates it", ErrInvalid, root)
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return -1, fmt.Errorf("%w: the exposures root %s is a symlink or not a directory", ErrInvalid, root)
	}
	return -1, fmt.Errorf("open the exposures root %s: %w", root, err)
}

// ensureDirAt creates name under dirFD as a 0711 directory when it is missing
// and opens it, refusing a symlink, a non-directory or a directory another uid
// owns. path is for messages only.
func ensureDirAt(dirFD int, name, path string) (int, error) {
	if err := unix.Mkdirat(dirFD, name, exposeParentMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("create %s: %w", path, err)
	}
	fd, err := unix.Openat(dirFD, name, openDirFlags, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, fmt.Errorf("%w: %s is a symlink or not a directory", ErrInvalid, path)
		}
		return -1, fmt.Errorf("open %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("stat %s: %w", path, err)
	}
	if int(st.Uid) != os.Geteuid() {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: %s is owned by uid %d, not this runtime", ErrInvalid, path, st.Uid)
	}
	if st.Mode&0o7777 != exposeParentMode {
		if err := unix.Fchmod(fd, exposeParentMode); err != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("chmod %s: %w", path, err)
		}
	}
	return fd, nil
}

// RemoveExposures deletes a pod's exposure directory,
// <dataRoot>/expose/<namespace>/<pod>, and everything in it, without
// following any symlink: it walks from a descriptor on the exposures root, so
// nothing outside it is reachable. A missing root or pod directory is not an
// error. Invalid names remove nothing and are ErrInvalid.
func RemoveExposures(dataRoot, namespace, pod string) error {
	// ExposeDir checks the namespace and pod name (and the data root); the
	// volume component is only a placeholder that passes its own check.
	if _, err := hostshare.ExposeDir(dataRoot, namespace, pod, "v"); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	rootFD, err := unix.Open(hostshare.ExposeRoot(dataRoot), openDirFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open the exposures root: %w", err)
	}
	defer unix.Close(rootFD)
	nsFD, err := unix.Openat(rootFD, namespace, openDirFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open exposure namespace %s: %w", namespace, err)
	}
	defer unix.Close(nsFD)
	if err := removeTreeAt(nsFD, pod); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove exposures of %s/%s: %w", namespace, pod, err)
	}
	return nil
}

// SweepExposures removes every <dataRoot>/expose/<namespace>/<pod> directory
// whose pod known does not report, and returns the "<namespace>/<pod>" names
// it removed. It is the startup sweep for pods deleted while the runtime was
// down. Entries that are not real directories are left alone, and nothing is
// followed out of the exposures root. A missing root sweeps nothing.
func SweepExposures(dataRoot string, known func(namespace, pod string) bool) ([]string, error) {
	rootFD, err := unix.Open(hostshare.ExposeRoot(dataRoot), openDirFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open the exposures root: %w", err)
	}
	root := os.NewFile(uintptr(rootFD), hostshare.ExposeRoot(dataRoot))
	defer root.Close()
	namespaces, err := root.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("list the exposures root: %w", err)
	}
	var removed []string
	var errs []error
	for _, ns := range namespaces {
		nsFD, err := unix.Openat(int(root.Fd()), ns, openDirFlags, 0)
		if err != nil {
			continue // not a real directory: nothing this sweep owns
		}
		nsDir := os.NewFile(uintptr(nsFD), ns)
		pods, err := nsDir.Readdirnames(-1)
		if err != nil {
			errs = append(errs, fmt.Errorf("list exposure namespace %s: %w", ns, err))
		}
		for _, pod := range pods {
			var st unix.Stat_t
			if unix.Fstatat(int(nsDir.Fd()), pod, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				continue
			}
			if known(ns, pod) {
				continue
			}
			if err := removeTreeAt(int(nsDir.Fd()), pod); err != nil {
				errs = append(errs, fmt.Errorf("remove exposures of %s/%s: %w", ns, pod, err))
				continue
			}
			removed = append(removed, ns+"/"+pod)
		}
		nsDir.Close()
	}
	return removed, errors.Join(errs...)
}

// removeTreeAt removes name under dirFD and everything below it without
// following a symlink. When the first attempt fails (a pod made an entry
// read-only or set a user flag on it), it makes the entries writable and
// clears their user flags, again without following, and tries once more.
func removeTreeAt(dirFD int, name string) error {
	if err := removeAt(dirFD, name); err == nil {
		return nil
	}
	unlockAt(dirFD, name)
	return removeAt(dirFD, name)
}

// removeAt unlinks name under dirFD, descending into it first when it is a
// real directory (opened O_NOFOLLOW, so a symlink is unlinked, never
// entered).
func removeAt(dirFD int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(dirFD, name, 0)
	}
	fd, err := unix.Openat(dirFD, name, openDirFlags, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), name)
	names, err := dir.Readdirnames(-1)
	if err != nil {
		dir.Close()
		return err
	}
	var first error
	for _, n := range names {
		if err := removeAt(int(dir.Fd()), n); err != nil && first == nil {
			first = err
		}
	}
	dir.Close()
	if first != nil {
		return first
	}
	return unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR)
}

// unlockAt undoes, best effort and without following a symlink, what keeps
// the owner from removing name and its subtree: directory modes without
// owner rwx, and the user-settable flags (uchg, uappnd and the rest of
// UF_SETTABLE) on any entry. Errors are ignored: the retry that follows
// reports whatever still fails.
func unlockAt(dirFD int, name string) {
	var st unix.Stat_t
	if unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return
	case unix.S_IFDIR:
		_ = unix.Fchmodat(dirFD, name, exposeLeafMode, unix.AT_SYMLINK_NOFOLLOW)
		fd, err := unix.Openat(dirFD, name, openDirFlags, 0)
		if err != nil {
			return
		}
		dir := os.NewFile(uintptr(fd), name)
		defer dir.Close()
		if st.Flags&unix.UF_SETTABLE != 0 {
			_ = unix.Fchflags(int(dir.Fd()), int(st.Flags&^unix.UF_SETTABLE))
			_ = unix.Fchmod(int(dir.Fd()), exposeLeafMode)
		}
		names, err := dir.Readdirnames(-1)
		if err != nil {
			return
		}
		for _, n := range names {
			unlockAt(int(dir.Fd()), n)
		}
	default:
		if st.Flags&unix.UF_SETTABLE == 0 {
			return // unlinking a plain entry needs only its parent writable
		}
		_ = unix.Fchmodat(dirFD, name, 0o600, unix.AT_SYMLINK_NOFOLLOW)
		fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return
		}
		_ = unix.Fchflags(fd, int(st.Flags&^unix.UF_SETTABLE))
		_ = unix.Close(fd)
	}
}
