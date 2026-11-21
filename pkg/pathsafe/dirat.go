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

package pathsafe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// DirFlags opens a directory for a descriptor-relative walk: never through a
// symlink, never blocking, never as a controlling terminal, closed on exec.
const DirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC

// OpenDirFrom opens rel below the open directory dirfd one component at a time,
// each with O_NOFOLLOW relative to the directory above it, and returns the
// last one's descriptor (the caller closes it; dirfd stays the caller's). It is
// the handle-held counterpart of RefuseSymlinkedPath: what it returns IS the
// directory the walk reached, whatever a name along the way means afterwards.
//
// A component that is a symlink or anything but a directory is refused with
// ErrSymlinkedPath, wrapping unix.ELOOP for a symlink and unix.ENOTDIR for
// anything else, and a ".." with ErrPathOutsideRoot. A missing component is
// created with mode when create is set (subject to the umask), and otherwise
// returned as an error satisfying errors.Is(err, fs.ErrNotExist). basePath is
// dirfd's path, for messages only. An empty or "." rel returns a new
// descriptor for dirfd itself.
func OpenDirFrom(dirfd int, basePath, rel string, create bool, mode uint32) (int, error) {
	fd, err := unix.Openat(dirfd, ".", DirFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", basePath, err)
	}
	cur := basePath
	for _, c := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			unix.Close(fd)
			return -1, fmt.Errorf("%w: %q leaves %s", ErrPathOutsideRoot, rel, basePath)
		}
		cur = filepath.Join(cur, c)
		next, err := openChildDir(fd, c, create, mode)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("%s: %w", cur, err)
		}
		fd = next
	}
	return fd, nil
}

// openChildDir opens the directory name under dirfd without following a link,
// creating it first when it is missing and create is set.
func openChildDir(dirfd int, name string, create bool, mode uint32) (int, error) {
	fd, err := unix.Openat(dirfd, name, DirFlags, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(dirfd, name, mode); err == nil || errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(dirfd, name, DirFlags, 0)
		}
	}
	switch {
	case err == nil:
		return fd, nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		// Darwin answers ENOTDIR for a symlink opened O_DIRECTORY|O_NOFOLLOW
		// as for a file, so the entry is examined to say which it is: the
		// error wraps unix.ELOOP for a link and unix.ENOTDIR otherwise.
		var st unix.Stat_t
		if unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && uint32(st.Mode)&unix.S_IFMT == unix.S_IFLNK {
			return -1, fmt.Errorf("%w: a symlink: %w", ErrSymlinkedPath, unix.ELOOP)
		}
		return -1, fmt.Errorf("%w: not a directory: %w", ErrSymlinkedPath, unix.ENOTDIR)
	default:
		return -1, err
	}
}

// TreeBounds bounds a RemoveTreeAt. Depth is how many directories deep the
// removal may go, counting name itself as 1, and must be positive; Entries is
// how many entries (files, links and directories, name included) it may
// remove, 0 for no bound.
type TreeBounds struct {
	Depth, Entries int
}

// ErrTreeTooLarge is returned by RemoveTreeAt when the tree passes its
// TreeBounds. What was not yet removed is left on disk.
var ErrTreeTooLarge = errors.New("tree is larger than its bound")

// removeBatch is how many names RemoveTreeAt reads from a directory at once.
const removeBatch = 256

// RemoveTreeAt removes name and everything below it, relative to the open
// directory dirfd. It never follows a link: a link is unlinked as a link, and
// each directory is opened with O_NOFOLLOW relative to its parent's
// descriptor, so a component swapped for a link while it runs is refused
// rather than descended. A name that is not there is not an error.
//
// It is iterative and holds a small, constant number of descriptors whatever
// the tree's shape: it keeps the path from name to the directory it is
// emptying as names, re-opens that directory from dirfd one component at a
// time for each step, reads at most removeBatch names, unlinks the
// non-directories among them and descends into the first directory. A tree
// deeper or larger than b stops it with ErrTreeTooLarge, the rest left on
// disk. Entries found gone while it runs count too, so the number of steps
// is bounded by Entries times Depth however the tree changes underneath.
func RemoveTreeAt(dirfd int, name string, b TreeBounds) error {
	if b.Depth < 1 {
		return fmt.Errorf("remove %s: no depth bound", name)
	}
	path := []string{name}
	removed := 0
	count := func() error {
		if removed++; b.Entries > 0 && removed > b.Entries {
			return fmt.Errorf("%w: more than %d entries under %s", ErrTreeTooLarge, b.Entries, name)
		}
		return nil
	}
	for len(path) > 0 {
		pfd, err := openPathAt(dirfd, path[:len(path)-1])
		if errors.Is(err, unix.ENOENT) {
			// An ancestor went away while this ran; what was below it went
			// with it. Counted like a removal, so a pod racing names in and
			// out cannot keep the loop going.
			if err := count(); err != nil {
				return err
			}
			path = path[:len(path)-1]
			continue
		}
		if err != nil {
			return fmt.Errorf("remove %s: %w", strings.Join(path, "/"), err)
		}
		leaf := path[len(path)-1]
		sub, done, err := removeStep(pfd, leaf, count)
		unix.Close(pfd)
		if err != nil {
			return fmt.Errorf("remove %s: %w", strings.Join(path, "/"), err)
		}
		switch {
		case done:
			path = path[:len(path)-1]
		case sub != "":
			if len(path)+1 > b.Depth {
				return fmt.Errorf("%w: %s nests more than %d deep", ErrTreeTooLarge, name, b.Depth)
			}
			path = append(path, sub)
		}
	}
	return nil
}

// removeStep makes one step of RemoveTreeAt on leaf, an entry of the open
// directory pfd: a non-directory is unlinked (done); a directory has up to
// removeBatch of its non-directory entries unlinked and returns its first
// subdirectory to descend into, or, empty, is removed itself (done).
// Every removal, and every entry found gone, is counted, so each step that
// does not descend counts at least once.
func removeStep(pfd int, leaf string, count func() error) (sub string, done bool, err error) {
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, leaf, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", true, count()
		}
		return "", false, err
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFDIR {
		if err := count(); err != nil {
			return "", false, err
		}
		if err := unix.Unlinkat(pfd, leaf, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return "", false, err
		}
		return "", true, nil
	}
	fd, err := unix.Openat(pfd, leaf, DirFlags, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", true, count()
		}
		return "", false, err
	}
	d := os.NewFile(uintptr(fd), leaf)
	names, rerr := d.Readdirnames(removeBatch)
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		d.Close()
		return "", false, rerr
	}
	for _, n := range names {
		var cst unix.Stat_t
		if err := unix.Fstatat(fd, n, &cst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				if err := count(); err != nil {
					d.Close()
					return "", false, err
				}
				continue
			}
			d.Close()
			return "", false, err
		}
		if uint32(cst.Mode)&unix.S_IFMT == unix.S_IFDIR {
			d.Close()
			return n, false, nil
		}
		if err := count(); err != nil {
			d.Close()
			return "", false, err
		}
		if err := unix.Unlinkat(fd, n, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			d.Close()
			return "", false, err
		}
	}
	d.Close()
	if len(names) > 0 {
		return "", false, nil // more may follow; the next step reads again
	}
	if err := count(); err != nil {
		return "", false, err
	}
	if err := unix.Unlinkat(pfd, leaf, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return "", false, err
	}
	return "", true, nil
}

// openPathAt opens the directory reached from dirfd through names, each
// opened with O_NOFOLLOW relative to the one before; no names opens dirfd
// itself. A component that is a link or not a directory is refused.
func openPathAt(dirfd int, names []string) (int, error) {
	fd, err := unix.Openat(dirfd, ".", DirFlags, 0)
	if err != nil {
		return -1, err
	}
	for _, n := range names {
		next, err := openChildDir(fd, n, false, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}
