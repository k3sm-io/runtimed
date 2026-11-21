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

// RemoveTreeAt removes name and everything below it, relative to the open
// directory dirfd. It never follows a link: a link is unlinked as a link, and
// each directory is opened with O_NOFOLLOW relative to its parent's
// descriptor, so a component swapped for a link while it runs is refused
// rather than descended. A name that is not there is not an error.
func RemoveTreeAt(dirfd int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(dirfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	}
	fd, err := unix.Openat(dirfd, name, DirFlags, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	d := os.NewFile(uintptr(fd), name)
	names, rerr := d.Readdirnames(-1)
	var first error
	for _, n := range names {
		if err := RemoveTreeAt(fd, n); err != nil && first == nil {
			first = err
		}
	}
	d.Close()
	if rerr != nil && first == nil {
		first = rerr
	}
	if first != nil {
		return first
	}
	if err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
