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

package mount

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/pathsafe"
)

// A pod owns its data volume and can rearrange it at any time: rename a
// directory away and plant a symlink in its place, or put a file where a
// directory was. Every write the daemon makes into the pod tree for a
// projected volume therefore goes through a directory descriptor (dirTarget)
// opened from a directory the pod cannot replace, one component at a time
// without following a link, and every name below it is resolved relative to
// that descriptor, never through a path string.

// dirTarget is an open directory the daemon writes into, with its path for
// messages. The path is never used to reach the directory.
type dirTarget struct {
	fd   int
	path string
}

// close releases the descriptor.
func (d *dirTarget) close() {
	if d != nil && d.fd >= 0 {
		unix.Close(d.fd)
		d.fd = -1
	}
}

// join is the path of name under d, for messages.
func (d *dirTarget) join(name string) string { return filepath.Join(d.path, name) }

// openAnchor opens base, a directory the pod cannot replace (the pod dir, or
// a data volume whose parent is the pod dir), without following a link.
func openAnchor(base string) (*dirTarget, error) {
	fd, err := unix.Open(base, pathsafe.DirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", base, err)
	}
	return &dirTarget{fd: fd, path: base}, nil
}

// openUnder opens dest, which lies under the anchor base, walking down from
// base without following a link (pathsafe.OpenDirFrom). A component that is a
// symlink or not a directory is refused (pathsafe.ErrSymlinkedPath); a missing
// one is created (0755, under the umask) when create is set.
func openUnder(base, dest string, create bool) (*dirTarget, error) {
	rel, err := filepath.Rel(base, dest)
	if err != nil || !isUnder(dest, base) {
		return nil, fmt.Errorf("%w: %s is not under %s", pathsafe.ErrPathOutsideRoot, dest, base)
	}
	anchor, err := openAnchor(base)
	if err != nil {
		return nil, err
	}
	defer anchor.close()
	fd, err := pathsafe.OpenDirFrom(anchor.fd, base, rel, create, 0o755)
	if err != nil {
		return nil, fmt.Errorf("mount dir %s: %w", dest, err)
	}
	return &dirTarget{fd: fd, path: dest}, nil
}

// fileOpenFlags opens a file the daemon writes or reads in the pod tree: never
// through a link, never blocking on a FIFO, never as a controlling terminal.
const fileOpenFlags = unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC

// splitRel checks rel is a non-empty path that stays under its base and
// returns its parent directory and last name.
func splitRel(rel string) (dir, name string, err error) {
	clean := filepath.Clean(rel)
	if rel == "" || clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path %q escapes the volume", rel)
	}
	return filepath.Dir(clean), filepath.Base(clean), nil
}

// writeFile writes content to rel under the open directory t, creating parent
// dirs (0755),
// then sets mode exactly (independent of umask). Every component is reached
// relative to t without following a link; the file itself is created with
// O_EXCL, or, when a projection earlier in the same render wrote it, reopened
// without following and checked to be a regular file.
func writeFile(t *dirTarget, rel string, content []byte, mode os.FileMode) error {
	if rel == "" {
		return errors.New("empty file path in volume projection")
	}
	dir, name, err := splitRel(rel)
	if err != nil {
		return fmt.Errorf("projection %w", err)
	}
	pfd, err := pathsafe.OpenDirFrom(t.fd, t.path, dir, true, 0o755)
	if err != nil {
		return fmt.Errorf("create dir for %s: %w", t.join(rel), err)
	}
	defer unix.Close(pfd)
	fd, err := unix.Openat(pfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|fileOpenFlags, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(pfd, name, unix.O_WRONLY|unix.O_TRUNC|fileOpenFlags, 0)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", t.join(rel), err)
	}
	f := os.NewFile(uintptr(fd), t.join(rel))
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("write %s: %w", t.join(rel), err)
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("write %s: not a regular file", t.join(rel))
	}
	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", t.join(rel), err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("chmod %s: %w", t.join(rel), err)
	}
	return nil
}

// readFileAt reads the regular file rel under t, reached without following a
// link, refusing a path that escapes t or names anything but a regular file.
func readFileAt(t *dirTarget, rel string) ([]byte, error) {
	dir, name, err := splitRel(rel)
	if err != nil {
		return nil, err
	}
	pfd, err := pathsafe.OpenDirFrom(t.fd, t.path, dir, false, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|fileOpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", t.join(rel), err)
	}
	f := os.NewFile(uintptr(fd), t.join(rel))
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", t.join(rel))
	}
	return io.ReadAll(f)
}

// readlinkAt reads the symlink name under dirfd.
func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// listAt returns the names in the open directory dirfd, read through a
// descriptor of its own so dirfd keeps no read position.
func listAt(dirfd int, path string) ([]string, error) {
	fd, err := unix.Openat(dirfd, ".", pathsafe.DirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}
	d := os.NewFile(uintptr(fd), path)
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}
	return names, nil
}

// fileMode is the os.FileMode of st: its type and permission and special bits.
func fileMode(st *unix.Stat_t) os.FileMode {
	m := uint32(st.Mode)
	mode := os.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFREG:
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	default:
		mode |= os.ModeIrregular
	}
	if m&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if m&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if m&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// walkAt calls visit for every entry below the open directory t, depth first,
// with its path relative to t and its lstat. Directories are entered relative
// to their parent's descriptor without following a link; visit returning an
// error stops the walk.
func walkAt(t *dirTarget, visit func(rel string, st *unix.Stat_t, parent int, name string) error) error {
	var walk func(fd int, prefix string) error
	walk = func(fd int, prefix string) error {
		names, err := listAt(fd, filepath.Join(t.path, prefix))
		if err != nil {
			return err
		}
		for _, name := range names {
			rel := filepath.Join(prefix, name)
			var st unix.Stat_t
			if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("stat %s: %w", t.join(rel), err)
			}
			if err := visit(rel, &st, fd, name); err != nil {
				return err
			}
			if uint32(st.Mode)&unix.S_IFMT != unix.S_IFDIR {
				continue
			}
			sub, err := unix.Openat(fd, name, pathsafe.DirFlags, 0)
			if err != nil {
				return fmt.Errorf("open %s: %w", t.join(rel), err)
			}
			err = walk(sub, rel)
			unix.Close(sub)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return walk(t.fd, "")
}

// sameEntry reports whether name under dirfd is, without following a link,
// the file open as fd.
func sameEntry(dirfd int, name string, fd int) bool {
	var a, b unix.Stat_t
	if unix.Fstatat(dirfd, name, &a, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(fd, &b) != nil {
		return false
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}
