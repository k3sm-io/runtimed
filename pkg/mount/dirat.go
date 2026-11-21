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
// messages. The path is never used to reach the directory. created records
// the files writeFile created under it in this render (by path relative to
// it), with the device and inode each got: only those may be written again.
// replace lets writeFile unlink a name it did not create and make a new file
// in its place, for a flat render into a directory an earlier create of the
// same pod may have rendered into (a vm pod's share dir); a generation never
// sets it. written is the bytes the files in created now hold, bounded by
// maxVolumeBytes, so a volume too large to be refreshed fails its render.
type dirTarget struct {
	fd      int
	path    string
	created map[string]fileID
	sizes   map[string]int64
	written int64
	replace bool
}

// fileID is a file's device and inode.
type fileID struct{ dev, ino uint64 }

// idOf is st's fileID.
func idOf(st *unix.Stat_t) fileID { return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)} }

// The bounds on what the daemon reads from a pod tree. The pod can write the
// live generation and the mount dir it sits in (a writable configMap mount),
// and can plant entries in a new generation while it is rendered, so each read
// is bounded and over a bound the volume's refresh fails. A ConfigMap or Secret
// holds at most 1 MiB; the byte bound sits well above that.
const (
	// maxVolumeBytes bounds the file bytes written to, and read from, one
	// generation.
	maxVolumeBytes = 8 << 20
	// maxTreeEntries bounds the entries walked in one generation.
	maxTreeEntries = 16384
	// maxTreeDepth bounds how deep a generation walk goes.
	maxTreeDepth = 64
)

// errTreeTooLarge is returned when a generation render, walk, read or
// removal passes one of the bounds above. It is pathsafe.ErrTreeTooLarge, so
// a removal over removeBounds is the same error.
var errTreeTooLarge = pathsafe.ErrTreeTooLarge

// removeBounds bounds every removal of a tree from a mount dir (a discarded
// or previous generation, or a ..data that was no link): the pod can grow any
// of them, and RemoveTreeAt stops at these with errTreeTooLarge. A tree that
// verifyGeneration accepts is within them.
var removeBounds = pathsafe.TreeBounds{Depth: maxTreeDepth + 1, Entries: maxTreeEntries + 1}

// close releases the descriptor.
func (d *dirTarget) close() {
	if d != nil && d.fd >= 0 {
		unix.Close(d.fd)
		d.fd = -1
	}
}

// join is the path of name under d, for messages.
func (d *dirTarget) join(name string) string { return filepath.Join(d.path, name) }

// openAnchor opens base without following a link. base is the data volume (or,
// for a vm pod's shares, the pod dir): the daemon's own path, trusted down to
// and including its last component, which O_NOFOLLOW refuses if it is a
// symlink. That trust holds while the pod cannot write base's parent. A
// profile whose dataVolumePath is the pod dir itself grants the pod exactly
// that, and then the pod can rename the data volume away and put another
// directory in its place; what is reached from base is then that directory,
// still inside the pod's own grant.
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
// dirs (0755), then sets mode exactly (independent of umask). Every component
// is reached relative to t without following a link. The file is created with
// O_EXCL and recorded in t.created. A name that exists already is written
// again only when this render created it (a later projection of the same
// render overwriting an earlier one): it is reopened without O_TRUNC and
// without following, must still be that file with one link, and is then
// truncated. Any other existing name is refused: a pod can plant an entry in
// a generation while it is rendered, a hard link to another file among them.
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
	key := filepath.Clean(rel)
	if total := t.written - t.sizes[key] + int64(len(content)); total > maxVolumeBytes {
		return fmt.Errorf("%w: %s would bring the volume to %d bytes, over %d", errTreeTooLarge, t.join(rel), total, maxVolumeBytes)
	}
	fd, err := unix.Openat(pfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|fileOpenFlags, 0o600)
	again := false
	if errors.Is(err, unix.EEXIST) {
		_, ours := t.created[key]
		switch {
		case ours:
			again = true
			fd, err = unix.Openat(pfd, name, unix.O_WRONLY|fileOpenFlags, 0)
		case t.replace:
			// Unlinking a name never touches what another link names.
			if err = unix.Unlinkat(pfd, name, 0); err == nil {
				fd, err = unix.Openat(pfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|fileOpenFlags, 0o600)
			}
		default:
			return fmt.Errorf("write %s: it exists and this render did not create it", t.join(rel))
		}
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
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return fmt.Errorf("write %s: not a regular file with one link", t.join(rel))
	}
	if again {
		if t.created[key] != idOf(&st) {
			return fmt.Errorf("write %s: not the file this render created", t.join(rel))
		}
		if err := unix.Ftruncate(fd, 0); err != nil {
			return fmt.Errorf("write %s: %w", t.join(rel), err)
		}
	} else {
		if t.created == nil {
			t.created = map[string]fileID{}
		}
		t.created[key] = idOf(&st)
	}
	if t.sizes == nil {
		t.sizes = map[string]int64{}
	}
	t.written += int64(len(content)) - t.sizes[key]
	t.sizes[key] = int64(len(content))
	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", t.join(rel), err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("chmod %s: %w", t.join(rel), err)
	}
	return nil
}

// readFileAt reads the regular file rel under t, reached without following a
// link, refusing a path that escapes t, anything but a regular file with one
// link (a second link could name a file the pod may not read, and the daemon
// would copy it into a generation the pod reads), and a file larger than max
// bytes (errTreeTooLarge).
func readFileAt(t *dirTarget, rel string, max int64) ([]byte, error) {
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
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return nil, fmt.Errorf("%s is not a regular file with one link", t.join(rel))
	}
	if st.Size > max {
		return nil, fmt.Errorf("%w: %s is %d bytes", errTreeTooLarge, t.join(rel), st.Size)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: %s grew past %d bytes", errTreeTooLarge, t.join(rel), max)
	}
	return b, nil
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
// descriptor of its own so dirfd keeps no read position. A directory with more
// than max names is refused with errTreeTooLarge, read in batches so the
// refusal costs no more than max names.
func listAt(dirfd int, path string, max int) ([]string, error) {
	fd, err := unix.Openat(dirfd, ".", pathsafe.DirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}
	d := os.NewFile(uintptr(fd), path)
	defer d.Close()
	var names []string
	for {
		batch, err := d.Readdirnames(256)
		names = append(names, batch...)
		if len(names) > max {
			return nil, fmt.Errorf("%w: more than %d entries in %s", errTreeTooLarge, max, path)
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", path, err)
		}
	}
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
// error stops the walk. More than maxTreeEntries entries, or a directory more
// than maxTreeDepth deep, stops it with errTreeTooLarge.
func walkAt(t *dirTarget, visit func(rel string, st *unix.Stat_t, parent int, name string) error) error {
	seen := 0
	var walk func(fd int, prefix string, depth int) error
	walk = func(fd int, prefix string, depth int) error {
		if depth > maxTreeDepth {
			return fmt.Errorf("%w: %s nests more than %d deep", errTreeTooLarge, t.join(prefix), maxTreeDepth)
		}
		names, err := listAt(fd, filepath.Join(t.path, prefix), maxTreeEntries-seen)
		if err != nil {
			return err
		}
		if seen += len(names); seen > maxTreeEntries {
			return fmt.Errorf("%w: more than %d entries under %s", errTreeTooLarge, maxTreeEntries, t.path)
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
			err = walk(sub, rel, depth+1)
			unix.Close(sub)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return walk(t.fd, "", 1)
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
