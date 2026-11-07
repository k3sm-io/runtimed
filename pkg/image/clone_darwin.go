//go:build darwin

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

package image

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// APFSCloner is the production Cloner: it copies via an APFS copy-on-write clone
// (unix.Clonefile — the x/sys binding, not hand cgo) and falls back to a byte
// copy on EXDEV (src and dst on different volumes) or ENOTSUP/EOPNOTSUPP (the
// filesystem is not APFS). The cache and pod rootfs must share an APFS volume for
// the clone to succeed; the fallback keeps materialize working otherwise.
type APFSCloner struct{}

// Clone CoW-clones src to dst. cow is true when the APFS clone succeeded, false
// when it fell back to a byte copy. dst must not already exist.
func (APFSCloner) Clone(src, dst string) (bool, error) {
	// CLONE_NOFOLLOW: clone the symlink itself, not its target (we handle real
	// symlinks separately in MaterializeTree, so this only guards regular files).
	err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
	if err == nil {
		return true, nil
	}
	if IsCloneUnsupported(err) {
		if cErr := byteCopyFile(src, dst); cErr != nil {
			return false, cErr
		}
		return false, nil
	}
	return false, err
}

// CloneOnly is the Cloner for a copy that must share extents with its source
// (an artifact view): it calls clonefile(2) and nothing else. Where the clone
// cannot be made (IsCloneUnsupported: another volume, or not APFS) it fails
// before any byte is written, where APFSCloner would copy. cow is true on
// every success.
type CloneOnly struct{}

// Clone CoW-clones src to dst, which must not already exist. It never copies.
func (CloneOnly) Clone(src, dst string) (bool, error) {
	// CLONE_NOFOLLOW: a symlink at src is cloned as itself, never followed.
	if err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW); err != nil {
		return false, &os.LinkError{Op: "clonefile", Old: src, New: dst, Err: err}
	}
	return true, nil
}

// cloneFileAt CoW-clones the open file src to name inside the open directory
// dir with fclonefileat(2) (the x/sys binding, not hand cgo). Cloning from the
// descriptor means the inode cloned is the inode the caller already checked;
// no path is resolved on the source side. CLONE_NOFOLLOW refuses a symlink at
// the destination name, and CLONE_NOOWNERCOPY makes the clone owned by this
// process rather than by the source file's owner. name must not exist.
//
// The clone still carries the source's mode, file flags and extended
// attributes: <sys/clonefile.h> has no flag that drops them (its 0x0004 is
// CLONE_ACL, which ADDS the source's ACL, and is deliberately not passed).
// The caller clones into a private directory and strips them with scrubClone
// before the clone is read.
func cloneFileAt(src, dir *os.File, name string) error {
	srcConn, err := src.SyscallConn()
	if err != nil {
		return err
	}
	dirConn, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var cloneErr, innerErr error
	err = srcConn.Control(func(srcFD uintptr) {
		innerErr = dirConn.Control(func(dirFD uintptr) {
			cloneErr = unix.Fclonefileat(int(srcFD), int(dirFD), name, unix.CLONE_NOFOLLOW|unix.CLONE_NOOWNERCOPY)
		})
	})
	if err = errors.Join(err, innerErr); err != nil {
		return err
	}
	if cloneErr != nil {
		return &os.PathError{Op: "fclonefileat", Path: name, Err: cloneErr}
	}
	return nil
}

// scrubClone clears every file flag (UF_IMMUTABLE, UF_APPEND, UF_NODUMP, ...)
// and removes every extended attribute on the open clone f, then confirms none
// remain, so nothing the source's owner set on its file reaches the cache.
func scrubClone(f *os.File) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var scrubErr error
	if err := conn.Control(func(fd uintptr) {
		scrubErr = scrubFD(int(fd))
	}); err != nil {
		return err
	}
	return scrubErr
}

// scrubFD is scrubClone on a raw descriptor.
func scrubFD(fd int) error {
	if err := unix.Fchflags(fd, 0); err != nil {
		return &os.PathError{Op: "fchflags", Path: "clone", Err: err}
	}
	names, err := listXattrs(fd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := unix.Fremovexattr(fd, n); err != nil && !errors.Is(err, unix.ENOATTR) {
			return &os.PathError{Op: "fremovexattr", Path: n, Err: err}
		}
	}
	left, err := listXattrs(fd)
	if err != nil {
		return err
	}
	if len(left) != 0 {
		return fmt.Errorf("extended attributes remain after scrub: %q", left)
	}
	return nil
}

// listXattrs returns the extended attribute names on fd.
func listXattrs(fd int) ([]string, error) {
	for range 4 {
		sz, err := unix.Flistxattr(fd, nil)
		if err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				return nil, nil
			}
			return nil, &os.PathError{Op: "flistxattr", Path: "clone", Err: err}
		}
		if sz == 0 {
			return nil, nil
		}
		buf := make([]byte, sz)
		n, err := unix.Flistxattr(fd, buf)
		if errors.Is(err, unix.ERANGE) {
			continue // the list grew between the two calls
		}
		if err != nil {
			return nil, &os.PathError{Op: "flistxattr", Path: "clone", Err: err}
		}
		var names []string
		for _, b := range bytes.Split(buf[:n], []byte{0}) {
			if len(b) > 0 {
				names = append(names, string(b))
			}
		}
		return names, nil
	}
	return nil, errors.New("flistxattr: attribute list kept changing")
}

// clearFlags clears every file flag on path without following a symlink. It
// is only called on names inside the private staging directory, where no
// other user can swap the entry.
func clearFlags(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	if st.Flags == 0 || st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil
	}
	if err := unix.Chflags(path, 0); err != nil {
		return &os.PathError{Op: "chflags", Path: path, Err: err}
	}
	return nil
}

// statusChanged returns fi's status-change time. A clone's ctime is when it
// was made (its mtime is the source's), which is what the staging sweep ages.
func statusChanged(fi os.FileInfo) time.Time {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.ModTime()
	}
	return time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec)
}

// renameFromStage renames name inside the open staging directory onto the
// absolute path dst with renameat(2), so the source side is resolved from the
// directory descriptor that was verified, not from a path.
func renameFromStage(stage *os.File, name, dst string) error {
	conn, err := stage.SyscallConn()
	if err != nil {
		return err
	}
	var renErr error
	if err := conn.Control(func(fd uintptr) {
		renErr = unix.Renameat(int(fd), name, unix.AT_FDCWD, dst)
	}); err != nil {
		return err
	}
	if renErr != nil {
		return &os.LinkError{Op: "renameat", Old: name, New: dst, Err: renErr}
	}
	return nil
}

// assertNoQuarantine returns ErrQuarantined if path carries the
// com.apple.quarantine xattr. On darwin, Getxattr with a zero-length buffer
// returns the attribute size (nil error) when the attr exists, or ENOATTR when
// it does not. ENOATTR / a filesystem without xattr support is the success case.
func assertNoQuarantine(path string) error {
	if _, err := unix.Getxattr(path, QuarantineXattr, nil); err == nil {
		return ErrQuarantined
	} else if !errors.Is(err, unix.ENOATTR) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
		// Unexpected stat error: do not falsely flag quarantine; surface nothing
		// (materialize succeeded) but the attr is, by absence of nil, not present.
		return nil
	}
	return nil
}
