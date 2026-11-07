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
	"errors"
	"os"

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
