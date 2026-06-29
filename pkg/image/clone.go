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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// QuarantineXattr is the macOS attribute Gatekeeper sets on downloaded files.
// Materialized pod files must not carry it (it would trigger a Gatekeeper prompt
// / block exec); MaterializeTree asserts its absence.
const QuarantineXattr = "com.apple.quarantine"

// ErrQuarantined reports that a materialized file unexpectedly carries the
// com.apple.quarantine xattr.
var ErrQuarantined = errors.New("image: materialized file has com.apple.quarantine xattr")

// Cloner copies a single regular file from src to dst. The production
// implementation (clonefile_darwin.go) uses an APFS copy-on-write clone and
// falls back to a byte copy on EXDEV/ENOTSUP; a portable byte-copy implementation
// (ByteCopier) is used off darwin and in unit tests that don't need real CoW.
type Cloner interface {
	// Clone copies the regular file src to dst (which must not yet exist). It
	// reports whether the copy was a real APFS clone (cow) via the bool, so
	// callers/tests can distinguish a clone from a byte-copy fallback.
	Clone(src, dst string) (cow bool, err error)
}

// ByteCopier is a Cloner that always byte-copies (never CoW). It is the portable
// fallback and the unit-test default.
type ByteCopier struct{}

// Clone byte-copies src to dst, preserving file mode. cow is always false.
func (ByteCopier) Clone(src, dst string) (bool, error) {
	if err := byteCopyFile(src, dst); err != nil {
		return false, err
	}
	return false, nil
}

// MaterializeTree recursively copies the directory tree rooted at srcDir into
// dstDir using c, preserving structure and mode. Existing destination files are
// left in place (idempotent re-materialize). After copying each regular file it
// asserts the file does not carry the com.apple.quarantine xattr. It returns the
// number of files that were materialized as real APFS clones.
func MaterializeTree(c Cloner, srcDir, dstDir string) (cloned int, err error) {
	walkErr := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(dstDir, rel)

		switch {
		case d.IsDir():
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			if err := os.MkdirAll(dst, info.Mode().Perm()|0o100); err != nil {
				return fmt.Errorf("mkdir %s: %w", dst, err)
			}
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return fmt.Errorf("readlink %s: %w", path, lerr)
			}
			if _, serr := os.Lstat(dst); serr == nil {
				return nil // idempotent: link already present
			}
			if err := os.Symlink(target, dst); err != nil {
				return fmt.Errorf("symlink %s: %w", dst, err)
			}
			return nil
		case d.Type().IsRegular():
			if _, serr := os.Stat(dst); serr == nil {
				// Idempotent: destination already materialized. Still assert the
				// quarantine invariant on the existing file.
				return assertNoQuarantine(dst)
			}
			cow, cerr := c.Clone(path, dst)
			if cerr != nil {
				return fmt.Errorf("clone %s -> %s: %w", path, dst, cerr)
			}
			if cow {
				cloned++
			}
			return assertNoQuarantine(dst)
		default:
			// Skip sockets/devices/pipes — not part of an image payload.
			return nil
		}
	})
	if walkErr != nil {
		return cloned, walkErr
	}
	return cloned, nil
}

// byteCopyFile copies src to dst preserving permission bits. dst must not exist.
func byteCopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
