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
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// QuarantineXattr is the macOS attribute Gatekeeper sets on downloaded files.
// Materialized pod files must not carry it (it would trigger a Gatekeeper prompt
// / block exec); MaterializeTree asserts its absence.
const QuarantineXattr = "com.apple.quarantine"

// ErrQuarantined reports that a materialized file unexpectedly carries the
// com.apple.quarantine xattr.
var ErrQuarantined = errors.New("image: materialized file has com.apple.quarantine xattr")

// Cloner copies a single regular file from src to dst. The production
// implementation (APFSCloner, clone_darwin.go) uses an APFS copy-on-write clone
// and falls back to a byte copy on EXDEV/ENOTSUP; CloneOnly never falls back; a portable byte-copy implementation
// (ByteCopier) is used off darwin and in unit tests that don't need real CoW.
//
// MaterializeTree copies only descriptor-relative (into the open parent
// directory, resolving no destination path), through the unexported cloneAt
// method every Cloner this package ships (ByteCopier, APFSCloner, CloneOnly,
// and CountClones's wrapper) has. It refuses a Cloner without that method with
// ErrPathOnlyCloner: copying by a joined path after the parent was checked
// would leave a race between that check and the copy.
type Cloner interface {
	// Clone copies the regular file src to dst (which must not yet exist). It
	// reports whether the copy was a real APFS clone (cow) via the bool, so
	// callers/tests can distinguish a clone from a byte-copy fallback.
	Clone(src, dst string) (cow bool, err error)
}

// IsCloneUnsupported reports whether err is clonefile(2) saying the clone
// cannot be made on these volumes at all: EXDEV (src and dst on different
// volumes), or ENOTSUP/EOPNOTSUPP (the filesystem is not APFS). It is the
// condition APFSCloner degrades to a byte copy on and CloneOnly refuses on.
func IsCloneUnsupported(err error) bool {
	// syscall.Errno matches errors.ErrUnsupported for ENOTSUP, EOPNOTSUPP and
	// ENOSYS.
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, errors.ErrUnsupported)
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

// cloneAt byte-copies src to name inside dir. cow is always false.
func (ByteCopier) cloneAt(src string, dir *os.File, name string) (bool, error) {
	return false, byteCopyAt(src, dir, name)
}

// ErrDestinationLink reports that MaterializeTree found a symlink, or some
// other non-directory, in the destination where the tree needs a directory, or
// a symlink where the tree lands a regular file. Nothing is written through it.
var ErrDestinationLink = errors.New("image: materialize destination holds a link where the tree needs a directory or file")

// ErrPathOnlyCloner reports that MaterializeTree was given a Cloner without
// the descriptor-relative clone method (one defined outside this package that
// does not wrap a Cloner it ships). Nothing is created or copied.
var ErrPathOnlyCloner = errors.New("image: cloner cannot copy relative to a directory descriptor")

// cloneAter is the descriptor-relative half of a Cloner: it copies the regular
// file src to name inside the open directory dir, resolving no destination
// path component. Every Cloner this package ships implements it, and
// MaterializeTree refuses a Cloner that does not (ErrPathOnlyCloner).
type cloneAter interface {
	cloneAt(src string, dir *os.File, name string) (cow bool, err error)
}

// CountClones returns a Cloner that copies with c and adds one to n before
// every file it is asked to copy, by either method. It lets a test outside
// this package observe how many files a materialize copied without giving up
// the descriptor-relative copy. c must be a Cloner this package ships (or
// another CountClones result): the returned Cloner's descriptor-relative copy
// fails with ErrPathOnlyCloner otherwise.
func CountClones(c Cloner, n *atomic.Int64) Cloner {
	return countClones{inner: c, n: n}
}

// countClones is CountClones's Cloner.
type countClones struct {
	inner Cloner
	n     *atomic.Int64
}

// Clone counts the copy and copies src to dst by path with the wrapped Cloner.
func (c countClones) Clone(src, dst string) (bool, error) {
	c.n.Add(1)
	return c.inner.Clone(src, dst)
}

// cloneAt counts the copy and copies src to name inside dir with the wrapped
// Cloner's descriptor-relative method.
func (c countClones) cloneAt(src string, dir *os.File, name string) (bool, error) {
	at, ok := c.inner.(cloneAter)
	if !ok {
		return false, ErrPathOnlyCloner
	}
	c.n.Add(1)
	return at.cloneAt(src, dir, name)
}

// ErrTreeTooDeep reports that MaterializeTree met a source directory nested
// deeper than maxMaterializeDepth. The walk stops before creating or opening it.
var ErrTreeTooDeep = errors.New("image: materialize source tree is nested too deeply")

// maxMaterializeDepth is the most directory levels below dstDir MaterializeTree
// descends. The destination walk keeps one open descriptor per level, so an
// unbounded tree could exhaust the daemon's descriptors (the default soft limit
// is 256). It equals maxLayerEntryDepth: an unpacked layer never names a path
// deeper than that, so no tree this package produced is refused.
const maxMaterializeDepth = maxLayerEntryDepth

// destDir is one open destination directory on the walk's stack.
type destDir struct {
	rel string
	f   *os.File
}

// MaterializeTree recursively copies the directory tree rooted at srcDir into
// dstDir using c, preserving structure and mode. Existing destination files are
// left in place (idempotent re-materialize). After copying each regular file it
// asserts the file does not carry the com.apple.quarantine xattr. It returns the
// number of files that were materialized as real APFS clones.
//
// dstDir itself is the caller's trust anchor and is created and opened by path.
// Beneath it the walk never leaves dstDir: every destination directory is
// opened relative to its parent's descriptor with O_NOFOLLOW|O_DIRECTORY, and
// every directory, file and symlink is created relative to its parent's
// descriptor. A symlink where the tree needs a directory is resolved beneath
// dstDir (os.Root), so images composed into one shared pod rootfs still compose
// (one ships lib -> usr/lib, the next writes lib/x into usr/lib); a link that
// would leave dstDir (an absolute target, a .. climb out, a chain stepping
// out), or resolves to a non-directory, fails with ErrDestinationLink, so a link
// a pod planted in its own rootfs cannot redirect a later re-materialize out of
// it. A destination directory link with an absolute target is refused and is
// never reinterpreted relative to dstDir, even when it spells a path inside it;
// a link resolving inside dstDir is followed, and one that dangles or cannot be
// opened fails with ErrDestinationLink. The in-root resolution re-walks the
// relative path from dstDir, so a writer that swaps an ancestor during the walk
// can misplace an entry inside dstDir but never outside it.
// A non-directory where the tree needs a directory, or a symlink where the
// tree lands a regular file, fails with ErrDestinationLink too. Idempotence is decided by lstat: an existing regular file
// (or any other non-link entry) where the tree lands a file is kept, and any
// existing entry where the tree lands a symlink is kept. Every file is copied
// relative to its parent's descriptor; a Cloner that cannot do that fails with
// ErrPathOnlyCloner before anything is created.
func MaterializeTree(c Cloner, srcDir, dstDir string) (cloned int, err error) {
	at, ok := c.(cloneAter)
	if !ok {
		return 0, fmt.Errorf("materialize %s: %T: %w", dstDir, c, ErrPathOnlyCloner)
	}
	srcInfo, err := os.Stat(srcDir)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dstDir, srcInfo.Mode().Perm()|0o100); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", dstDir, err)
	}
	root, err := os.OpenFile(dstDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open destination %s: %w", dstDir, err)
	}
	stack := []destDir{{rel: ".", f: root}}
	// inRoot resolves a destination directory link beneath dstDir. It follows
	// links whose targets stay inside dstDir (a merged-usr lib -> usr/lib one
	// image shipped and the next image writes through) and refuses any that
	// leave it (an absolute target, a .. climb, a chain stepping out).
	inRoot, err := os.OpenRoot(dstDir)
	if err != nil {
		root.Close()
		return 0, fmt.Errorf("open destination root %s: %w", dstDir, err)
	}
	defer inRoot.Close()
	defer func() {
		for _, d := range stack {
			d.f.Close()
		}
	}()

	walkErr := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil // the root is already open
		}
		dst := filepath.Join(dstDir, rel)
		parentRel := filepath.Dir(rel)
		for len(stack) > 1 && stack[len(stack)-1].rel != parentRel {
			stack[len(stack)-1].f.Close()
			stack = stack[:len(stack)-1]
		}
		if stack[len(stack)-1].rel != parentRel {
			return fmt.Errorf("materialize %s: parent directory not open", dst)
		}
		parent := stack[len(stack)-1].f
		name := filepath.Base(rel)

		switch {
		case d.IsDir():
			// stack[0] is dstDir, so this directory is len(stack) levels deep.
			if len(stack) > maxMaterializeDepth {
				return fmt.Errorf("%w: %s exceeds %d levels", ErrTreeTooDeep, rel, maxMaterializeDepth)
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			f, oerr := mkdirOpenAt(inRoot, parent, name, rel, info.Mode().Perm()|0o100)
			if oerr != nil {
				return fmt.Errorf("mkdir %s: %w", dst, oerr)
			}
			stack = append(stack, destDir{rel: rel, f: f})
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return fmt.Errorf("readlink %s: %w", path, lerr)
			}
			if _, present, serr := lstatAt(parent, name); serr != nil {
				return fmt.Errorf("lstat %s: %w", dst, serr)
			} else if present {
				return nil // idempotent: an entry is already present
			}
			if err := symlinkAt(target, parent, name); err != nil {
				return fmt.Errorf("symlink %s: %w", dst, err)
			}
			return nil
		case d.Type().IsRegular():
			mode, present, serr := lstatAt(parent, name)
			if serr != nil {
				return fmt.Errorf("lstat %s: %w", dst, serr)
			}
			if present {
				switch mode & unix.S_IFMT {
				case unix.S_IFLNK:
					return fmt.Errorf("materialize %s: %w", dst, ErrDestinationLink)
				case unix.S_IFREG:
					// Idempotent: destination already materialized. Still
					// assert the quarantine invariant on the existing file.
					return assertNoQuarantineAt(parent, name)
				default:
					return nil // idempotent, as before: something is there
				}
			}
			cow, cerr := at.cloneAt(path, parent, name)
			if cerr != nil {
				return fmt.Errorf("clone %s -> %s: %w", path, dst, cerr)
			}
			if cow {
				cloned++
			}
			return assertNoQuarantineAt(parent, name)
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

// withFD runs fn with dir's descriptor.
func withFD(dir *os.File, fn func(fd int) error) error {
	conn, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := conn.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

// mkdirOpenAt creates name inside dir (an existing directory is kept) and
// opens it without following a link. A symlink at name is resolved beneath
// root instead, by rel (name's path from the destination root): a link that
// stays inside root and reaches a directory is opened there, and one that
// would leave root, or reaches a non-directory, fails with ErrDestinationLink.
// A non-directory, non-link entry at name fails with ErrDestinationLink.
func mkdirOpenAt(root *os.Root, dir *os.File, name, rel string, perm os.FileMode) (*os.File, error) {
	var fd int
	isLink := false
	err := withFD(dir, func(dfd int) error {
		if err := unix.Mkdirat(dfd, name, uint32(perm)); err != nil && !errors.Is(err, unix.EEXIST) {
			return &os.PathError{Op: "mkdirat", Path: name, Err: err}
		}
		var oerr error
		fd, oerr = unix.Openat(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr == nil {
			return nil
		}
		if errors.Is(oerr, unix.ELOOP) || errors.Is(oerr, unix.ENOTDIR) {
			// Some kernels report a link opened O_NOFOLLOW|O_DIRECTORY as
			// ENOTDIR rather than ELOOP; lstat tells a link from a file.
			var st unix.Stat_t
			if serr := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				isLink = true
				return nil
			}
		}
		if errors.Is(oerr, unix.ELOOP) || errors.Is(oerr, unix.ENOTDIR) {
			return fmt.Errorf("%w: %s: %w", ErrDestinationLink, name, oerr)
		}
		return &os.PathError{Op: "openat", Path: name, Err: oerr}
	})
	if err != nil {
		return nil, err
	}
	if isLink {
		return openDirInRoot(root, rel)
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

// openDirInRoot opens rel beneath root, following only links that stay inside
// root, and requires the result to be a directory. Every failure is
// ErrDestinationLink with the cause kept in the chain: a resolution that would
// leave root (os.Root refuses it), a dangling or unopenable target, and a
// target that is not a directory all mean a link stands where the tree needs a
// directory and cannot be used.
func openDirInRoot(root *os.Root, rel string) (*os.File, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDestinationLink, rel, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%w: %s resolves to a non-directory", ErrDestinationLink, rel)
	}
	return f, nil
}

// lstatAt reports the type bits of name inside dir without following a link,
// and whether anything is there at all.
func lstatAt(dir *os.File, name string) (mode uint32, present bool, err error) {
	err = withFD(dir, func(dfd int) error {
		var st unix.Stat_t
		serr := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(serr, unix.ENOENT) {
			return nil
		}
		if serr != nil {
			return &os.PathError{Op: "fstatat", Path: name, Err: serr}
		}
		mode, present = uint32(st.Mode), true
		return nil
	})
	return mode, present, err
}

// symlinkAt creates the symlink name -> target inside dir.
func symlinkAt(target string, dir *os.File, name string) error {
	return withFD(dir, func(dfd int) error {
		if err := unix.Symlinkat(target, dfd, name); err != nil {
			return &os.LinkError{Op: "symlinkat", Old: target, New: name, Err: err}
		}
		return nil
	})
}

// openNoFollowAt opens name inside dir read-only without following a link and
// without blocking on a FIFO.
func openNoFollowAt(dir *os.File, name string) (*os.File, error) {
	var fd int
	err := withFD(dir, func(dfd int) error {
		var oerr error
		fd, oerr = unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if oerr != nil {
			return &os.PathError{Op: "openat", Path: name, Err: oerr}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

// byteCopyAt copies src to name inside dir, preserving permission bits. name
// must not exist; a link at name is refused, never followed.
func byteCopyAt(src string, dir *os.File, name string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	var fd int
	if err := withFD(dir, func(dfd int) error {
		var oerr error
		fd, oerr = unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(info.Mode().Perm()))
		if oerr != nil {
			return &os.PathError{Op: "openat", Path: name, Err: oerr}
		}
		return nil
	}); err != nil {
		return err
	}
	out := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name))
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
