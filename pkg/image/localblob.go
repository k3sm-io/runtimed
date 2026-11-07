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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sys/unix"
)

// LocalBlobSource is a blob store on this machine that may already hold a blob
// the cache is about to pull — the node's own registry, when it runs on the
// same volume. The cache knows nothing of the store's layout: it asks for a
// digest and gets back an open file or ErrBlobNotLocal.
//
// OpenBlob returns the store's file for digest, opened read-only, and the size
// the store believes it has. The caller owns the returned file and closes it.
// A store that does not hold digest returns an error matching ErrBlobNotLocal
// (fs.ErrNotExist is accepted as the same answer).
//
// An implementation must open the file with O_NOFOLLOW, beneath a directory
// the source itself controls, and must return regular files only. The cache
// refuses anything else it is handed, but a source that follows a planted
// symlink has already let a third party choose which file is offered.
//
// It returns an open file rather than a path on purpose. The clone is made
// from the descriptor (fclonefileat(2)), so the inode whose volume is checked
// is the inode that is cloned: a path would be resolved twice, once for the
// volume check and once by clonefile, and the store's directory — writable by
// a different user — could swap the file between the two.
//
// Nothing the source returns is trusted. Its file is never read as the blob:
// the cache re-hashes its own clone and commits only on a digest match.
//
// That integrity boundary holds only when the source's files are owned by a
// different uid than the daemon. A source running as the daemon's own uid
// could write the cache directly, so for it the clone adds no protection —
// and loses none either.
type LocalBlobSource interface {
	OpenBlob(digest string) (*os.File, int64, error)
}

// ErrBlobNotLocal reports that a blob cannot be taken from a LocalBlobSource:
// the source does not hold it, its file is on another volume, the volume
// cannot make a copy-on-write clone, or the blob's size is unknown. It is the
// "pull it the normal way" answer, and it is the only error from
// CommitFromLocal that means nothing is wrong.
var ErrBlobNotLocal = errors.New("image: blob not available from the local blob store")

// localStageDir is the private staging directory clones are made in, under the
// cache root. It is not under the blobs dir so it never appears in the blob
// inventory (EnumerateBlobs) as an unknown algorithm directory.
const localStageDir = ".local-stage"

// maxCloneNameAttempts bounds the retries for an unused temp name.
const maxCloneNameAttempts = 8

// CommitFromLocal commits the blob for digest by cloning it from src instead of
// fetching it, and reports whether a new blob was written (false == this blob
// was already cached). size is the descriptor's declared size; unlike
// CommitBlob, SizeUnknown is refused with ErrBlobNotLocal, so a blob of
// unknown size always takes the fetch path and its bounds.
//
// The clone is a copy-on-write clonefile(2), never a hard link: the source's
// owner must not share an inode with a file in the cache. It is made in a
// private staging directory (mode 0700, owned by this process, verified on
// every use), so no other user can open the clone while it is being checked:
// clonefile gives the clone the SOURCE's mode, and in a directory others could
// traverse, a foreign process could open a world-writable clone before its
// mode is fixed and keep writing to it after the hash. Through that one
// descriptor the clone is then required to be a regular, singly-linked file
// owned by this process, set to 0600, cleared of file flags and extended
// attributes, and re-hashed — never the source path — under the same size
// guard and digest comparison CommitBlob applies. Only on a match is it
// renamed into the blob store. A mismatch removes the clone and returns an
// error naming the digest and wrapping ErrDigestMismatch.
//
// The checks above defend against a source owned by a different uid than the
// daemon; see LocalBlobSource for why a same-uid source is outside them.
//
// It returns an error matching ErrBlobNotLocal when src does not hold the
// blob, when size is SizeUnknown, when the source or its clone has a mode this
// process cannot read, when the source file is on a different
// volume from the store (st_dev mismatch), or when the clone cannot be made
// there (EXDEV, ENOTSUP, or a platform without clonefile); the caller then
// pulls normally. Any other error is a refusal the caller must surface: it may
// still pull, but not silently.
func (c *Cache) CommitFromLocal(digest string, size int64, src LocalBlobSource) (wrote bool, err error) {
	want, err := parseBlobDigest(digest)
	if err != nil {
		return false, err
	}
	if src == nil {
		return false, fmt.Errorf("commit blob %s from local store: %w", quoteBounded(digest, maxDigestLen), ErrBlobNotLocal)
	}
	if err := checkCommitSize(digest, size); err != nil {
		return false, err
	}
	if size == SizeUnknown {
		return false, fmt.Errorf("commit blob %s from local store: size unknown: %w", quoteBounded(digest, maxDigestLen), ErrBlobNotLocal)
	}
	dst := c.pathFor(want)
	if blobHit(dst) {
		return false, nil
	}

	f, claimed, err := src.OpenBlob(want.String())
	if err != nil {
		if errors.Is(err, ErrBlobNotLocal) || errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("commit blob %s from local store: %w", quoteBounded(digest, maxDigestLen), ErrBlobNotLocal)
		}
		return false, fmt.Errorf("open local blob %s: %w", quoteBounded(digest, maxDigestLen), boundErr(err))
	}
	if f == nil {
		return false, fmt.Errorf("open local blob %s: source returned no file", quoteBounded(digest, maxDigestLen))
	}
	defer f.Close()
	srcInfo, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("stat local blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if !srcInfo.Mode().IsRegular() {
		return false, fmt.Errorf("local blob %s is not a regular file (mode %s)", quoteBounded(digest, maxDigestLen), srcInfo.Mode())
	}
	if claimed != srcInfo.Size() {
		return false, fmt.Errorf("local blob %s: source claims %d bytes, its file has %d",
			quoteBounded(digest, maxDigestLen), claimed, srcInfo.Size())
	}
	// Refuse an oversized file before cloning or reading a byte of it. A short
	// one needs no early check: its bytes cannot hash to digest.
	if srcInfo.Size() > size {
		return false, fmt.Errorf("local blob %s: %d bytes, descriptor declares %d: %w",
			quoteBounded(digest, maxDigestLen), srcInfo.Size(), size, ErrBlobTooLarge)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, fmt.Errorf("mkdir blob dir: %w", err)
	}
	stage, stageInfo, err := c.openStageDir()
	if err != nil {
		return false, err
	}
	defer stage.Close()
	same := c.sameVolume
	if same == nil {
		same = sameDevice
	}
	if !same(srcInfo, stageInfo) {
		return false, fmt.Errorf("commit blob %s from local store: source is on another volume: %w",
			quoteBounded(digest, maxDigestLen), ErrBlobNotLocal)
	}

	name, err := cloneToTemp(f, stage)
	if err != nil {
		// EACCES: the kernel refuses to clone a source this process cannot
		// read (mode 0000/0200 for a non-root daemon). Like an unreadable
		// clone (hashClone), that is the source's choice, not tampering.
		if IsCloneUnsupported(err) || errors.Is(err, fs.ErrPermission) {
			return false, fmt.Errorf("commit blob %s from local store: %v: %w",
				quoteBounded(digest, maxDigestLen), err, ErrBlobNotLocal)
		}
		return false, fmt.Errorf("clone local blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	defer func() {
		// No-op after a successful rename. A clone that cannot be removed is
		// reported with the refusal rather than dropped, so the debris is seen.
		if rerr := removeStaged(stage, name); rerr != nil {
			err = errors.Join(err, fmt.Errorf("remove staged clone of blob %s: %w", quoteBounded(digest, maxDigestLen), rerr))
		}
	}()

	if err := hashClone(digest, want, size, stage, name, dst); err != nil {
		return false, err
	}
	return true, nil
}

// openStageDir creates (once) and opens the private staging directory, and
// verifies on every use that it is a real directory — never a symlink — of
// mode exactly 0700, owned by this process, carrying no ACL, and that the
// directory opened is the one checked. A staging directory anyone else could
// reach is refused, not repaired: it would mean the cache root is not what
// this package made. It then sweeps stale clones a crash left (sweepStage).
func (c *Cache) openStageDir() (*os.File, os.FileInfo, error) {
	p := filepath.Join(c.root, localStageDir)
	if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, nil, fmt.Errorf("create local blob staging dir: %w", err)
	}
	li, err := os.Lstat(p)
	if err != nil {
		return nil, nil, fmt.Errorf("stat local blob staging dir: %w", err)
	}
	if err := checkPrivateDir(li); err != nil {
		return nil, nil, fmt.Errorf("local blob staging dir %s: %w", p, err)
	}
	d, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open local blob staging dir: %w", err)
	}
	fi, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, nil, fmt.Errorf("stat local blob staging dir: %w", err)
	}
	if !os.SameFile(li, fi) {
		d.Close()
		return nil, nil, fmt.Errorf("local blob staging dir %s changed while it was opened", p)
	}
	if err := checkPrivateDir(fi); err != nil {
		d.Close()
		return nil, nil, fmt.Errorf("local blob staging dir %s: %w", p, err)
	}
	acl, err := hasACL(d)
	if err != nil {
		d.Close()
		if errors.Is(err, errors.ErrUnsupported) {
			return nil, nil, fmt.Errorf("local blob staging dir %s: %v: %w", p, err, ErrBlobNotLocal)
		}
		return nil, nil, fmt.Errorf("local blob staging dir %s: %w", p, err)
	}
	if acl {
		d.Close()
		return nil, nil, fmt.Errorf("local blob staging dir %s carries an ACL", p)
	}
	c.sweepStage(d)
	return d, fi, nil
}

// staleStageAge is how long a staged clone may exist before a later call
// treats it as a crash's debris. It is far longer than any one clone takes to
// hash, so an in-flight clone of another call is never swept.
const staleStageAge = time.Hour

// maxStageSweep bounds the entries one sweep looks at, so a staging directory
// full of debris costs each call a fixed amount of work.
const maxStageSweep = 64

// sweepStage removes up to maxStageSweep ".blob-*" clones in stage whose
// status-change time is older than staleStageAge, clearing their file flags
// first. It is best-effort: a clone it cannot remove is left for the next
// sweep, and nothing it does can affect a commit.
func (c *Cache) sweepStage(stage *os.File) {
	entries, err := stage.ReadDir(maxStageSweep)
	if err != nil && len(entries) == 0 {
		return
	}
	cutoff := c.now().Add(-staleStageAge)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".blob-") {
			continue
		}
		info, err := e.Info()
		if err != nil || !statusChanged(info).Before(cutoff) {
			continue
		}
		// Best-effort by design (see above): the next sweep retries.
		_ = removeStaged(stage, e.Name())
	}
}

// removeStaged clears the file flags on the clone name in stage — an inherited
// UF_IMMUTABLE or UF_APPEND would otherwise make it undeletable — and removes
// it. A clone that is already gone is not an error.
func removeStaged(stage *os.File, name string) error {
	p := filepath.Join(stage.Name(), name)
	if err := clearFlags(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// checkPrivateDir requires a directory of mode exactly 0700 owned by the
// effective uid.
func checkPrivateDir(fi os.FileInfo) error {
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("not a directory (mode %s)", fi.Mode())
	}
	if fi.Mode().Perm() != 0o700 || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return fmt.Errorf("mode %s, want drwx------", fi.Mode())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no ownership information")
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, os.Geteuid())
	}
	return nil
}

// hashClone opens the staged clone name inside stage, makes it the cache's own
// private file, re-hashes it from that one descriptor under the size guard,
// syncs it, and renames it from stage onto dst through verifyAndRename.
//
// The order matters: flags are cleared and xattrs removed before the chmod,
// because an inherited UF_IMMUTABLE would make the chmod fail.
func hashClone(digest string, want ggcrv1.Hash, size int64, stage *os.File, name, dst string) error {
	clone, err := openAt(stage, name)
	if errors.Is(err, fs.ErrPermission) {
		// The clone inherited a mode this process cannot read (0000, 0200).
		// That is the source's choice, not tampering; the deferred cleanup
		// removes the clone and the caller pulls normally.
		return fmt.Errorf("commit blob %s from local store: clone is unreadable: %v: %w",
			quoteBounded(digest, maxDigestLen), err, ErrBlobNotLocal)
	}
	if err != nil {
		return fmt.Errorf("open clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	defer clone.Close()
	fi, err := clone.Stat()
	if err != nil {
		return fmt.Errorf("stat clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := checkOwnClone(fi); err != nil {
		return fmt.Errorf("clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := scrubClone(clone); err != nil {
		return fmt.Errorf("scrub clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	acl, err := hasACL(clone)
	if err != nil {
		return fmt.Errorf("clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if acl {
		return fmt.Errorf("clone of blob %s carries an ACL", quoteBounded(digest, maxDigestLen))
	}
	if err := clone.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	hasher := blobHashers[want.Algorithm]()
	capped := &cappedWriter{w: hasher, remaining: size}
	// The clone is a snapshot of the source inode at clone time, so the size
	// checked against the source before cloning proves nothing about it: the
	// cap is re-applied to the bytes actually hashed.
	if _, err := io.Copy(capped, clone); err != nil {
		if errors.Is(err, ErrBlobTooLarge) {
			return fmt.Errorf("local blob %s: %w", quoteBounded(digest, maxDigestLen), err)
		}
		return fmt.Errorf("read clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	// rename(2) on APFS orders metadata but not data; see CommitBlob.
	if err := clone.Sync(); err != nil {
		return fmt.Errorf("sync blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := verifyAndRename(digest, want, hasher, func() error { return renameFromStage(stage, name, dst) }); err != nil {
		return fmt.Errorf("local blob store copy refused: %w", err)
	}
	return nil
}

// checkOwnClone requires the staged clone to be a regular file with one link,
// owned by the effective uid (CLONE_NOOWNERCOPY makes it ours).
func checkOwnClone(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (mode %s)", fi.Mode())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no ownership information")
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, os.Geteuid())
	}
	if st.Nlink != 1 {
		return fmt.Errorf("%d links, want 1", st.Nlink)
	}
	return nil
}

// openAt opens name inside dir read-only, refusing a symlink.
func openAt(dir *os.File, name string) (*os.File, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var openErr error
	if err := conn.Control(func(dfd uintptr) {
		fd, openErr = unix.Openat(int(dfd), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: openErr}
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

// cloneToTemp clones src into dir under a fresh ".blob-*" name and returns the
// name.
func cloneToTemp(src, dir *os.File) (string, error) {
	for range maxCloneNameAttempts {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("temp name: %w", err)
		}
		name := ".blob-" + hex.EncodeToString(b[:])
		err := cloneFileAt(src, dir, name)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("temp name: no unused name found")
}

// sameDevice reports whether two files are on the same volume by st_dev.
func sameDevice(a, b os.FileInfo) bool {
	sa, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	sb, ok := b.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return sa.Dev == sb.Dev
}
