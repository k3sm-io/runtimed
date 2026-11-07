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
	"syscall"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
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
// It returns an open file rather than a path on purpose. The clone is made
// from the descriptor (fclonefileat(2)), so the inode whose volume is checked
// is the inode that is cloned: a path would be resolved twice, once for the
// volume check and once by clonefile, and the store's directory — writable by
// a different user — could swap the file between the two.
//
// Nothing the source returns is trusted. Its file is never read as the blob:
// the cache re-hashes its own clone and commits only on a digest match.
type LocalBlobSource interface {
	OpenBlob(digest string) (*os.File, int64, error)
}

// ErrBlobNotLocal reports that a blob cannot be taken from a LocalBlobSource:
// the source does not hold it, its file is on another volume, or the volume
// cannot make a copy-on-write clone. It is the "pull it the normal way"
// answer, and it is the only error from CommitFromLocal that means nothing is
// wrong.
var ErrBlobNotLocal = errors.New("image: blob not available from the local blob store")

// maxCloneNameAttempts bounds the retries for an unused temp name.
const maxCloneNameAttempts = 8

// CommitFromLocal commits the blob for digest by cloning it from src instead of
// fetching it, and reports whether a new blob was written (false == this blob
// was already cached). size is the descriptor's declared size, exactly as for
// CommitBlob.
//
// The clone is a copy-on-write clonefile(2) into the store's temp area, never
// a hard link: the source's owner must not share an inode with a file in the
// cache, and CLONE_NOOWNERCOPY makes the clone the cache's own file. The cache
// then re-hashes the CLONE — never the source path — under the same size guard
// and digest comparison CommitBlob applies, and renames it into place only on a
// match. A clone whose bytes contradict digest is removed and the error names
// the digest and wraps ErrDigestMismatch.
//
// It returns an error matching ErrBlobNotLocal when src does not hold the
// blob, when the source file is on a different volume from the store (st_dev
// mismatch), or when the clone cannot be made there (EXDEV, ENOTSUP, or a
// platform without clonefile); the caller then pulls normally. Any other error
// is a refusal the caller must surface: it may still pull, but not silently.
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
	if size != SizeUnknown && srcInfo.Size() > size {
		return false, fmt.Errorf("local blob %s: %d bytes, descriptor declares %d: %w",
			quoteBounded(digest, maxDigestLen), srcInfo.Size(), size, ErrBlobTooLarge)
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("mkdir blob dir: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return false, fmt.Errorf("open blob dir: %w", err)
	}
	defer d.Close()
	dirInfo, err := d.Stat()
	if err != nil {
		return false, fmt.Errorf("stat blob dir: %w", err)
	}
	same := c.sameVolume
	if same == nil {
		same = sameDevice
	}
	if !same(srcInfo, dirInfo) {
		return false, fmt.Errorf("commit blob %s from local store: source is on another volume: %w",
			quoteBounded(digest, maxDigestLen), ErrBlobNotLocal)
	}

	name, err := cloneToTemp(f, d)
	if err != nil {
		if IsCloneUnsupported(err) {
			return false, fmt.Errorf("commit blob %s from local store: %v: %w",
				quoteBounded(digest, maxDigestLen), err, ErrBlobNotLocal)
		}
		return false, fmt.Errorf("clone local blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	tmpName := filepath.Join(dir, name)
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := hashClone(digest, want, size, tmpName, dst); err != nil {
		return false, err
	}
	return true, nil
}

// hashClone re-hashes the cloned temp file tmpName under the size guard, makes
// it the cache's own file (mode 0600, as CreateTemp gives CommitBlob's temps),
// syncs it, and commits it through verifyAndRename.
func hashClone(digest string, want ggcrv1.Hash, size int64, tmpName, dst string) error {
	clone, err := os.OpenFile(tmpName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := clone.Chmod(0o600); err != nil {
		clone.Close()
		return fmt.Errorf("chmod clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	hasher := blobHashers[want.Algorithm]()
	var w io.Writer = hasher
	var capped *cappedWriter
	if size != SizeUnknown {
		capped = &cappedWriter{w: w, remaining: size}
		w = capped
	}
	// The clone is a snapshot of the source inode at clone time, so the size
	// checked against the source before cloning proves nothing about it: the
	// cap is re-applied to the bytes actually hashed.
	if _, err := io.Copy(w, clone); err != nil {
		clone.Close()
		if errors.Is(err, ErrBlobTooLarge) {
			return fmt.Errorf("local blob %s: %w", quoteBounded(digest, maxDigestLen), err)
		}
		return fmt.Errorf("read clone of blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	// rename(2) on APFS orders metadata but not data; see CommitBlob.
	if err := clone.Sync(); err != nil {
		clone.Close()
		return fmt.Errorf("sync blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := clone.Close(); err != nil {
		return fmt.Errorf("close blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := verifyAndRename(digest, want, hasher, tmpName, dst); err != nil {
		return fmt.Errorf("local blob store copy refused: %w", err)
	}
	return nil
}

// cloneToTemp clones src into dir under a fresh ".blob-*" name — the pattern of
// CommitBlob's temps, so a leftover from a crash is the same kind of debris
// (BlobKindTemp) — and returns the name.
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
