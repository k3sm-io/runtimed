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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// DefaultRoot is the on-disk root for the content-addressed image cache and pod
// rootfs dirs. /var/lib/k3sm is root-owned in production; tests pass a temp root.
const DefaultRoot = "/var/lib/k3sm"

// Cache is the content-addressed on-disk store for pulled image blobs. Blobs
// live under <root>/blobs/<algo>/<hex>, keyed by their content digest, so a
// second pull of identical content is a cache hit. The cache MUST be on the same
// APFS volume as the pod rootfs dirs for clonefile materialization to CoW.
//
// Cache is safe for use by one process; concurrent writers to the same digest
// race on the temp+rename and are harmless (identical content).
type Cache struct {
	root string
}

// NewCache returns a Cache rooted at root (DefaultRoot if empty), creating the
// blobs dir. It errors only if the dir cannot be created.
func NewCache(root string) (*Cache, error) {
	if root == "" {
		root = DefaultRoot
	}
	c := &Cache{root: root}
	if err := os.MkdirAll(c.blobsDir(), 0o755); err != nil {
		return nil, fmt.Errorf("create image cache %s: %w", c.blobsDir(), err)
	}
	return c, nil
}

// Root returns the cache root dir.
func (c *Cache) Root() string { return c.root }

// blobsDir is the content-addressed blob store.
func (c *Cache) blobsDir() string { return filepath.Join(c.root, "blobs") }

// ErrUnsupportedDigestAlgorithm is returned for a digest whose ALGORITHM half is
// not in the closed allowlist below. It is distinct from ErrInvalidDigest so a
// caller (B117's tarball ingest) can tell "this store cannot handle that
// algorithm at all" from "that string is not a digest", and both from
// ErrDigestMismatch, which means the bytes were poisoned.
var ErrUnsupportedDigestAlgorithm = errors.New("image: unsupported digest algorithm")

// ErrInvalidDigest is returned for a digest that is malformed for an allowlisted
// algorithm: bad shape, a non-lowercase-hex body, or the wrong hex length.
var ErrInvalidDigest = errors.New("image: malformed digest")

// ErrDigestMismatch reports that content contradicts the manifest that named it.
// CommitBlob returns it when the bytes written hash to something other than the
// digest they were committed under — the blob is NOT committed and the
// destination path is left untouched — and Pull returns it when a fetched image
// disagrees with its own manifest about how many layers it has.
var ErrDigestMismatch = errors.New("image: blob content does not match its claimed digest")

// ErrBlobTooLarge is returned by CommitBlob when fill streams more bytes than the
// declared size. It is a RESOURCE GUARD, not an integrity mechanism — see
// CommitBlob.
var ErrBlobTooLarge = errors.New("image: blob exceeds its declared size")

// blobHashers is the CLOSED ALLOWLIST of digest algorithms this store accepts,
// and simultaneously the way it verifies them. Membership in this one table is
// what lets a digest become a filesystem path (blobPath) AND what supplies the
// hasher that checks the bytes (CommitBlob), so the store structurally cannot
// hold a blob under an algorithm it is unable to re-hash.
//
// sha512 is deliberately ABSENT. go-containerregistry v0.21.6's v1.Hasher
// supports sha256 only, so a sha512 digest cannot be parsed, fetched or verified
// anywhere else on this pull path; admitting it here would create a directory
// this package can never validate. Adding an algorithm means adding it here, and
// nowhere else.
var blobHashers = map[string]func() hash.Hash{
	"sha256": sha256.New,
}

// parseBlobDigest validates digest against the closed allowlist and returns the
// parsed hash.
//
// This is the ONLY place a digest string becomes trusted path components. It
// fails closed in algorithm-first order so an unknown algorithm reports
// ErrUnsupportedDigestAlgorithm rather than whatever go-containerregistry's
// parser happens to say about it.
//
// The body validation is delegated to ggcrv1.NewHash, which rejects any
// non-lowercase-hex character and enforces the algorithm's exact hex length, so
// neither half of the returned Hash can contain a separator, a dot, or any other
// path metacharacter. The digest is untrusted registry input, so it is rendered
// bounded (quoteBounded) in every error.
func parseBlobDigest(digest string) (ggcrv1.Hash, error) {
	algo, _, ok := cutAlgorithm(digest)
	if !ok {
		return ggcrv1.Hash{}, fmt.Errorf("digest %s: %w", quoteBounded(digest, maxDigestLen), ErrInvalidDigest)
	}
	if _, allowed := blobHashers[algo]; !allowed {
		return ggcrv1.Hash{}, fmt.Errorf("digest %s: %w", quoteBounded(digest, maxDigestLen), ErrUnsupportedDigestAlgorithm)
	}
	h, err := ggcrv1.NewHash(digest)
	if err != nil {
		// ggcr's parser formats the offending digest into its own message, so it
		// is quoted as bounded DATA, never adopted.
		return ggcrv1.Hash{}, fmt.Errorf("digest %s: %v: %w",
			quoteBounded(digest, maxDigestLen), boundErr(err), ErrInvalidDigest)
	}
	return h, nil
}

// cutAlgorithm splits "<algo>:<body>" into its two halves, reporting false when
// the string has no separator or an empty half.
func cutAlgorithm(digest string) (algo, body string, ok bool) {
	algo, body, found := strings.Cut(digest, ":")
	return algo, body, found && algo != "" && body != ""
}

// blobPath maps a digest ("<algo>:<hex>") to its on-disk path.
//
// It validates through parseBlobDigest and builds the path from the PARSED
// halves, never the raw string, so no caller can construct a path outside the
// blob root: an algorithm that is not allowlisted yields no path at all, and an
// allowlisted one has a fixed hex body. (Before B129 the algorithm half flowed
// into filepath.Join unchecked, so "../../etc:passwd" resolved to
// /var/lib/etc/passwd — which pull.go then MkdirAll'd as the root LaunchDaemon.)
func (c *Cache) blobPath(digest string) (string, error) {
	h, err := parseBlobDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.blobsDir(), h.Algorithm, h.Hex), nil
}

// Has reports whether the blob for digest is already cached.
//
// A non-regular file at the blob path (a directory, a symlink, a device node) is
// NOT a cache hit — only a regular file can be a blob, and treating anything else
// as one would let a planted directory suppress a pull.
func (c *Cache) Has(digest string) bool {
	p, err := c.blobPath(digest)
	if err != nil {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// CommitBlob writes the blob for digest via fill and commits it atomically
// (temp + fsync + rename) ONLY IF the bytes written hash to digest. It returns
// whether a new blob was written (false == this blob was already cached).
//
// This is the SINGLE HOME for the content-addressed store's integrity invariant:
// every path that puts bytes into the cache — Puller.writeBlob today, B117's
// tarball ingest next — commits through here, so the invariant is stated once.
//
// # What this defends against, honestly
//
// The claimed digest MUST come from the image manifest descriptor, not from the
// object that supplies the bytes (see Puller.Pull). Given that, this check
// defends against a FetchFunc that does not verify what the network gave it, and
// against write-path corruption between the fetcher and the disk. It does NOT
// authenticate the image: a wholly hostile FetchFunc supplies the manifest too,
// and can therefore make its bytes and its claimed digests agree. Image
// authenticity is a signature problem, not a CAS problem.
//
// # The verification ceiling
//
// Verification happens at WRITE time only. The cache-hit fast path below is an
// os.Stat, and every downstream reader (materialize, the unpacker) trusts the
// on-disk bytes; every blob written before B129 was never hashed by this repo at
// all. Verify-on-read is deliberately NOT done here — it is O(image bytes) on the
// hot path and would regress the M1.1-a1 cache-hit acceptance path. The natural
// closer is M11.2-d7, the unpacker, which already reads each blob once per rootfs
// creation and can hash it there for free.
//
// # size is a RESOURCE GUARD, not a second integrity mechanism
//
// The hash is only known at EOF, so without a cap a swapped fetcher could stream
// unbounded bytes into the root-owned cache volume before the mismatch is
// detected — on a single-Mac cluster that is the same volume as the kine
// datastore, so filling it takes the control plane down. size (the descriptor's
// declared size) caps the write: an overrun fails with ErrBlobTooLarge. It is not
// an integrity check — a stream that is short, or that is the wrong bytes at the
// right length, is caught by the ONE digest comparison, not by size. size <= 0
// means unbounded; the pull path always passes the declared size, and a
// legitimately empty blob is unbounded-but-still-verified, which is harmless.
func (c *Cache) CommitBlob(digest string, size int64, fill func(io.Writer) error) (wrote bool, err error) {
	want, err := parseBlobDigest(digest)
	if err != nil {
		return false, err
	}
	dst := filepath.Join(c.blobsDir(), want.Algorithm, want.Hex)
	// Cache hit — a REGULAR file only. A directory or a symlink at the blob path
	// is not a blob, and accepting one would let it suppress the write forever.
	if fi, serr := os.Stat(dst); serr == nil && fi.Mode().IsRegular() {
		return false, nil
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("mkdir blob dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".blob-*")
	if err != nil {
		return false, fmt.Errorf("temp blob: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	// Hash WHILE writing: a post-Close re-read would double the IO on every
	// uncached layer, the largest objects the daemon touches.
	//
	// DO NOT "optimize" this by handing tmp (an *os.File) to the copier: *os.File
	// implements io.ReaderFrom, so io.Copy would use its fast path and the bytes
	// would never reach the hasher. io.MultiWriter deliberately does not implement
	// io.ReaderFrom, which is what keeps the hasher on the path.
	hasher := blobHashers[want.Algorithm]()
	var w io.Writer = io.MultiWriter(tmp, hasher)
	if size > 0 {
		w = &cappedWriter{w: w, remaining: size}
	}
	if ferr := fill(w); ferr != nil {
		// A short write (io.ErrShortWrite, from MultiWriter) surfaces here rather
		// than being swallowed, so a truncated blob fails BEFORE the comparison
		// instead of arriving at it as a plain mismatch.
		tmp.Close()
		if errors.Is(ferr, ErrBlobTooLarge) {
			return false, fmt.Errorf("write blob %s: %w", quoteBounded(digest, maxDigestLen), ferr)
		}
		// fill streams REGISTRY bytes (layer.Compressed / io.Copy), so its error is
		// third-party content — bounded, never adopted.
		return false, fmt.Errorf("write blob %s: %w", quoteBounded(digest, maxDigestLen), boundErr(ferr))
	}
	// rename(2) on APFS orders metadata but not data, so without this fsync a
	// crash can leave a correctly-NAMED but truncated blob — the one blob for
	// which the commit-time check provably did not hold, trusted forever by the
	// existence-only fast path.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, fmt.Errorf("sync blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}

	// Plain ==, on the canonical lowercase hex both sides are normalized to.
	// Deliberately NOT hmac.Equal / subtle.ConstantTimeCompare: there is no secret
	// on either side and the attacker controls both operands, so a constant-time
	// helper would buy nothing and would mislead every future reader into thinking
	// one of these values is confidential.
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != want.Hex {
		// The deferred Remove drops the temp file, so the destination is never
		// created: a rejected blob leaves NO artifact at its blob path.
		return false, fmt.Errorf("blob %s hashed to %s:%s: %w",
			quoteBounded(digest, maxDigestLen), want.Algorithm, got, ErrDigestMismatch)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return false, fmt.Errorf("commit blob %s: %w", quoteBounded(digest, maxDigestLen), err)
	}
	return true, nil
}

// cappedWriter fails once more than remaining bytes are written. It is the
// CommitBlob resource guard (see there); it is not an integrity check.
type cappedWriter struct {
	w         io.Writer
	remaining int64
}

// Write rejects the whole overrunning write rather than passing a prefix through,
// so at most the declared number of bytes ever reaches the disk.
func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.remaining {
		return 0, ErrBlobTooLarge
	}
	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	return n, err
}

// PodRootfs returns the per-pod rootfs dir under the cache root:
// <root>/pods/<podID>/rootfs. It does not create it.
func (c *Cache) PodRootfs(podID string) string {
	return filepath.Join(c.root, "pods", podID, "rootfs")
}
