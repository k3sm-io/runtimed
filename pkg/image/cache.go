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
//
// The LAYOUT BENEATH IT IS NOT PUBLIC API. Do not join "blobs"/<algo>/<hex> onto
// this yourself — that re-derives the content-addressed layout rule in a second
// place, without the digest allowlist that makes it safe. Use BlobPath (or Has /
// CommitBlob), which are the only sanctioned ways to reach a blob, so the layout
// and its validation can only ever be changed here.
func (c *Cache) Root() string { return c.root }

// blobsDir is the content-addressed blob store.
func (c *Cache) blobsDir() string { return filepath.Join(c.root, "blobs") }

// pathFor is the ONE place the content-addressed layout is expressed. Every
// path-producing entry point goes through it, so a future change (a sharded
// blobs/<algo>/<xx>/<hex>, B128's GC) has exactly one edit site. It takes a
// PARSED hash, so it is unreachable without parseBlobDigest having run.
func (c *Cache) pathFor(h ggcrv1.Hash) string {
	return filepath.Join(c.blobsDir(), h.Algorithm, h.Hex)
}

// ErrUnsupportedDigestAlgorithm is returned for a digest whose ALGORITHM half is
// not in the closed allowlist below. It is distinct from ErrInvalidDigest so a
// caller (B117's tarball ingest) can tell "this store cannot handle that
// algorithm at all" from "that string is not a digest", and both from
// ErrDigestMismatch, which means the bytes were poisoned.
var ErrUnsupportedDigestAlgorithm = errors.New("image: unsupported digest algorithm")

// ErrInvalidDigest is returned for a digest that is malformed for an allowlisted
// algorithm: bad shape, a non-lowercase-hex body, or the wrong hex length.
var ErrInvalidDigest = errors.New("image: malformed digest")

// ErrDigestMismatch reports that a BLOB's bytes contradict the digest they were
// committed under: CommitBlob returns it when the bytes written hash to something
// else — the blob is NOT committed and the destination path is left untouched.
//
// It is deliberately NOT reused for a manifest that contradicts itself (see
// ErrManifestInconsistent). The two imply different remediations — refetch the
// blob versus reject the whole source — so a caller branching on the sentinel
// must be able to tell them apart.
var ErrDigestMismatch = errors.New("image: blob content does not match its claimed digest")

// ErrManifestInconsistent reports that an image's own manifest is
// self-contradictory — today, that it disagrees with the fetched image about how
// many layers it has. No blob was hashed when this is returned, which is exactly
// why it is not an ErrDigestMismatch: that sentinel's message would be false here,
// and a consumer (B117's ingest, the M12 pull-failure taxonomy) needs "this source
// is malformed" to stay distinguishable from "this blob is poisoned".
var ErrManifestInconsistent = errors.New("image: image contradicts its own manifest")

// ErrBlobTooLarge is returned by CommitBlob when fill streams more bytes than the
// declared size. It is a RESOURCE GUARD, not an integrity mechanism — see
// CommitBlob.
var ErrBlobTooLarge = errors.New("image: blob exceeds its declared size")

// SizeUnknown is the explicit "no declared size" value for CommitBlob's size
// parameter — the ONLY way to opt out of the resource guard.
//
// It is a named sentinel rather than 0 or a negative range because 0 is a real,
// legitimate size (the empty blob), and the caller who supplies the size is the
// same actor a swapped fetcher controls: an opt-out spelled "0" would be
// reachable by exactly the party the guard defends against, and silently so.
const SizeUnknown int64 = -1

// blobHashers is the CLOSED ALLOWLIST of digest algorithms this store accepts,
// and simultaneously the way it verifies them. Membership in this one table is
// what lets a digest become a filesystem path (blobPath) AND what supplies the
// hasher that checks the bytes (CommitBlob), so the store structurally cannot
// hold a blob under an algorithm it is unable to re-hash.
//
// sha512 is deliberately ABSENT. go-containerregistry v0.21.6's v1.Hasher
// supports sha256 only, so a sha512 digest cannot be parsed, fetched or verified
// anywhere else on this pull path; admitting it here would create a directory
// this package can never validate.
//
// Adding an algorithm means adding it here AND in the parser: parseBlobDigest
// delegates body validation to ggcrv1.NewHash, which accepts sha256 only, so an
// entry added here alone would clear the allowlist and then be rejected by the
// parser as ErrInvalidDigest rather than ErrUnsupportedDigestAlgorithm.
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
	algo, ok := cutAlgorithm(digest)
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

// cutAlgorithm returns the ALGORITHM half of "<algo>:<body>", reporting false
// when the string has no separator or an empty half. The body is deliberately not
// returned: it is validated by ggcrv1.NewHash on the whole string, so handing a
// caller an unvalidated body would invite exactly the "sanitize one half only"
// bug B129 fixed.
func cutAlgorithm(digest string) (algo string, ok bool) {
	algo, body, found := strings.Cut(digest, ":")
	return algo, found && algo != "" && body != ""
}

// BlobPath maps a digest ("<algo>:<hex>") to its on-disk path, validating the
// digest first. It is the ONLY sanctioned way for an out-of-package caller
// (B117's tarball ingest, B128's GC) to name a blob on disk.
//
// It validates through parseBlobDigest and builds the path from the PARSED
// halves, never the raw string, so no caller can construct a path outside the
// blob root: an algorithm that is not allowlisted yields no path at all, and an
// allowlisted one has a fixed hex body. (Before B129 the algorithm half flowed
// into filepath.Join unchecked, so "../../etc:passwd" resolved to
// /var/lib/etc/passwd — which pull.go then MkdirAll'd as the root LaunchDaemon.)
//
// A returned path is validated, NOT verified: it names where the blob for digest
// belongs, and says nothing about what is there. Reading it is subject to the
// verification ceiling documented on CommitBlob — in particular, a path that
// exists may be a symlink planted after the commit, so a reader that opens it as
// the root daemon should do so O_NOFOLLOW.
func (c *Cache) BlobPath(digest string) (string, error) {
	h, err := parseBlobDigest(digest)
	if err != nil {
		return "", err
	}
	return c.pathFor(h), nil
}

// Has reports whether the blob for digest is already cached.
//
// A non-regular file at the blob path (a directory, a SYMLINK, a device node) is
// NOT a cache hit — only a regular file can be a blob. It uses Lstat, not Stat,
// precisely so a symlink is judged on ITSELF: Stat resolves the link, so a
// symlink pointing at any regular file anywhere satisfied IsRegular and was
// accepted as a cached blob, which suppressed verification for that digest
// forever and pointed every downstream reader — running as the root daemon — at
// an attacker-chosen path.
func (c *Cache) Has(digest string) bool {
	p, err := c.BlobPath(digest)
	if err != nil {
		return false
	}
	fi, err := os.Lstat(p)
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
// object that supplies the bytes (see Puller.Pull). Given that — AND given a
// FetchFunc whose Manifest() is the registry's own manifest, as RemoteFetch's is
// — this check defends against a fetcher that does not verify what the network
// gave it, and against write-path corruption between the fetcher and the disk.
//
// That qualifier is load-bearing, not boilerplate. For an image whose manifest is
// SYNTHESIZED from its content — any go-containerregistry partial/tarball-backed
// image, a test fake, a future local-layout fetcher, i.e. exactly B117/M12's
// neighbourhood — mfst.*.Digest is derived from the very bytes being checked, so
// the comparison is a tautology that cannot fail. It does NOT authenticate the
// image either: a wholly hostile FetchFunc supplies the manifest too, and can
// therefore make its bytes and its claimed digests agree. Image authenticity is a
// signature problem, not a CAS problem.
//
// # The verification ceiling
//
// Verification happens at WRITE time only. The cache-hit fast path below is an
// os.Lstat, and every downstream reader (materialize, the unpacker) trusts the
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
// right length, is caught by the ONE digest comparison, not by size.
//
// size must be >= 0, or exactly SizeUnknown to opt out of the guard; any other
// negative value is an error. 0 means an EMPTY blob and is enforced as such — it
// is NOT an opt-out. The pull path always passes the descriptor's declared size.
func (c *Cache) CommitBlob(digest string, size int64, fill func(io.Writer) error) (wrote bool, err error) {
	want, err := parseBlobDigest(digest)
	if err != nil {
		return false, err
	}
	if fill == nil {
		// Explicit, like NewPuller's required-argument checks: this is an exported
		// API called from the root daemon, and a nil fill must not panic there.
		return false, fmt.Errorf("commit blob %s: fill is required", quoteBounded(digest, maxDigestLen))
	}
	if size < 0 && size != SizeUnknown {
		return false, fmt.Errorf("commit blob %s: negative size %d (use SizeUnknown to opt out of the size guard)",
			quoteBounded(digest, maxDigestLen), size)
	}
	dst := c.pathFor(want)
	// Cache hit — a REGULAR file only, judged by Lstat so a SYMLINK is not
	// silently accepted (Stat would resolve it and report the target's mode). A
	// directory or a symlink at the blob path is not a blob, and accepting one
	// would suppress the write — and with it the verification — forever. Falling
	// through is safe and self-healing: rename(2) replaces a symlink at the
	// destination with the verified file.
	if fi, serr := os.Lstat(dst); serr == nil && fi.Mode().IsRegular() {
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
	// size == 0 is a REAL cap (the empty blob), not "no cap": only the explicit
	// SizeUnknown sentinel opts out. A `size > 0` test here would silently disable
	// the guard for any descriptor declaring zero, and the actor who can author
	// that descriptor is the same one the guard defends against.
	var capped *cappedWriter
	if size != SizeUnknown {
		capped = &cappedWriter{w: w, remaining: size}
		w = capped
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
	// fill returned nil but the cap fired: it swallowed the write error. The bytes
	// were bounded either way, but the VERDICT would otherwise fall through to the
	// digest comparison and be reported as a mismatch — see cappedWriter.
	if capped != nil && capped.overflowed {
		tmp.Close()
		return false, fmt.Errorf("write blob %s: %w", quoteBounded(digest, maxDigestLen), ErrBlobTooLarge)
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
//
// overflowed latches the refusal so the verdict survives a fill that discards its
// write error. Without it, such a fill returns nil, control falls through to the
// digest comparison, and an OVERSIZED input gets reported as a POISONED blob —
// the wrong operator signal (reject the source vs quarantine the blob), and
// exactly the taxonomy collapse ErrManifestInconsistent was split out to avoid.
type cappedWriter struct {
	w          io.Writer
	remaining  int64
	overflowed bool
}

// Write rejects the whole overrunning write rather than passing a prefix through,
// so at most the declared number of bytes ever reaches the disk.
func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.remaining {
		c.overflowed = true
		return 0, ErrBlobTooLarge
	}
	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	return n, err
}

// PodRootfs returns the per-pod rootfs dir under the cache root:
// <root>/pods/<podID>/rootfs. It does not create it.
//
// It takes a PodID, not a string, so — like pathFor and its parsed digest — the
// layout is unreachable without validation having run. That is what keeps the
// containment structural: a caller cannot derive a pod path from an untrusted
// identifier even by forgetting to check it, because it has nothing to pass.
func (c *Cache) PodRootfs(podID PodID) string {
	return filepath.Join(c.PodsRoot(), podID.String(), "rootfs")
}

// PodsRoot returns the directory every pod dir lives under (<root>/pods).
//
// It exists so a caller that must BOUND an operation to the pods tree — the
// daemon's pod-dir delete, for one — asks this package where that tree is
// instead of re-spelling the component. A guard and the deriver it guards must
// agree on the root or the guard means nothing, and two string literals in two
// packages have no coupling that would catch a drift.
func (c *Cache) PodsRoot() string {
	return filepath.Join(c.root, "pods")
}

// PodDir returns the per-pod directory itself (<root>/pods/<podID>), the parent
// of PodRootfs. It exists so callers that need the pod dir do not re-derive the
// layout with filepath.Dir on a rootfs path, which would put a second copy of
// the layout outside this file.
func (c *Cache) PodDir(podID PodID) string {
	return filepath.Join(c.PodsRoot(), podID.String())
}
