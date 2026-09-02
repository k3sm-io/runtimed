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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// IndexSubdir is the cache-root-relative directory the ref->digest index lives
// in: <root>/index, a SIBLING of blobs/ and pods/.
//
// Being a sibling is the structural half of the edge-not-root invariant (see
// FileIndex): the GC's enumerators read blobs/ (Cache.EnumerateBlobs), pods/
// (Cache.Roots) and the tree stores (Cache.EnumerateTrees), and none of them can
// reach this tree, so an index entry cannot become a reachability root by any
// code path — not merely by convention.
//
// It is a named constant because a confined pod must never be able to write
// here (a writable index is a way to make a reference resolve to another
// image's blobs), so the sandbox deny-list that will name this directory takes
// the name from here rather than re-spelling "index".
const IndexSubdir = "index"

// indexSchema is the on-disk format version of an index entry. A record written
// under a version this binary does not know is an ERROR, never a miss — see
// FileIndex.Lookup on why a miss is the unsafe direction.
const indexSchema = 1

// IndexRoot returns the directory the ref->digest index lives under
// (<root>/index). Like PodsRoot, it exists so a caller that must BOUND an
// operation to that tree asks this package where it is instead of re-spelling
// the component.
func (c *Cache) IndexRoot() string {
	return filepath.Join(c.root, IndexSubdir)
}

// ErrIndexEntryCorrupt reports that an index entry exists but cannot be
// believed: it does not decode, it was written under an unknown schema version,
// or its recorded key does not match the key it was found under.
//
// It is an ERROR and never a miss, and the caller propagates it (Puller.Pull
// does). A miss would fail `imagePullPolicy: Never` for an image that IS on the
// node, and would send an IfNotPresent pod to the registry at precisely the
// moment the operator asked it not to go — so a damaged index degrades loudly
// rather than silently changing what the node does.
var ErrIndexEntryCorrupt = errors.New("image: index entry is unreadable or inconsistent")

// ErrIndexNotOwned reports that the index directory is not owned by this process
// or is writable by another principal, so nothing under it may be believed.
//
// This is the fail-closed answer to the one door the directory's own 0700 mode
// does not close: /var/lib/k3sm is not owned by the daemon in every install
// posture, and rename(2) on a directory entry needs write permission on the
// PARENT only. A party who can write the parent can therefore rename the index
// aside and substitute its own — through which a forged entry would make a
// reference resolve to blobs of the attacker's choosing. Verifying owner and
// mode at every open turns that substitution into a loud refusal instead of a
// silent redirection.
var ErrIndexNotOwned = errors.New("image: index directory is not owned by this process")

// ErrIndexEntryNotFound reports that the index holds no entry for the key a
// caller named. It is the store's "no such image", and it is deliberately
// distinct from a Lookup miss: Lookup answers a pod's presence question, where
// absence is an ordinary outcome, while a caller that named one entry to tag,
// untag, inspect or export asked about something it believed existed.
var ErrIndexEntryNotFound = errors.New("image: no such image in the local index")

// ErrIndexEntryAmbiguous reports that a reference names more than one
// (reference x platform) entry and the caller supplied no platform to choose
// between them.
//
// It is an ERROR and never a pick. The index is keyed by the pair, so a
// reference alone can name a darwin/arm64 entry and a linux/arm64 one; guessing
// would let an operator untag or export the image they did not mean, and the two
// are not interchangeable — one of them cannot even execute here.
var ErrIndexEntryAmbiguous = errors.New("image: the reference names more than one platform entry")

// ErrIndexDigestMismatch reports that the entry a caller named does not resolve
// to the manifest digest that caller pinned.
//
// The pin exists because a reference is MUTABLE: a concurrent re-pull can move
// an entry between the caller's read and its write. Refusing here — and removing
// nothing — is what keeps "untag the image I just looked at" from removing an
// image that arrived in between.
var ErrIndexDigestMismatch = errors.New("image: the index entry resolves to a different manifest digest")

// FileIndex is the on-disk ref->digest image index: the record of which image
// REFERENCES this node has resolved, and to which manifest, keyed
// (reference x platform).
//
// It exists because the content-addressed store cannot answer presence by
// reference: blobs are keyed by DIGEST, and a reference becomes a digest only by
// asking a registry. Without this record `imagePullPolicy: IfNotPresent` cannot
// avoid the registry and `Never` can never be satisfied.
//
// # Entries are EDGES, never roots
//
// An entry records that a reference resolved to a manifest. It does NOT assert
// that anything still needs those blobs, and it can NEVER protect a blob from
// the GC. Reachability roots are daemon-authored per-pod records under pods/
// (see ImageRoot) and in-flight leases; this tree is not consulted by
// Cache.Roots, by Cache.EnumerateBlobs, or by PlanPrune. A blob whose only
// mention is an index entry is UNREFERENCED and is reclaimed — which is what
// makes an index entry safe to write from the pull path without any GC
// interaction at all, and why a mutable tag re-pointing an entry can never
// orphan a subtree the way a re-pointed ROOT would.
//
// The consequence is deliberate and is handled at the consumer: an entry can
// outlive its blobs. That is why presence is decided in TWO halves and this type
// owns only the first — Lookup answers "was this reference recorded", and
// Puller.presentLocally then verifies every blob the recorded manifest names is
// still in the CAS. A recorded reference whose bytes are gone is a MISS at the
// consumer, not here; duplicating the blob check here would put the same rule in
// two places, and this type would then need an opinion on leasing, which is
// Puller's.
//
// # Single-writer daemon authority
//
// Only the daemon writes here, and only from a pull that has already succeeded
// AND been verified (Puller.Pull records the manifest IT resolved, after the
// image's own config was checked against the platform policy and every blob was
// committed digest-verified). Nothing derived from registry bytes at LOOKUP time
// ever enters the decision. Entries are written atomically (temp + rename), so a
// crashed write cannot leave a truncated record; concurrent writers of the same
// key race on the rename and are harmless (identical content).
//
// A FileIndex is safe for concurrent use.
type FileIndex struct {
	dir string
}

// NewFileIndex returns the on-disk index for cache, creating its directory
// (0700) if absent and verifying that it is a directory this process owns.
//
// It creates the directory EAGERLY at construction — i.e. at daemon startup,
// before any pod exists — so the directory that ends up there is the daemon's
// own 0700 one; a tree first created on demand can be created by whoever gets
// there first. Record re-creates a tree that has since vanished, which is not a
// relaxation: the ownership check runs on every open, so a substituted
// directory is refused either way (see open and ErrIndexNotOwned).
func NewFileIndex(cache *Cache) (*FileIndex, error) {
	if cache == nil {
		return nil, errors.New("image index: cache is required")
	}
	x := &FileIndex{dir: cache.IndexRoot()}
	if err := os.MkdirAll(x.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create image index %s: %w", x.dir, err)
	}
	root, err := x.open()
	if err != nil {
		return nil, err
	}
	if err := root.Close(); err != nil {
		return nil, fmt.Errorf("close image index %s: %w", x.dir, err)
	}
	return x, nil
}

// open opens the index directory as an fd-anchored os.Root and verifies its
// ownership and mode. Every read and write goes through it, so no path under the
// index can be redirected by a symlink and a substituted directory is refused on
// every operation rather than only at startup (see ErrIndexNotOwned).
func (x *FileIndex) open() (*os.Root, error) {
	root, err := os.OpenRoot(x.dir)
	if err != nil {
		return nil, fmt.Errorf("open image index %s: %w", x.dir, err)
	}
	fi, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("stat image index %s: %w", x.dir, err)
	}
	if !fi.IsDir() {
		root.Close()
		return nil, fmt.Errorf("%w: %s is not a directory (mode %v)", ErrIndexNotOwned, x.dir, fi.Mode().Type())
	}
	// Group/other WRITE is what matters: a readable index leaks only which
	// references this node has pulled, but a writable one lets another principal
	// choose which blobs a reference resolves to.
	if fi.Mode().Perm()&0o022 != 0 {
		root.Close()
		return nil, fmt.Errorf("%w: %s is writable by group or other (mode %v)", ErrIndexNotOwned, x.dir, fi.Mode().Perm())
	}
	// The owner check is best-effort by construction: FileInfo.Sys is
	// platform-defined, so a build whose stat carries no uid keeps the mode check
	// and loses this one. On darwin (the target) it is always present.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if euid := os.Geteuid(); int(st.Uid) != euid {
			root.Close()
			return nil, fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrIndexNotOwned, x.dir, st.Uid, euid)
		}
	}
	return root, nil
}

// indexEntry is the on-disk shape of one index record.
//
// The manifest is carried as its protojson encoding rather than as re-spelled
// fields: a hand-rolled mirror of runtimev1.ImageManifest would silently drop
// whatever apis adds next (URLs, annotations, a future descriptor field), and
// the warm path would then hand the caller a DIFFERENT manifest from the one the
// pull path produced. Schema names the format of this envelope, so the encoding
// can change without the ambiguity of "an old record or a corrupt one".
type indexEntry struct {
	// Schema is the envelope version (indexSchema).
	Schema int `json:"schema"`
	// Reference is the pull reference this entry was recorded for. It is
	// re-checked against the lookup key — see FileIndex.lookupOne.
	Reference string `json:"reference"`
	// Platform is the resolved platform the reference was pulled for.
	Platform indexPlatform `json:"platform"`
	// Manifest is the protojson encoding of the recorded runtimev1.ImageManifest.
	Manifest json.RawMessage `json:"manifest"`
	// Descriptor is the manifest's OWN content descriptor — media type, digest
	// and size — when the writing path knew it. It is OPTIONAL, and additively
	// so: an entry written before manifest retention carries none, which a
	// reader must treat as "this daemon cannot name that image by digest",
	// never as a corrupt record.
	Descriptor *indexDescriptor `json:"manifestDescriptor,omitempty"`
	// Raw is the manifest's EXACT bytes, as the registry served them or the
	// archive carried them (encoding/json renders it base64). It is the ONLY
	// copy this store keeps: the content-addressed store commits config and
	// layer blobs and never the manifest itself, so without these bytes an
	// export could only re-encode a manifest — and a re-encoded manifest has a
	// different digest, i.e. a different image id.
	//
	// It lives in the index rather than in the CAS deliberately. The index is an
	// EDGE tree that no GC enumerator can reach (see FileIndex), so retaining
	// the manifest here pins nothing and is discarded with the name it belongs
	// to; a manifest blob in the CAS would need a reachability root of its own.
	Raw []byte `json:"manifestRaw,omitempty"`
}

// indexDescriptor is a content descriptor in its on-disk form. As with
// indexPlatform, the apis Descriptor is not serialized directly, so the file
// format does not move whenever that message gains a field.
type indexDescriptor struct {
	MediaType string `json:"mediaType,omitempty"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// maxIndexManifestBytes caps the manifest bytes one entry may retain.
//
// It is a RESOURCE guard on the daemon's private state, not an integrity one:
// the digest check in Record is what makes the bytes believable. The ceiling is
// far above any real manifest (a few kilobytes) and far below the 100 MiB
// go-containerregistry will hand over for one, so a hostile registry cannot
// turn the index tree into a disk-filling primitive.
const maxIndexManifestBytes = 4 << 20

// indexPlatform is Platform in its on-disk form. Platform itself is not
// serialized directly so the file format does not move whenever that type gains
// a field for matching purposes.
type indexPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	OSVersion    string `json:"osVersion,omitempty"`
}

func toIndexPlatform(p Platform) indexPlatform {
	n := p.Normalize()
	return indexPlatform{OS: n.OS, Architecture: n.Architecture, Variant: n.Variant, OSVersion: n.OSVersion}
}

func (p indexPlatform) platform() Platform {
	return Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant, OSVersion: p.OSVersion}.Normalize()
}

// entryName is the file name for one (reference x platform) key: the hex sha256
// of the LENGTH-PREFIXED key fields.
//
// Hashing, rather than encoding the reference into the name, is what keeps the
// name a fixed, path-safe token — a reference carries slashes, colons and
// registry-supplied bytes, and this package's whole posture is that untrusted
// strings never become path components (see parseBlobDigest). Length-prefixing
// makes the concatenation unambiguous, so no two distinct keys can collide by
// moving a separator between fields.
//
// A hashed name means the name alone does not prove which key an entry holds,
// which is why lookupOne re-checks the recorded reference and platform against
// the key it asked for.
func entryName(ref string, p Platform) string {
	n := toIndexPlatform(p)
	var b strings.Builder
	for _, f := range []string{ref, n.OS, n.Architecture, n.Variant, n.OSVersion} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:]) + ".json"
}

// Record records e, replacing any previous entry for its exact
// (reference x platform) key.
//
// It is called ONLY from a path that has already succeeded and been verified,
// with the manifest that path itself resolved. Recording anything else — a
// manifest re-derived from registry bytes, or one recorded before its blobs were
// committed — would let a lookup report an image present that this node never
// verified, which is the one failure mode an index has that a cache does not.
//
// e.Descriptor and e.ManifestRaw are OPTIONAL but not independent: supplying
// either without the other is refused, and supplied bytes must hash to the
// supplied digest. A half-recorded manifest is worse than none — an export would
// emit bytes under a digest nothing checked — so the pair is validated here, at
// the one place entries are written, rather than at each reader.
func (x *FileIndex) Record(ctx context.Context, e IndexEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ref := e.Reference
	if ref == "" {
		return errors.New("record image index: reference is required")
	}
	if e.Manifest == nil {
		return fmt.Errorf("record image index %q: manifest is required", ref)
	}
	// The recorded manifest names the reference it was recorded for; a lookup
	// re-checks it, and RecordPodImage keys the pod's root on it. A disagreement
	// here is a wiring bug, and admitting it would write an entry that can only
	// ever be read back as corrupt.
	if got := e.Manifest.GetReference(); got != ref {
		return fmt.Errorf("record image index %q: manifest names reference %q", ref, got)
	}
	p := e.Platform.Normalize()
	if p.OS == "" || p.Architecture == "" {
		return fmt.Errorf("record image index %q: incomplete platform %s", ref, p)
	}
	desc, err := recordedManifestDescriptor(ref, e)
	if err != nil {
		return err
	}
	raw, err := protojson.Marshal(e.Manifest)
	if err != nil {
		return fmt.Errorf("encode image index %q: %w", ref, err)
	}
	buf, err := json.Marshal(indexEntry{
		Schema:     indexSchema,
		Reference:  ref,
		Platform:   toIndexPlatform(p),
		Manifest:   raw,
		Descriptor: desc,
		Raw:        e.ManifestRaw,
	})
	if err != nil {
		return fmt.Errorf("encode image index %q: %w", ref, err)
	}
	// Re-create the tree if it has gone missing since construction. This is not
	// a weakening of the eager create: MkdirAll is a no-op on an existing
	// directory, so a SUBSTITUTED one is not repaired into legitimacy — it is
	// still caught by the ownership check in open() below. What it does buy is
	// that an operator who removes the daemon's private state does not break
	// every pull on the node until a restart (a failed record fails the pull).
	if err := os.MkdirAll(x.dir, 0o700); err != nil {
		return fmt.Errorf("create image index %s: %w", x.dir, err)
	}
	root, err := x.open()
	if err != nil {
		return err
	}
	defer root.Close()
	return x.commit(root, entryName(ref, p), buf)
}

// commit writes buf to name under root atomically: a temp file in the same
// directory, fsync'd, then renamed. A crashed write therefore leaves either the
// previous entry or none — never a truncated one, which would read back as
// corrupt and take out the reference it describes.
//
// A crash between create and rename leaves a ".index-" temp behind. It is inert
// — no lookup can name it, since entry names are hashes — and the next write for
// the same key reuses and replaces it, so it is bounded by the number of keys.
func (x *FileIndex) commit(root *os.Root, name string, buf []byte) error {
	tmp := ".index-" + name
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("temp image index entry: %w", err)
	}
	defer root.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return fmt.Errorf("write image index entry: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync image index entry: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close image index entry: %w", err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("commit image index entry: %w", err)
	}
	return nil
}

// Lookup returns the ENTRY recorded for ref under one of policy's platforms, in
// the policy's own PREFERENCE ORDER (native before a translated fallback), and
// ok=false when no such entry exists.
//
// It returns the entry rather than the bare manifest because the key's platform
// and the manifest's own descriptor are facts the caller needs and cannot
// re-derive: the manifest carries a platform only when it resolved through a
// multi-platform index, and the store commits no manifest blob to hash.
//
// It answers only "was this reference recorded, for a platform this pod may
// run" — NOT "are its bytes still here". The caller (Puller.presentLocally)
// owns the second half. See FileIndex for why the two halves are split.
//
// It fails closed in both directions that matter:
//
//   - an entry recorded for a platform outside policy's candidates is not
//     returned. The index is keyed (reference x platform) precisely so a node
//     that pulled linux/arm64 for a vm pod cannot serve those bytes to a native
//     pod, which could not execute them;
//   - an entry that exists but cannot be BELIEVED (undecodable, unknown schema,
//     or recorded under a different key than the one it was found at) is an
//     ERROR, not a miss (see ErrIndexEntryCorrupt).
//
// An absent index directory is a genuine miss: nothing has been recorded.
func (x *FileIndex) Lookup(ctx context.Context, ref string, policy PlatformPolicy) (IndexEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return IndexEntry{}, false, err
	}
	if ref == "" {
		return IndexEntry{}, false, errors.New("image index lookup: reference is required")
	}
	// The policy is resolved through the SAME seam the pull path uses, so a zero
	// or unknown backend fails closed here too rather than looking up under an
	// empty platform.
	want, err := Candidates(policy)
	if err != nil {
		return IndexEntry{}, false, err
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return IndexEntry{}, false, nil
		}
		return IndexEntry{}, false, err
	}
	defer root.Close()
	for _, p := range want {
		e, ok, err := x.lookupOne(root, ref, p)
		if err != nil {
			return IndexEntry{}, false, err
		}
		if ok {
			return e, true, nil
		}
	}
	return IndexEntry{}, false, nil
}

// Get returns the entry for EXACTLY one (reference x platform) key.
//
// It is the tag/untag/inspect/export lookup, and it is deliberately not Lookup:
// Lookup answers a pod's presence question and therefore walks a platform
// POLICY's candidates in preference order, which would silently serve a
// darwin/arm64 entry to a caller that named linux/arm64. A caller naming one
// entry gets that entry or nothing.
func (x *FileIndex) Get(ctx context.Context, ref string, p Platform) (IndexEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return IndexEntry{}, false, err
	}
	if ref == "" {
		return IndexEntry{}, false, errors.New("image index get: reference is required")
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return IndexEntry{}, false, nil
		}
		return IndexEntry{}, false, err
	}
	defer root.Close()
	return x.lookupOne(root, ref, p)
}

// Remove deletes exactly ONE (reference x platform) index entry, reporting
// whether an entry was there to delete.
//
// This is the write side of the operator's explicit untag, and it removes a NAME
// and nothing else: no blob is unlinked here, and no other key's entry is
// touched. Content is reclaimed only by a prune, which re-derives reachability
// first — so removing the last name for an image leaves its bytes on disk and
// merely reclaim-eligible, which is the same state a `k3sm image load`ed image
// has always been in.
//
// It reports false (not an error) for a key that is already absent. The RPC
// layer is where "the caller asked to remove a specific name that does not
// exist" becomes NOT_FOUND; at this layer the removal simply had nothing to do.
func (x *FileIndex) Remove(ctx context.Context, ref string, p Platform) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if ref == "" {
		return false, errors.New("image index remove: reference is required")
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer root.Close()
	if err := root.Remove(entryName(ref, p)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		// LOCAL-ONLY, no boundErr: an fs.PathError over an entry file name that
		// is a hex hash of the key (entryName), plus an errno.
		return false, fmt.Errorf("remove image index entry for %q: %w", ref, err)
	}
	return true, nil
}

// Resolve returns the single entry a caller's (reference, optional platform)
// names, or a typed refusal.
//
// It is the shared target resolution for every verb that acts on ONE named
// entry. p == nil means "the reference's only entry": exactly one is returned,
// zero is ErrIndexEntryNotFound, and more than one is ErrIndexEntryAmbiguous —
// never a pick (see ErrIndexEntryAmbiguous).
func (x *FileIndex) Resolve(ctx context.Context, ref string, p *Platform) (IndexEntry, error) {
	if ref == "" {
		return IndexEntry{}, fmt.Errorf("%w: a reference is required", ErrIndexEntryNotFound)
	}
	if p != nil {
		e, ok, err := x.Get(ctx, ref, *p)
		if err != nil {
			return IndexEntry{}, err
		}
		if !ok {
			return IndexEntry{}, fmt.Errorf("%w: %s for %s", ErrIndexEntryNotFound, quoteBounded(ref, maxDigestLen), p.Normalize())
		}
		return e, nil
	}
	all, err := x.List(ctx)
	if err != nil {
		return IndexEntry{}, err
	}
	var hits []IndexEntry
	for _, e := range all {
		if e.Reference == ref {
			hits = append(hits, e)
		}
	}
	switch len(hits) {
	case 0:
		return IndexEntry{}, fmt.Errorf("%w: %s", ErrIndexEntryNotFound, quoteBounded(ref, maxDigestLen))
	case 1:
		return hits[0], nil
	default:
		return IndexEntry{}, fmt.Errorf("%w: %s has %d platform entries; name one",
			ErrIndexEntryAmbiguous, quoteBounded(ref, maxDigestLen), len(hits))
	}
}

// ResolveDigest returns an entry whose recorded manifest digest is digest.
//
// A digest names CONTENT, so several entries can legitimately match it — that is
// exactly what a tag is — and they are interchangeable by construction: they
// describe the same manifest bytes. The lowest-sorting one (List's order) is
// returned deterministically rather than refused as ambiguous.
//
// An entry that predates manifest retention carries no descriptor and therefore
// matches nothing. That is the honest answer: this daemon cannot prove which
// manifest such an entry names, and a digest verb may not guess.
func (x *FileIndex) ResolveDigest(ctx context.Context, digest string) (IndexEntry, error) {
	if _, err := parseBlobDigest(digest); err != nil {
		return IndexEntry{}, err
	}
	all, err := x.List(ctx)
	if err != nil {
		return IndexEntry{}, err
	}
	for _, e := range all {
		if e.Descriptor.GetDigest() == digest {
			return e, nil
		}
	}
	return IndexEntry{}, fmt.Errorf("%w: %s", ErrIndexEntryNotFound, quoteBounded(digest, maxDigestLen))
}

// lookupOne reads the entry for exactly one (reference x platform) key.
//
// It re-derives the key from the record's OWN contents and requires it to match
// the key that was asked for. The file name is a hash, so it identifies but does
// not prove; without this check an entry moved, copied, or planted under another
// key's name would be served for that key — which is exactly how a writable
// index would make a reference resolve to another image.
func (x *FileIndex) lookupOne(root *os.Root, ref string, p Platform) (IndexEntry, bool, error) {
	name := entryName(ref, p)
	buf, err := readAnchored(root, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return IndexEntry{}, false, nil
		}
		// LOCAL-ONLY, no boundErr: readAnchored's error names the entry FILE — a
		// hex hash of the key (entryName) — plus an errno. No record content and
		// no registry-supplied bytes reach it, which is what boundErr guards.
		return IndexEntry{}, false, fmt.Errorf("%w: read %q: %v", ErrIndexEntryCorrupt, ref, err)
	}
	e, err := decodeEntry(ref, buf)
	if err != nil {
		return IndexEntry{}, false, err
	}
	if e.Reference != ref || e.Platform != p.Normalize() {
		return IndexEntry{}, false, fmt.Errorf("%w: %q is recorded as %q/%s",
			ErrIndexEntryCorrupt, ref, e.Reference, e.Platform)
	}
	return e, true, nil
}

// decodeEntry decodes one on-disk record and checks that it is SELF-consistent:
// a schema this daemon speaks, and a manifest that names the record's own
// reference.
//
// It deliberately does NOT check the record against a key. The two callers hold
// DIFFERENT keys — lookupOne holds the (reference x platform) that was asked
// for, List holds the file name the record was found under — and each applies
// its own, because a shared "check the key" would have to be one or the other
// and the unchecked caller would then serve a record it never bound to
// anything. what names the record in the error text (a reference, or a file
// name).
//
// It DOES check the record against itself: retained manifest bytes are re-hashed
// against the digest the record claims for them, so a half-written or
// partially-rewritten record is refused here rather than exported later.
func decodeEntry(what string, buf []byte) (IndexEntry, error) {
	var e indexEntry
	if err := json.Unmarshal(buf, &e); err != nil {
		// Both decoders here are THIRD-PARTY and both echo fragments of the
		// document they were handed — encoding/json quotes the offending byte,
		// protojson names the offending field — and that document is a record
		// whose fields were filled from a registry manifest. Bounded as DATA.
		return IndexEntry{}, fmt.Errorf("%w: decode %q: %v", ErrIndexEntryCorrupt, what, boundErr(err))
	}
	if e.Schema != indexSchema {
		return IndexEntry{}, fmt.Errorf("%w: %q was written under schema %d, this daemon speaks %d",
			ErrIndexEntryCorrupt, what, e.Schema, indexSchema)
	}
	mfst := &runtimev1.ImageManifest{}
	if err := protojson.Unmarshal(e.Manifest, mfst); err != nil {
		return IndexEntry{}, fmt.Errorf("%w: decode manifest for %q: %v", ErrIndexEntryCorrupt, what, boundErr(err))
	}
	// The manifest is what the caller will act on, so it must name the reference
	// the record was written for: RecordPodImage keys a pod's reachability root
	// on ImageManifest.Reference, and a manifest naming something else would
	// record a root for a reference this pod never asked for.
	if mfst.GetReference() != e.Reference {
		return IndexEntry{}, fmt.Errorf("%w: manifest for %q names %q",
			ErrIndexEntryCorrupt, what, mfst.GetReference())
	}
	out := IndexEntry{
		Reference:   e.Reference,
		Platform:    e.Platform.platform(),
		Manifest:    mfst,
		ManifestRaw: e.Raw,
	}
	if e.Descriptor != nil {
		out.Descriptor = &runtimev1.Descriptor{
			MediaType: e.Descriptor.MediaType,
			Digest:    e.Descriptor.Digest,
			Size:      e.Descriptor.Size,
		}
	}
	// The retained bytes are re-checked against the digest the SAME record
	// claims for them on every read, not only at write. The two halves live in
	// one file, so a party who can rewrite one can rewrite the other — this
	// check therefore proves consistency, not authenticity, and its value is
	// that a truncated or partially-rewritten record is refused rather than
	// exported under a digest it does not have.
	if err := validateRecordedManifest(what, out.Descriptor, out.ManifestRaw); err != nil {
		return IndexEntry{}, err
	}
	return out, nil
}

// recordedManifestDescriptor validates the descriptor/bytes pair Record was
// handed and returns its on-disk form (nil when the caller retained neither).
func recordedManifestDescriptor(ref string, e IndexEntry) (*indexDescriptor, error) {
	if e.Descriptor == nil && len(e.ManifestRaw) == 0 {
		return nil, nil
	}
	if e.Descriptor == nil || len(e.ManifestRaw) == 0 {
		return nil, fmt.Errorf("record image index %q: the manifest descriptor and its bytes are recorded together or not at all", ref)
	}
	if len(e.ManifestRaw) > maxIndexManifestBytes {
		return nil, fmt.Errorf("record image index %q: manifest is %d bytes, over the %d-byte ceiling",
			ref, len(e.ManifestRaw), maxIndexManifestBytes)
	}
	if got := int64(len(e.ManifestRaw)); e.Descriptor.GetSize() != got {
		return nil, fmt.Errorf("record image index %q: manifest descriptor declares %d bytes but carries %d",
			ref, e.Descriptor.GetSize(), got)
	}
	if err := validateRecordedManifest(ref, e.Descriptor, e.ManifestRaw); err != nil {
		return nil, err
	}
	return &indexDescriptor{
		MediaType: e.Descriptor.GetMediaType(),
		Digest:    e.Descriptor.GetDigest(),
		Size:      e.Descriptor.GetSize(),
	}, nil
}

// validateRecordedManifest checks that raw hashes to desc's digest. A record
// carrying one half of the pair without the other is refused, since a reader
// cannot tell such a record from a truncated one.
func validateRecordedManifest(what string, desc *runtimev1.Descriptor, raw []byte) error {
	if desc == nil && len(raw) == 0 {
		return nil
	}
	if desc == nil || len(raw) == 0 {
		return fmt.Errorf("%w: %q retains only half of the manifest descriptor/bytes pair", ErrIndexEntryCorrupt, what)
	}
	h, err := parseBlobDigest(desc.GetDigest())
	if err != nil {
		return fmt.Errorf("%w: %q: manifest digest: %v", ErrIndexEntryCorrupt, what, err)
	}
	if err := verifyBytes(raw, h, "recorded image manifest"); err != nil {
		return fmt.Errorf("%w: %q: %v", ErrIndexEntryCorrupt, what, err)
	}
	return nil
}

// IndexEntry is one recorded (reference x platform) -> manifest binding.
//
// It is both the READ shape (List / Lookup / Get / Resolve return it) and the
// WRITE shape (Record takes it). One type, not two: the index's unit of record
// is an entry, and a separate write struct would drift from the read struct the
// moment either grew a field — which is exactly the duplication ErrIndexEntry*
// exists to make impossible.
//
// It carries the KEY's platform, not the manifest's: ImageManifest.platform is
// populated only for a reference that resolved through a multi-platform index,
// whereas the key's platform is what the entry is filed under and therefore
// what a per-platform filter must match.
type IndexEntry struct {
	// Reference is the pull reference the entry was recorded for.
	Reference string
	// Platform is the resolved platform half of the entry's key.
	Platform Platform
	// Manifest is the manifest the pull (or ingest) resolved and verified.
	Manifest *runtimev1.ImageManifest
	// Descriptor is the manifest's OWN content descriptor: media type, digest
	// (what a user reads as the image id) and size.
	//
	// OPTIONAL, and a nil is a FACT, not a default: an entry written before this
	// store retained manifests carries none, and every reader must then report
	// the image as unnameable-by-digest rather than substitute a re-encoded one.
	// A digest a reader invented would not be the digest the registry served.
	Descriptor *runtimev1.Descriptor
	// ManifestRaw is the manifest's exact bytes. Optional exactly when
	// Descriptor is — Record refuses one half without the other, and refuses
	// bytes that do not hash to the digest — so a reader may test either.
	ManifestRaw []byte
}

// TotalSize returns the sum of the sizes of the DISTINCT blobs this image is
// made of: the manifest, the config and each layer, counted once.
//
// It is what the image MEASURES, never what removing it would reclaim — a layer
// shared with another image is counted here and would survive a prune. A
// descriptor the entry does not carry contributes nothing rather than a guess,
// so an entry predating manifest retention reports the manifest's bytes as 0.
func (e IndexEntry) TotalSize() int64 {
	seen := make(map[string]bool)
	var total int64
	add := func(digest string, size int64) {
		if digest == "" || size <= 0 || seen[digest] {
			return
		}
		seen[digest] = true
		total += size
	}
	add(e.Descriptor.GetDigest(), e.Descriptor.GetSize())
	add(e.Manifest.GetConfig().GetDigest(), e.Manifest.GetConfig().GetSize())
	for _, l := range e.Manifest.GetLayers() {
		add(l.GetDigest(), l.GetSize())
	}
	return total
}

// List returns every entry recorded in the index, sorted by reference then
// platform.
//
// This is the LISTING authority for the node's images, and it is deliberately a
// different question from the GC's. Reachability roots (Cache.Roots) answer
// "what is some pod still using"; an image that no pod references has no root
// and yet is unambiguously present — which is why a freshly `image load`ed
// archive was invisible to a listing built on roots while `image df` measured
// its bytes. Listing from here does not make an entry a root: entries are edges
// and this tree is unreachable from every GC enumerator (see FileIndex), so a
// listed image with no pod behind it stays reclaim-eligible.
//
// It fails CLOSED on a damaged record, exactly as Lookup does: a listing that
// silently omitted an unreadable entry would report a smaller store than the
// node has, and the operator asking what is on this node is the person who most
// needs to hear that the index is broken.
//
// An absent index directory is an empty listing, not an error: nothing has been
// recorded yet.
func (x *FileIndex) List(ctx context.Context) ([]IndexEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open image index %s: %w", x.dir, err)
	}
	names, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("read image index %s: %w", x.dir, err)
	}
	out := make([]IndexEntry, 0, len(names))
	for _, d := range names {
		name := d.Name()
		// Entry names are hex hashes with a .json suffix (entryName). Anything
		// else is not a record this daemon wrote: a ".index-" temp left by a
		// crashed commit, or a node some other party dropped in. Skipping is not
		// a relaxation — a planted record still has to hash-match the name it
		// sits under, which is checked below.
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") || !d.Type().IsRegular() {
			continue
		}
		buf, err := readAnchored(root, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // raced with a concurrent replace; the next list sees it
			}
			// LOCAL-ONLY, no boundErr: as in lookupOne, this is an fs.PathError over
			// an entry file name the loop above already restricted to "<hex>.json".
			return nil, fmt.Errorf("%w: read %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		e, err := decodeEntry(name, buf)
		if err != nil {
			return nil, err
		}
		// The same key re-derivation lookupOne applies, from the other side: the
		// file name is a hash of the key, so a record moved, copied or planted
		// under another key's name is refused rather than listed under a
		// reference it was never recorded for.
		if entryName(e.Reference, e.Platform) != name {
			return nil, fmt.Errorf("%w: %q holds the record for %q/%s",
				ErrIndexEntryCorrupt, name, e.Reference, e.Platform)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reference != out[j].Reference {
			return out[i].Reference < out[j].Reference
		}
		return out[i].Platform.String() < out[j].Platform.String()
	})
	return out, nil
}
