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
}

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

// Record records that ref resolved to mfst for platform, replacing any previous
// entry for that exact key.
//
// It is called ONLY from a pull that has already succeeded and been verified,
// with the manifest that pull itself resolved. Recording anything else — a
// manifest re-derived from registry bytes, or one recorded before its blobs were
// committed — would let a lookup report an image present that this node never
// verified, which is the one failure mode an index has that a cache does not.
func (x *FileIndex) Record(ctx context.Context, ref string, platform Platform, mfst *runtimev1.ImageManifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ref == "" {
		return errors.New("record image index: reference is required")
	}
	if mfst == nil {
		return fmt.Errorf("record image index %q: manifest is required", ref)
	}
	// The recorded manifest names the reference it was recorded for; a lookup
	// re-checks it, and RecordPodImage keys the pod's root on it. A disagreement
	// here is a wiring bug, and admitting it would write an entry that can only
	// ever be read back as corrupt.
	if got := mfst.GetReference(); got != ref {
		return fmt.Errorf("record image index %q: manifest names reference %q", ref, got)
	}
	p := platform.Normalize()
	if p.OS == "" || p.Architecture == "" {
		return fmt.Errorf("record image index %q: incomplete platform %s", ref, p)
	}
	raw, err := protojson.Marshal(mfst)
	if err != nil {
		return fmt.Errorf("encode image index %q: %w", ref, err)
	}
	buf, err := json.Marshal(indexEntry{
		Schema:    indexSchema,
		Reference: ref,
		Platform:  toIndexPlatform(p),
		Manifest:  raw,
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

// Lookup returns the manifest recorded for ref under one of policy's platforms,
// in the policy's own PREFERENCE ORDER (native before a translated fallback), and
// ok=false when no such entry exists.
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
func (x *FileIndex) Lookup(ctx context.Context, ref string, policy PlatformPolicy) (*runtimev1.ImageManifest, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if ref == "" {
		return nil, false, errors.New("image index lookup: reference is required")
	}
	// The policy is resolved through the SAME seam the pull path uses, so a zero
	// or unknown backend fails closed here too rather than looking up under an
	// empty platform.
	want, err := Candidates(policy)
	if err != nil {
		return nil, false, err
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer root.Close()
	for _, p := range want {
		mfst, ok, err := x.lookupOne(root, ref, p)
		if err != nil {
			return nil, false, err
		}
		if ok {
			return mfst, true, nil
		}
	}
	return nil, false, nil
}

// lookupOne reads the entry for exactly one (reference x platform) key.
//
// It re-derives the key from the record's OWN contents and requires it to match
// the key that was asked for. The file name is a hash, so it identifies but does
// not prove; without this check an entry moved, copied, or planted under another
// key's name would be served for that key — which is exactly how a writable
// index would make a reference resolve to another image.
func (x *FileIndex) lookupOne(root *os.Root, ref string, p Platform) (*runtimev1.ImageManifest, bool, error) {
	name := entryName(ref, p)
	buf, err := readAnchored(root, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%w: read %q: %v", ErrIndexEntryCorrupt, ref, err)
	}
	e, mfst, err := decodeEntry(ref, buf)
	if err != nil {
		return nil, false, err
	}
	if e.Reference != ref || e.Platform.platform() != p.Normalize() {
		return nil, false, fmt.Errorf("%w: %q is recorded as %q/%s",
			ErrIndexEntryCorrupt, ref, e.Reference, e.Platform.platform())
	}
	return mfst, true, nil
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
func decodeEntry(what string, buf []byte) (indexEntry, *runtimev1.ImageManifest, error) {
	var e indexEntry
	if err := json.Unmarshal(buf, &e); err != nil {
		return e, nil, fmt.Errorf("%w: decode %q: %v", ErrIndexEntryCorrupt, what, err)
	}
	if e.Schema != indexSchema {
		return e, nil, fmt.Errorf("%w: %q was written under schema %d, this daemon speaks %d",
			ErrIndexEntryCorrupt, what, e.Schema, indexSchema)
	}
	mfst := &runtimev1.ImageManifest{}
	if err := protojson.Unmarshal(e.Manifest, mfst); err != nil {
		return e, nil, fmt.Errorf("%w: decode manifest for %q: %v", ErrIndexEntryCorrupt, what, err)
	}
	// The manifest is what the caller will act on, so it must name the reference
	// the record was written for: RecordPodImage keys a pod's reachability root
	// on ImageManifest.Reference, and a manifest naming something else would
	// record a root for a reference this pod never asked for.
	if mfst.GetReference() != e.Reference {
		return e, nil, fmt.Errorf("%w: manifest for %q names %q",
			ErrIndexEntryCorrupt, what, mfst.GetReference())
	}
	return e, mfst, nil
}

// IndexEntry is one recorded (reference x platform) -> manifest binding, as
// returned by List.
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
			return nil, fmt.Errorf("%w: read %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		e, mfst, err := decodeEntry(name, buf)
		if err != nil {
			return nil, err
		}
		// The same key re-derivation lookupOne applies, from the other side: the
		// file name is a hash of the key, so a record moved, copied or planted
		// under another key's name is refused rather than listed under a
		// reference it was never recorded for.
		p := e.Platform.platform()
		if entryName(e.Reference, p) != name {
			return nil, fmt.Errorf("%w: %q holds the record for %q/%s",
				ErrIndexEntryCorrupt, name, e.Reference, p)
		}
		out = append(out, IndexEntry{Reference: e.Reference, Platform: p, Manifest: mfst})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reference != out[j].Reference {
			return out[i].Reference < out[j].Reference
		}
		return out[i].Platform.String() < out[j].Platform.String()
	})
	return out, nil
}
