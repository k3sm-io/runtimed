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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ArtifactIndexSubdir is the index-relative directory artifact records live
// in: <root>/index/artifact. It is the distinct key namespace that keeps an
// artifact record and an image entry from ever aliasing: image entries are the
// regular files directly under the index directory, and FileIndex.List skips
// every directory, this one included.
const ArtifactIndexSubdir = "artifact"

// MaxArtifactRecordBytes caps one artifact record. A record carries the
// manifest bytes (capped at 4 MiB by the artifact path) plus a digest list, so
// the cap is a resource guard on the daemon's private state, never a limit a
// real artifact reaches.
const MaxArtifactRecordBytes = 8 << 20

// ErrArtifactRecordTooLarge reports a record over MaxArtifactRecordBytes.
var ErrArtifactRecordTooLarge = errors.New("image: artifact record exceeds its size cap")

// artifactEntryName is the file name for an artifact key: the hex sha256 of the
// key, so a reference's slashes and colons never become path components. The
// name alone does not prove which key a record holds; the record's owner
// re-checks the key it finds inside (pkg/artifact).
func artifactEntryName(key string) string {
	sum := sha256.Sum256([]byte("artifact\x00" + key))
	return hex.EncodeToString(sum[:]) + ".json"
}

// PutArtifactRecord writes record under key in the artifact namespace,
// atomically (temp, fsync, rename) and replacing any previous record for key.
// The record's format belongs to its caller (pkg/artifact); this type owns
// only where and how it is stored, so the ownership and anchoring rules of the
// image index apply to artifact records unchanged.
//
// Unlike an image entry, an artifact record is a reachability ROOT: while it
// exists, the config and layer blobs it names are never pruned or reclaimed
// (Cache.Roots). The daemon writes it only after it verified and committed
// every blob it names, so it is daemon-authored in the sense roots.go
// requires. RemoveArtifactRecord is what makes those blobs collectable.
func (x *FileIndex) PutArtifactRecord(ctx context.Context, key string, record []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == "" {
		return errors.New("record artifact index: key is required")
	}
	if len(record) > MaxArtifactRecordBytes {
		return fmt.Errorf("record artifact index: %d bytes: %w", len(record), ErrArtifactRecordTooLarge)
	}
	name := artifactEntryName(key)
	mu := x.stripeFor(ArtifactIndexSubdir + "/" + name)
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(x.dir, 0o700); err != nil {
		return fmt.Errorf("create image index %s: %w", x.dir, err)
	}
	root, err := x.open()
	if err != nil {
		return err
	}
	defer root.Close()
	sub, err := x.openArtifactRoot(root, true)
	if err != nil {
		return err
	}
	defer sub.Close()
	if fi, err := sub.Lstat(name); err == nil && fi.Mode().IsRegular() && fi.Size() <= MaxArtifactRecordBytes {
		x.keepReplaced(root, sub, name, record)
	}
	return x.commit(sub, name, record)
}

// keepReplaced keeps a released copy of the record under name in sub when it
// differs from record, the bytes about to replace it. The caller has checked
// the file is regular and within its cap.
func (x *FileIndex) keepReplaced(root, sub *os.Root, name string, record []byte) {
	if prev, err := readAnchoredLimit(sub, name, MaxArtifactRecordBytes); err == nil && !bytes.Equal(prev, record) {
		// A replaced record keeps its artifactType for the blobs only it named.
		// The copy is an eviction-order hint and never a root, so failing to
		// write it must not fail the put; the blobs it would describe are
		// classed as unattributed instead.
		_ = x.keepReleased(root, prev)
	}
}

// ArtifactRecord returns the record stored under key, ok=false when there is
// none. An absent index or artifact directory is a miss.
func (x *FileIndex) ArtifactRecord(ctx context.Context, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if key == "" {
		return nil, false, errors.New("artifact index lookup: key is required")
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer root.Close()
	sub, err := x.openArtifactRoot(root, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer sub.Close()
	name := artifactEntryName(key)
	fi, err := sub.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%w: stat artifact record: %v", ErrIndexEntryCorrupt, err)
	}
	if fi.Size() > MaxArtifactRecordBytes {
		return nil, false, fmt.Errorf("%w: artifact record of %d bytes: %w", ErrIndexEntryCorrupt, fi.Size(), ErrArtifactRecordTooLarge)
	}
	buf, err := readAnchored(sub, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%w: read artifact record: %v", ErrIndexEntryCorrupt, err)
	}
	return buf, true, nil
}

// RemoveArtifactRecord removes the record stored under key, reporting whether
// one was there. Removing a record is what makes its blobs collectable: while
// it exists they are reachability roots (see Cache.Roots).
func (x *FileIndex) RemoveArtifactRecord(ctx context.Context, key string) (bool, error) {
	return x.RemoveArtifactRecordIf(ctx, key, nil)
}

// RemoveArtifactRecordIf removes the record stored under key only if match
// accepts its current bytes (nil accepts any), reporting whether it removed
// one. The read, the decision and the unlink run under the lock
// PutArtifactRecord takes for key, so a concurrent put lands wholly before the
// read or wholly after the unlink: a caller that matches on what it last read
// can never remove a record written since.
func (x *FileIndex) RemoveArtifactRecordIf(ctx context.Context, key string, match func(record []byte) bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" {
		return false, errors.New("remove artifact record: key is required")
	}
	name := artifactEntryName(key)
	mu := x.stripeFor(ArtifactIndexSubdir + "/" + name)
	mu.Lock()
	defer mu.Unlock()
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer root.Close()
	sub, err := x.openArtifactRoot(root, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer sub.Close()
	var buf []byte
	if match != nil {
		fi, err := sub.Lstat(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("%w: stat artifact record: %v", ErrIndexEntryCorrupt, err)
		}
		if fi.Size() > MaxArtifactRecordBytes {
			return false, fmt.Errorf("%w: artifact record of %d bytes: %w", ErrIndexEntryCorrupt, fi.Size(), ErrArtifactRecordTooLarge)
		}
		buf, err = readAnchored(sub, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("%w: read artifact record: %v", ErrIndexEntryCorrupt, err)
		}
		if !match(buf) {
			return false, nil
		}
	} else if fi, err := sub.Lstat(name); err == nil && fi.Mode().IsRegular() && fi.Size() <= MaxArtifactRecordBytes {
		// An unconditional removal still removes a record it cannot read; it
		// only keeps no released copy of one.
		buf, _ = readAnchored(sub, name)
	}
	if buf != nil {
		// Kept before the root goes, so no instant has the blobs collectable
		// with their artifactType lost. A copy that cannot be written is an
		// eviction-order hint lost, never a reason to keep the root: the
		// caller asked for the blobs to become collectable.
		_ = x.keepReleased(root, buf)
	}
	if err := sub.Remove(name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("remove artifact record: %w", err)
	}
	return true, nil
}

// ArtifactRecords returns every record in the artifact namespace, in no
// particular order. An absent index or artifact directory is an empty list.
//
// It fails closed on a record it cannot read or that exceeds its cap, as List
// does: the GC unions these records into its root set, and a list silently
// short of one record would let a prune take that artifact's blobs. For the
// same reason a *.json entry that is not a regular file (a directory, a
// symlink) is an error: it holds the name of a record, so it is damage, not
// furniture. A name that is not a record this index writes (a ".index-" temp
// left by a crashed commit, a name without the .json suffix) is skipped; no
// record is ever stored under such a name.
func (x *FileIndex) ArtifactRecords(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	recs, err := x.artifactRecords()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.buf)
	}
	return out, nil
}

// namedRecord is one artifact record and the file name it was read from.
type namedRecord struct {
	name string
	buf  []byte
}

// artifactRecords is ArtifactRecords without the context check, for the GC's
// root enumerator, which runs under no request context. It keeps each record's
// file name, so a record the GC cannot decode is named in its refusal.
func (x *FileIndex) artifactRecords() ([]namedRecord, error) {
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	sub, err := x.openArtifactRoot(root, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer sub.Close()
	dir, err := sub.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open artifact index: %w", err)
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("read artifact index: %w", err)
	}
	var out []namedRecord
	for _, d := range entries {
		name := d.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if !d.Type().IsRegular() {
			return nil, fmt.Errorf("%w: artifact record %q is not a regular file (mode %v)", ErrIndexEntryCorrupt, name, d.Type())
		}
		fi, err := sub.Lstat(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // removed since the read; it is no longer a record
			}
			return nil, fmt.Errorf("%w: stat artifact record %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: artifact record %q is not a regular file (mode %v)", ErrIndexEntryCorrupt, name, fi.Mode().Type())
		}
		if fi.Size() > MaxArtifactRecordBytes {
			return nil, fmt.Errorf("%w: artifact record %q of %d bytes: %w", ErrIndexEntryCorrupt, name, fi.Size(), ErrArtifactRecordTooLarge)
		}
		buf, err := readAnchored(sub, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("%w: read artifact record %q: %v", ErrIndexEntryCorrupt, name, err)
		}
		if int64(len(buf)) > MaxArtifactRecordBytes {
			return nil, fmt.Errorf("%w: artifact record %q grew past its cap: %w", ErrIndexEntryCorrupt, name, ErrArtifactRecordTooLarge)
		}
		out = append(out, namedRecord{name: name, buf: buf})
	}
	return out, nil
}

// artifactRecordRoot is the part of an artifact record the GC reads. The
// record's format belongs to pkg/artifact; these field names are the contract
// between the two packages, pinned by a round-trip test there. ArtifactType
// only classes the blobs for accounting and eviction order; reachability never
// reads it.
type artifactRecordRoot struct {
	Reference    string   `json:"reference"`
	ArtifactType string   `json:"artifactType"`
	ConfigDigest string   `json:"configDigest"`
	LayerDigests []string `json:"layerDigests"`
}

// ArtifactReleasedIndexSubdir is the index-relative directory that keeps a
// copy of every artifact record removed (RemoveArtifactRecordIf) or replaced
// for different bytes (PutArtifactRecord): <root>/index/artifact-released.
//
// A released copy is NEVER a reachability root: nothing in Cache.Roots reads
// this directory, so keeping one makes no blob less collectable. It exists so
// that once a record is gone, and its blobs are reclaim-eligible, the store
// still knows which artifactType they belonged to and when they were released:
// that is what lets reclaim evict them before unreferenced images, oldest
// release first, and lets StoreBytesByClass class them. Each copy is named by
// the sha256 of its bytes, so releasing the same record twice refreshes one
// file. The reclaim pass removes a copy once every blob it names is gone or is
// named by a live record (sweepReleasedArtifacts).
//
// The directory is bounded (boundReleased): at most MaxReleasedArtifacts
// copies and MaxReleasedArtifactBytes in total, the oldest dropped first, and
// no file that is not a decodable copy under its own name. Losing a copy only
// costs eviction order, so the bound is enforced by dropping, never by
// refusing a release.
const ArtifactReleasedIndexSubdir = "artifact-released"

// MaxReleasedArtifacts and MaxReleasedArtifactBytes bound the released
// copies kept (see ArtifactReleasedIndexSubdir). releasedTempMaxAge is how old
// a commit temp in that directory must be before a sweep takes it for a crash
// leftover rather than a commit in flight.
const (
	MaxReleasedArtifacts     = 256
	MaxReleasedArtifactBytes = 64 << 20
	releasedTempMaxAge       = time.Hour
)

// releasedMu serializes, in this process and across FileIndex values (the
// cache builds its own for the GC), the writes of a released directory: each
// release's commit, and each bound's re-check-and-remove of the names it
// condemned. It is never held across a directory scan or a decode, so a pull
// or delete that releases a record never waits on a sweep reading the whole
// directory. A removal that races a release in another process only loses a
// hint.
var releasedMu sync.Mutex

// validReleasedName reports whether name is <64 lowercase hex>.json, the only
// name keepReleased writes.
func validReleasedName(name string) bool {
	h, ok := strings.CutSuffix(name, ".json")
	if !ok || len(h) != 64 {
		return false
	}
	for _, r := range h {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// releasedName is the file name of the released copy of record.
func releasedName(record []byte) string {
	sum := sha256.Sum256(record)
	return hex.EncodeToString(sum[:]) + ".json"
}

// keepReleased writes a released copy of record (see
// ArtifactReleasedIndexSubdir) under root, the open index directory.
func (x *FileIndex) keepReleased(root *os.Root, record []byte) error {
	sub, err := x.openSubdir(root, ArtifactReleasedIndexSubdir, true)
	if err != nil {
		return err
	}
	defer sub.Close()
	// The commit runs under releasedMu so a bound's re-check and removal of a
	// name (boundReleased) never interleave with a release rewriting it. The
	// lock is never held across a scan or a decode, so this waits only for
	// another commit or another bound's removals.
	releasedMu.Lock()
	err = x.commit(sub, releasedName(record), record)
	releasedMu.Unlock()
	if err != nil {
		return err
	}
	// The release path bounds by name, size and count only; decoding every
	// copy on each pod deletion would cost up to the byte cap per release. The
	// reclaim pass's sweep (BoundReleasedArtifacts) decodes.
	return boundReleased(sub, MaxReleasedArtifacts, MaxReleasedArtifactBytes, time.Now(), false)
}

// releasedArtifact is one released copy as the classifier reads it.
type releasedArtifact struct {
	name       string
	root       artifactRecordRoot
	releasedAt time.Time
}

// releasedArtifacts returns every released copy that decodes under its own
// name, with its release time (the copy's mtime). It is advisory input to
// accounting and eviction order, so a file that is not such a copy is skipped
// (boundReleased removes it) rather than failing the caller; only a released
// directory that cannot be opened or listed is an error. An absent index or
// directory is the empty list.
func (x *FileIndex) releasedArtifacts() ([]releasedArtifact, error) {
	sub, err := x.openReleased()
	if sub == nil || err != nil {
		return nil, err
	}
	defer sub.Close()
	copies, _, err := scanReleased(sub, time.Now(), true)
	if err != nil {
		return nil, err
	}
	out := make([]releasedArtifact, 0, len(copies))
	for _, rc := range copies {
		out = append(out, rc.releasedArtifact)
	}
	return out, nil
}

// openReleased opens the released directory, nil with no error when it or the
// index is absent.
func (x *FileIndex) openReleased() (*os.Root, error) {
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactReleasedIndexSubdir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return sub, nil
}

// scannedCopy is a released copy with its size, for the bound.
type scannedCopy struct {
	releasedArtifact
	size int64
	fi   fs.FileInfo
}

// scannedFile is a file a scan condemned, with what it saw, so the removal can
// re-check the name still holds that file.
type scannedFile struct {
	name string
	fi   fs.FileInfo
}

// scanReleased reads the released directory sub. It returns the copies that
// decode under their own name, and the names of the files that should not be
// there: a name keepReleased never writes, a non-regular or over-cap file, a
// copy that does not decode as a record (DecodeArtifactRoot, bounded), and a
// commit temp older than releasedTempMaxAge at now. A younger temp may be a
// commit in flight and is neither. With decode unset nothing is read or
// decoded: every well-named regular file within the cap counts as a copy with
// a zero root, which is enough to bound the directory.
func scanReleased(sub *os.Root, now time.Time, decode bool) (copies []scannedCopy, junk []scannedFile, err error) {
	dir, err := sub.Open(".")
	if err != nil {
		return nil, nil, fmt.Errorf("open released artifact records: %w", err)
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("read released artifact records: %w", err)
	}
	for _, d := range entries {
		name := d.Name()
		fi, err := sub.Lstat(name)
		if err != nil {
			continue // removed since the read
		}
		if strings.HasPrefix(name, ".index-") {
			if fi.Mode().IsRegular() && now.Sub(fi.ModTime()) > releasedTempMaxAge {
				junk = append(junk, scannedFile{name, fi})
			}
			continue
		}
		if !validReleasedName(name) || !fi.Mode().IsRegular() || fi.Size() > MaxArtifactRecordBytes {
			junk = append(junk, scannedFile{name, fi})
			continue
		}
		var r artifactRecordRoot
		if !decode {
			copies = append(copies, scannedCopy{releasedArtifact{name: name, releasedAt: fi.ModTime()}, fi.Size(), fi})
			continue
		}
		buf, err := readAnchoredLimit(sub, name, MaxArtifactRecordBytes)
		if err != nil {
			continue
		}
		if decodeRecordRoot(buf, &r) != nil {
			junk = append(junk, scannedFile{name, fi})
			continue
		}
		copies = append(copies, scannedCopy{releasedArtifact{name: name, root: r, releasedAt: fi.ModTime()}, fi.Size(), fi})
	}
	return copies, junk, nil
}

// readAnchoredLimit is readAnchored reading at most limit bytes: a file that
// grew past limit since its Lstat is an error, never read in full.
func readAnchoredLimit(root *os.Root, rel string, limit int64) ([]byte, error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (mode %v)", rel, fi.Mode().Type())
	}
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes: %w", rel, limit, ErrArtifactRecordTooLarge)
	}
	return buf, nil
}

// boundReleased removes from the released directory sub every file
// scanReleased calls junk (decoding each copy when decode is set), then the
// oldest copies beyond maxCount copies or maxBytes in total. It never
// recurses: a directory planted there stays, and its failed removal is
// reported.
func boundReleased(sub *os.Root, maxCount int, maxBytes int64, now time.Time, decode bool) error {
	// Scan and decode with NO lock held: this is the part that can read the
	// whole directory, and a release must never wait on it.
	copies, junk, err := scanReleased(sub, now, decode)
	if err != nil {
		return err
	}
	sort.Slice(copies, func(i, j int) bool {
		if !copies[i].releasedAt.Equal(copies[j].releasedAt) {
			return copies[i].releasedAt.After(copies[j].releasedAt)
		}
		return copies[i].name < copies[j].name
	})
	var total int64
	for i, rc := range copies {
		if i >= maxCount || total+rc.size > maxBytes {
			junk = append(junk, scannedFile{rc.name, rc.fi})
			continue
		}
		total += rc.size
	}
	if len(junk) == 0 {
		return nil
	}
	// Remove under the lock every release's commit takes, and only a name
	// that still holds the file the scan judged: same file, size and mtime. A
	// copy released again since the scan was rewritten, so it is left.
	releasedMu.Lock()
	defer releasedMu.Unlock()
	var errs []error
	for _, j := range junk {
		cur, err := sub.Lstat(j.name)
		if err != nil || !os.SameFile(cur, j.fi) || cur.Size() != j.fi.Size() || !cur.ModTime().Equal(j.fi.ModTime()) {
			continue
		}
		if err := sub.Remove(j.name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove released artifact record %s: %w", QuoteBounded(j.name, 256), err))
		}
	}
	return errors.Join(errs...)
}

// BoundReleasedArtifacts applies the released directory's bound
// (boundReleased) with the package limits. The reclaim pass runs it on every
// pass, triggered or not, so the directory stays bounded on an idle node too.
func (x *FileIndex) BoundReleasedArtifacts() error {
	sub, err := x.openReleased()
	if sub == nil || err != nil {
		return err
	}
	defer sub.Close()
	return boundReleased(sub, MaxReleasedArtifacts, MaxReleasedArtifactBytes, time.Now(), true)
}

// sweepReleasedArtifacts removes the released copies named in names. The
// reclaim pass names the copies whose blobs are all gone from the store or
// named by a live record, so they class nothing any more. A copy released
// again between that read and this removal loses its hint, which costs only
// eviction order. A copy that cannot be removed is left for the next pass.
func (x *FileIndex) sweepReleasedArtifacts(names []string) error {
	if len(names) == 0 {
		return nil
	}
	sub, err := x.openReleased()
	if sub == nil || err != nil {
		return err
	}
	defer sub.Close()
	releasedMu.Lock()
	defer releasedMu.Unlock()
	var errs []error
	for _, name := range names {
		if !validReleasedName(name) {
			continue
		}
		if err := sub.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove released artifact record %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// DecodeArtifactRoot returns the blobs an artifact record names, as a
// reachability root. A record that does not decode, names no blob, or names a
// digest this store cannot map to a path is an error: a root that cannot be
// read cannot protect anything, so the caller must not drop it quietly.
func DecodeArtifactRoot(record []byte) (ImageRoot, error) {
	var r artifactRecordRoot
	if err := json.Unmarshal(record, &r); err != nil {
		return ImageRoot{}, fmt.Errorf("decode artifact record: %v", boundErr(err))
	}
	root := ImageRoot{Reference: r.Reference, Config: r.ConfigDigest, Layers: r.LayerDigests}
	ds := root.Digests()
	if len(ds) == 0 {
		return ImageRoot{}, errors.New("artifact record names no blob")
	}
	for _, d := range ds {
		if _, err := parseBlobDigest(d); err != nil {
			return ImageRoot{}, fmt.Errorf("artifact record: %w", err)
		}
	}
	return root, nil
}

// openArtifactRoot opens the artifact namespace under root, creating it (0700)
// when create is set, and refuses one that is not a directory or is writable by
// group or other, for the reason FileIndex.open gives.
func (x *FileIndex) openArtifactRoot(root *os.Root, create bool) (*os.Root, error) {
	return x.openSubdir(root, ArtifactIndexSubdir, create)
}

// openSubdir opens the index-relative directory name under root, creating it
// (0700) when create is set, and refuses one that is not a directory or is
// writable by group or other, for the reason FileIndex.open gives.
func (x *FileIndex) openSubdir(root *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create %s index: %w", name, err)
		}
	}
	path := filepath.Join(x.dir, name)
	// Lstat first, so a symlink planted at the name is refused rather than
	// followed to another directory under the index (OpenRoot would follow it).
	pre, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !pre.IsDir() {
		return nil, fmt.Errorf("%w: index subdirectory %s is not a directory (mode %v)", ErrIndexNotOwned, path, pre.Mode().Type())
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s index: %w", name, err)
	}
	// Mode and owner are judged on the OPENED handle, and it must be the
	// directory the Lstat saw: a swap between the two is refused.
	fi, err := sub.Stat(".")
	if err != nil {
		sub.Close()
		return nil, fmt.Errorf("stat index subdirectory %s: %w", path, err)
	}
	if !os.SameFile(pre, fi) {
		sub.Close()
		return nil, fmt.Errorf("%w: index subdirectory %s was replaced while it was opened", ErrIndexNotOwned, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		sub.Close()
		return nil, fmt.Errorf("%w: index subdirectory %s is writable by group or other (mode %v); expected 0700", ErrIndexNotOwned, path, fi.Mode().Perm())
	}
	// The owner check FileIndex.open makes, for the same reason and with the
	// same best-effort caveat where stat carries no uid.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if euid := os.Geteuid(); int(st.Uid) != euid {
			sub.Close()
			return nil, fmt.Errorf("%w: index subdirectory %s is owned by uid %d; expected uid %d (the daemon's effective uid)",
				ErrIndexNotOwned, path, st.Uid, euid)
		}
	}
	return sub, nil
}
