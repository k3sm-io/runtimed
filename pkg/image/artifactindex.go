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
	"io/fs"
	"os"
	"strings"
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
	if prev, err := readAnchored(sub, name); err == nil && !bytes.Equal(prev, record) && int64(len(prev)) <= MaxArtifactRecordBytes {
		// A replaced record keeps its artifactType for the blobs only it named.
		// The copy is an eviction-order hint and never a root, so failing to
		// write it must not fail the put; the blobs it would describe are
		// classed as unattributed instead.
		_ = x.keepReleased(root, prev)
	}
	return x.commit(sub, name, record)
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
// still knows which artifactType they belonged to and when they were released,
// which is what lets StoreBytesByClass class them. Each copy is named by the
// sha256 of its bytes, so releasing the same record twice refreshes one file.
const ArtifactReleasedIndexSubdir = "artifact-released"

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
	return x.commit(sub, releasedName(record), record)
}

// releasedArtifact is one released copy as the classifier reads it.
type releasedArtifact struct {
	name       string
	root       artifactRecordRoot
	releasedAt time.Time
}

// releasedArtifacts returns every released copy that decodes, with its
// release time (the copy's mtime). It is advisory input to accounting and
// eviction order, so a copy that cannot be read or decoded is skipped rather
// than failing the caller; only a released directory that cannot be listed
// is an error. An absent index or directory is the empty list.
func (x *FileIndex) releasedArtifacts() ([]releasedArtifact, error) {
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
	defer sub.Close()
	dir, err := sub.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open released artifact records: %w", err)
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("read released artifact records: %w", err)
	}
	var out []releasedArtifact
	for _, d := range entries {
		name := d.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") || !d.Type().IsRegular() {
			continue
		}
		fi, err := sub.Lstat(name)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxArtifactRecordBytes {
			continue
		}
		buf, err := readAnchored(sub, name)
		if err != nil {
			continue
		}
		var r artifactRecordRoot
		if json.Unmarshal(buf, &r) != nil {
			continue
		}
		out = append(out, releasedArtifact{name: name, root: r, releasedAt: fi.ModTime()})
	}
	return out, nil
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
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s/%s is not a directory (mode %v)", ErrIndexNotOwned, x.dir, name, fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s/%s is writable by group or other (mode %v)", ErrIndexNotOwned, x.dir, name, fi.Mode().Perm())
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s index: %w", name, err)
	}
	return sub, nil
}
