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
	"errors"
	"fmt"
	"io/fs"
	"os"
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
// Like an image entry, an artifact record is an EDGE, never a reachability
// root: no GC enumerator reads this tree.
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

// openArtifactRoot opens the artifact namespace under root, creating it (0700)
// when create is set, and refuses one that is not a directory or is writable by
// group or other, for the reason FileIndex.open gives.
func (x *FileIndex) openArtifactRoot(root *os.Root, create bool) (*os.Root, error) {
	if create {
		if err := root.Mkdir(ArtifactIndexSubdir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create artifact index: %w", err)
		}
	}
	fi, err := root.Lstat(ArtifactIndexSubdir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s/%s is not a directory (mode %v)", ErrIndexNotOwned, x.dir, ArtifactIndexSubdir, fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s/%s is writable by group or other (mode %v)", ErrIndexNotOwned, x.dir, ArtifactIndexSubdir, fi.Mode().Perm())
	}
	sub, err := root.OpenRoot(ArtifactIndexSubdir)
	if err != nil {
		return nil, fmt.Errorf("open artifact index: %w", err)
	}
	return sub, nil
}
