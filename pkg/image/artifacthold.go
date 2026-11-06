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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// ArtifactHoldIndexSubdir is the index-relative directory a pod's artifact
// holds live in: <root>/index/artifact-hold/<pod-id>.json. A hold names the
// artifact references a pod mounts, from before their fetch to the pod's
// deletion. It is under the index, which every pod is denied, rather than in
// the pod dir, which a pod may be able to write.
const ArtifactHoldIndexSubdir = "artifact-hold"

// MaxArtifactHoldBytes caps one hold record: a pod names at most a few hundred
// volumes, each reference bounded by the reference validator.
const MaxArtifactHoldBytes = 1 << 20

// ErrArtifactHoldsIncomplete reports that the set of pod holds could not be
// read in full, so no artifact may be released from it.
var ErrArtifactHoldsIncomplete = errors.New("image: artifact hold set is incomplete")

// artifactHold is the on-disk shape of one pod's hold.
type artifactHold struct {
	References []string `json:"references"`
}

func artifactHoldName(id PodID) string { return id.String() + ".json" }

// PutArtifactHold records that pod id holds refs, replacing any previous hold
// for it, atomically (temp, fsync, rename).
func (x *FileIndex) PutArtifactHold(ctx context.Context, id PodID, refs []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	refs = append([]string(nil), refs...)
	sort.Strings(refs)
	buf, err := json.Marshal(artifactHold{References: refs})
	if err != nil {
		return fmt.Errorf("encode artifact hold: %w", err)
	}
	if len(buf) > MaxArtifactHoldBytes {
		return fmt.Errorf("artifact hold for pod %s is %d bytes, at most %d", id, len(buf), MaxArtifactHoldBytes)
	}
	name := artifactHoldName(id)
	mu := x.stripeFor(ArtifactHoldIndexSubdir + "/" + name)
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
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, true)
	if err != nil {
		return err
	}
	defer sub.Close()
	return x.commit(sub, name, buf)
}

// RemoveArtifactHold removes pod id's hold. A missing hold is not an error.
func (x *FileIndex) RemoveArtifactHold(id PodID) error {
	name := artifactHoldName(id)
	mu := x.stripeFor(ArtifactHoldIndexSubdir + "/" + name)
	mu.Lock()
	defer mu.Unlock()
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer sub.Close()
	if err := sub.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove artifact hold of pod %s: %w", id, err)
	}
	return nil
}

// ArtifactHolds returns every pod's hold, keyed by pod. An absent index or
// hold directory is the empty set.
//
// It fails closed, with ErrArtifactHoldsIncomplete: an entry whose name is not
// a pod id, one that is not a regular file, or one that cannot be read or
// decoded aborts the whole set, because a set silently short of one pod's hold
// would release an artifact that pod still mounts. A ".index-" temp left by a
// crashed commit is skipped; no hold is stored under a dot name.
func (x *FileIndex) ArtifactHolds(ctx context.Context) (map[PodID][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := x.open()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[PodID][]string{}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrArtifactHoldsIncomplete, err)
	}
	defer root.Close()
	sub, err := x.openSubdir(root, ArtifactHoldIndexSubdir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[PodID][]string{}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrArtifactHoldsIncomplete, err)
	}
	defer sub.Close()
	dir, err := sub.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: open artifact holds: %v", ErrArtifactHoldsIncomplete, err)
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: read artifact holds: %v", ErrArtifactHoldsIncomplete, err)
	}
	out := make(map[PodID][]string, len(entries))
	for _, d := range entries {
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		id, perr := ParsePodID(strings.TrimSuffix(name, ".json"))
		if perr != nil || !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("%w: entry %s is not a pod's hold", ErrArtifactHoldsIncomplete, QuoteBounded(name, 256))
		}
		fi, err := sub.Lstat(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // removed since the read; that pod holds nothing now
			}
			return nil, fmt.Errorf("%w: stat hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, err)
		}
		if !fi.Mode().IsRegular() || fi.Size() > MaxArtifactHoldBytes {
			return nil, fmt.Errorf("%w: hold of pod %s is not a regular file within its cap (mode %v, %d bytes)", ErrArtifactHoldsIncomplete, id, fi.Mode().Type(), fi.Size())
		}
		buf, err := readAnchored(sub, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("%w: read hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, err)
		}
		var h artifactHold
		if err := json.Unmarshal(buf, &h); err != nil {
			return nil, fmt.Errorf("%w: decode hold of pod %s: %v", ErrArtifactHoldsIncomplete, id, boundErr(err))
		}
		out[id] = h.References
	}
	return out, nil
}
