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

package mount

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/pathsafe"
)

// The kubelet atomic-writer layout (pkg/volume/util/atomic_writer.go upstream).
// A generation-backed mount dir holds:
//
//	<dir>/..2026_09_26_23_10_05.123456789/   one rendered generation
//	<dir>/..data -> ..2026_09_26_23_10_05.123456789
//	<dir>/<key>  -> ..data/<key>            one per top-level entry
//
// A reader that opens <dir>/<key> resolves through ..data, whose target changes
// with one rename(2), so it sees the whole old set or the whole new set, never a
// mix; a reader already holding a file of the old generation open keeps reading
// it after the old generation is removed.
const (
	// dataLink is the symlink naming the live generation.
	dataLink = "..data"
	// dataLinkTmp is the fresh symlink renamed over dataLink to flip it.
	dataLinkTmp = "..data_tmp"
	// generationLayout is the time layout of a generation dir name;
	// makeGeneration appends a random numeric suffix, retrying a name that
	// exists, which makes every name unique.
	generationLayout = "..2006_01_02_15_04_05."
	// generationMode is a generation dir's mode: a pod that runs as a
	// different uid must still traverse it.
	generationMode os.FileMode = 0o755
)

// renameAt is unix.Renameat, a seam so a test can observe the flip.
var renameAt = unix.Renameat

// writeGeneration renders one generation of dir and makes it live. fill renders
// the content into gen (a fresh, empty generation dir inside dir) and is handed
// live, the current generation dir (nil if there is none).
//
// dir is an open directory (dirTarget), reached from a directory the pod
// cannot replace without following a link (openUnder). Every step below acts
// relative to it, or to the generation's own descriptor, and never through a
// path: a pod can rename any directory of its data volume away and plant a
// symlink in its place, and a path through it would make the daemon create,
// replace and remove entries wherever the link points.
//
// The steps, in order, and what each guarantees:
//
//  1. fill renders into a new generation dir. On any error the new dir is
//     removed and the live generation is untouched.
//  2. The new generation is checked (verifyGeneration): regular files and
//     directories only, and no top-level name starting "..". It is walked
//     through its descriptor, so what is checked is what was rendered — the
//     CVE-2021-25741 containment check, done before anything a reader can
//     reach points at it.
//  3. A generation identical to the live one is discarded (no flip): a refresh
//     of unchanged data changes nothing on disk.
//  4. The generation's name must still be the directory that was rendered;
//     then ..data is flipped by renaming a freshly created symlink over it —
//     one rename(2), atomic for every reader.
//  5. Missing top-level <key> -> ..data/<key> symlinks are created; one that
//     already exists is left alone.
//  6. The previous generation is removed, then any top-level symlink into
//     ..data whose key no longer exists.
//
// It never writes into the live generation. flipped reports whether step 4 ran.
func writeGeneration(dir *dirTarget, fill func(gen, live *dirTarget) error) (flipped bool, err error) {
	var live *dirTarget
	var oldGen string
	if target, lerr := readlinkAt(dir.fd, dataLink); lerr == nil {
		if !isGenerationName(target) {
			return false, fmt.Errorf("%s/%s points at %q, not a generation dir", dir.path, dataLink, target)
		}
		oldGen = target
		lfd, err := unix.Openat(dir.fd, target, pathsafe.DirFlags, 0)
		if err != nil {
			return false, fmt.Errorf("open live generation %s: %w", dir.join(target), err)
		}
		live = &dirTarget{fd: lfd, path: dir.join(target)}
		defer live.close()
	} else if !errors.Is(lerr, unix.ENOENT) {
		return false, fmt.Errorf("read %s/%s: %w", dir.path, dataLink, lerr)
	}

	genName, gen, err := makeGeneration(dir)
	if err != nil {
		return false, err
	}
	defer gen.close()
	keep := false
	defer func() {
		if !keep {
			if rmErr := pathsafe.RemoveTreeAt(dir.fd, genName); rmErr != nil && err == nil {
				err = fmt.Errorf("remove discarded generation %s: %w", gen.path, rmErr)
			}
		}
	}()
	if err := unix.Fchmod(gen.fd, uint32(generationMode)); err != nil {
		return false, fmt.Errorf("chmod generation dir: %w", err)
	}

	if err := fill(gen, live); err != nil {
		return false, err
	}
	keys, err := verifyGeneration(gen)
	if err != nil {
		return false, err
	}
	if live != nil {
		same, err := sameTree(live, gen)
		if err != nil {
			return false, err
		}
		if same {
			return false, nil
		}
	}

	// Flip ..data: one rename of a fresh symlink over the old one, to a name
	// that is still the directory rendered and verified above.
	if !sameEntry(dir.fd, genName, gen.fd) {
		return false, fmt.Errorf("generation %s is no longer the directory that was rendered", gen.path)
	}
	if err := unix.Unlinkat(dir.fd, dataLinkTmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return false, fmt.Errorf("clear %s: %w", dir.join(dataLinkTmp), err)
	}
	if err := unix.Symlinkat(genName, dir.fd, dataLinkTmp); err != nil {
		return false, fmt.Errorf("create %s: %w", dir.join(dataLinkTmp), err)
	}
	if err := renameAt(dir.fd, dataLinkTmp, dir.fd, dataLink); err != nil {
		_ = unix.Unlinkat(dir.fd, dataLinkTmp, 0) // best effort; the next write clears it too
		return false, fmt.Errorf("flip %s/%s: %w", dir.path, dataLink, err)
	}
	keep = true

	var errs []error
	for key := range keys {
		if err := linkKey(dir, key); err != nil {
			errs = append(errs, err)
		}
	}
	if oldGen != "" {
		if err := pathsafe.RemoveTreeAt(dir.fd, oldGen); err != nil {
			errs = append(errs, fmt.Errorf("remove previous generation %s: %w", oldGen, err))
		}
	}
	if err := pruneKeys(dir, keys); err != nil {
		errs = append(errs, err)
	}
	return true, errors.Join(errs...)
}

// makeGeneration creates a new, uniquely named generation dir in dir (0700
// until the caller sets generationMode) and opens it without following a
// link. Its name is generationLayout at the current time plus a random
// suffix, as os.MkdirTemp names one.
func makeGeneration(dir *dirTarget) (string, *dirTarget, error) {
	prefix := time.Now().UTC().Format(generationLayout)
	for try := 0; try < 10000; try++ {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10)
		err := unix.Mkdirat(dir.fd, name, 0o700)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("create generation dir: %w", err)
		}
		fd, err := unix.Openat(dir.fd, name, pathsafe.DirFlags, 0)
		if err != nil {
			_ = pathsafe.RemoveTreeAt(dir.fd, name)
			return "", nil, fmt.Errorf("open generation dir %s: %w", dir.join(name), err)
		}
		return name, &dirTarget{fd: fd, path: dir.join(name)}, nil
	}
	return "", nil, fmt.Errorf("create generation dir in %s: no free name", dir.path)
}

// isGenerationName reports whether name is a single path component shaped like
// a generation dir (starts with "..", is not ..data itself).
func isGenerationName(name string) bool {
	return strings.HasPrefix(name, "..") && name != dataLink && name != dataLinkTmp &&
		!strings.ContainsRune(name, filepath.Separator) && name != ".."
}

// verifyGeneration checks a rendered generation before it can go live and
// returns its top-level entry names. Every entry must be a regular file or a
// directory — a render writes key->bytes only, so a symlink here is either a
// bug or an attack, and refusing it closes the CVE-2021-25741 class (a link
// resolved against the host root, k3sm having no mount namespace). No top-level
// name may start with "..", the namespace the layout itself uses. The walk goes
// through gen's descriptor and never follows a link, so every entry it checks
// is inside the generation that was rendered.
func verifyGeneration(gen *dirTarget) (map[string]struct{}, error) {
	keys := map[string]struct{}{}
	err := walkAt(gen, func(rel string, st *unix.Stat_t, _ int, _ string) error {
		kind := uint32(st.Mode) & unix.S_IFMT
		if kind != unix.S_IFREG && kind != unix.S_IFDIR {
			return fmt.Errorf("entry %q is neither a regular file nor a directory", rel)
		}
		if !strings.ContainsRune(rel, filepath.Separator) {
			if strings.HasPrefix(rel, "..") {
				return fmt.Errorf("entry %q uses the reserved \"..\" prefix", rel)
			}
			keys[rel] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify generation: %w", err)
	}
	return keys, nil
}

// linkKey makes <dir>/<key> the relative symlink ..data/<key>. An existing
// correct link is kept; anything else at the name is replaced by renaming a
// fresh link over it (a non-empty directory there fails the rename, and the
// error is returned rather than the directory removed). Every name is
// resolved relative to dir.
func linkKey(dir *dirTarget, key string) error {
	want := dataLink + string(filepath.Separator) + key
	if got, err := readlinkAt(dir.fd, key); err == nil && got == want {
		return nil
	}
	tmp := "..tmp_" + key
	if err := unix.Unlinkat(dir.fd, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("clear %s: %w", dir.join(tmp), err)
	}
	if err := unix.Symlinkat(want, dir.fd, tmp); err != nil {
		return fmt.Errorf("create link for key %q: %w", key, err)
	}
	if err := renameAt(dir.fd, tmp, dir.fd, key); err != nil {
		_ = unix.Unlinkat(dir.fd, tmp, 0) // best effort; the next write clears it too
		return fmt.Errorf("link key %q: %w", key, err)
	}
	return nil
}

// pruneKeys removes every top-level symlink of dir that points into ..data but
// whose key is not in keys (a key the new generation dropped).
func pruneKeys(dir *dirTarget, keys map[string]struct{}) error {
	names, err := listAt(dir.fd, dir.path)
	if err != nil {
		return fmt.Errorf("list mount dir: %w", err)
	}
	var errs []error
	for _, name := range names {
		if strings.HasPrefix(name, "..") {
			continue
		}
		if _, ok := keys[name]; ok {
			continue
		}
		target, err := readlinkAt(dir.fd, name)
		if err != nil || !strings.HasPrefix(target, dataLink+string(filepath.Separator)) {
			continue // not a symlink, or not one of ours
		}
		if err := unix.Unlinkat(dir.fd, name, 0); err != nil {
			errs = append(errs, fmt.Errorf("remove stale key %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// sameTree reports whether two generation dirs hold the same entries with the
// same kinds, permission bits, and file contents.
//
// The trade, stated: every refresh of a changeable volume re-renders it and then
// re-reads and diffs BOTH generations in full — for a token or downwardAPI
// volume that is every tick, even when nothing changed. The alternative, keeping
// the last rendered bytes in memory to compare against, would hold every pod's
// Secret and token bytes in the daemon for the pod's lifetime. Projected volumes
// are small, so the read is chosen over caching credential bytes.
func sameTree(a, b *dirTarget) (bool, error) {
	ta, err := snapshotTree(a)
	if err != nil {
		return false, err
	}
	tb, err := snapshotTree(b)
	if err != nil {
		return false, err
	}
	if len(ta) != len(tb) {
		return false, nil
	}
	for rel, ea := range ta {
		eb, ok := tb[rel]
		if !ok || ea.mode != eb.mode || !bytes.Equal(ea.data, eb.data) {
			return false, nil
		}
	}
	return true, nil
}

// treeEntry is one entry of a snapshotTree.
type treeEntry struct {
	mode os.FileMode
	data []byte
}

// snapshotTree reads every entry under the open directory root: its
// type+permission bits and, for a regular file, its content, each reached
// relative to its parent's descriptor without following a link.
func snapshotTree(root *dirTarget) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	err := walkAt(root, func(rel string, st *unix.Stat_t, parent int, name string) error {
		e := treeEntry{mode: fileMode(st)}
		if e.mode.IsRegular() {
			var err error
			if e.data, err = readFileAt(&dirTarget{fd: parent, path: filepath.Dir(root.join(rel))}, name); err != nil {
				return err
			}
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read generation %s: %w", root.path, err)
	}
	return out, nil
}
