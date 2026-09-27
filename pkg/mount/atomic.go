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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	// generationLayout is the time layout of a generation dir name; MkdirTemp
	// appends a random numeric suffix, which makes every name unique.
	generationLayout = "..2006_01_02_15_04_05."
	// generationMode is a generation dir's mode: a pod that runs as a
	// different uid must still traverse it.
	generationMode os.FileMode = 0o755
)

// rename is os.Rename, a seam so a test can observe the flip.
var rename = os.Rename

// writeGeneration renders one generation of dir and makes it live. fill renders
// the content into gen (a fresh, empty generation dir inside dir) and is handed
// live, the current generation dir ("" if there is none).
//
// The steps, in order, and what each guarantees:
//
//  1. fill renders into a new generation dir. On any error the new dir is
//     removed and the live generation is untouched.
//  2. The new generation is checked (verifyGeneration): regular files and
//     directories only, no top-level name starting "..", and it resolves under
//     dir — the CVE-2021-25741 containment check, done before anything a
//     reader can reach points at it.
//  3. A generation identical to the live one is discarded (no flip): a refresh
//     of unchanged data changes nothing on disk.
//  4. ..data is flipped by renaming a freshly created symlink over it — one
//     rename(2), atomic for every reader.
//  5. Missing top-level <key> -> ..data/<key> symlinks are created; one that
//     already exists is left alone.
//  6. The previous generation is removed, then any top-level symlink into
//     ..data whose key no longer exists.
//
// It never writes into the live generation. flipped reports whether step 4 ran.
func writeGeneration(dir string, fill func(gen, live string) error) (flipped bool, err error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return false, fmt.Errorf("stat mount dir: %w", err)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("mount dir %s is not a directory", dir)
	}

	var live, oldGen string
	if target, lerr := os.Readlink(filepath.Join(dir, dataLink)); lerr == nil {
		if !isGenerationName(target) {
			return false, fmt.Errorf("%s/%s points at %q, not a generation dir", dir, dataLink, target)
		}
		oldGen = target
		live = filepath.Join(dir, target)
	} else if !errors.Is(lerr, fs.ErrNotExist) {
		return false, fmt.Errorf("read %s/%s: %w", dir, dataLink, lerr)
	}

	gen, err := os.MkdirTemp(dir, time.Now().UTC().Format(generationLayout))
	if err != nil {
		return false, fmt.Errorf("create generation dir: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			if rmErr := os.RemoveAll(gen); rmErr != nil && err == nil {
				err = fmt.Errorf("remove discarded generation %s: %w", gen, rmErr)
			}
		}
	}()
	if err := os.Chmod(gen, generationMode); err != nil {
		return false, fmt.Errorf("chmod generation dir: %w", err)
	}

	if err := fill(gen, live); err != nil {
		return false, err
	}
	keys, err := verifyGeneration(dir, gen)
	if err != nil {
		return false, err
	}
	if live != "" {
		same, err := sameTree(live, gen)
		if err != nil {
			return false, err
		}
		if same {
			return false, nil
		}
	}

	// Flip ..data: one rename of a fresh symlink over the old one.
	tmp := filepath.Join(dir, dataLinkTmp)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("clear %s: %w", tmp, err)
	}
	if err := os.Symlink(filepath.Base(gen), tmp); err != nil {
		return false, fmt.Errorf("create %s: %w", tmp, err)
	}
	if err := rename(tmp, filepath.Join(dir, dataLink)); err != nil {
		_ = os.Remove(tmp) // best effort; the next write clears it too
		return false, fmt.Errorf("flip %s/%s: %w", dir, dataLink, err)
	}
	keep = true

	var errs []error
	for key := range keys {
		if err := linkKey(dir, key); err != nil {
			errs = append(errs, err)
		}
	}
	if oldGen != "" {
		if err := os.RemoveAll(filepath.Join(dir, oldGen)); err != nil {
			errs = append(errs, fmt.Errorf("remove previous generation %s: %w", oldGen, err))
		}
	}
	if err := pruneKeys(dir, keys); err != nil {
		errs = append(errs, err)
	}
	return true, errors.Join(errs...)
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
// name may start with "..", the namespace the layout itself uses. And the
// generation, resolved, must sit under the resolved mount dir.
func verifyGeneration(dir, gen string) (map[string]struct{}, error) {
	dirResolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve mount dir: %w", err)
	}
	genResolved, err := filepath.EvalSymlinks(gen)
	if err != nil {
		return nil, fmt.Errorf("resolve generation dir: %w", err)
	}
	if !IsStrictlyUnder(genResolved, dirResolved) {
		return nil, fmt.Errorf("generation %s resolves outside mount dir %s", gen, dir)
	}
	keys := map[string]struct{}{}
	err = filepath.WalkDir(gen, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if p == gen {
			return nil
		}
		rel, rerr := filepath.Rel(gen, p)
		if rerr != nil || !isUnder(p, gen) {
			return fmt.Errorf("entry %s escapes the generation", p)
		}
		if !d.Type().IsRegular() && !d.IsDir() {
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
// error is returned rather than the directory removed).
func linkKey(dir, key string) error {
	want := dataLink + string(filepath.Separator) + key
	p := filepath.Join(dir, key)
	if got, err := os.Readlink(p); err == nil && got == want {
		return nil
	}
	tmp := filepath.Join(dir, "..tmp_"+key)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear %s: %w", tmp, err)
	}
	if err := os.Symlink(want, tmp); err != nil {
		return fmt.Errorf("create link for key %q: %w", key, err)
	}
	if err := rename(tmp, p); err != nil {
		_ = os.Remove(tmp) // best effort; the next write clears it too
		return fmt.Errorf("link key %q: %w", key, err)
	}
	return nil
}

// pruneKeys removes every top-level symlink of dir that points into ..data but
// whose key is not in keys (a key the new generation dropped).
func pruneKeys(dir string, keys map[string]struct{}) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list mount dir: %w", err)
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "..") || e.Type()&fs.ModeSymlink == 0 {
			continue
		}
		if _, ok := keys[name]; ok {
			continue
		}
		target, err := os.Readlink(filepath.Join(dir, name))
		if err != nil || !strings.HasPrefix(target, dataLink+string(filepath.Separator)) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
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
func sameTree(a, b string) (bool, error) {
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

// snapshotTree reads every entry under root: its type+permission bits and, for
// a regular file, its content.
func snapshotTree(root string) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := treeEntry{mode: info.Mode()}
		if info.Mode().IsRegular() {
			if e.data, err = os.ReadFile(p); err != nil {
				return err
			}
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read generation %s: %w", root, err)
	}
	return out, nil
}
