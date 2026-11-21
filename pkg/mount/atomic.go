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

// MountIdentity is what a render leaves for the next Refresh of one
// generation-backed mount: the mount dir's device and inode, and the name,
// device and inode of the generation made live in it. Refresh trusts the live
// generation it finds only when it is exactly that one; the pod can write a
// mount dir (a configMap mount it may write, or anything it renames into the
// mount path) and could otherwise plant a ..data naming a directory of its
// own, whose files the daemon would read back as the live generation.
type MountIdentity struct {
	DirDev, DirIno   uint64
	Live             string
	LiveDev, LiveIno uint64
}

// writeGeneration renders one generation of dir and makes it live. fill renders
// the content into gen (a fresh, empty generation dir inside dir) and is handed
// live, the current generation dir, or nil when there is none it can trust.
// expect is what the previous render of dir left (nil at create, or after a
// daemon restart): the mount dir must still be that directory, and the
// generation ..data names is trusted as live only when it is the one expect
// names. An untrusted or missing live generation means a full render (a token
// is minted fresh) and a flip, never a comparison. It returns the identity to
// expect next time.
//
// dir is an open directory (dirTarget), reached from the data volume without
// following a link (openUnder). Every step below acts relative to it, or to
// the generation's own descriptor, and never through a path: a pod can rename
// any directory of its data volume away and plant a symlink in its place, and
// a path through it would make the daemon create, replace and remove entries
// wherever the link points.
//
// The steps, in order, and what each guarantees:
//
//  1. A ..data that is not a symlink (a directory or a file the pod put there)
//     is removed, so it cannot freeze the mount's rotation; one that names
//     something other than a generation is replaced by the flip.
//  2. fill renders into a new generation dir. On any error the new dir is
//     removed and the live generation is untouched.
//  3. The new generation is checked (verifyGeneration): regular files with
//     one link and directories only, and no top-level name starting "..". It
//     is walked through its descriptor, so what is checked is what was
//     rendered — the CVE-2021-25741 containment check, done before anything a
//     reader can reach points at it.
//  4. A generation identical to a trusted live one is discarded (no flip): a
//     refresh of unchanged data changes nothing on disk.
//  5. The generation's name must still be the directory that was rendered;
//     then ..data is flipped by renaming a freshly created symlink over it —
//     one rename(2), atomic for every reader.
//  6. Missing top-level <key> -> ..data/<key> symlinks are created; one that
//     already exists is left alone.
//  7. The generation ..data named before is removed, then any top-level
//     symlink into ..data whose key no longer exists.
//
// It never writes into the live generation. flipped reports whether step 5 ran.
func writeGeneration(dir *dirTarget, expect *MountIdentity, fill func(gen, live *dirTarget) error) (flipped bool, now MountIdentity, err error) {
	var dst unix.Stat_t
	if err := unix.Fstat(dir.fd, &dst); err != nil {
		return false, now, fmt.Errorf("stat mount dir %s: %w", dir.path, err)
	}
	now.DirDev, now.DirIno = uint64(dst.Dev), uint64(dst.Ino)
	if expect != nil && (expect.DirDev != now.DirDev || expect.DirIno != now.DirIno) {
		return false, now, fmt.Errorf("mount dir %s is not the directory that was materialized", dir.path)
	}

	var live *dirTarget
	var oldGen string
	switch target, lerr := readlinkAt(dir.fd, dataLink); {
	case lerr == nil && isGenerationName(target):
		oldGen = target
		if l, id, ok := openTrusted(dir, target, expect); ok {
			live = l
			defer live.close()
			now.Live, now.LiveDev, now.LiveIno = target, id.dev, id.ino
		}
	case lerr == nil, errors.Is(lerr, unix.ENOENT):
		// A link to something that is no generation: the flip replaces it.
	case errors.Is(lerr, unix.EINVAL):
		// Not a symlink: a directory or file the pod made. The flip cannot
		// rename over a directory, so it goes first.
		if err := pathsafe.RemoveTreeAt(dir.fd, dataLink); err != nil {
			return false, now, fmt.Errorf("remove %s/%s, which is not a symlink: %w", dir.path, dataLink, err)
		}
	default:
		return false, now, fmt.Errorf("read %s/%s: %w", dir.path, dataLink, lerr)
	}

	genName, gen, err := makeGeneration(dir)
	if err != nil {
		return false, now, err
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
		return false, now, fmt.Errorf("chmod generation dir: %w", err)
	}

	if err := fill(gen, live); err != nil {
		return false, now, err
	}
	keys, err := verifyGeneration(gen)
	if err != nil {
		return false, now, err
	}
	if live != nil {
		same, err := sameTree(live, gen)
		if err != nil {
			return false, now, err
		}
		if same {
			return false, now, nil
		}
	}

	// Flip ..data: one rename of a fresh symlink over the old one, to a name
	// that is still the directory rendered and verified above.
	var gst unix.Stat_t
	if err := unix.Fstat(gen.fd, &gst); err != nil || !sameEntry(dir.fd, genName, gen.fd) {
		return false, now, fmt.Errorf("generation %s is no longer the directory that was rendered", gen.path)
	}
	if err := unix.Unlinkat(dir.fd, dataLinkTmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return false, now, fmt.Errorf("clear %s: %w", dir.join(dataLinkTmp), err)
	}
	if err := unix.Symlinkat(genName, dir.fd, dataLinkTmp); err != nil {
		return false, now, fmt.Errorf("create %s: %w", dir.join(dataLinkTmp), err)
	}
	if err := renameAt(dir.fd, dataLinkTmp, dir.fd, dataLink); err != nil {
		_ = unix.Unlinkat(dir.fd, dataLinkTmp, 0) // best effort; the next write clears it too
		return false, now, fmt.Errorf("flip %s/%s: %w", dir.path, dataLink, err)
	}
	keep = true
	now.Live, now.LiveDev, now.LiveIno = genName, uint64(gst.Dev), uint64(gst.Ino)

	var errs []error
	for key := range keys {
		if err := linkKey(dir, key); err != nil {
			errs = append(errs, err)
		}
	}
	if oldGen != "" && oldGen != genName {
		if err := pathsafe.RemoveTreeAt(dir.fd, oldGen); err != nil {
			errs = append(errs, fmt.Errorf("remove previous generation %s: %w", oldGen, err))
		}
	}
	if err := pruneKeys(dir, keys); err != nil {
		errs = append(errs, err)
	}
	return true, now, errors.Join(errs...)
}

// openTrusted opens the generation name in dir without following a link and
// reports it trusted only when expect names it with the same device and inode.
func openTrusted(dir *dirTarget, name string, expect *MountIdentity) (*dirTarget, fileID, bool) {
	if expect == nil || expect.Live != name {
		return nil, fileID{}, false
	}
	fd, err := unix.Openat(dir.fd, name, pathsafe.DirFlags, 0)
	if err != nil {
		return nil, fileID{}, false
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != expect.LiveDev || uint64(st.Ino) != expect.LiveIno {
		unix.Close(fd)
		return nil, fileID{}, false
	}
	return &dirTarget{fd: fd, path: dir.join(name)}, idOf(&st), true
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
// returns its top-level entry names. Every entry must be a regular file with
// one link or a directory — a render writes key->bytes only, so a symlink here is either a
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
		if kind == unix.S_IFREG && st.Nlink != 1 {
			return fmt.Errorf("entry %q has %d hard links; a rendered file has one", rel, st.Nlink)
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
	names, err := listAt(dir.fd, dir.path, maxTreeEntries)
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
// same kinds, permission bits, and file contents. The kinds, bits and sizes
// are compared first, and the contents are read only when those all agree;
// each tree's reads are bounded (snapshotTree).
//
// The trade, stated: every refresh of a changeable volume re-renders it and then
// re-reads and diffs BOTH generations in full — for a token or downwardAPI
// volume that is every tick, even when nothing changed. The alternative, keeping
// the last rendered bytes in memory to compare against, would hold every pod's
// Secret and token bytes in the daemon for the pod's lifetime. Projected volumes
// are small, so the read is chosen over caching credential bytes.
func sameTree(a, b *dirTarget) (bool, error) {
	for _, withData := range []bool{false, true} {
		ta, err := snapshotTree(a, withData)
		if err != nil {
			return false, err
		}
		tb, err := snapshotTree(b, withData)
		if err != nil {
			return false, err
		}
		if len(ta) != len(tb) {
			return false, nil
		}
		for rel, ea := range ta {
			eb, ok := tb[rel]
			if !ok || ea.mode != eb.mode || ea.size != eb.size || !bytes.Equal(ea.data, eb.data) {
				return false, nil
			}
		}
	}
	return true, nil
}

// treeEntry is one entry of a snapshotTree.
type treeEntry struct {
	mode os.FileMode
	size int64
	data []byte
}

// snapshotTree reads every entry under the open directory root: its
// type+permission bits, its size and, for a regular file when withData is
// set, its content, each reached relative to its parent's descriptor without
// following a link. The walk is bounded (walkAt), and so is the content read
// in all: more than maxVolumeBytes is errTreeTooLarge.
func snapshotTree(root *dirTarget, withData bool) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	budget := int64(maxVolumeBytes)
	err := walkAt(root, func(rel string, st *unix.Stat_t, parent int, name string) error {
		e := treeEntry{mode: fileMode(st), size: st.Size}
		if withData && e.mode.IsRegular() {
			if e.size > budget {
				return fmt.Errorf("%w: more than %d bytes under %s", errTreeTooLarge, maxVolumeBytes, root.path)
			}
			var err error
			if e.data, err = readFileAt(&dirTarget{fd: parent, path: filepath.Dir(root.join(rel))}, name, budget); err != nil {
				return err
			}
			budget -= int64(len(e.data))
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read generation %s: %w", root.path, err)
	}
	return out, nil
}
