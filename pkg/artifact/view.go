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

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// View refusals.
var (
	ErrCrossVolume       = errors.New("artifact: a view file would be a copy, not a clone; the blob store and the views must share one APFS volume")
	ErrNotRecorded       = errors.New("artifact: no artifact record names the manifest")
	ErrLayerNotCommitted = errors.New("artifact: a layer the view needs is not committed to the cache")
	ErrViewsRoot         = errors.New("artifact: views directory is not a private directory")
	ErrViewsNotOwned     = errors.New("artifact: views directory is not owned by this process or has the wrong mode")
)

// viewDirMode is the mode of every directory in a built view, the view root
// included; viewFileMode is the mode of every file. Both are applied in
// staging, before the view is renamed into place.
const (
	viewDirMode  = 0o555
	viewFileMode = 0o444
	// viewParentMode is the mode of the views root and of each manifest
	// directory: traversable, so a pod's uid can reach the one view it is
	// granted, but not listable by anyone but the owner.
	viewParentMode = 0o711
	// stagePrefix names a staging directory. A view name is 64 hex digits, so
	// a staging name can never be taken for a view.
	stagePrefix = ".stage-"
)

var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// BlobPaths is the cache seam the view builder clones from; *image.Cache
// satisfies it. BlobStoreDir is read once, at start, for the volume check.
type BlobPaths interface {
	Has(digest string) bool
	BlobPath(digest string) (string, error)
	BlobStoreDir() string
}

// RecordStore reads and removes artifact records; *image.FileIndex satisfies
// it.
type RecordStore interface {
	ArtifactRecords(ctx context.Context) ([][]byte, error)
	ArtifactRecord(ctx context.Context, key string) ([]byte, bool, error)
	RemoveArtifactRecordIf(ctx context.Context, key string, match func(record []byte) bool) (bool, error)
}

// ViewsConfig configures Views.
type ViewsConfig struct {
	// StorePath is the cache root. Views live under
	// <StorePath>/<sandbox.ArtifactViewsSubdir>, on the blob store's volume.
	// Required, absolute.
	StorePath string
	// Cloner clones a blob into a view. Nil means image.CloneOnly, which never
	// copies. It is used strictly: a clone that reports cow == false, or fails
	// because the volume cannot clone (image.IsCloneUnsupported), is
	// ErrCrossVolume.
	Cloner image.Cloner
	// Log receives reaping and collection notes. Nil discards.
	Log *slog.Logger

	// statDev returns the st_dev of a path; nil means stat(2). A test seam.
	statDev func(path string) (uint64, error)
}

// Views builds and owns the read-only artifact views: one directory per
// manifest and path set, holding each selected layer under its file path as
// an APFS clone of the cache blob. It is safe for concurrent use.
//
// Layout: <StorePath>/artifacts/<manifest-hex>/<PathSetKey>/. A view is built
// in a staging directory beside it (<manifest-hex>/.stage-*), every file
// chmodded 0444 and every directory 0555 there, then renamed into place, so a
// view path either does not exist or holds the complete, read-only view. A
// pod is granted one view directory, never the root, so it cannot reach a
// staging directory or another model's view.
//
// A view exists only while some artifact record names its manifest; Forget
// removes a record and, with the last record of a manifest, its views. A
// record replaced for another manifest, or removed some other way, leaves the
// old manifest's views to SweepOrphans, which the image prune calls, and to
// the start-up reap.
//
// Views are a rebuildable cache, so nothing in one is fsynced: a crash can
// publish a view whose clones or modes never reached the disk. The start-up
// pass is the recovery: it removes every published view that is not exactly
// 0555 directories over 0444 regular files, and the next View rebuilds it.
//
// View trusts the daemon-private blob store. A blob was digest-verified when
// it was committed, and a view clones it without hashing it again: a party
// that can rewrite the blob store already has the daemon's privilege.
type Views struct {
	root    string
	cloner  image.Cloner
	blobs   BlobPaths
	records RecordStore
	log     *slog.Logger

	// stripes serialize every build and removal for one manifest (keyed by its
	// hex), so a view is never removed while it is being built, and two builds
	// of one view never race. Builds of different manifests run in parallel
	// unless they share a stripe.
	stripes [32]sync.Mutex

	// beforeRemove, when set, runs in Forget with the manifest lock held, just
	// before the record is removed. A test seam for the re-put interleaving.
	beforeRemove func()
}

// NewViews returns the daemon's view builder. It creates the views root
// (exactly 0711) when absent and refuses one that is not a directory, is not
// owned by the daemon's euid, or has any other mode (ErrViewsNotOwned); it
// refuses a views root on another device than the blob store (ErrCrossVolume),
// before any clone is tried. It is called once at daemon start, and it reaps
// there what a crash left behind: every half-built staging directory, every
// published view that is no longer read-only, and every manifest directory no
// artifact record names any more (a crash between removing a record and
// removing its views). A failure to list the records skips the last step,
// never the others.
func NewViews(ctx context.Context, cfg ViewsConfig, blobs BlobPaths, records RecordStore) (*Views, error) {
	if cfg.StorePath == "" || !filepath.IsAbs(cfg.StorePath) {
		return nil, fmt.Errorf("%w: store path %q is not absolute", ErrViewsRoot, cfg.StorePath)
	}
	if blobs == nil || records == nil {
		return nil, errors.New("artifact views: blobs and records are required")
	}
	if cfg.Cloner == nil {
		cfg.Cloner = image.CloneOnly{}
	}
	statDev := cfg.statDev
	if statDev == nil {
		statDev = deviceOf
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	v := &Views{
		root:    filepath.Join(filepath.Clean(cfg.StorePath), sandbox.ArtifactViewsSubdir),
		cloner:  cfg.Cloner,
		blobs:   blobs,
		records: records,
		log:     log,
	}
	if err := ensurePrivateDir(v.root); err != nil {
		return nil, err
	}
	vdev, err := statDev(v.root)
	if err != nil {
		return nil, fmt.Errorf("stat views root: %w", err)
	}
	bdev, err := statDev(blobs.BlobStoreDir())
	if err != nil {
		return nil, fmt.Errorf("stat blob store: %w", err)
	}
	if vdev != bdev {
		return nil, fmt.Errorf("%w: views root %s is on device %d, the blob store on %d", ErrCrossVolume, v.root, vdev, bdev)
	}
	v.reap(ctx)
	return v, nil
}

// deviceOf returns the st_dev of path, not following a final symlink.
func deviceOf(path string) (uint64, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: no device number", path)
	}
	return uint64(st.Dev), nil
}

// Root returns the views root directory.
func (v *Views) Root() string { return v.root }

// PathSetKey is the view name for a path set: the hex sha256 of the sorted
// paths, each terminated by a NUL byte. Validated paths never contain NUL, so
// distinct sets never share a key. The order of paths does not matter.
func PathSetKey(paths []string) string {
	sorted := slices.Clone(paths)
	sort.Strings(sorted)
	h := sha256.New()
	for _, p := range sorted {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// View returns the directory of the view of manifestDigest restricted to
// paths, building it when absent. Empty paths means every file of the
// artifact, and keys the view by that whole set, so it is the same view as an
// explicit request for every path.
//
// The manifest must be named by an artifact record (ErrNotRecorded), every
// requested path must be in it (ErrPathNotInArtifact), and every layer the
// view needs must be committed (ErrLayerNotCommitted). Concurrent calls for
// one view build it once and return the same path.
func (v *Views) View(ctx context.Context, manifestDigest string, paths []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !sha256Digest.MatchString(manifestDigest) {
		return "", fmt.Errorf("manifest digest %s: %w", image.QuoteBounded(manifestDigest, 128), ErrManifestInvalid)
	}
	if len(paths) > 0 {
		if err := artifactv1.ValidatePathSet(paths); err != nil {
			return "", fmt.Errorf("requested paths: %w", err)
		}
	}
	mhex := strings.TrimPrefix(manifestDigest, "sha256:")
	mu := v.stripe(mhex)
	mu.Lock()
	defer mu.Unlock()

	recs, err := v.recordsFor(ctx, manifestDigest)
	if err != nil {
		return "", err
	}
	if len(recs) == 0 {
		return "", fmt.Errorf("%s: %w", manifestDigest, ErrNotRecorded)
	}
	files, err := manifestFiles(recs[0].ManifestRaw, manifestDigest)
	if err != nil {
		return "", err
	}
	set := paths
	if len(set) == 0 {
		set = make([]string, 0, len(files))
		for p := range files {
			set = append(set, p)
		}
	}
	for _, p := range set {
		if _, ok := files[p]; !ok {
			return "", fmt.Errorf("%q: %w", p, ErrPathNotInArtifact)
		}
	}
	mdir := filepath.Join(v.root, mhex)
	final := filepath.Join(mdir, PathSetKey(set))
	if fi, err := os.Lstat(final); err == nil {
		if !fi.IsDir() {
			return "", fmt.Errorf("%w: %s is not a directory (mode %v)", ErrViewsRoot, final, fi.Mode().Type())
		}
		return final, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("stat view: %w", err)
	}

	committed := map[string]bool{}
	for _, r := range recs {
		for _, d := range r.LayerDigests {
			committed[d] = true
		}
	}
	for _, p := range set {
		d := files[p]
		if !committed[d] || !v.blobs.Has(d) {
			return "", fmt.Errorf("%q (%s): %w", p, d, ErrLayerNotCommitted)
		}
	}
	if err := ensurePrivateDir(v.root); err != nil {
		return "", err
	}
	if err := ensurePrivateDir(mdir); err != nil {
		return "", err
	}
	if err := v.build(mdir, final, set, files); err != nil {
		return "", err
	}
	v.log.Info("artifact view built", "manifest", manifestDigest, "files", len(set), "view", final)
	return final, nil
}

// build clones set into a fresh staging directory in mdir, makes it read-only
// there and renames it to final. Every failure removes the staging directory.
func (v *Views) build(mdir, final string, set []string, files map[string]string) (err error) {
	stage, err := os.MkdirTemp(mdir, stagePrefix+filepath.Base(final)[:16]+"-")
	if err != nil {
		return fmt.Errorf("create view staging: %w", err)
	}
	defer func() {
		if err != nil {
			if rerr := removeTree(stage); rerr != nil {
				v.log.Warn("artifact view: remove staging", "dir", stage, "err", rerr)
			}
		}
	}()
	seen := map[string]bool{}
	var dirs []string
	for _, p := range set {
		dst := filepath.Join(stage, filepath.FromSlash(p))
		for d := filepath.Dir(dst); d != stage && !seen[d]; d = filepath.Dir(d) {
			seen[d] = true
			dirs = append(dirs, d)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fmt.Errorf("create view dir: %w", err)
		}
		src, err := v.blobs.BlobPath(files[p])
		if err != nil {
			return fmt.Errorf("view %q: %w", p, err)
		}
		cow, err := v.cloner.Clone(src, dst)
		if err != nil {
			if image.IsCloneUnsupported(err) {
				return fmt.Errorf("clone %q: %w: %w", p, ErrCrossVolume, err)
			}
			return fmt.Errorf("clone %q: %w", p, err)
		}
		if !cow {
			return fmt.Errorf("clone %q: %w", p, ErrCrossVolume)
		}
		if err := os.Chmod(dst, viewFileMode); err != nil {
			return fmt.Errorf("chmod view file %q: %w", p, err)
		}
	}
	// Deepest first, so a parent is closed only after its children are done.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range append(dirs, stage) {
		if err := os.Chmod(d, viewDirMode); err != nil {
			return fmt.Errorf("chmod view dir: %w", err)
		}
	}
	if err := os.Rename(stage, final); err != nil {
		if fi, serr := os.Lstat(final); serr == nil && fi.IsDir() {
			// Another builder (another process over the same store) won; its
			// view is complete by construction, so this one is discarded.
			if rerr := removeTree(stage); rerr != nil {
				v.log.Warn("artifact view: remove losing staging", "dir", stage, "err", rerr)
			}
			return nil
		}
		return fmt.Errorf("publish view: %w", err)
	}
	return nil
}

// Forget removes the artifact record for ref and artifactType and, when no
// other record names its manifest, every view of that manifest. Its blobs
// become collectable once no record roots them (image.Cache.Roots). A missing
// record is not an error.
//
// The record is removed only if it still names the manifest Forget read, and
// that check runs under the record's own lock (RecordStore.
// RemoveArtifactRecordIf), so a concurrent pull that re-puts the key for a new
// manifest is never undone: Forget then removes nothing and is ordered before
// that put.
func (v *Views) Forget(ctx context.Context, ref, artifactType string) error {
	return v.forget(ctx, Key(ref, artifactType), func([]byte) bool { return true })
}

// forget is Forget for key, removing the record only while keep accepts its
// current bytes as well; keep runs under the record's lock.
func (v *Views) forget(ctx context.Context, key string, keep func(record []byte) bool) error {
	raw, ok, err := v.records.ArtifactRecord(ctx, key)
	if err != nil {
		return fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return nil
	}
	mdigest := recordManifest(raw)
	if mdigest == "" {
		// A record that names no manifest has no views; remove exactly it.
		if _, err := v.records.RemoveArtifactRecordIf(ctx, key, func(cur []byte) bool { return bytes.Equal(cur, raw) && keep(cur) }); err != nil {
			return fmt.Errorf("remove artifact record: %w", err)
		}
		return nil
	}
	mhex := strings.TrimPrefix(mdigest, "sha256:")
	mu := v.stripe(mhex)
	mu.Lock()
	defer mu.Unlock()
	if v.beforeRemove != nil {
		v.beforeRemove()
	}
	removed, err := v.records.RemoveArtifactRecordIf(ctx, key, func(cur []byte) bool { return recordManifest(cur) == mdigest && keep(cur) })
	if err != nil {
		return fmt.Errorf("remove artifact record: %w", err)
	}
	if !removed {
		v.log.Info("artifact forget: the record was replaced or removed meanwhile; left in place",
			"key", image.QuoteBounded(key, 512), "manifest", mdigest)
	}
	return v.removeIfOrphanLocked(ctx, mhex)
}

// ReleasePodOnly forgets every PodOnly record whose reference no pod holds:
// held reports whether some pod still holds a reference. Each record is
// removed only if it is still PodOnly and still names the manifest read here,
// decided under the record's lock, so an operator pull that pins it meanwhile
// keeps it. With its last record a manifest's views go too (Forget), and its
// blobs become collectable after the store's grace.
//
// It fails closed: a record that cannot be listed or decoded releases nothing.
// It returns the keys it found unheld and forgot (a key replaced meanwhile is
// left in place, and still listed).
func (v *Views) ReleasePodOnly(ctx context.Context, held func(ref string) bool) ([]string, error) {
	all, err := v.allRecords(ctx)
	if err != nil {
		return nil, err
	}
	var released []string
	for _, r := range all {
		if !r.PodOnly || held(r.Reference) {
			continue
		}
		mdigest := r.ManifestDigest
		stillPodOnly := func(cur []byte) bool {
			var c Record
			return json.Unmarshal(cur, &c) == nil && c.PodOnly && c.ManifestDigest == mdigest
		}
		if err := v.forget(ctx, r.Key, stillPodOnly); err != nil {
			return released, fmt.Errorf("release %s: %w", image.QuoteBounded(r.Key, 512), err)
		}
		released = append(released, r.Key)
	}
	return released, nil
}

// recordManifest returns the manifest digest a raw record names, or "" when
// it does not decode to a valid one.
func recordManifest(raw []byte) string {
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil || r.Schema != recordSchema || !sha256Digest.MatchString(r.ManifestDigest) {
		return ""
	}
	return r.ManifestDigest
}

// SweepOrphans removes the views of every manifest no artifact record names:
// those of a record replaced for another manifest, or removed other than by
// Forget. It is the start-up reap's rule, run again by the image prune
// (image.ReclaimConfig.SweepDerived). Every removal is decided again under the
// manifest's lock, against a fresh read of the records, so a manifest recorded
// since the first read keeps its views. A record that does not decode fails
// the sweep and keeps every view. Staging directories are left alone: outside
// start-up one may be a build in flight in another process over this store.
func (v *Views) SweepOrphans(ctx context.Context) error {
	named, err := v.namedManifests(ctx)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(v.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read views root: %w", err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := e.Name()
		if !hex64.MatchString(name) || !e.IsDir() || named[name] {
			continue
		}
		if err := v.removeIfOrphan(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

// removeIfOrphan takes the manifest's lock and removes its views if no record
// names it.
func (v *Views) removeIfOrphan(ctx context.Context, mhex string) error {
	mu := v.stripe(mhex)
	mu.Lock()
	defer mu.Unlock()
	return v.removeIfOrphanLocked(ctx, mhex)
}

// removeIfOrphanLocked removes the views of mhex if no record names it. The
// caller holds the manifest's stripe.
func (v *Views) removeIfOrphanLocked(ctx context.Context, mhex string) error {
	left, err := v.recordsFor(ctx, "sha256:"+mhex)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return nil
	}
	mdir := filepath.Join(v.root, mhex)
	if err := removeTree(mdir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove views of sha256:%s: %w", mhex, err)
	}
	v.log.Info("artifact views: removed views no record names", "dir", mdir)
	return nil
}

// reap removes every staging directory, every published view that is not
// read-only (checkPublished), and every manifest directory no record names.
// It runs once, at daemon start, before any build.
func (v *Views) reap(ctx context.Context) {
	entries, err := os.ReadDir(v.root)
	if err != nil {
		v.log.Warn("artifact views: read root for reaping", "err", err)
		return
	}
	named, lerr := v.namedManifests(ctx)
	if lerr != nil {
		v.log.Warn("artifact views: records unreadable; keeping every view", "err", lerr)
	}
	for _, e := range entries {
		name := e.Name()
		mdir := filepath.Join(v.root, name)
		if !hex64.MatchString(name) || !e.IsDir() {
			v.log.Warn("artifact views: unexpected entry left in place", "entry", mdir)
			continue
		}
		if lerr == nil && !named[name] {
			if err := v.removeIfOrphan(ctx, name); err != nil {
				v.log.Warn("artifact views: remove orphaned views", "dir", mdir, "err", err)
			}
			continue
		}
		views, err := os.ReadDir(mdir)
		if err != nil {
			v.log.Warn("artifact views: read manifest dir for reaping", "dir", mdir, "err", err)
			continue
		}
		for _, s := range views {
			p := filepath.Join(mdir, s.Name())
			switch {
			case strings.HasPrefix(s.Name(), stagePrefix):
				if err := removeTree(p); err != nil {
					v.log.Warn("artifact views: reap staging", "dir", p, "err", err)
				} else {
					v.log.Info("artifact views: reaped half-built staging", "dir", p)
				}
			case hex64.MatchString(s.Name()):
				cerr := checkPublished(p)
				if cerr == nil {
					continue
				}
				if err := removeTree(p); err != nil {
					v.log.Warn("artifact views: remove a view that is not read-only", "dir", p, "reason", cerr, "err", err)
				} else {
					v.log.Warn("artifact views: removed a view that is not read-only; the next use rebuilds it", "dir", p, "reason", cerr)
				}
			default:
				v.log.Warn("artifact views: unexpected entry left in place", "entry", p)
			}
		}
	}
}

// checkPublished reports why a published view is not what build leaves:
// directories exactly 0555, regular files exactly 0444, and nothing else (no
// symlink, no special bit). Nothing is followed.
func checkPublished(view string) error {
	return filepath.WalkDir(view, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		switch m := fi.Mode(); {
		case m.IsDir():
			if m != fs.ModeDir|viewDirMode {
				return fmt.Errorf("directory %s has mode %v, want %v", p, m, fs.ModeDir|viewDirMode)
			}
		case m.IsRegular():
			if m != viewFileMode {
				return fmt.Errorf("file %s has mode %v, want %v", p, m, fs.FileMode(viewFileMode))
			}
		default:
			return fmt.Errorf("%s is not a file or a directory (mode %v)", p, m.Type())
		}
		return nil
	})
}

// namedManifests returns the hex of every manifest some record names.
func (v *Views) namedManifests(ctx context.Context) (map[string]bool, error) {
	all, err := v.allRecords(ctx)
	if err != nil {
		return nil, err
	}
	named := make(map[string]bool, len(all))
	for _, r := range all {
		named[strings.TrimPrefix(r.ManifestDigest, "sha256:")] = true
	}
	return named, nil
}

// allRecords decodes every artifact record. A record that does not decode, or
// whose schema this binary does not know, is an error: it may be the one that
// names the manifest a caller asks about.
func (v *Views) allRecords(ctx context.Context) ([]Record, error) {
	raws, err := v.records.ArtifactRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("list artifact records: %w", err)
	}
	out := make([]Record, 0, len(raws))
	for _, raw := range raws {
		var r Record
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("%w: artifact record: %v", image.ErrIndexEntryCorrupt, err)
		}
		if r.Schema != recordSchema {
			return nil, fmt.Errorf("%w: artifact record schema %d", image.ErrIndexEntryCorrupt, r.Schema)
		}
		out = append(out, r)
	}
	return out, nil
}

// recordsFor returns the records naming manifestDigest.
func (v *Views) recordsFor(ctx context.Context, manifestDigest string) ([]Record, error) {
	all, err := v.allRecords(ctx)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, r := range all {
		if r.ManifestDigest == manifestDigest {
			out = append(out, r)
		}
	}
	return out, nil
}

func (v *Views) stripe(mhex string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(mhex)) // hash.Hash.Write never returns an error
	return &v.stripes[h.Sum32()%uint32(len(v.stripes))]
}

// manifestFiles re-checks a recorded manifest against its digest and returns
// its file path to layer digest map, under the same path rules the pull
// applied. The record is daemon-written, but a view is what a pod reads, so
// the paths are validated again rather than trusted.
func manifestFiles(raw []byte, manifestDigest string) (map[string]string, error) {
	sum := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != manifestDigest {
		return nil, fmt.Errorf("recorded manifest hashed to %s, record names %s: %w", got, manifestDigest, ErrManifestDigest)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: recorded manifest: %v", ErrManifestInvalid, err)
	}
	if len(m.Layers) == 0 || len(m.Layers) > MaxLayers {
		return nil, fmt.Errorf("recorded manifest with %d layers: %w", len(m.Layers), ErrManifestInvalid)
	}
	files := make(map[string]string, len(m.Layers))
	paths := make([]string, 0, len(m.Layers))
	for i, l := range m.Layers {
		if err := checkDescriptor(fmt.Sprintf("layer %d", i), l); err != nil {
			return nil, err
		}
		p, err := layerFilePath(i, l)
		if err != nil {
			return nil, err
		}
		files[p] = l.Digest
		paths = append(paths, p)
	}
	if err := artifactv1.ValidatePathSet(paths); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLayerPath, err)
	}
	return files, nil
}

// ensurePrivateDir creates dir at exactly 0711 when absent (Mkdir's mode is
// filtered by the umask, so it is chmodded after) and refuses one that is not
// a directory (a symlink planted in its place included, ErrViewsRoot), or is
// not owned by the daemon's euid or has any other mode (ErrViewsNotOwned). An
// existing directory is never repaired: a mode or owner this process did not
// set means someone else touched it.
func ensurePrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, viewParentMode); err == nil {
			if err := os.Chmod(dir, viewParentMode); err != nil {
				return fmt.Errorf("chmod %s: %w", dir, err)
			}
		} else if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory (mode %v)", ErrViewsRoot, dir, fi.Mode().Type())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: no owner", ErrViewsNotOwned, dir)
	}
	if euid := os.Geteuid(); int(st.Uid) != euid {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrViewsNotOwned, dir, st.Uid, euid)
	}
	if want := fs.ModeDir | viewParentMode; fi.Mode() != want {
		return fmt.Errorf("%w: %s has mode %v, want %v", ErrViewsNotOwned, dir, fi.Mode(), want)
	}
	return nil
}

// removeTree removes a view or staging tree. Its directories are 0555, which
// keeps even the owner from unlinking their entries unless it is root, so
// each directory is reopened (0700) first. Symlinks are never followed: a
// directory is chmodded only when the walk saw it as one.
func removeTree(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return os.Remove(dir)
	}
	werr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o700)
		}
		return nil
	})
	if werr != nil && !errors.Is(werr, fs.ErrNotExist) {
		return werr
	}
	return os.RemoveAll(dir)
}
