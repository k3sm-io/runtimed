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

// Package xcodecache is the per-node Xcode build cache behind the
// k3sm.io/xcode-cache pod annotation: one DerivedData and SwiftPM cache
// snapshot per namespace, key and Xcode build, checked out into a pod's home as
// a private APFS copy-on-write clone when the pod is created and published back
// when a pod that succeeded is deleted.
//
// Why clones and not a shared volume. Two builds writing one DerivedData
// corrupt it (Xcode's build database and the index store are single-writer), and
// a writable cache shared between pods is a build-poisoning channel. A clone is
// private to its pod from the first write, so concurrent builds of one key never
// share a writable file, and the pod's profile needs no grant beyond its own
// data volume: the snapshot lives in a daemon-only tree the profile denies
// (sandbox.XcodeCacheSubdir).
//
// Consistency. A reader clones under a shared flock; a publisher clones the
// pod's tree into a staging directory and swaps it into place under an exclusive
// flock (renamex_np RENAME_SWAP), so a reader always sees one complete snapshot
// and the last successful publisher wins. Only a pod whose main containers all
// exited 0 publishes: a failed, killed or still-running build never does.
//
// Trust, stated plainly: within one namespace and key the cache is a shared
// channel across time. Any pod that may carry the annotation there and exits 0
// decides what the next build on that key starts from, so builds of different
// trust (a fork's pull request and a release) must not share a key, and are
// better kept in different namespaces. Isolation holds between namespaces and
// between concurrent pods, not between successive builds of one key.
//
// Disk use, recorded rather than hidden: there is no quota and no eviction beyond keeping one
// snapshot per (namespace, key, Xcode build). A key that is never used again, or
// a snapshot for an Xcode build the node no longer has, stays until an operator
// removes <work-dir>/xcode-cache/<namespace>/<key>. A clone shares blocks with
// its source until either side writes, so a checkout costs metadata only, but a
// published snapshot keeps every block it references alive.
package xcodecache

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/pathsafe"
)

// Annotation opts a pod into the cache. Its value is the cache key, scoped to
// the pod's namespace; it is honoured only on a pod granted a full Xcode
// (k3sm.io/xcode-toolchain on a node whose developer dir is inside Xcode.app).
const Annotation = "k3sm.io/xcode-cache"

// SnapshotName is the directory under a key's build dir that holds the
// published tree, laid out as a home directory (Parts).
const SnapshotName = "home-cache"

// lockName is the flock file under a key's build dir.
const lockName = ".lock"

// incomingPrefix names a publisher's staging directory under a key's build dir.
const incomingPrefix = ".incoming-"

// Parts are the home-relative trees the cache carries: Xcode's default
// DerivedData (which holds the build products, the index, the module cache and
// SourcePackages, the SwiftPM checkouts of an xcodebuild resolve) and SwiftPM's
// own repository cache.
var Parts = []string{
	filepath.Join("Library", "Developer", "Xcode", "DerivedData"),
	filepath.Join("Library", "Caches", "org.swift.swiftpm"),
}

var (
	keyRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	buildRE     = regexp.MustCompile(`^[A-Za-z0-9.]{1,32}$`)
)

// ErrInvalid marks a key, namespace or Xcode build the cache refuses.
var ErrInvalid = errors.New("xcode cache")

// removeBounds bounds the removal of a part whose clone failed: a cache
// tree nests far less than this, and it may hold any number of entries.
var removeBounds = pathsafe.TreeBounds{Depth: 1024}

// ValidKey reports whether key can name a cache entry: a lowercase letter or
// digit, then up to 62 of [a-z0-9._-]. ".." and anything with a slash are
// refused by construction, so a key can never leave its namespace directory.
func ValidKey(key string) error {
	if !keyRE.MatchString(key) || strings.Contains(key, "..") {
		return fmt.Errorf("%w: key %q must match %s and contain no \"..\"", ErrInvalid, key, keyRE)
	}
	return nil
}

// validNamespace is the Kubernetes namespace (DNS label) shape, checked again
// here because the namespace becomes a path component.
func validNamespace(ns string) error {
	if !namespaceRE.MatchString(ns) {
		return fmt.Errorf("%w: namespace %q is not a DNS label", ErrInvalid, ns)
	}
	return nil
}

// BundleRoot returns the Xcode.app bundle that holds developerDir
// (<bundle>/Contents/Developer), and false when developerDir is not one.
func BundleRoot(developerDir string) (string, bool) {
	d := filepath.Clean(developerDir)
	contents := filepath.Dir(d)
	if filepath.Base(d) != "Developer" || filepath.Base(contents) != "Contents" {
		return "", false
	}
	bundle := filepath.Dir(contents)
	if !strings.HasSuffix(bundle, ".app") {
		return "", false
	}
	return bundle, true
}

// maxVersionPlist bounds the version.plist read; the real file is under 1 KiB.
const maxVersionPlist = 64 << 10

// ReadBuildVersion returns the ProductBuildVersion of the Xcode that holds
// developerDir (for example "17E5159k"), read from <bundle>/Contents/version.plist.
// The cache is keyed by it because DerivedData from another Xcode build is not
// reusable: the build service rebuilds it from scratch, so a shared snapshot
// would only churn.
func ReadBuildVersion(developerDir string) (string, error) {
	bundle, ok := BundleRoot(developerDir)
	if !ok {
		return "", fmt.Errorf("%w: developer dir %q is not inside an Xcode.app bundle", ErrInvalid, developerDir)
	}
	f, err := os.Open(filepath.Join(bundle, "Contents", "version.plist"))
	if err != nil {
		return "", fmt.Errorf("xcode cache: read Xcode version: %w", err)
	}
	defer f.Close()
	v, err := plistString(io.LimitReader(f, maxVersionPlist), "ProductBuildVersion")
	if err != nil {
		return "", fmt.Errorf("xcode cache: %s/Contents/version.plist: %w", bundle, err)
	}
	if !buildRE.MatchString(v) {
		return "", fmt.Errorf("%w: ProductBuildVersion %q is not [A-Za-z0-9.]{1,32}", ErrInvalid, v)
	}
	return v, nil
}

// plistString returns the <string> that follows <key>name</key> in an XML
// property list. It reads the token stream rather than unmarshalling the whole
// document: version.plist is a flat dict, and only one value is wanted.
func plistString(r io.Reader, name string) (string, error) {
	dec := xml.NewDecoder(r)
	var cur, lastKey string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("no %s string", name)
		}
		if err != nil {
			return "", fmt.Errorf("parse: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			cur = t.Name.Local
			if cur == "string" && lastKey != name {
				// A value of some other key: skip it.
				if err := dec.Skip(); err != nil {
					return "", fmt.Errorf("parse: %w", err)
				}
				cur, lastKey = "", ""
			}
		case xml.CharData:
			switch cur {
			case "key":
				lastKey = strings.TrimSpace(string(t))
			case "string":
				if lastKey == name {
					return strings.TrimSpace(string(t)), nil
				}
			}
		case xml.EndElement:
			if t.Name.Local == "string" && cur == "string" && lastKey == name {
				// <string></string>: an empty value.
				return "", nil
			}
			cur = ""
		}
	}
}

// FS is the filesystem seam: production is APFS clonefile and renamex_np; the
// tests may substitute either.
type FS interface {
	// CloneAt makes dstName under the directory dstDirFd a copy of the
	// directory tree srcName under the directory srcDirFd, never following a
	// link at either final name. Either fd may be unix.AT_FDCWD with an
	// absolute name, for a path only the daemon can write. The destination
	// must not exist.
	CloneAt(srcDirFd int, srcName string, dstDirFd int, dstName string) error
	// Swap atomically exchanges two existing paths.
	Swap(a, b string) error
}

// Store is one node's cache, rooted at <work-dir>/xcode-cache.
type Store struct {
	// Root is the cache root. It must be on the same APFS volume as the pod
	// data volumes, or every clone fails (EXDEV) and the cache is skipped.
	Root string
	// FS performs the clones and the swap; nil means APFS.
	FS FS
	// LockWait bounds how long a checkout or publish waits for the key's
	// lock before giving up; 0 means DefaultLockWait.
	LockWait time.Duration
}

// DefaultLockWait bounds a lock wait. A commit holds the exclusive lock only
// for a rename and a checkout holds the shared one for a clone (metadata), so a
// longer wait means a stuck holder, and a build is better started cold than
// held.
const DefaultLockWait = 30 * time.Second

// Entry names one cache entry.
type Entry struct {
	Namespace, Key, Build string
}

// Validate checks every component that becomes a path element.
func (e Entry) Validate() error {
	if err := validNamespace(e.Namespace); err != nil {
		return err
	}
	if err := ValidKey(e.Key); err != nil {
		return err
	}
	if !buildRE.MatchString(e.Build) {
		return fmt.Errorf("%w: Xcode build %q", ErrInvalid, e.Build)
	}
	return nil
}

// Dir is the entry's build dir: <Root>/<namespace>/<key>/<build>.
func (s Store) Dir(e Entry) string {
	return filepath.Join(s.Root, e.Namespace, e.Key, e.Build)
}

func (s Store) fs() FS {
	if s.FS != nil {
		return s.FS
	}
	return apfsFS{}
}

func (s Store) wait() time.Duration {
	if s.LockWait > 0 {
		return s.LockWait
	}
	return DefaultLockWait
}

// Checkout clones each published part of the entry's snapshot into home, which
// must exist, and returns the parts it cloned. No snapshot is not an error: the
// pod starts cold and returns nil. A part already present in home is left
// alone. On an error a partly cloned part is removed, so home holds each part
// whole or not at all.
func (s Store) Checkout(e Entry, home string) ([]string, error) {
	return s.CheckoutAt(e, home, ".")
}

// CheckoutAt is Checkout for a home that lies under a directory its owner can
// rearrange: base is a directory the pod cannot replace (its pod dir), and
// homeRel is the home's path below it. Every component of homeRel is opened
// with O_NOFOLLOW, so a component the pod swapped for a link (its rootfs, for
// one) is refused instead of followed into another pod's tree. The home must
// already exist.
func (s Store) CheckoutAt(e Entry, base, homeRel string) ([]string, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	home := filepath.Join(base, homeRel)
	if h, ok, err := pinDir(base, homeRel, false); err != nil {
		return nil, fmt.Errorf("xcode cache: checkout: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("%w: home %s is not a directory", ErrInvalid, home)
	} else {
		h.Close()
	}
	dir := s.Dir(e)
	snap := filepath.Join(dir, SnapshotName)
	if _, err := os.Lstat(snap); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	unlock, err := lock(filepath.Join(dir, lockName), unix.LOCK_SH, s.wait())
	if err != nil {
		return nil, err
	}
	defer unlock()
	var cloned []string
	for _, part := range Parts {
		src := filepath.Join(snap, part)
		if fi, err := os.Lstat(src); err != nil || !fi.IsDir() {
			continue
		}
		// The destination's parents are created and opened one component at
		// a time, never through a link, and the clone lands relative to the
		// pinned parent: nothing in home is resolved by path.
		parent, _, err := pinDir(base, filepath.Join(homeRel, filepath.Dir(part)), true)
		if err != nil {
			return cloned, fmt.Errorf("xcode cache: checkout %s: %w", part, err)
		}
		name := filepath.Base(part)
		var st unix.Stat_t
		if err := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			parent.Close()
			continue
		}
		err = s.fs().CloneAt(unix.AT_FDCWD, src, int(parent.Fd()), name)
		if err != nil {
			// Removed relative to the pinned parent, never by path: the
			// daemon runs this as root, and a path through the home could
			// by now name another tree.
			_ = pathsafe.RemoveTreeAt(int(parent.Fd()), name, removeBounds)
		}
		parent.Close()
		if err != nil {
			return cloned, fmt.Errorf("xcode cache: checkout %s: %w", part, err)
		}
		cloned = append(cloned, part)
	}
	return cloned, nil
}

// Publish replaces the entry's snapshot with a clone of the parts present in
// home and returns the parts it published: Stage, then Commit. A home with none
// of the parts publishes nothing and keeps the old snapshot. stage names the
// staging directory and must be unique per publisher (the pod id).
func (s Store) Publish(e Entry, home, stage string) ([]string, error) {
	incoming, parts, err := s.Stage(e, home, stage)
	if err != nil || incoming == "" {
		return nil, err
	}
	if err := s.Commit(e, incoming); err != nil {
		return nil, err
	}
	return parts, nil
}

// Stage clones the parts present in home into a staging directory under the
// entry's build dir and returns it, with the parts. It takes no lock: it reads
// only home, and no reader looks at a staging directory. It is the half of a
// publish that must run while home still exists; Commit, which may wait on a
// reader's lock, can run after home is gone. An empty incoming means home held
// nothing to publish.
func (s Store) Stage(e Entry, home, stage string) (incoming string, parts []string, err error) {
	return s.StageAt(e, home, ".", stage)
}

// StageAt is Stage for a home that lies under a directory its owner can
// rearrange: base is a directory the pod cannot replace (its pod dir), and
// homeRel is the home's path below it. Every component of homeRel is opened
// with O_NOFOLLOW. A pod can replace its own rootfs with a link to another
// pod's; resolving the home by path would then stage the OTHER pod's build
// products into this pod's cache, where its next pod reads them.
func (s Store) StageAt(e Entry, base, homeRel, stage string) (incoming string, parts []string, err error) {
	home := filepath.Join(base, homeRel)
	if err := e.Validate(); err != nil {
		return "", nil, err
	}
	if stage == "" || strings.ContainsAny(stage, `/\`) || strings.Contains(stage, "..") {
		return "", nil, fmt.Errorf("%w: staging name %q", ErrInvalid, stage)
	}
	// Each part's parent directory is opened one component at a time with
	// O_NOFOLLOW and held open, and the clone below is made relative to that
	// descriptor. The home was written by the pod, and a process that escaped
	// the pod's stop could still swap a directory for a link: a path-based
	// check-then-clone would then have the daemon clone whatever the link
	// names (another namespace's snapshot, another pod's home) into this
	// cache. Pinned descriptors name the inodes that were checked, and
	// CLONE_NOFOLLOW covers the last name, so a swap can at worst publish a
	// link as a link, which Checkout never clones.
	type pinned struct {
		part   string
		parent *os.File
	}
	var pins []pinned
	defer func() {
		for _, p := range pins {
			p.parent.Close()
		}
	}()
	for _, part := range Parts {
		parent, ok, err := pinDir(base, filepath.Join(homeRel, filepath.Dir(part)), false)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			continue
		}
		var st unix.Stat_t
		err = unix.Fstatat(int(parent.Fd()), filepath.Base(part), &st, unix.AT_SYMLINK_NOFOLLOW)
		switch {
		case err == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK:
			parent.Close()
			return "", nil, fmt.Errorf("%w: %s is a symlink", ErrInvalid, filepath.Join(home, part))
		case err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR:
			parent.Close()
			continue
		}
		pins = append(pins, pinned{part, parent})
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "", nil, nil
	}
	dir := s.Dir(e)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("xcode cache: stage: %w", err)
	}
	incoming = filepath.Join(dir, incomingPrefix+stage)
	if err := os.RemoveAll(incoming); err != nil {
		return "", nil, fmt.Errorf("xcode cache: stage: clear: %w", err)
	}
	for i, part := range parts {
		dst := filepath.Join(incoming, part)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			_ = os.RemoveAll(incoming)
			return "", nil, fmt.Errorf("xcode cache: stage %s: %w", part, err)
		}
		if err := s.fs().CloneAt(int(pins[i].parent.Fd()), filepath.Base(part), unix.AT_FDCWD, dst); err != nil {
			_ = os.RemoveAll(incoming)
			return "", nil, fmt.Errorf("xcode cache: stage %s: %w", part, err)
		}
	}
	return incoming, parts, nil
}

// Commit makes a staged tree the entry's snapshot under the exclusive lock:
// RENAME_SWAP over an existing snapshot (so the name never points at nothing),
// or a rename when there is none. The replaced snapshot, or the staged tree on
// any failure, is removed after the lock is released.
func (s Store) Commit(e Entry, incoming string) error {
	if err := e.Validate(); err != nil {
		return err
	}
	dir := s.Dir(e)
	if filepath.Dir(incoming) != dir || !strings.HasPrefix(filepath.Base(incoming), incomingPrefix) {
		return fmt.Errorf("%w: %q is not a staging dir of %s", ErrInvalid, incoming, dir)
	}
	// Whatever is left at incoming afterwards (the old snapshot after a swap,
	// or the staged tree after a failure) is garbage.
	defer func() { _ = os.RemoveAll(incoming) }()
	unlock, err := lock(filepath.Join(dir, lockName), unix.LOCK_EX, s.wait())
	if err != nil {
		return err
	}
	defer unlock()
	sweepStale(dir, incoming)
	snap := filepath.Join(dir, SnapshotName)
	if _, err := os.Lstat(snap); err == nil {
		if err := s.fs().Swap(incoming, snap); err != nil {
			return fmt.Errorf("xcode cache: commit: swap: %w", err)
		}
		return nil
	}
	if err := os.Rename(incoming, snap); err != nil {
		return fmt.Errorf("xcode cache: commit: rename: %w", err)
	}
	return nil
}

// staleStage is how old another publisher's staging dir must be before a
// commit removes it: a stage is committed within the lock wait, so one this old
// was orphaned (the daemon exited between the stage and the commit).
const staleStage = time.Hour

// sweepStale removes orphaned staging dirs under dir, other than keep.
func sweepStale(dir, keep string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if !strings.HasPrefix(e.Name(), incomingPrefix) || p == keep {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > staleStage {
			_ = os.RemoveAll(p)
		}
	}
}

// pinDir opens base/rel as a directory, one component at a time with
// O_NOFOLLOW (pathsafe.OpenDirFrom), and returns the open directory. A symlink
// anywhere, base included, is refused (ErrInvalid). A missing or non-directory
// component returns ok=false, unless create is set, which makes a missing one
// (0700). The caller closes the returned file.
func pinDir(base, rel string, create bool) (*os.File, bool, error) {
	bfd, err := unix.Open(base, pathsafe.DirFlags, 0)
	if err != nil {
		return nil, false, fmt.Errorf("%w: open %s: %v", ErrInvalid, base, err)
	}
	defer unix.Close(bfd)
	fd, err := pathsafe.OpenDirFrom(bfd, base, rel, create, 0o700)
	switch {
	case err == nil:
		return os.NewFile(uintptr(fd), filepath.Join(base, rel)), true, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		return nil, false, nil
	case errors.Is(err, pathsafe.ErrSymlinkedPath), errors.Is(err, pathsafe.ErrPathOutsideRoot):
		return nil, false, fmt.Errorf("%w: %v", ErrInvalid, err)
	default:
		return nil, false, fmt.Errorf("xcode cache: %w", err)
	}
}

// lock takes a flock of kind how on path, creating it, retrying a busy lock
// until wait runs out. The descriptor is close-on-exec and never follows a
// symlink. The returned func releases it.
func lock(path string, how int, wait time.Duration) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("xcode cache: lock: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("xcode cache: lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("xcode cache: lock %s: %w", path, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
