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
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrLayerEscapes reports that a layer entry names a location OUTSIDE the tree
// being built: an absolute path, a "../" traversal, a hard-link target that
// leaves the tree, or a symlink whose target would resolve outside it.
//
// It is the unpacker's containment sentinel and it is always fatal to the whole
// unpack, never a per-entry skip. A skip would leave a tree that is a SUBSET of
// the image the manifest describes while still being committed under that
// image's key — so the next pod to hit the key would silently get an image with
// a file missing, with nothing on disk recording why.
var ErrLayerEscapes = errors.New("image: layer entry escapes the unpacked tree")

// ErrLayerMalformed reports a layer tar this package refuses to apply: an
// unreadable stream, an empty or undecodable entry name, or a tar entry type
// outside the closed set below.
//
// It is distinct from ErrLayerEscapes because the two imply different verdicts
// about the SOURCE: an escaping entry is an image actively reaching outside its
// own tree, a malformed one is an image this unpacker cannot represent. Only the
// first is an attack signature, and an operator triaging a refused image needs
// to be able to tell them apart.
var ErrLayerMalformed = errors.New("image: layer tar is malformed")

// ErrUnpackTooLarge reports that a layer stream exceeded the unpack RESOURCE
// GUARD — total decompressed bytes or total entries (see ApplyLimits).
//
// Like Cache.CommitBlob's size cap it is a resource guard, NOT an integrity
// mechanism: the compressed blob was already verified against its manifest
// descriptor, but a verified blob may still be a decompression bomb, and the
// bytes it expands to land on the same volume as the kine datastore.
var ErrUnpackTooLarge = errors.New("image: unpacked layer exceeds the unpack size limits")

// LayerSemantics selects the DIALECT a layer tar is applied in. It is part of
// the unpacked tree's key (UnpackPolicy), so two dialects of one image can never
// collide on a single tree.
//
// It is a closed vocabulary validated by UnpackPolicy.Validate, and unknown
// values fail closed. A dialect is added by adding a constant here AND a case in
// LayerApplier.applyEntry — never by letting an unrecognised value fall through
// to the native path, which would apply Linux layer semantics with the wrong
// rules and commit the result under a key that claims otherwise.
type LayerSemantics string

// SemanticsNative is the DARWIN-NATIVE layer dialect: an image whose payload is
// Mach-O and runs as a host process at host paths (DESIGN §5a), with no chroot
// and no guest.
//
// Two consequences follow from "no chroot", and they are the whole reason the
// dialect is named rather than assumed:
//
//   - an ABSOLUTE symlink in the tree does not mean "inside the image" the way
//     it does under a chroot — it resolves against the HOST root the moment the
//     tree is cloned into a pod rootfs — so this dialect refuses one outright;
//   - OCI whiteouts (".wh.*", ".wh..wh..opq") carry no meaning here and are
//     applied as ordinary files. The Linux dialect that interprets them is
//     M11.2-d1's, and it arrives as its own LayerSemantics constant precisely so
//     a tree built under one dialect is never served to the other.
const SemanticsNative LayerSemantics = "native"

// ApplyLimits bounds one unpack. The zero value means DefaultApplyLimits; a
// negative field is an error, and zero on a single field is the default for that
// field (there is no "unlimited" spelling, deliberately — the guard exists
// because the store volume is shared with the control plane's datastore).
type ApplyLimits struct {
	// MaxBytes caps the total DECOMPRESSED regular-file bytes one tree may hold.
	MaxBytes int64
	// MaxEntries caps the total number of tar entries one tree may apply.
	MaxEntries int
}

// Default unpack resource guards. They are sized to admit every image k3sm is
// expected to run (a Linux base image is single-digit GiB; an MLX model image is
// tens of GiB) while still refusing an unbounded expansion.
const (
	// DefaultMaxUnpackBytes is the default ApplyLimits.MaxBytes.
	DefaultMaxUnpackBytes int64 = 64 << 30 // 64 GiB
	// DefaultMaxUnpackEntries is the default ApplyLimits.MaxEntries.
	DefaultMaxUnpackEntries = 4_000_000
)

// withDefaults returns l with unset fields replaced by the defaults, erroring on
// a negative field.
func (l ApplyLimits) withDefaults() (ApplyLimits, error) {
	if l.MaxBytes < 0 || l.MaxEntries < 0 {
		return ApplyLimits{}, fmt.Errorf("unpack limits: negative bound (bytes %d, entries %d)", l.MaxBytes, l.MaxEntries)
	}
	if l.MaxBytes == 0 {
		l.MaxBytes = DefaultMaxUnpackBytes
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = DefaultMaxUnpackEntries
	}
	return l, nil
}

// maxLayerEntryNameLen bounds one rendered layer entry name. Entry names are
// registry-supplied bytes that reach slog, the Pod status message and kine, so
// they are quoted as bounded DATA exactly like a digest or a media type.
const maxLayerEntryNameLen = 256

// ApplyStats counts what one tree's layers produced. It is recorded in the
// tree's daemon-authored record (see treeRecord) so a later reader can tell what
// the unpacker DID without re-walking the tree — in particular how much of the
// image was dropped.
type ApplyStats struct {
	// Files, Dirs, Symlinks and Hardlinks count the entries actually created.
	// A later layer replacing an earlier entry counts once per application, so
	// these are apply counts, not a final inventory.
	Files     int `json:"files"`
	Dirs      int `json:"dirs"`
	Symlinks  int `json:"symlinks"`
	Hardlinks int `json:"hardlinks"`
	// SkippedSpecial counts character/block device, FIFO and socket entries,
	// which an unprivileged daemon cannot create and a native pod has no use
	// for. They are SKIPPED and counted rather than refused: refusing would
	// reject a large share of real base images over nodes nothing on the native
	// path reads, and the count is what keeps the loss visible.
	SkippedSpecial int `json:"skipped_special"`
	// StrippedSetIDs counts entries whose setuid/setgid/sticky bits were
	// dropped. See LayerApplier.entryPerm for why they are always dropped.
	StrippedSetIDs int `json:"stripped_setids"`
	// Bytes is the total decompressed regular-file content written.
	Bytes int64 `json:"bytes"`
}

// add accumulates o into s (per-layer stats summed across a whole tree).
func (s *ApplyStats) add(o ApplyStats) {
	s.Files += o.Files
	s.Dirs += o.Dirs
	s.Symlinks += o.Symlinks
	s.Hardlinks += o.Hardlinks
	s.SkippedSpecial += o.SkippedSpecial
	s.StrippedSetIDs += o.StrippedSetIDs
	s.Bytes += o.Bytes
}

// LayerApplier applies decompressed OCI layer tar streams, in order, into ONE
// tree. Later layers overwrite earlier ones (the OCI apply order), which is why
// the applier is stateful: the limits and the stats are per-TREE, not per-layer.
//
// # Containment
//
// Every filesystem operation goes through an os.Root anchored at the tree, so no
// path this applier constructs can leave it even if the sanitizer below were
// wrong — the sanitizer and the anchor are independent controls and both must
// fail for an escape. On top of that:
//
//   - an entry NAME is refused outright if it is absolute or contains any ".."
//     component, so a traversal never even reaches the anchor;
//   - a SYMLINK's target is refused if it is absolute or resolves above the
//     tree, because os.Root deliberately does NOT validate a symlink target it
//     is asked to create, and because the tree is later CLONED into a pod rootfs
//     that has no chroot around it — an absolute link there resolves against the
//     host root;
//   - a HARD LINK's target must already exist in the tree as a regular file, so
//     a link can never alias a node the layer did not itself supply.
//
// # What it does NOT do
//
// It does not interpret OCI whiteouts, record ownership, or preserve xattrs or
// mtimes — those are the Linux dialect's (M11.2-d1), which extends this type
// under its own LayerSemantics. Under SemanticsNative a ".wh."-prefixed name is
// an ordinary file, and that is correct: nothing on the native path consumes it.
type LayerApplier struct {
	root   *os.Root
	policy UnpackPolicy
	limits ApplyLimits
	stats  ApplyStats
	// entries counts applied entries against limits.MaxEntries.
	entries int
}

// NewLayerApplier returns an applier writing into the tree anchored at root
// under policy, bounded by limits (the zero value means the defaults).
//
// root is BORROWED: the applier never closes it, because a caller that applies
// several layers into one tree owns the anchor's lifetime and a self-closing
// applier would make the second layer unrepresentable.
func NewLayerApplier(root *os.Root, policy UnpackPolicy, limits ApplyLimits) (*LayerApplier, error) {
	if root == nil {
		return nil, errors.New("layer applier: root is required")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	lim, err := limits.withDefaults()
	if err != nil {
		return nil, err
	}
	return &LayerApplier{root: root, policy: policy, limits: lim}, nil
}

// Stats returns the counts accumulated across every Apply so far.
func (a *LayerApplier) Stats() ApplyStats { return a.stats }

// Apply reads one DECOMPRESSED layer tar from r and applies it into the tree.
//
// ctx is honored between entries, so a cancelled pod create abandons a large
// layer promptly rather than at the end of it. A failed Apply leaves the tree
// PARTIALLY written by construction — the caller is responsible for staging the
// tree somewhere disposable and committing only on success (see Unpacker), and
// that division is deliberate: a rollback inside the applier would have to
// delete files it cannot prove it wrote.
func (a *LayerApplier) Apply(ctx context.Context, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// The tar stream is registry-supplied content, so archive/tar's
			// message (which formats offending header bytes into itself) is
			// quoted as bounded DATA, never adopted.
			return fmt.Errorf("%w: read entry: %v", ErrLayerMalformed, boundErr(err))
		}
		a.entries++
		if a.entries > a.limits.MaxEntries {
			return fmt.Errorf("layer exceeds %d entries: %w", a.limits.MaxEntries, ErrUnpackTooLarge)
		}
		if err := a.applyEntry(hdr, tr); err != nil {
			return err
		}
	}
}

// applyEntry applies one tar header (plus its content, for a regular file).
//
// The typeflag switch is a CLOSED set: an unrecognised type is refused rather
// than guessed at. Guessing is how an unpacker ends up materializing a GNU
// long-name or sparse-file extension as a real file at a name the archive never
// meant to write.
func (a *LayerApplier) applyEntry(hdr *tar.Header, content io.Reader) error {
	// PAX/GNU metadata entries carry no filesystem node. archive/tar folds their
	// contents into the FOLLOWING header for us, so they are skipped here rather
	// than run through the name sanitizer, whose grammar they do not satisfy
	// ("pax_global_header").
	switch hdr.Typeflag {
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return nil
	}

	name, err := layerEntryPath(hdr.Name)
	if err != nil {
		return err
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		return a.applyDir(name, hdr)
	case tar.TypeReg:
		return a.applyRegular(name, hdr, content)
	case tar.TypeSymlink:
		return a.applySymlink(name, hdr)
	case tar.TypeLink:
		return a.applyHardlink(name, hdr)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		// Skipped and COUNTED — an unprivileged daemon cannot mknod, and a
		// native pod reads none of these. See ApplyStats.SkippedSpecial.
		a.stats.SkippedSpecial++
		return nil
	default:
		return fmt.Errorf("%w: entry %s has unsupported tar type %q",
			ErrLayerMalformed, quoteBounded(hdr.Name, maxLayerEntryNameLen), string(hdr.Typeflag))
	}
}

// applyDir creates (or re-modes) a directory.
//
// An existing directory is kept and re-moded rather than replaced: replacing it
// would delete every earlier layer's contents under it, which is precisely the
// silent data loss OCI's "later layer wins" rule does NOT mean for directories.
func (a *LayerApplier) applyDir(name string, hdr *tar.Header) error {
	perm := a.entryPerm(hdr, 0o700)
	if fi, err := a.root.Lstat(name); err == nil {
		if !fi.IsDir() {
			// A later layer replacing a file with a directory: the file goes.
			if rerr := a.root.RemoveAll(name); rerr != nil {
				return fmt.Errorf("replace %s with a directory: %w", quoteBounded(name, maxLayerEntryNameLen), rerr)
			}
		} else {
			if cerr := a.root.Chmod(name, perm); cerr != nil {
				return fmt.Errorf("chmod dir %s: %w", quoteBounded(name, maxLayerEntryNameLen), cerr)
			}
			a.stats.Dirs++
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	if err := a.root.MkdirAll(name, perm); err != nil {
		return fmt.Errorf("mkdir %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	// MkdirAll only applies perm to components it CREATES, and it is umask-free
	// only for the leaf on some platforms; re-mode the leaf explicitly so the
	// applied mode is the header's, not the process umask's.
	if err := a.root.Chmod(name, perm); err != nil {
		return fmt.Errorf("chmod dir %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	a.stats.Dirs++
	return nil
}

// applyRegular writes a regular file, replacing whatever the earlier layers left
// at that name.
//
// The REMOVE-then-create-O_EXCL shape is load-bearing twice over: it implements
// "later layer wins" for a name an earlier layer wrote, and it means an existing
// SYMLINK at the name is unlinked rather than written THROUGH — the difference
// between replacing a link and clobbering whatever it points at.
func (a *LayerApplier) applyRegular(name string, hdr *tar.Header, content io.Reader) error {
	if hdr.Size < 0 {
		return fmt.Errorf("%w: entry %s declares negative size %d",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen), hdr.Size)
	}
	if err := a.ensureParent(name); err != nil {
		return err
	}
	if err := a.replace(name); err != nil {
		return err
	}
	perm := a.entryPerm(hdr, 0o600)
	f, err := a.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	remaining := a.limits.MaxBytes - a.stats.Bytes
	// LimitReader at remaining+1 so an overrun is DETECTED rather than silently
	// truncated into a short file that would then fail the layer's diffID check
	// with a misleading verdict.
	n, cerr := io.Copy(f, io.LimitReader(content, remaining+1))
	if closeErr := f.Close(); closeErr != nil && cerr == nil {
		cerr = closeErr
	}
	if cerr != nil {
		return fmt.Errorf("write %s: %w", quoteBounded(name, maxLayerEntryNameLen), boundErr(cerr))
	}
	if n > remaining {
		return fmt.Errorf("tree exceeds %d bytes at %s: %w",
			a.limits.MaxBytes, quoteBounded(name, maxLayerEntryNameLen), ErrUnpackTooLarge)
	}
	a.stats.Bytes += n
	a.stats.Files++
	// The QUARANTINE INVARIANT, asserted at the TREE rather than only at the pod
	// copy (clone.go's MaterializeTree asserts it on the destination). The tree
	// is what M8.2-d3's AdHocSignTree walks and what every pod rootfs is cloned
	// from, so a quarantined file here would be re-discovered once per pod
	// instead of once per image.
	return assertNoQuarantine(filepath.Join(a.root.Name(), name))
}

// applySymlink creates a symlink after proving its target stays inside the tree.
//
// os.Root.Symlink explicitly does NOT validate the target ("Symlink does not
// validate oldname, which may reference a location outside the root"), so the
// containment for this one operation is entirely this function's. It matters
// more here than anywhere else in the package: the tree is cloned verbatim into
// a pod rootfs by MaterializeTree, and the native spine puts no chroot around
// that rootfs, so a surviving "/etc/passwd" link would resolve against the HOST
// root the first time the pod followed it.
func (a *LayerApplier) applySymlink(name string, hdr *tar.Header) error {
	target := hdr.Linkname
	if err := symlinkTargetContained(name, target); err != nil {
		return err
	}
	if err := a.ensureParent(name); err != nil {
		return err
	}
	if err := a.replace(name); err != nil {
		return err
	}
	if err := a.root.Symlink(target, name); err != nil {
		return fmt.Errorf("symlink %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	a.stats.Symlinks++
	return nil
}

// applyHardlink creates a hard link to a target the tree ALREADY holds.
//
// The target must resolve inside the tree AND already exist there as a regular
// file. Both halves are required: the first stops a link from aliasing a host
// path, the second stops it from aliasing a node no layer supplied — a tar whose
// link target is created LATER (or never) would otherwise leave the tree holding
// a link to whatever ends up at that name.
func (a *LayerApplier) applyHardlink(name string, hdr *tar.Header) error {
	target, err := layerEntryPath(hdr.Linkname)
	if err != nil {
		return fmt.Errorf("hard link %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	fi, err := a.root.Lstat(target)
	if err != nil {
		return fmt.Errorf("%w: hard link %s targets %s, which the tree does not hold: %v",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen),
			quoteBounded(target, maxLayerEntryNameLen), boundErr(err))
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: hard link %s targets %s (mode %v), which is not a regular file",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen),
			quoteBounded(target, maxLayerEntryNameLen), fi.Mode().Type())
	}
	if err := a.ensureParent(name); err != nil {
		return err
	}
	if err := a.replace(name); err != nil {
		return err
	}
	if err := a.root.Link(target, name); err != nil {
		return fmt.Errorf("hard link %s -> %s: %w", quoteBounded(name, maxLayerEntryNameLen),
			quoteBounded(target, maxLayerEntryNameLen), err)
	}
	a.stats.Hardlinks++
	return nil
}

// ensureParent creates the entry's parent directories. A tar is not required to
// carry a directory entry before the files under it, so the parents are created
// on demand with owner-only perms; a later explicit directory entry re-modes
// them (applyDir).
func (a *LayerApplier) ensureParent(name string) error {
	dir := path.Dir(name)
	if dir == "." {
		return nil
	}
	if err := a.root.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	return nil
}

// replace unlinks whatever an earlier layer left at name, so the caller can
// create the node fresh. An absent name is not an error.
//
// RemoveAll (not Remove) because OCI permits a later layer to replace a
// populated DIRECTORY with a file. It is bounded by the os.Root anchor, so the
// recursive delete provably cannot reach outside the tree being built.
func (a *LayerApplier) replace(name string) error {
	if err := a.root.RemoveAll(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("replace %s: %w", quoteBounded(name, maxLayerEntryNameLen), err)
	}
	return nil
}

// entryPerm is the mode this applier writes for hdr, and it diverges from the
// tar header in two documented ways.
//
//   - setuid / setgid / sticky are ALWAYS STRIPPED (and counted). k3sm runs pods
//     at the daemon's own uid with no per-pod uid isolation (docs/privilege-model.md),
//     so a setuid bit surviving into a pod rootfs is a live escalation whenever the
//     daemon is root, and it buys nothing when it is not.
//   - the OWNER bits are always widened by ownerMin (0700 for a directory, 0600
//     for a file). An unprivileged daemon that cannot read back what it wrote can
//     neither clone the tree into a pod rootfs, nor sign it (M8.2-d3), nor
//     inventory it — and mode 0 entries are common in real layer tars. GROUP and
//     OTHER bits are never widened.
//
// The true recorded mode is therefore LOST on this path. That is acceptable
// because nothing on the native spine consumes it; the Linux dialect that does
// need it records it in M11.2-d1's ownership sidecar and re-applies it in-guest.
func (a *LayerApplier) entryPerm(hdr *tar.Header, ownerMin fs.FileMode) fs.FileMode {
	// hdr.Mode is the raw UNIX mode word, so setuid/setgid/sticky are 0o4000 /
	// 0o2000 / 0o1000 here — NOT Go's fs.ModeSetuid family, which lives in the
	// high bits of an fs.FileMode and would silently never match.
	if hdr.Mode&0o7000 != 0 {
		a.stats.StrippedSetIDs++
	}
	return fs.FileMode(hdr.Mode&0o777) | ownerMin
}

// layerEntryPath validates one tar entry name and returns it in the
// tree-relative, cleaned form every filesystem call in this file uses.
//
// It is the FIRST of the two independent containment controls (the os.Root
// anchor is the second), and it is deliberately stricter than path.Clean: a
// ".."-bearing name is REFUSED rather than cleaned away, because a cleaned name
// silently writes to a different file than the archive asked for, and a
// traversal attempt is exactly the event an operator needs to see.
func layerEntryPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty entry name", ErrLayerMalformed)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: entry name %s contains NUL",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
	}
	// Tar paths are slash-separated by specification, so path.IsAbs (not
	// filepath.IsAbs) is the right predicate: it asks the archive's question, not
	// the host filesystem's.
	if path.IsAbs(name) {
		return "", fmt.Errorf("%w: entry name %s is absolute",
			ErrLayerEscapes, quoteBounded(name, maxLayerEntryNameLen))
	}
	// Trim the "./" prefix and any trailing slash (a directory entry's
	// conventional spelling) BEFORE the component scan, so "./a/" and "a" are
	// one name — the same normalization tarEntryName does for archive lookups.
	trimmed := strings.TrimPrefix(name, "./")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" || trimmed == "." {
		return "", fmt.Errorf("%w: entry name %s names the tree root itself",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
	}
	for _, comp := range strings.Split(trimmed, "/") {
		switch comp {
		case "":
			return "", fmt.Errorf("%w: entry name %s has an empty path component",
				ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
		case ".":
			return "", fmt.Errorf("%w: entry name %s has a \".\" component",
				ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
		case "..":
			return "", fmt.Errorf("%w: entry name %s traverses upward",
				ErrLayerEscapes, quoteBounded(name, maxLayerEntryNameLen))
		}
	}
	return trimmed, nil
}

// symlinkTargetContained reports whether a symlink at the (already sanitized)
// tree-relative path name may point at target.
//
// The rule is the whole native dialect in one place: the target must be
// RELATIVE, and resolving it against the link's own directory must not leave the
// tree. Both conditions are checked on the STRING, before anything is created,
// because the link's target need not exist yet and so cannot be checked by
// stat'ing it.
//
// Containment composes: every link in the tree resolves to a path inside the
// tree, so a chain of links does too, and no chain can therefore reach outside.
func symlinkTargetContained(name, target string) error {
	if target == "" {
		return fmt.Errorf("%w: symlink %s has an empty target",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
	}
	if strings.ContainsRune(target, 0) {
		return fmt.Errorf("%w: symlink %s target contains NUL",
			ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
	}
	if path.IsAbs(target) {
		return fmt.Errorf("%w: symlink %s targets the absolute path %s",
			ErrLayerEscapes, quoteBounded(name, maxLayerEntryNameLen),
			quoteBounded(target, maxLayerEntryNameLen))
	}
	// path.Join cleans, so an escape shows up as a leading "..". Both operands
	// are relative, so the result is relative too.
	resolved := path.Join(path.Dir(name), target)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("%w: symlink %s targets %s, which resolves to %s",
			ErrLayerEscapes, quoteBounded(name, maxLayerEntryNameLen),
			quoteBounded(target, maxLayerEntryNameLen), quoteBounded(resolved, maxLayerEntryNameLen))
	}
	return nil
}
