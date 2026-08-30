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
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// SemanticsLinux is the LINUX layer dialect: an OCI image whose payload is ELF
// and runs inside a micro-VM guest that CHROOTS (or pivot_roots) into the
// materialized rootfs.
//
// Everything this dialect does differently from SemanticsNative follows from
// that one fact — there IS a root, and it is the tree:
//
//   - OCI WHITEOUTS are interpreted. A ".wh.<name>" entry DELETES <name> from the
//     lower layers instead of being written as a file, and ".wh..wh..opq" makes
//     its containing directory opaque. Under the native dialect the same bytes
//     are ordinary files, which is why the two dialects must never share a tree
//     (they key differently — see UnpackPolicy).
//   - an ABSOLUTE SYMLINK is ADMITTED, because it resolves against the guest's
//     root, which is this tree. The native dialect refuses one for the exactly
//     opposite reason: no chroot stands between a native pod and the host root,
//     so "/etc/passwd" there names the HOST's file.
//   - the true tar OWNERSHIP (uid/gid/mode, including setuid) is recorded in an
//     ownership SIDECAR rather than applied, because an unprivileged daemon
//     cannot chown and a host-side setuid bit is a live escalation
//     (docs/privilege-model.md). The guest re-applies it — see OwnershipEntry.
//   - two entries whose paths differ only by CASE or by Unicode NORMALIZATION
//     are refused (ErrPathCollision): they are distinct files to Linux and one
//     file to a case-insensitive APFS volume.
//
// Adding this constant is HALF of adding a dialect; the other half is the case
// in LayerApplier.applyEntry and in UnpackPolicy.Validate. Both fail closed on
// an unknown value, so a dialect can never be half-added.
const SemanticsLinux LayerSemantics = "linux"

// LinuxUnpackPolicy is the policy for the vm (Linux-guest) spine.
func LinuxUnpackPolicy() UnpackPolicy { return UnpackPolicy{Semantics: SemanticsLinux} }

// ErrPathCollision reports that a Linux layer names two DISTINCT paths that a
// case-insensitive (or normalization-insensitive) filesystem would merge into
// one file.
//
// It is FAIL-CLOSED and fatal to the whole unpack — never a per-entry skip, and
// never a silent merge — because the two outcomes of a merge are both
// unacceptable: the later entry's content silently replaces the earlier one's
// under a name the image never wrote, and the resulting tree is then committed
// under a ChainID that claims to be the image. The design puts the
// snapshot store on a dedicated case-sensitive APFS volume so this condition
// should be unreachable in production; this check is the defense in depth that
// makes a mis-provisioned volume LOUD instead of silently lossy.
var ErrPathCollision = errors.New("image: linux layer paths collide on a case-insensitive filesystem")

// OCI/AUFS whiteout markers, as specified by the OCI image-spec ("Applying
// Changesets") and as produced by every builder that writes an OCI layer.
const (
	// whiteoutPrefix marks a deletion: a ".wh.<name>" entry in directory d
	// deletes d/<name> as contributed by the LOWER layers.
	whiteoutPrefix = ".wh."
	// whiteoutOpaqueDir marks its containing directory OPAQUE: everything the
	// lower layers put in it disappears, and only what THIS layer put there
	// remains.
	whiteoutOpaqueDir = ".wh..wh..opq"
	// whiteoutMetaPrefix marks AUFS bookkeeping entries (".wh..wh.plnk",
	// ".wh..wh.orph", ...). They describe the builder's own scratch state, name
	// no tree node, and are skipped and counted. whiteoutOpaqueDir shares this
	// prefix and is therefore matched FIRST.
	whiteoutMetaPrefix = ".wh..wh."
)

// whiteoutKind classifies one already-sanitized entry path as a whiteout marker.
type whiteoutKind int

const (
	// whiteoutNone means the entry is an ordinary tree node.
	whiteoutNone whiteoutKind = iota
	// whiteoutFile means "delete the named sibling".
	whiteoutFile
	// whiteoutOpaque means "the containing directory is opaque".
	whiteoutOpaque
	// whiteoutMeta means an AUFS bookkeeping entry to skip.
	whiteoutMeta
)

// classifyWhiteout reports what kind of whiteout marker name is, and — for
// whiteoutFile — the tree-relative path it deletes.
//
// name MUST already have passed layerEntryPath, so it is relative, cleaned, and
// free of ".." components; the returned target is therefore inside the tree by
// construction and never needs a second containment proof.
//
// The order of the tests is load-bearing: whiteoutOpaqueDir begins with
// whiteoutMetaPrefix, which begins with whiteoutPrefix, so a prefix test taken
// in the wrong order would classify an opaque marker as a plain deletion of the
// file ".wh..opq".
func classifyWhiteout(name string) (whiteoutKind, string, error) {
	base := path.Base(name)
	switch {
	case base == whiteoutOpaqueDir:
		return whiteoutOpaque, "", nil
	case strings.HasPrefix(base, whiteoutMetaPrefix):
		return whiteoutMeta, "", nil
	case strings.HasPrefix(base, whiteoutPrefix):
		target := strings.TrimPrefix(base, whiteoutPrefix)
		// A marker naming nothing, ".", or ".." is MALFORMED, not a deletion:
		// ".wh." alone names no sibling and ".wh..", after the opaque and meta
		// tests above, could only mean "delete the parent directory", which the
		// spec has no spelling for. Guessing either way would delete a node the
		// archive never named.
		if target == "" || target == "." || target == ".." {
			return whiteoutNone, "", fmt.Errorf("%w: whiteout entry %s names no sibling",
				ErrLayerMalformed, quoteBounded(name, maxLayerEntryNameLen))
		}
		dir := path.Dir(name)
		if dir == "." {
			return whiteoutFile, target, nil
		}
		return whiteoutFile, dir + "/" + target, nil
	default:
		return whiteoutNone, "", nil
	}
}

// foldKey renders a tree-relative path in the form a case-insensitive,
// normalization-insensitive APFS volume compares by, so two paths that would
// land on ONE file share a key.
//
// It composes the two independent insensitivities this host actually exhibits
// (both measured on an APFS boot volume): NFC normalization first, so a
// decomposed "café" and a precomposed "café" agree, then Unicode simple
// case folding via strings.ToLower.
//
// It is deliberately an OVER-approximation of what APFS merges. A false
// collision REFUSES a legitimate image, which is visible and fixable; a missed
// one silently merges two files, which is neither. The residual gap is that
// strings.ToLower is SIMPLE case folding, so a pair that full folding equates
// but simple folding does not (the classic "ß"/"SS") is not detected — APFS does
// not merge that pair either, so the gap is not known to be reachable.
func foldKey(p string) string {
	return strings.ToLower(norm.NFC.String(p))
}

// OwnershipEntryType names the kind of node an OwnershipEntry describes. The
// guest needs it because the apply differs: a symlink takes lchown and NO chmod
// (Linux ignores a symlink's mode bits), everything else takes chown then chmod.
type OwnershipEntryType string

// The closed OwnershipEntryType set. A hard link is recorded as
// OwnershipTypeFile because it IS a second name for a regular file: chowning
// both names is idempotent, and recording it as its own kind would invite a
// guest to treat the second apply as a conflict.
const (
	OwnershipTypeDir     OwnershipEntryType = "dir"
	OwnershipTypeFile    OwnershipEntryType = "file"
	OwnershipTypeSymlink OwnershipEntryType = "symlink"
)

// OwnershipEntry is one line of the ownership sidecar: what the LAYER TAR said
// about a path, as opposed to what the unprivileged host was able to write.
//
// # Why a sidecar at all
//
// runtimed runs unprivileged wherever it can (docs/privilege-model.md), so it
// cannot chown; and even as root it must not write a setuid bit into a tree that
// is cloned into every pod rootfs, because k3sm has no per-pod uid isolation on
// the native spine. The host tree therefore carries the daemon's own ownership
// and a setuid-stripped mode, and the TRUTH travels beside it in this record for
// the guest — which does have a root and a private mount namespace — to apply.
//
// # The apply order the guest MUST use
//
// chown → chmod → setxattr, in that order, and the order is not stylistic:
// chown(2) CLEARS the setuid and setgid bits on most Linux filesystems, so a
// chmod before the chown would be silently undone; and setxattr of a
// "security.*" attribute is likewise dropped by a subsequent chown, so it goes
// last.
type OwnershipEntry struct {
	// Path is the tree-relative path, slash-separated, exactly as the sanitized
	// tar entry named it.
	Path string `json:"path"`
	// Type selects the guest's apply calls (see OwnershipEntryType).
	Type OwnershipEntryType `json:"type"`
	// UID and GID are the tar header's numeric owner. Names (Uname/Gname) are
	// deliberately NOT recorded: resolving a name requires the image's own
	// /etc/passwd, which is a file inside this very tree, so resolution belongs
	// in the guest and a host-side guess would be wrong for every image that
	// ships its own users.
	UID int64 `json:"uid"`
	GID int64 `json:"gid"`
	// Mode is the tar header's permission word masked to 0o7777 — the FULL
	// mode, setuid/setgid/sticky INCLUDED. This is the field the host copy
	// cannot carry (see LayerApplier.entryPerm), and it is why the sidecar
	// exists at all.
	Mode uint32 `json:"mode"`
	// Xattrs are the PAX extended attributes the xattr allowlist admitted,
	// keyed by attribute name. It is EMPTY in every tree this build produces —
	// see xattrAllowlist for the allowlist, and for the documented consequence
	// (security.capability file capabilities are dropped).
	Xattrs map[string][]byte `json:"xattrs,omitempty"`
}

// xattrAllowlist is the CLOSED set of PAX extended attributes carried from a
// layer tar into the ownership sidecar. It is EMPTY, and the emptiness is the
// decision, not an omission.
//
// The consequence, stated where a reader meets it: an image that relies on
// file capabilities — "security.capability", as set by setcap(8), the modern
// replacement for a setuid root binary in ping, dumpcap, and similar — loses
// them. Such an image FAILS VISIBLY IN-GUEST (the binary runs and gets EPERM on
// the operation the capability authorized) rather than silently running with
// more or less privilege than its author intended.
//
// Admitting one is a two-line change — add the name here and a case to the
// guest's setxattr step — but it is deliberately not taken on speculation,
// because "security.capability" is a PRIVILEGE GRANT expressed as file content:
// honouring it means a registry-supplied byte string decides what a guest
// process may do, and that is a trust decision for a human, not a default.
//
// If this set ever becomes CONFIGURABLE it must join UnpackPolicy as a
// comparable field and be rendered by UnpackPolicy.canonical(). It is a package
// constant with no setter today, so it cannot vary between two trees in one
// build and therefore cannot make two trees collide on one key.
var xattrAllowlist = map[string]bool{}

// selectXattrs partitions a tar header's PAX records into the allowlisted
// extended attributes (returned) and the count of dropped ones.
//
// archive/tar surfaces extended attributes under the "SCHILY.xattr." PAX prefix
// (the de-facto encoding every OCI builder emits). Records outside that prefix
// are tar metadata — mtime, atime, path, size — not extended attributes, and are
// neither carried nor counted as dropped.
func selectXattrs(pax map[string]string) (map[string][]byte, int) {
	const paxSchilyXattr = "SCHILY.xattr."
	var kept map[string][]byte
	dropped := 0
	for k, v := range pax {
		name, ok := strings.CutPrefix(k, paxSchilyXattr)
		if !ok {
			continue
		}
		if !xattrAllowlist[name] {
			dropped++
			continue
		}
		if kept == nil {
			kept = make(map[string][]byte, 1)
		}
		kept[name] = []byte(v)
	}
	return kept, dropped
}

// sortOwnership orders the sidecar by path so the committed bytes are a function
// of the image's content alone — two unpacks of one chain produce one file.
//
// Byte order on a slash-separated path also happens to put every parent before
// its children ('/' is 0x2F, below every character a path component may end
// with), so a guest that applies the file top to bottom never touches a path
// whose parent it has not seen.
func sortOwnership(entries []OwnershipEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}
