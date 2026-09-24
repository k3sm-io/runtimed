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

package guestinit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strings"
)

// the OWNERSHIP SIDECAR, guest half.
//
// runtimed unpacks a Linux image's layers on the host as an unprivileged
// process, so the tree a vm pod's rootfs share exports carries the daemon's own
// uid and a setuid-stripped mode. The TRUTH — the tar headers' uid, gid and full
// mode — travels beside the tree as a newline-delimited JSON sidecar
// (pkg/image.OwnershipEntry), and this file is the guest's end of it: the plan
// step that says where the sidecar is and which rootfs it belongs to
// (OwnershipStep), and the streaming apply that interprets it (ApplyOwnership).
//
// # How the file crosses without a guest/v1 field
//
// The host stages the sidecar into the k3sm.spec share, beside guest-spec.json,
// under a name DERIVED from the container's rootfs tag (OwnershipSidecarName).
// That is the SpecShareTag precedent exactly: a host/guest convention both sides
// import from this package rather than a spec field, so a disagreement fails to
// compile rather than to boot. It is never placed inside the rootfs share
// itself, whose namespace belongs to the image — an image could ship a file at
// any name chosen there.
//
// # The recorded ceiling it inherits
//
// The host's share plan carries ONE rootfs share for the whole pod, so only the
// first container's image is materialized into it and only that tree's sidecar
// exists (pkg/runtime vmRootfsShareTag, vmcontainers.go:186-202). Every
// container naming that tag gets the same sidecar applied to its own overlay —
// which is correct for the tree it actually sees. Per-container rootfs shares
// lift the ceiling with no change here: the sidecar name is keyed by the tag.

// OwnershipSidecarSuffix is appended to a container's rootfs tag to name its
// ownership sidecar in the k3sm.spec share.
const OwnershipSidecarSuffix = ".ownership.jsonl"

// OwnershipSidecarName is the basename of the ownership sidecar for the rootfs
// share tagged rootfsTag, as it appears in the k3sm.spec share root on the host
// and under SpecMountPoint in the guest.
func OwnershipSidecarName(rootfsTag string) string { return rootfsTag + OwnershipSidecarSuffix }

// OwnershipStep applies an ownership sidecar to one container's composed rootfs.
//
// It carries the sidecar's PATH, never its decoded entries: an unpacked base
// image is routinely six figures of entries, and the JSONL format exists so the
// guest can apply it streaming, in constant memory (pkg/image
// writeOwnershipSidecar).
type OwnershipStep struct {
	// Sidecar is the guest path of the JSONL file, under SpecMountPoint.
	Sidecar string

	// Root is the container's composed rootfs (ContainerRootDir): the OVERLAY,
	// never the lower. The lower is a read-only virtiofs share, and the overlay
	// is mounted metacopy=on, so a chown or chmod there copies up metadata only.
	Root string

	// AfterMount is the number of ContainerPlan.Mounts steps applied BEFORE
	// this one: exactly the rootfs composition (RootfsMounts). It runs after
	// the overlay exists and before anything is mounted inside it — /dev, the
	// kernel filesystems, the pod mounts, the /etc binds — so an entry naming
	// one of those paths reaches the image's own node, never a pod volume or a
	// read-only credential bind stacked over it. The container starts after
	// every mount, so the step is also always before the start.
	AfterMount int

	// Why is the boot-log rationale.
	Why string
}

// ownershipStep plans the sidecar apply for one container, or returns nil when
// the spec share carries no sidecar for its rootfs tag (an older host, or a
// dialect that records none). present is the set of basenames in the spec share.
func ownershipStep(name, rootfsTag string, present map[string]bool, afterMount int) *OwnershipStep {
	sidecar := OwnershipSidecarName(rootfsTag)
	// The name must be ONE path element: the tag crosses the host/guest
	// boundary, and a tag carrying a separator would compose a path outside
	// SpecMountPoint. A real directory listing could not match such a name,
	// but the plan does not lean on its caller for that.
	if strings.ContainsRune(sidecar, '/') || !present[sidecar] {
		return nil
	}
	return &OwnershipStep{
		Sidecar:    path.Join(SpecMountPoint, sidecar),
		Root:       ContainerRootDir(name),
		AfterMount: afterMount,
		Why:        "restore the image's uid/gid/mode the unprivileged host could not write",
	}
}

// OwnershipKind is the node kind an OwnershipRecord describes. The values are
// pkg/image.OwnershipEntryType's, restated because this package is linked into
// the guest init and must not import the host's image stack; a test pins the two.
type OwnershipKind string

// The closed OwnershipKind set.
const (
	OwnershipDir     OwnershipKind = "dir"
	OwnershipFile    OwnershipKind = "file"
	OwnershipSymlink OwnershipKind = "symlink"
)

// OwnershipRecord is one decoded sidecar line — the guest's reading of
// pkg/image.OwnershipEntry, field for field.
type OwnershipRecord struct {
	Path   string            `json:"path"`
	Type   OwnershipKind     `json:"type"`
	UID    int64             `json:"uid"`
	GID    int64             `json:"gid"`
	Mode   uint32            `json:"mode"`
	Xattrs map[string][]byte `json:"xattrs,omitempty"`
}

// OwnershipNode is one opened node of the rootfs the sidecar is applied to.
type OwnershipNode interface {
	Chown(uid, gid int64) error
	Chmod(mode uint32) error
	Setxattr(name string, value []byte) error
	io.Closer
}

// OwnershipTarget opens a sidecar path inside the rootfs being restored. The
// implementation must resolve rel with chroot semantics (the image decides what
// is a symlink), must not follow a final-component symlink, and must refuse a
// node whose kind is not kind.
type OwnershipTarget interface {
	Open(rel string, kind OwnershipKind) (OwnershipNode, error)
}

// MaxOwnershipErrors bounds how many per-entry errors an OwnershipReport keeps.
// The count is exact; only the detail is capped, so a pathological sidecar
// cannot turn the boot log into the failure.
const MaxOwnershipErrors = 8

// maxOwnershipLine bounds one sidecar line. An over-long line is one failed
// entry, skipped to its newline, never a reason to buffer without limit.
const maxOwnershipLine = 256 << 10

// OwnershipReport is the outcome of one ApplyOwnership.
type OwnershipReport struct {
	// Applied counts entries whose every call succeeded.
	Applied int
	// Failed counts entries with at least one failed call, plus undecodable
	// or over-long lines.
	Failed int
	// Errors are the first MaxOwnershipErrors failures, each naming its line.
	Errors []string
}

func (r *OwnershipReport) fail(line int, format string, args ...any) {
	r.Failed++
	if len(r.Errors) < MaxOwnershipErrors {
		r.Errors = append(r.Errors, fmt.Sprintf("line %d: ", line)+fmt.Sprintf(format, args...))
	}
}

// Summary renders the report as one boot-log line.
func (r OwnershipReport) Summary() string {
	s := fmt.Sprintf("applied=%d failed=%d", r.Applied, r.Failed)
	if len(r.Errors) > 0 {
		s += " first_errors=[" + strings.Join(r.Errors, "; ") + "]"
	}
	return s
}

// ApplyOwnership streams an ownership sidecar from r and applies each entry to
// target, in constant memory.
//
// Per entry the order is chown -> chmod -> setxattr (pkg/image linuxlayer.go's
// documented order, and not stylistic: chown(2) clears setuid/setgid, and a
// security.* xattr is dropped by a later chown). A symlink takes chown only —
// Linux ignores a symlink's mode. A failed chown skips the rest of that entry:
// applying a setuid mode to a file still owned by the wrong uid would grant
// setuid to an identity the image never named.
//
// One bad entry never stops the walk: it is counted, its detail kept up to
// MaxOwnershipErrors, and the next line is applied. The returned error is only
// a READ failure of r or ctx's cancellation; the report is valid either way.
func ApplyOwnership(ctx context.Context, r io.Reader, target OwnershipTarget) (OwnershipReport, error) {
	var rep OwnershipReport
	br := bufio.NewReaderSize(r, maxOwnershipLine)
	for line := 1; ; line++ {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		raw, overlong, err := readOwnershipLine(br)
		if len(bytes.TrimSpace(raw)) > 0 || overlong {
			applyOwnershipLine(line, raw, overlong, target, &rep)
		}
		if errors.Is(err, io.EOF) {
			return rep, nil
		}
		if err != nil {
			return rep, fmt.Errorf("read ownership sidecar at line %d: %w", line, err)
		}
	}
}

// readOwnershipLine returns the next line without its newline. A line longer
// than the reader's buffer is consumed to its newline and reported overlong,
// with no bytes returned.
func readOwnershipLine(br *bufio.Reader) ([]byte, bool, error) {
	raw, err := br.ReadSlice('\n')
	if !errors.Is(err, bufio.ErrBufferFull) {
		return bytes.TrimSuffix(raw, []byte("\n")), false, err
	}
	for errors.Is(err, bufio.ErrBufferFull) {
		_, err = br.ReadSlice('\n')
	}
	return nil, true, err
}

// applyOwnershipLine decodes and applies one line, recording its outcome.
func applyOwnershipLine(line int, raw []byte, overlong bool, target OwnershipTarget, rep *OwnershipReport) {
	if overlong {
		rep.fail(line, "entry exceeds %d bytes", maxOwnershipLine)
		return
	}
	var rec OwnershipRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		rep.fail(line, "decode: %v", err)
		return
	}
	if err := validOwnershipRecord(rec); err != nil {
		rep.fail(line, "%v", err)
		return
	}
	node, err := target.Open(rec.Path, rec.Type)
	if err != nil {
		rep.fail(line, "open %q: %v", rec.Path, err)
		return
	}
	defer func() { _ = node.Close() }() // an O_PATH descriptor; nothing to flush
	if err := node.Chown(rec.UID, rec.GID); err != nil {
		rep.fail(line, "chown %q: %v", rec.Path, err)
		return
	}
	if rec.Type != OwnershipSymlink {
		if err := node.Chmod(rec.Mode & 0o7777); err != nil {
			rep.fail(line, "chmod %q: %v", rec.Path, err)
			return
		}
	}
	for _, name := range sortedXattrNames(rec.Xattrs) {
		if rec.Type == OwnershipSymlink {
			rep.fail(line, "xattr %q on symlink %q is not applied", name, rec.Path)
			return
		}
		if err := node.Setxattr(name, rec.Xattrs[name]); err != nil {
			rep.fail(line, "setxattr %q on %q: %v", name, rec.Path, err)
			return
		}
	}
	rep.Applied++
}

// validOwnershipRecord rejects a record whose path could leave the rootfs or
// whose kind or ids the apply has no call for.
func validOwnershipRecord(rec OwnershipRecord) error {
	p := rec.Path
	switch {
	case p == "" || strings.HasPrefix(p, "/"):
		return fmt.Errorf("path %q is not tree-relative", p)
	case path.Clean(p) != p:
		return fmt.Errorf("path %q is not clean", p)
	case p == ".." || strings.HasPrefix(p, "../"):
		return fmt.Errorf("path %q escapes the tree", p)
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("path %q contains NUL", p)
	}
	switch rec.Type {
	case OwnershipDir, OwnershipFile, OwnershipSymlink:
	default:
		return fmt.Errorf("path %q has unknown type %q", p, rec.Type)
	}
	// maxID itself is (uid_t)-1, which chown(2) reads as "leave unchanged".
	if rec.UID < 0 || rec.GID < 0 || rec.UID >= maxID || rec.GID >= maxID {
		return fmt.Errorf("path %q has out-of-range owner %d:%d", p, rec.UID, rec.GID)
	}
	return nil
}

// sortedXattrNames returns m's keys in a stable order.
func sortedXattrNames(m map[string][]byte) []string {
	if len(m) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(m))
}
