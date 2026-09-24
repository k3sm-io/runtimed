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

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/guestinit"
)

// applyOwnership interprets one container's OwnershipStep: it streams the
// sidecar into the overlay at st.Root through guestinit.ApplyOwnership, whose
// per-entry order and error tolerance are tested on darwin.
//
// A setuid/setgid bit it restores is INERT at exec today: ContainerRootDir is
// mounted nosuid (guestinit.RootfsMounts), a second barrier independent of the
// chown-before-chmod ordering.
//
// It NEVER fails the boot. A missing sidecar is a clean no-op (a host that
// staged none); an unreadable one, or entries that fail, are logged with a
// bounded summary and the container starts on the host-written ownership —
// exactly the state every vm pod booted in before this step existed. Refusing
// the pod over one bad entry of a six-figure sidecar would trade a narrow
// ownership error for a pod that cannot run at all.
//
// Only the first container image's tree is materialized into the pod-wide
// rootfs share today (pkg/runtime vmRootfsShareTag, vmcontainers.go:186-202),
// so every container sharing that tag applies that one tree's sidecar to its
// own overlay — correct for the tree it sees, and the same named ceiling.
func applyOwnership(ctx context.Context, log *slog.Logger, container string, st *guestinit.OwnershipStep) {
	f, err := os.Open(st.Sidecar)
	if errors.Is(err, fs.ErrNotExist) {
		log.Info("no ownership sidecar staged; the rootfs keeps the host-written ownership",
			"container", container, "sidecar", st.Sidecar)
		return
	}
	if err != nil {
		log.Warn("could not open the ownership sidecar; the rootfs keeps the host-written ownership",
			"container", container, "sidecar", st.Sidecar, "err", err)
		return
	}
	defer func() { _ = f.Close() }() // read-only; nothing to flush

	rootFD, err := unix.Open(st.Root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		log.Warn("could not open the container rootfs for the ownership apply",
			"container", container, "root", st.Root, "err", err)
		return
	}
	defer func() { _ = unix.Close(rootFD) }()

	rep, err := guestinit.ApplyOwnership(ctx, f, ownershipRoot{fd: rootFD})
	switch {
	case err != nil:
		log.Warn("ownership apply stopped early", "container", container,
			"sidecar", st.Sidecar, "err", err, "report", rep.Summary())
	case rep.Failed > 0:
		log.Warn("ownership apply finished with failed entries", "container", container,
			"sidecar", st.Sidecar, "report", rep.Summary())
	default:
		log.Info("applied the ownership sidecar", "container", container,
			"sidecar", st.Sidecar, "entries", rep.Applied)
	}
}

// ownershipRoot is guestinit.OwnershipTarget over a directory descriptor.
//
// Every path is resolved by openat2 with RESOLVE_IN_ROOT: the image decides
// what is a symlink inside its rootfs, and an ABSOLUTE symlink in an
// intermediate component (/var/run -> /run is in nearly every base image) must
// resolve against the container's root, never the guest's. The final component
// is opened O_PATH|O_NOFOLLOW, so a symlink entry is the link itself.
type ownershipRoot struct{ fd int }

// Open implements guestinit.OwnershipTarget.
func (r ownershipRoot) Open(rel string, kind guestinit.OwnershipKind) (guestinit.OwnershipNode, error) {
	fd, err := unix.Openat2(r.fd, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if !kindMatches(st.Mode&unix.S_IFMT, kind) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("node is mode %o, not a %s", st.Mode&unix.S_IFMT, kind)
	}
	return ownershipNode{fd: fd}, nil
}

// kindMatches reports whether a node's S_IFMT is the kind the sidecar recorded.
// "file" is anything that is neither a directory nor a symlink: the host
// records a hard link as a file, and the unpacker creates no other kind.
func kindMatches(ifmt uint32, kind guestinit.OwnershipKind) bool {
	switch kind {
	case guestinit.OwnershipDir:
		return ifmt == unix.S_IFDIR
	case guestinit.OwnershipSymlink:
		return ifmt == unix.S_IFLNK
	case guestinit.OwnershipFile:
		return ifmt != unix.S_IFDIR && ifmt != unix.S_IFLNK
	}
	return false
}

// ownershipNode is one O_PATH descriptor. chmod and setxattr go through the
// descriptor's /proc/self/fd magic link — the kernel's way to reach an O_PATH
// node by path without re-resolving the name — because fchmod and fsetxattr
// refuse an O_PATH descriptor. Open has already refused a symlink for them
// (guestinit.ApplyOwnership never chmods one), so following the magic link
// reaches exactly the node that was checked.
type ownershipNode struct{ fd int }

func (n ownershipNode) procPath() string { return "/proc/self/fd/" + strconv.Itoa(n.fd) }

// Chown implements guestinit.OwnershipNode; AT_EMPTY_PATH acts on the node
// itself, so a symlink is chowned as a link.
func (n ownershipNode) Chown(uid, gid int64) error {
	return unix.Fchownat(n.fd, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// Chmod implements guestinit.OwnershipNode.
func (n ownershipNode) Chmod(mode uint32) error {
	return unix.Fchmodat(unix.AT_FDCWD, n.procPath(), mode, 0)
}

// Setxattr implements guestinit.OwnershipNode.
func (n ownershipNode) Setxattr(name string, value []byte) error {
	return unix.Setxattr(n.procPath(), name, value, 0)
}

// Close implements guestinit.OwnershipNode.
func (n ownershipNode) Close() error { return unix.Close(n.fd) }
