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

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/guestinit"
)

// stageOwnershipSidecars copies each rootfs tree's ownership sidecar into the
// pod's k3sm.spec share root, beside guest-spec.json, under the name the guest
// derives from the container's rootfs tag (guestinit.OwnershipSidecarName).
//
// That is the whole host/guest handoff, and it needs no guest/v1 field: the
// share and its tag already exist, and the name is a convention both sides
// import from pkg/guestinit, like guestinit.SpecShareTag itself. The sidecar is
// staged in the SPEC share and never in the rootfs share, whose namespace is the
// image's — an image could ship a file at any name chosen there.
//
// One sidecar per TAG: several containers can name one rootfs share. The loop
// keeps the first non-empty path it meets in slice order, and that is correct
// only because of the single-rootfs ceiling — exactly one container
// materializes a tree into a share (pkg/runtime resolveVMContainers), so at
// most one path per tag is non-empty and there is nothing to choose between.
// Per-container rootfs shares keep that true by giving each tree its own tag.
// A tag with no sidecar has any stale copy
// from an earlier boot of this pod dir removed, so a guest never applies a
// sidecar describing a tree it is no longer given.
//
// It runs after writeVMHostSpec has created (and symlink-checked) the share
// root and before the helper is spawned, so no guest exists while it writes and
// the guest that does exist holds the share read-only at the VZ device. The copy
// is a byte copy: the file is O(entries), a few MiB for a large base image.
func stageOwnershipSidecars(podDir string, containers []VMContainer) error {
	specRoot := filepath.Join(podDir, guestinit.SpecShareTag)
	sources := map[string]string{} // rootfs tag -> sidecar source
	var tags []string
	for _, c := range containers {
		if _, seen := sources[c.RootfsTag]; !seen {
			tags = append(tags, c.RootfsTag)
			sources[c.RootfsTag] = ""
		}
		if sources[c.RootfsTag] == "" {
			sources[c.RootfsTag] = c.OwnershipPath
		}
	}
	for _, tag := range tags {
		name := guestinit.OwnershipSidecarName(tag)
		if strings.ContainsAny(name, `/\`) || tag == "" || tag == "." || tag == ".." {
			return fmt.Errorf("%w: rootfs tag %q cannot name an ownership sidecar", ErrInvalidGuestSpec, tag)
		}
		dst := filepath.Join(specRoot, name)
		src := sources[tag]
		if src == "" {
			if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("clear a stale ownership sidecar %s: %w", dst, err)
			}
			continue
		}
		if err := copySealed(src, dst); err != nil {
			return fmt.Errorf("stage the ownership sidecar for rootfs %s: %w", tag, err)
		}
	}
	return nil
}

// copySealed copies src to dst atomically (temp + rename) and leaves it 0444.
// The temp name is fixed, so it is opened O_EXCL|O_NOFOLLOW after clearing a
// stale REGULAR leftover — the writeVMHostSpec posture: a pre-planted link is
// refused by the open rather than followed.
func copySealed(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }() // read-only; nothing to flush

	tmp := dst + ".tmp"
	if fi, lerr := os.Lstat(tmp); lerr == nil && fi.Mode().IsRegular() {
		if rerr := os.Remove(tmp); rerr != nil {
			return fmt.Errorf("clear stale %s: %w", tmp, rerr)
		}
	}
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy %s: %w", src, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("seal %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit %s: %w", dst, err)
	}
	return nil
}
