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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// ErrUserDatabase reports that a container's /etc/passwd or /etc/group could
// not be read safely: it is not a regular file, it is too large, it is a
// symlink that dangles or leaves the container root, or the read failed for a
// reason other than the file being absent. Compare with errors.Is.
var ErrUserDatabase = errors.New("cannot read the container's user database")

// maxUserDatabaseBytes caps how much of /etc/passwd or /etc/group is read. Both
// files come from the image, so their size is the image author's choice; a cap
// turns a hostile multi-gigabyte file into a refusal instead of a guest OOM.
const maxUserDatabaseBytes int64 = 1 << 20

// splitImageUser checks the GuestContainer.image_user grammar,
// <user>[:<group>], and returns its two halves. More than two segments, an
// empty segment, or a control character is ErrInvalidSpec.
func splitImageUser(imageUser string) (user, group string, err error) {
	if imageUser == "" {
		return "", "", fmt.Errorf("%w: empty image user", ErrInvalidSpec)
	}
	if strings.ContainsAny(imageUser, "\x00\n\r") {
		return "", "", fmt.Errorf("%w: image user %q contains a control character", ErrInvalidSpec, imageUser)
	}
	if strings.Count(imageUser, ":") > 1 {
		return "", "", fmt.Errorf("%w: image user %q has more than two colon-separated segments", ErrInvalidSpec, imageUser)
	}
	user, group, hasGroup := strings.Cut(imageUser, ":")
	if user == "" {
		return "", "", fmt.Errorf("%w: image user %q has an empty user part", ErrInvalidSpec, imageUser)
	}
	if hasGroup && group == "" {
		return "", "", fmt.Errorf("%w: image user %q has an empty group part", ErrInvalidSpec, imageUser)
	}
	return user, group, nil
}

// ResolveImageUser resolves a GuestContainer.image_user against the container's
// own composed rootfs and returns the identity the container runs as.
//
// # What wins
//
// The resolved uid and gid replace whatever the host stamped: image_user takes
// precedence by the guest/v1 contract. supplemental is carried over unchanged
// (it is the host's supplemental_gids plus the pod's fsGroup), because the pod's
// group grants do not come from the image.
//
// # Resolution rules (ResolveUser's)
//
//   - A numeric user is used as given and never needs to resolve, so a scratch
//     image with USER 1000 and no /etc/passwd runs. With no group half its gid
//     is the gid of the passwd entry for that uid when one exists, else 0 —
//     containerd's WithUserID behaviour.
//   - A name must be present in /etc/passwd. A missing name is ErrNoSuchUser:
//     it never falls back to uid 0, because that would run the container as a
//     more privileged identity than the image asked for.
//   - A group half overrides the gid: numeric as given, a name via /etc/group.
//
// # Reading the image's files
//
// /etc/passwd and /etc/group are resolved with CHROOT SEMANTICS inside rootfs
// (the walk ResolveTarget uses), so an absolute symlink is container-absolute
// and a relative one that climbs out is refused; nothing outside rootfs is ever
// opened. Only a regular file is read, opened non-blocking and capped at
// maxUserDatabaseBytes, so a FIFO cannot hang PID 1 and a device cannot feed it
// forever. A file that does not exist reads as empty (a scratch image has
// neither), which is an error only if a name then has to be looked up in it; a
// symlink that dangles, or any other failure, is ErrUserDatabase. /etc/group is
// read only when a group name needs it; /etc/passwd whenever a name, or a
// numeric user's default gid, needs it.
func ResolveImageUser(rootfs, imageUser string, supplemental []int64) (Ident, error) {
	user, group, err := splitImageUser(imageUser)
	if err != nil {
		return Ident{}, err
	}
	var passwd, groupDB string
	// passwd is needed to resolve a name, and for a numeric user with no group
	// half, whose gid comes from its passwd entry when it has one.
	if !isNumericID(user) || group == "" {
		if passwd, err = readUserDatabase(rootfs, "/etc/passwd"); err != nil {
			return Ident{}, err
		}
	}
	if group != "" && !isNumericID(group) {
		if groupDB, err = readUserDatabase(rootfs, "/etc/group"); err != nil {
			return Ident{}, err
		}
	}
	id, err := ResolveUser(imageUser, passwd, groupDB)
	if err != nil {
		return Ident{}, err
	}
	if isNumericID(user) && group == "" {
		if gid, ok := gidForUID(passwd, id.UID); ok {
			id.GID = gid
		}
	}
	if len(supplemental) > 0 {
		id.Groups = append([]int64{}, supplemental...)
	}
	return id, nil
}

// ResolvePlanIdent settles a container's pending identity: when the plan
// carries an unresolved image_user it is resolved against the container's
// composed root (cp.Root), the result replaces cp.Ident, and the pending mark
// is cleared. A container with nothing pending is left untouched.
//
// The executor calls it at the end of the container's composition, once its
// overlay root exists and before anything is spawned; RunStart refuses a
// container that still carries the mark. A failure leaves cp unchanged.
func ResolvePlanIdent(cp *ContainerPlan) error {
	if cp.PendingImageUser == "" {
		return nil
	}
	id, err := ResolveImageUser(cp.Root, cp.PendingImageUser, cp.Ident.Groups)
	if err != nil {
		return fmt.Errorf("container %q: resolve image user %q: %w", cp.Name, cp.PendingImageUser, err)
	}
	cp.Ident = id
	cp.PendingImageUser = ""
	return nil
}

// gidForUID returns the primary gid of the first well-formed passwd(5) entry
// whose uid is uid. Malformed lines are skipped, as lookupPasswd skips them.
func gidForUID(passwd string, uid int64) (int64, bool) {
	for _, line := range strings.Split(passwd, "\n") {
		f, valid := colonFields(line, 4)
		if !valid {
			continue
		}
		u, err := parseID(f[2])
		if err != nil || u != uid {
			continue
		}
		g, err := parseID(f[3])
		if err != nil {
			continue
		}
		return g, true
	}
	return 0, false
}

// isNumericID reports whether s is an all-digit token (ResolveUser range-checks
// it; this only decides whether a database has to be read at all).
func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// readUserDatabase reads one of the container's user database files, resolved
// with chroot semantics inside rootfs. See ResolveImageUser for the rules.
func readUserDatabase(rootfs, guestPath string) (string, error) {
	r, err := os.OpenRoot(rootfs)
	if err != nil {
		return "", fmt.Errorf("%w: open the container root %s: %w", ErrUserDatabase, rootfs, err)
	}
	defer func() { _ = r.Close() }()

	resolved, hops, exists, err := walkContainerPath(r, guestPath)
	switch {
	case err != nil:
		return "", fmt.Errorf("%w: %s: %w", ErrUserDatabase, guestPath, err)
	case !exists && hops > 0:
		return "", fmt.Errorf("%w: %s is a symlink whose target does not exist in the container", ErrUserDatabase, guestPath)
	case !exists:
		return "", nil
	}
	fi, err := r.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrUserDatabase, guestPath, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file (%s)", ErrUserDatabase, guestPath, fi.Mode().Type())
	}
	// O_NONBLOCK: if the name was swapped for a FIFO after the Lstat, the open
	// returns instead of waiting for a writer. O_NOFOLLOW: the walk already
	// resolved every link, so a link here is a swap and is refused.
	f, err := r.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("%w: open %s: %w", ErrUserDatabase, guestPath, err)
	}
	defer func() { _ = f.Close() }()
	fi, err = f.Stat()
	if err != nil {
		return "", fmt.Errorf("%w: stat %s: %w", ErrUserDatabase, guestPath, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file (%s)", ErrUserDatabase, guestPath, fi.Mode().Type())
	}
	if fi.Size() > maxUserDatabaseBytes {
		return "", fmt.Errorf("%w: %s is %d bytes, over the %d-byte cap", ErrUserDatabase, guestPath, fi.Size(), maxUserDatabaseBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxUserDatabaseBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", ErrUserDatabase, guestPath, err)
	}
	if int64(len(raw)) > maxUserDatabaseBytes {
		return "", fmt.Errorf("%w: %s grew past the %d-byte cap while being read", ErrUserDatabase, guestPath, maxUserDatabaseBytes)
	}
	return string(raw), nil
}
