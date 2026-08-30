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
	"math"
	"sort"
	"strconv"
	"strings"

	guestv1 "k3sm.io/apis/guest/v1"
)

// ErrInvalidSpec is returned for any GuestSpec the guest refuses to realize.
// It is a single sentinel because the caller's response is always the same —
// fail the pod with the wrapped reason — and because the executor is PID 1: it
// has nowhere to degrade to.
var ErrInvalidSpec = errors.New("invalid guest spec")

// ErrNoSuchUser is returned when a name cannot be resolved against the
// container rootfs's own /etc/passwd or /etc/group.
var ErrNoSuchUser = errors.New("no such user or group in the container rootfs")

// maxID is the largest id a Linux uid_t/gid_t holds. An id outside the range
// is refused rather than truncated: (uint32)(1<<32) is 0, i.e. root.
const maxID int64 = math.MaxUint32

// Ident is the resolved process identity a container runs as.
type Ident struct {
	// UID and GID are the effective numeric ids.
	UID int64
	GID int64

	// Groups are the supplementary groups, deduplicated and sorted. The pod's
	// fsGroup is one of them.
	Groups []int64
}

// ResolveUser resolves an OCI USER spec against a container rootfs's passwd
// and group databases, in the guest, at start time.
//
// The accepted forms are the OCI ones: "", "uid", "uid:gid", "user",
// "user:group", and the mixed "uid:group" / "user:gid". Resolution rules,
// which follow the runtime behaviour images are built against:
//
//   - "" means 0:0. guest/v1 has no way to say "unset" (uid 0 IS root), so an
//     empty spec is the caller's explicit request for root.
//   - A NUMERIC id is used as given and is NEVER looked up. An image whose
//     passwd file lacks the uid still runs — that is how scratch images with a
//     numeric USER work.
//   - A NAME must be present in the database. A missing name is
//     ErrNoSuchUser, never a silent fallback to root: falling back would run
//     as a more privileged identity than the image asked for.
//   - When only a user is given and it resolved by NAME, the gid comes from
//     that passwd entry. When the uid was numeric, the gid is 0 — there is no
//     entry to take one from.
//
// passwd and group are the raw file contents; either may be empty (a scratch
// image has neither), which is only an error if a name has to be resolved.
func ResolveUser(user string, passwd, group string) (Ident, error) {
	if user == "" {
		return Ident{UID: 0, GID: 0}, nil
	}
	userPart, groupPart, hasGroup := strings.Cut(user, ":")
	if userPart == "" {
		return Ident{}, fmt.Errorf("%w: user spec %q has an empty user part", ErrInvalidSpec, user)
	}

	var id Ident
	if uid, err := parseID(userPart); err == nil {
		id.UID, id.GID = uid, 0
	} else if !errors.Is(err, errNotNumeric) {
		return Ident{}, fmt.Errorf("user spec %q: %w", user, err)
	} else {
		uid, gid, ok := lookupPasswd(passwd, userPart)
		if !ok {
			return Ident{}, fmt.Errorf("%w: user %q", ErrNoSuchUser, userPart)
		}
		id.UID, id.GID = uid, gid
	}

	if !hasGroup {
		return id, nil
	}
	if groupPart == "" {
		return Ident{}, fmt.Errorf("%w: user spec %q has an empty group part", ErrInvalidSpec, user)
	}
	if gid, err := parseID(groupPart); err == nil {
		id.GID = gid
		return id, nil
	} else if !errors.Is(err, errNotNumeric) {
		return Ident{}, fmt.Errorf("user spec %q: %w", user, err)
	}
	gid, ok := lookupGroup(group, groupPart)
	if !ok {
		return Ident{}, fmt.Errorf("%w: group %q", ErrNoSuchUser, groupPart)
	}
	id.GID = gid
	return id, nil
}

// errNotNumeric distinguishes "this token is a name" from "this token is a
// malformed number", so a typo'd id ("99x9") is an error instead of being
// looked up as a user name and reported as a missing user.
var errNotNumeric = errors.New("not a numeric id")

// parseID parses an all-digit id and range-checks it.
func parseID(s string) (int64, error) {
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errNotNumeric
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 || v > maxID {
		return 0, fmt.Errorf("%w: id %q is out of range 0..%d", ErrInvalidSpec, s, maxID)
	}
	return v, nil
}

// lookupPasswd finds name in a passwd(5) database and returns its uid and gid.
//
// A malformed line is SKIPPED rather than fatal: the database comes from the
// pod's own image, and a stray line in some vendor's /etc/passwd must not stop
// the pod from starting. A malformed line for the name being looked up simply
// fails to match, which surfaces as ErrNoSuchUser.
func lookupPasswd(passwd, name string) (uid, gid int64, ok bool) {
	for _, line := range strings.Split(passwd, "\n") {
		f, valid := colonFields(line, 4)
		if !valid || f[0] != name {
			continue
		}
		u, err := parseID(f[2])
		if err != nil {
			continue
		}
		g, err := parseID(f[3])
		if err != nil {
			continue
		}
		return u, g, true
	}
	return 0, 0, false
}

// lookupGroup finds name in a group(5) database and returns its gid.
func lookupGroup(group, name string) (gid int64, ok bool) {
	for _, line := range strings.Split(group, "\n") {
		f, valid := colonFields(line, 3)
		if !valid || f[0] != name {
			continue
		}
		g, err := parseID(f[2])
		if err != nil {
			continue
		}
		return g, true
	}
	return 0, false
}

// colonFields splits a passwd/group line, rejecting comments, blanks, and
// lines with fewer than min fields.
func colonFields(line string, min int) ([]string, bool) {
	line = strings.TrimRight(line, "\r")
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}
	f := strings.Split(line, ":")
	if len(f) < min {
		return nil, false
	}
	return f, true
}

// ContainerIdent is the identity a container starts with, taken from the ids
// the host already resolved and stamped into the spec.
//
// Supplementary groups are the spec's list UNIONED with the pod's fsGroup,
// deduplicated and sorted so the plan is deterministic. fsGroup is included
// here rather than only in the idmapped mounts because a process must be IN
// the group to benefit from group-owned files; a fsGroup that appears on the
// volume but not in the process's group set grants nothing.
func ContainerIdent(c *guestv1.GuestContainer, fsGroup int64) (Ident, error) {
	if c == nil {
		return Ident{}, fmt.Errorf("%w: nil container", ErrInvalidSpec)
	}
	if err := checkID("uid", c.GetUid()); err != nil {
		return Ident{}, fmt.Errorf("container %q: %w", c.GetName(), err)
	}
	if err := checkID("gid", c.GetGid()); err != nil {
		return Ident{}, fmt.Errorf("container %q: %w", c.GetName(), err)
	}
	if err := checkID("fsGroup", fsGroup); err != nil {
		return Ident{}, fmt.Errorf("container %q: %w", c.GetName(), err)
	}
	seen := map[int64]bool{}
	var groups []int64
	add := func(g int64) error {
		if err := checkID("supplemental gid", g); err != nil {
			return fmt.Errorf("container %q: %w", c.GetName(), err)
		}
		if !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
		return nil
	}
	for _, g := range c.GetSupplementalGids() {
		if err := add(g); err != nil {
			return Ident{}, err
		}
	}
	if fsGroup != 0 {
		if err := add(fsGroup); err != nil {
			return Ident{}, err
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i] < groups[j] })
	return Ident{UID: c.GetUid(), GID: c.GetGid(), Groups: groups}, nil
}

// checkID range-checks one id from the spec.
func checkID(what string, id int64) error {
	if id < 0 || id > maxID {
		return fmt.Errorf("%w: %s %d is outside 0..%d", ErrInvalidSpec, what, id, maxID)
	}
	return nil
}
