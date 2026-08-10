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
	"regexp"
)

// Pod identifiers that become directory names.
//
// A pod id arrives over the runtimed gRPC seam and is used to derive the pod's
// on-disk directory — which the ROOT daemon then MkdirAll's, writes into, and
// RemoveAll's. An unvalidated id is therefore an attacker-chosen path, the same
// defect the blob store closed by refusing to build a path from an unparsed
// digest. It is not a hypothetical reach: pods run at the same uid as the daemon
// and the daemon's socket is not denied by the pod sandbox profile, so a
// confined pod can issue these RPCs itself.
//
// PodID makes the fix structural rather than disciplinary: Cache.PodRootfs takes
// a PodID, PodID's field is unexported, and ParsePodID is the only way to make
// one. A caller cannot derive a pod path without having been validated, and no
// future caller can reintroduce the hole by forgetting a check — the same shape
// as parseBlobDigest feeding pathFor.

// podIDRe is the closed character class for a pod id.
//
// The class is LOWERCASE ASCII, which is deliberately narrower than "contains no
// separator". Two properties motivate it:
//
//   - Traversal: the id may not start with a dot, so "." and ".." are rejected,
//     and no separator is admitted, so "a/b" and "/abs" are rejected. A rejected
//     id yields no path at all, rather than a path that is checked afterwards.
//   - Aliasing: the default macOS APFS volume is case-insensitive, while the
//     daemon's live pod registry is keyed by the raw byte string. Admitting case
//     would let "Pod-A" and "pod-a" be two registry entries sharing ONE on-disk
//     directory, so deleting either would destroy the other's data volume — a
//     cross-pod escape that contains no traversal metacharacter and that a
//     traversal-only test would pass.
//
// Every value produced today is inside this class: production ids are
// apiserver-generated RFC 4122 UUIDs (lowercase hex and hyphens), and the test
// corpus across both repos is lowercase alphanumerics and hyphens.
var podIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ErrInvalidPodID is returned for a pod id that is not a legal directory name.
// Callers surface it as an invalid-argument failure; it is never retried, since
// the id cannot become valid without the caller changing it.
var ErrInvalidPodID = errors.New("invalid pod id")

// PodID is a pod identifier that has been validated as safe to use as a single
// path component. The zero value is not usable; obtain one from ParsePodID.
type PodID struct{ s string }

// String returns the validated identifier.
func (p PodID) String() string { return p.s }

// ParsePodID validates s as a pod identifier and returns it wrapped.
//
// The length ceiling is 128 bytes: comfortably above the 36-byte UUIDs every
// producer emits, and well under both the 255-byte APFS path-component limit and
// the size at which the id — which is embedded verbatim as a literal in each
// pod's generated sandbox profile — would bloat that profile.
func ParsePodID(s string) (PodID, error) {
	if s == "" {
		return PodID{}, fmt.Errorf("%w: empty", ErrInvalidPodID)
	}
	if !podIDRe.MatchString(s) {
		return PodID{}, fmt.Errorf("%w: %q must match %s (lowercase, no separators, may not begin with a dot)",
			ErrInvalidPodID, s, podIDRe.String())
	}
	return PodID{s: s}, nil
}
