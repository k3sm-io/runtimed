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
	"path/filepath"
	"strings"
)

// The per-pod Darwin user directories.
//
// macOS gives every uid one temp tree and one cache tree under /var/folders,
// and hands them out through confstr(_CS_DARWIN_USER_TEMP_DIR) and
// confstr(_CS_DARWIN_USER_CACHE_DIR). Foundation's NSTemporaryDirectory and
// FileManager.temporaryDirectory, swift-driver's temp-dir fallback and clang's
// default module cache all ask confstr, and confstr ignores $TMPDIR. Every pod
// on a node runs as the one daemon uid, so those two trees are SHARED by every
// pod: the profile denies them, and granting them would be a cross-pod write
// channel (the module cache holds .pcm files the next compile loads).
//
// libSystem's dirhelper honours DIRHELPER_USER_DIR_SUFFIX: with it set to S,
// confstr answers <T>/S/ and <C>/S/ instead (measured on macOS 26 and 27, for
// ordinary, ad-hoc and library-validation-only binaries; platform binaries and
// the hardened runtime ignore it, as they ignore DYLD_*). runtimed sets S to
// UserDirSuffix(pod id) and makes <T>/S and <C>/S symlinks into the pod's own
// data volume. The only grant a pod then needs is to resolve those two links:
// file-read-metadata on each link path, as a literal. Every read and write
// through a link lands in the data volume, which the profile already allows;
// nothing on <T> or <C> themselves is granted, so a pod can neither list the
// shared trees nor create, replace or remove a link.
//
// Measured: without the metadata literal Seatbelt denies the lookup through the
// link (EPERM), and with it a confined write lands in the data volume.

// UserDirSuffixPrefix starts every per-pod suffix, so a link is recognisable as
// k3sm's in a listing of the shared trees.
const UserDirSuffixPrefix = "k3sm."

// ErrInvalidUserDirLink is returned for a per-pod user-dir link path that is
// not an absolute, clean <T or C>/k3sm.<id> path made of plain characters.
var ErrInvalidUserDirLink = errors.New("sbpl: invalid per-pod user-dir link")

// UserDirSuffixEnv is the variable libSystem's dirhelper reads.
const UserDirSuffixEnv = "DIRHELPER_USER_DIR_SUFFIX"

// UserDirSuffix is the DIRHELPER_USER_DIR_SUFFIX value for a pod: the prefix
// plus the pod id. It is the one derivation: the runtime's env injection, its
// links and Generate's grant all call it. ok is false for an id dirhelper
// would refuse as a suffix (empty, or holding "/" or ".."; measured: dirhelper
// then silently answers the unsuffixed tree), so such a pod gets no suffix, no
// link and no grant.
func UserDirSuffix(podID string) (string, bool) {
	if podID == "" || strings.Contains(podID, "/") || strings.Contains(podID, "..") {
		return "", false
	}
	return UserDirSuffixPrefix + podID, true
}

// UserDirs names the node user's two shared trees (confstr's unsuffixed
// answers, symlinks resolved). The zero value grants nothing.
type UserDirs struct {
	Temp, Cache string
}

// userDirLinks returns the pod's two link paths under u, or nil when u is
// unset or the pod id makes no usable suffix. A base that is not an absolute
// clean path is refused here, before filepath.Join would clean it into
// something else.
func userDirLinks(u UserDirs, podID string) ([]string, error) {
	if u.Temp == "" || u.Cache == "" {
		return nil, nil
	}
	for _, base := range []string{u.Temp, u.Cache} {
		if !filepath.IsAbs(base) || filepath.Clean(base) != base {
			return nil, fmt.Errorf("%w: user dir %q is not an absolute clean path", ErrInvalidUserDirLink, base)
		}
	}
	sfx, ok := UserDirSuffix(podID)
	if !ok {
		return nil, nil
	}
	return []string{filepath.Join(u.Temp, sfx), filepath.Join(u.Cache, sfx)}, nil
}

// validateUserDirLinks checks the links Generate renders. They are derived by
// the runtime, never sent by a caller, so this is defence in depth: a link is
// an absolute clean path whose parent directory is named T or C (the dirhelper
// layout) and whose own name starts with UserDirSuffixPrefix, it contains no
// character that would need escaping in an SBPL string, and it is not under a
// protected prefix.
func validateUserDirLinks(links, protectedPrefixes []string) error {
	for _, l := range links {
		if !filepath.IsAbs(l) || filepath.Clean(l) != l || l == "/" {
			return fmt.Errorf("%w: %q is not an absolute clean path", ErrInvalidUserDirLink, l)
		}
		if strings.ContainsAny(l, "\"\\()\n\r\t") {
			return fmt.Errorf("%w: %q holds a character SBPL would need escaped", ErrInvalidUserDirLink, l)
		}
		if parent := filepath.Base(filepath.Dir(l)); parent != "T" && parent != "C" {
			return fmt.Errorf("%w: %q is not directly under a T or C user dir", ErrInvalidUserDirLink, l)
		}
		if name := filepath.Base(l); !strings.HasPrefix(name, UserDirSuffixPrefix) || name == UserDirSuffixPrefix {
			return fmt.Errorf("%w: %q is not named %s<pod id>", ErrInvalidUserDirLink, l, UserDirSuffixPrefix)
		}
		for _, pre := range protectedPrefixes {
			if underAnyForm(l, pre) {
				return fmt.Errorf("%w: %q is under protected %q", ErrInvalidUserDirLink, l, pre)
			}
		}
	}
	return nil
}

// userDirLinkStanza renders the grant for the pod's own links: one
// file-read-metadata literal per firmlink form of each link, and nothing else.
// Never a subpath, never file-read-data, never anything on the T or C
// directory itself. Empty links render nothing (an empty filter list would be
// a filterless allow on the whole filesystem).
func userDirLinkStanza(links []string) string {
	if len(links) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(";; per-pod Darwin user dirs: resolve THIS pod's own links in the node\n")
	b.WriteString(";; user's /var/folders T and C trees (DIRHELPER_USER_DIR_SUFFIX). The\n")
	b.WriteString(";; links point into the data volume; metadata on the link itself only,\n")
	b.WriteString(";; nothing on T or C, so no listing and no write in the shared trees.\n")
	b.WriteString("(allow file-read-metadata\n")
	writeFirmlinkLiterals(&b, links)
	b.WriteString("  )\n")
	return b.String()
}
