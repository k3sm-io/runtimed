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

package pathsafe

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrSymlinkedPath reports that a component of a path the daemon was about to
// create, stamp, or delete through is not the plain directory the caller
// believes it is: it is a symlink, or it exists as something other than a
// directory.
//
// The two are ONE class on purpose. What the callers need is not "is this a
// symlink" but "does this path name exactly the tree I think it does" — and a
// regular file sitting where a directory belongs answers that question the same
// way a symlink does: no.
var ErrSymlinkedPath = errors.New("unsafe path component")

// ErrPathOutsideRoot reports that a path is neither its containment root nor
// under it, so no walk from that root could bound it.
var ErrPathOutsideRoot = errors.New("path outside its containment root")

// RefuseSymlinkedPath reports an error unless every EXISTING component of path,
// from root (inclusive) down to path itself, is a plain directory.
//
// It lives in its own package because the sites that need it sit in two others
// that must not depend on each other: pkg/mount renders a vm pod's share roots —
// and the credential bytes inside them — before pkg/sandbox's CreateVM ever
// runs, so a check that lived in pkg/sandbox would either run after the writes
// it guards or drag that package's cgo into pkg/mount.
//
// WHY A WALK, when isAtOrUnderDir already says the path is in the right tree:
// isAtOrUnderDir compares STRINGS. `<run>/vm/p1` is textually inside `<run>`
// whether `vm` is a directory or a symlink to somewhere else entirely, and every
// syscall the daemon then makes on that string — MkdirAll, WriteFile, Stat,
// RemoveAll — resolves the symlink silently and acts on the target. So the
// string check bounds the NAME, and only a walk bounds the PLACE.
//
// root is the trusted base and is checked like any other component, but nothing
// ABOVE it is: the daemon's own state root is configuration, and on macOS the
// paths it is routinely given already sit under symlinked ancestors (/tmp is a
// symlink to /private/tmp, /var to /private/var). Walking above the root would
// refuse ordinary, correct installations while proving nothing about the tree
// the caller owns.
//
// A MISSING component ends the walk successfully. Every caller is about to
// create what is not there, and nothing that does not exist can redirect a
// syscall; refusing an absent leaf would just forbid the first boot of every pod.
//
// This is an LSTAT PRE-CHECK, not a handle-held traversal. It proves what the
// path resolved to at the instant it ran, and a same-euid process can still swap
// a component between this walk and the caller's syscall (see clearOrphanRunDir
// for the accepted residual). Closing that would mean an openat(O_NOFOLLOW)
// descent holding a directory fd at every level and operating relative to the
// last one — which os.MkdirAll and os.RemoveAll have no form of. The walk is
// what removes the PRE-PLANTED link, which is the reachable attack; the race is
// stated rather than papered over.
func RefuseSymlinkedPath(root, path string) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path != root && !isAtOrUnderDir(path, root) {
		return fmt.Errorf("%w: %s is not at or under %s", ErrPathOutsideRoot, path, root)
	}
	var rest []string
	if path != root {
		rest = strings.Split(path[len(root)+1:], string(filepath.Separator))
	}
	at := root
	for i := 0; ; i++ {
		fi, err := os.Lstat(at)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil // the caller creates it; nothing that is absent can redirect a syscall
		case err != nil:
			return fmt.Errorf("inspect the path component %s: %w", at, err)
		case fi.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("%w: %s is a symlink", ErrSymlinkedPath, at)
		case !fi.IsDir():
			return fmt.Errorf("%w: %s exists and is not a directory", ErrSymlinkedPath, at)
		}
		if i == len(rest) {
			return nil
		}
		at = filepath.Join(at, rest[i])
	}
}

// isAtOrUnderDir reports whether path lies strictly beneath dir, separator-aware
// so a sibling whose name merely starts the same is not admitted.
//
// It is a local copy rather than an import: this package's whole value is that
// it depends on nothing but the standard library, and the check is three
// comparisons. pkg/sandbox keeps its own for the containment decisions that are
// its own (which run dirs and share roots it will act on at all).
func isAtOrUnderDir(path, dir string) bool {
	return len(path) > len(dir)+1 &&
		path[:len(dir)] == dir &&
		path[len(dir)] == filepath.Separator
}
