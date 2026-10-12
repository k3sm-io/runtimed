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
	"os"
	"path"
	"strings"
)

// MaxSymlinkHops bounds the symlink chain one WalkInRoot call may traverse. It
// is Linux's own SYMLOOP_MAX: a chain longer than this is a loop in every case
// that matters, and the bound is what stops "a -> b -> a" from spinning.
const MaxSymlinkHops = 40

// WalkInRoot resolves p inside r one component at a time, with chroot
// semantics, and reports the resolved root-relative path, how many symlinks it
// followed, and whether the final component exists.
//
// It is the one home for resolving a path INSIDE a container or pod root: the
// guest's argv[0], mount-target and user-database lookups, and the daemon's
// ad-hoc signing of a pod binary whose argv[0] is an image symlink, all call it.
//
// COMPONENT BY COMPONENT, not one Lstat of the whole path. os.Root resolves
// intermediate components itself, but it refuses an ABSOLUTE symlink anywhere in
// the chain — correctly, by its own contract, since it has no notion of a
// chroot. This walk exists to do the one thing that contract cannot: treat an
// absolute target as root-absolute. Everything else — per-component
// confinement, the refusal of anything reaching outside — is still os.Root's,
// because the rewritten name is handed straight back to it.
//
// The answer describes the tree at the moment of the walk. A caller acting on a
// tree another party can write must still open what it resolved without
// following links (O_NOFOLLOW) and act on the descriptor, not the name.
func WalkInRoot(r *os.Root, p string) (resolved string, hops int, exists bool, err error) {
	parts := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	var out []string
	for i := 0; i < len(parts); {
		c := parts[i]
		if c == "" || c == "." {
			i++
			continue
		}
		cand := path.Join(append(append([]string{}, out...), c)...)
		fi, lerr := r.Lstat(cand)
		switch {
		case errors.Is(lerr, os.ErrNotExist):
			// This component and everything after it is yet to be created. The
			// tail carries no symlinks precisely because it does not exist.
			return path.Join(append(out, parts[i:]...)...), hops, false, nil
		case lerr != nil:
			// os.Root refusing an escape lands here, which is the answer this
			// wants: a target reaching outside the root is not resolved.
			return "", hops, false, lerr
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			out = append(out, c)
			i++
			continue
		}
		hops++
		if hops > MaxSymlinkHops {
			return "", hops, false, errors.New("too many levels of symbolic links")
		}
		target, rerr := r.Readlink(cand)
		if rerr != nil {
			return "", hops, false, rerr
		}
		rest := parts[i+1:]
		if path.IsAbs(target) {
			// Root-absolute: the kernel would resolve it against the HOST root,
			// which is exactly the escape this walk exists to prevent.
			out = nil
		}
		parts = append(strings.Split(strings.TrimPrefix(path.Clean(target), "/"), "/"), rest...)
		i = 0
	}
	return path.Join(out...), hops, true, nil
}
