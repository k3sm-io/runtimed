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
	"os"
	"path"
	"strings"
)

// DefaultPath is the PATH used when a container's environment carries none. It
// is POSIX's default (confstr _CS_PATH) widened with the /usr/local pair every
// container runtime and every Linux distribution ships, which is where an image
// like nats:2.10-alpine puts its entrypoint.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// ErrProgramNotFound reports that a container's argv[0] does not resolve to an
// executable inside that container's root. Compare with errors.Is.
var ErrProgramNotFound = errors.New("guestinit: no executable for argv[0] in the container")

// PathFromEnv returns the PATH value from a container's resolved KEY=VALUE
// environment, or DefaultPath when the container sets none.
//
// The LAST assignment wins, which is what execve does: the environment is a list,
// not a map, and a duplicate key is resolved by the libc that reads it taking the
// final entry. Matching that here keeps the program this guest resolves and the
// PATH the process itself would compute from the same list.
func PathFromEnv(env []string) string {
	out := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			out = v
		}
	}
	if out == "" {
		return DefaultPath
	}
	return out
}

// ResolveProgram resolves a container's argv[0] execvp-style INSIDE the container
// rooted at root, and returns the path as the CONTAINER will see it — rooted at
// "/", because the child is chrooted before it execs.
//
// why this EXISTS. An image's Entrypoint is very often a BARE NAME resolved
// through PATH at exec time: nats:2.10-alpine runs "docker-entrypoint.sh", which
// lives at /usr/local/bin/docker-entrypoint.sh. syscall.ForkExec is execve, not
// execvp — it does no PATH search and requires a path — so a bare name failed with
// ENOENT and the container never started. Neither side was doing the job: the host
// spine deliberately does NOT resolve argv[0] for a vm pod (createVMPod's doc says
// so, and it is right — the host does not have the guest's rootfs and cannot stat
// a path inside it), and the guest had not taken it up. Most official images
// (nginx, node, postgres, nats) are shaped this way, so this was most of them.
//
// The rules are execvp's:
//
//   - argv0 containing a '/' is used AS GIVEN — no PATH search. An absolute one is
//     verified under root; a relative one under root + workingDir, which is where
//     the chrooted child's chdir will put it.
//   - a bare name is searched along pathEnv in order, first executable wins.
//   - an empty PATH element means the working directory (POSIX), not an empty
//     string.
//   - a candidate that exists but is not executable does not end the search; it is
//     remembered, and reported specifically if nothing else resolves — the
//     difference between "you spelled it wrong" and "you forgot chmod +x", which
//     are opposite fixes.
//
// The failure names argv[0] AND the PATH that was searched, because with the
// console fix (Reaper.Fail) that message is now what an operator actually sees.
//
// SEARCHED under root with CHROOT SEMANTICS, never under the guest's own /. Both
// halves of that are load-bearing and the second was learned the hard way.
//
// Confining the PATH JOIN is not enough. The first version did that and still
// resolved symlinks with os.Stat, which hands the target to the kernel to resolve
// against the calling process's own root — so alpine's /bin/sh, an ABSOLUTE
// symlink to /bin/busybox, was looked for at the guest init's /bin/busybox, which
// does not exist in the initramfs. A file that was present and executable was
// reported absent, and `command: ["/bin/sh","-c"]` — the most common command
// there is — could not start. Busybox images symlink nearly every applet this
// way, so the same failure reaches the PATH branch too; a bare name resolving is
// no evidence that it is safe.
//
// So every candidate is resolved through an os.Root opened on the container root:
// each component is confined by the standard library, and this walks the symlink
// chain itself only to do the one thing os.Root deliberately will not — treat an
// ABSOLUTE target as container-absolute rather than as an escape. A relative
// target is resolved against the link's own directory, as the kernel would.
//
// A link that leaves the container root is REFUSED, never followed: os.Root
// rejects it, and that is the right answer rather than an inconvenience. Resolving
// it would let an image reach the guest's own filesystem by shipping a symlink —
// and would silently run the guest's copy of a binary under the container's name.
// A dangling link is likewise refused, with a message that says which.
//
// A host-side lookup (os/exec.LookPath) would search the wrong filesystem
// entirely and is the specific mistake this signature is shaped to make
// impossible: there is no way to call it without naming a root.
func ResolveProgram(root, workingDir, argv0, pathEnv string) (string, error) {
	if argv0 == "" {
		return "", fmt.Errorf("%w: argv[0] is empty", ErrProgramNotFound)
	}
	if workingDir == "" {
		workingDir = "/"
	}
	if pathEnv == "" {
		pathEnv = DefaultPath
	}

	// One handle for the whole search: os.Root holds a descriptor on the container
	// root, so every candidate below is resolved against THAT directory even if
	// something renames or replaces a path component mid-search.
	r, err := os.OpenRoot(root)
	if err != nil {
		return "", fmt.Errorf("%w: open the container root %s: %w", ErrProgramNotFound, root, err)
	}
	defer func() { _ = r.Close() }()

	if strings.ContainsRune(argv0, '/') {
		guest := argv0
		if !path.IsAbs(guest) {
			guest = path.Join(workingDir, guest)
		}
		ok, exec, why := candidate(r, guest)
		switch {
		case !ok && why != "":
			return "", fmt.Errorf("%w: %q %s", ErrProgramNotFound, argv0, why)
		case !ok:
			return "", fmt.Errorf("%w: %q names a path that does not exist in the container", ErrProgramNotFound, argv0)
		case !exec:
			return "", fmt.Errorf("%w: %q exists in the container but is not executable", ErrProgramNotFound, argv0)
		}
		// Returned AS GIVEN, not as the cleaned absolute form: a relative argv[0]
		// is execed after the child chdirs into workingDir, so the kernel resolves
		// it the same way this check just did.
		return argv0, nil
	}

	var notExecutable, rejected string
	for _, dir := range strings.Split(pathEnv, ":") {
		guestDir := dir
		if guestDir == "" || !path.IsAbs(guestDir) {
			// POSIX: an empty element is the working directory. A relative element
			// is resolved against it for the same reason.
			guestDir = path.Join(workingDir, guestDir)
		}
		guest := path.Join(guestDir, argv0)
		ok, exec, why := candidate(r, guest)
		switch {
		case !ok:
			// A candidate that was there but unusable — dangling, or pointing out
			// of the container — does not end the search, exactly as an
			// unreadable one does not. It is remembered so the failure can name
			// the specific problem instead of a bare "not found".
			if why != "" && rejected == "" {
				rejected = fmt.Sprintf("%s %s", guest, why)
			}
			continue
		case !exec:
			if notExecutable == "" {
				notExecutable = guest
			}
			continue
		}
		return guest, nil
	}
	switch {
	case notExecutable != "":
		return "", fmt.Errorf("%w: %q resolved to %s in the container, which is not executable (searched PATH %q)",
			ErrProgramNotFound, argv0, notExecutable, pathEnv)
	case rejected != "":
		return "", fmt.Errorf("%w: %q: %s (searched PATH %q)", ErrProgramNotFound, argv0, rejected, pathEnv)
	}
	return "", fmt.Errorf("%w: %q (searched PATH %q)", ErrProgramNotFound, argv0, pathEnv)
}

// maxSymlinkHops bounds the symlink chain one candidate may traverse. It is
// Linux's own SYMLOOP_MAX: a chain longer than this is a loop in every case that
// matters, and the bound is what stops "a -> b -> a" from spinning here.
const maxSymlinkHops = 40

// candidate resolves one container-absolute path inside r with chroot semantics
// and reports whether it exists and is an executable regular file. When it is
// unusable for a reason worth telling the operator, why says which.
//
// The loop is the whole subtlety. r.Lstat does NOT follow the final component,
// which is what lets this read the link and decide how to interpret its target;
// every INTERMEDIATE component is resolved and confined by os.Root itself, so
// nothing here has to re-implement containment. An ABSOLUTE target is rewritten
// relative to the container root — the one thing os.Root will not do, and exactly
// what a chroot would — while a relative one is joined onto the link's own
// directory. A target that escapes the root after that rewrite is refused by the
// next r.Lstat, which is where the containment guarantee comes from.
//
// A path that does not exist, and one whose link chain dangles, are reported
// apart: "you spelled it wrong" and "this image ships a broken link" are
// different problems with different fixes.
func candidate(r *os.Root, guestPath string) (exists, executable bool, why string) {
	name := strings.TrimPrefix(path.Clean(guestPath), "/")
	if name == "" || name == "." {
		return false, false, ""
	}
	for hop := 0; hop <= maxSymlinkHops; hop++ {
		fi, err := r.Lstat(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if hop > 0 {
				return false, false, "is a symlink whose target does not exist in the container"
			}
			return false, false, ""
		case errors.Is(err, os.ErrPermission):
			// A directory along the way this process cannot read is the same
			// "cannot use this element" as absence: a container whose PATH names
			// an unreadable directory still runs.
			return false, false, ""
		case err != nil:
			// os.Root refuses anything leaving the container root, which is the
			// case this arm exists for: a symlink out of the image must never
			// resolve to the guest's own copy of a binary.
			return false, false, "resolves outside the container root"
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if !fi.Mode().IsRegular() {
				// A directory or a device named where a program should be is "not
				// it", exactly as execvp treats it.
				return true, false, ""
			}
			return true, fi.Mode().Perm()&0o111 != 0, ""
		}
		target, err := r.Readlink(name)
		if err != nil {
			return false, false, "resolves outside the container root"
		}
		if path.IsAbs(target) {
			// Container-absolute, not host-absolute. This is the line the
			// regression turned on: /bin/sh -> /bin/busybox means the container's
			// /bin/busybox, and resolving it against the guest's root found
			// nothing.
			name = strings.TrimPrefix(path.Clean(target), "/")
		} else {
			name = path.Join(path.Dir(name), target)
		}
		if name == "" || name == "." {
			return false, false, "resolves outside the container root"
		}
	}
	return false, false, "has too many levels of symbolic links"
}
