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
	"path/filepath"
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
// SEARCHED under root, NEVER under the guest's own /. Every candidate is joined
// onto root before it is stat'd, and one that escapes root after cleaning is
// skipped — pathEnv is pod-controlled, so a "../../.." element must not be able to
// address the guest init's own filesystem. A host-side lookup (os/exec.LookPath)
// would search the wrong filesystem entirely and is the specific mistake this
// signature is shaped to make impossible: there is no way to call it without
// naming a root.
//
// One residual, stated rather than hidden: an ABSOLUTE symlink inside the
// container is followed against the filesystem doing the stat, not against the
// container root, so such a link can be reported resolvable for a target the
// chrooted child cannot reach. The exec then fails exactly as it does today, so
// the check is never worse than not checking — it is only not a proof.
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

	if strings.ContainsRune(argv0, '/') {
		guest := argv0
		if !path.IsAbs(guest) {
			guest = path.Join(workingDir, guest)
		}
		ok, exec, err := candidate(root, guest)
		switch {
		case err != nil:
			return "", err
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

	var notExecutable string
	for _, dir := range strings.Split(pathEnv, ":") {
		guestDir := dir
		if guestDir == "" || !path.IsAbs(guestDir) {
			// POSIX: an empty element is the working directory. A relative element
			// is resolved against it for the same reason.
			guestDir = path.Join(workingDir, guestDir)
		}
		guest := path.Join(guestDir, argv0)
		ok, exec, err := candidate(root, guest)
		if err != nil {
			return "", err
		}
		switch {
		case !ok:
			continue
		case !exec:
			if notExecutable == "" {
				notExecutable = guest
			}
			continue
		}
		return guest, nil
	}
	if notExecutable != "" {
		return "", fmt.Errorf("%w: %q resolved to %s in the container, which is not executable (searched PATH %q)",
			ErrProgramNotFound, argv0, notExecutable, pathEnv)
	}
	return "", fmt.Errorf("%w: %q (searched PATH %q)", ErrProgramNotFound, argv0, pathEnv)
}

// candidate stats one container-absolute path under root, reporting whether it
// exists and whether it is an executable regular file.
//
// A path that escapes root after cleaning reports "does not exist" rather than an
// error: pathEnv is pod-controlled, an element like "../../.." is a mistake or an
// attempt rather than a fatal condition, and skipping it lets the remaining
// elements resolve normally. The guard is what keeps the search inside the
// container.
func candidate(root, guestPath string) (exists, executable bool, err error) {
	root = filepath.Clean(root)
	host := filepath.Join(root, filepath.FromSlash(guestPath))
	if host != root && !strings.HasPrefix(host, root+string(filepath.Separator)) {
		return false, false, nil
	}
	fi, serr := os.Stat(host)
	if serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return false, false, nil
		}
		// A permission error on a directory along the way is the same "cannot use
		// this element" as absence, and must not fail the whole resolution: a
		// container whose PATH names an unreadable directory still runs.
		if errors.Is(serr, os.ErrPermission) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("stat %s in the container: %w", guestPath, serr)
	}
	if !fi.Mode().IsRegular() {
		// A directory or a device named where a program should be is "not it",
		// exactly as execvp treats it (EACCES/EISDIR both continue the search).
		return true, false, nil
	}
	return true, fi.Mode().Perm()&0o111 != 0, nil
}
