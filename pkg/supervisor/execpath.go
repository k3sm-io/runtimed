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

package supervisor

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

// DefaultExecPath is the search path ResolveExecPath uses when the session's
// PATH is empty or unset: the base system directories every macOS host has.
const DefaultExecPath = "/usr/bin:/bin:/usr/sbin:/sbin"

// ErrExecNotFound reports that a bare command name matched no executable on the
// search path. Callers map it to the not-found convention (exit 127).
var ErrExecNotFound = errors.New("executable not found")

// notFoundError carries the user-facing not-found text while matching
// ErrExecNotFound under errors.Is.
type notFoundError struct{ name string }

func (e *notFoundError) Error() string {
	return `exec: "` + e.name + `": executable not found on the pod's PATH`
}

func (e *notFoundError) Unwrap() error { return ErrExecNotFound }

// ResolveExecPath returns the file to execve for an exec session's command
// name, searching pathEnv the way execvp(3) does for a bare name.
//
// A name containing a slash is returned unchanged, absolute or relative (a
// relative one still resolves against the session's working directory). An
// empty pathEnv searches DefaultExecPath. Empty and relative PATH elements are
// skipped: POSIX reads them as the working directory, which a pod-controlled
// PATH must not turn into an implicit lookup (the posture of Go's
// exec.ErrDot). The first element holding a regular file with any execute bit
// wins; a stat error of any kind (absent, or denied by the sandbox) moves on to
// the next element, as execvp continues past EACCES. When nothing matches the
// error wraps ErrExecNotFound and names only the command, never the path or the
// directories tried.
//
// It resolves against the HOST-visible filesystem only. guestinit.ResolveProgram
// is the guest-rootfs sibling, kept separate on purpose: it resolves under a
// chosen root with different semantics. This function grants nothing — the
// session's execve under the pod profile remains the authority, and the file
// can change between the stat and the exec (an acknowledged TOCTOU with no
// security consequence for that reason). It runs inside the session's
// confinement, so it can only probe what the pod could stat itself: it is not
// an oracle for host files the pod cannot see.
//
// Divergence from execvp(3): there is no /bin/sh retry on ENOEXEC, so a
// script without a "#!" line found on PATH fails to exec; "#!" scripts work
// through the kernel.
func ResolveExecPath(name, pathEnv string, stat func(string) (fs.FileInfo, error)) (string, error) {
	if name == "" {
		return "", errors.New("exec: empty command name")
	}
	if strings.Contains(name, "/") {
		return name, nil
	}
	if pathEnv == "" {
		pathEnv = DefaultExecPath
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, name)
		fi, err := stat(candidate)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", &notFoundError{name: name}
}
