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
	"os"
	"path/filepath"
)

// executableSibling reports the path of the file called name that sits beside
// the real (symlink-resolved) current executable, and whether it exists as a
// regular file. It is the one seam FindExecShim and FindVMHost share.
//
// Darwin semantics, documented here because they are the reason this seam
// exists: os.Executable on darwin is backed by _NSGetExecutablePath (dyld's
// executable_path), which returns the path AS INVOKED. A binary run through a
// symlink (the /usr/local/bin/k3sm install link) reports the link, not its
// target, unlike Linux's /proc/self/exe, which the kernel resolves. The
// helpers ship beside the real binary, so the executable path is resolved
// with filepath.EvalSymlinks before taking its directory.
func executableSibling(name string) (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	return siblingOf(exe, name)
}

// siblingOf is the pure part of executableSibling: the candidate path for name
// beside filepath.EvalSymlinks(exe), falling back to the unresolved directory of
// exe only when the symlinks cannot be resolved (a dangling or unreadable link),
// and whether that candidate is a regular file (os.Stat follows a symlinked
// helper to its target).
func siblingOf(exe, name string) (string, bool) {
	dir := filepath.Dir(exe)
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		dir = filepath.Dir(real)
	}
	cand := filepath.Join(dir, name)
	fi, err := os.Stat(cand)
	if err != nil || !fi.Mode().IsRegular() {
		return cand, false
	}
	return cand, true
}
