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
	"fmt"
	"os"
	"path/filepath"
)

// ErrWorkingDir reports that a SpawnSpec.Dir cannot be used as the spawned
// child's working directory. It is a sentinel so a caller (and a test) can name
// the refusal with errors.Is rather than matching on a message, and so a bad
// working directory is never mistaken for a bad executable.
//
// A Dir that is set but unusable fails the spawn. There is deliberately no
// fallback to the caller's cwd: the caller is a root daemon whose cwd is its own
// working directory, the pod sandbox profile denies that tree, and a pod that
// silently landed there would run somewhere nothing in its spec asked for. That
// is the failure this sentinel exists to make loud — an M8 lab pod declaring
// workingDir /usr got EPERM stat'ing "." because it had inherited the daemon's
// cwd under /Users and the chdir was never performed at all.
var ErrWorkingDir = errors.New("supervisor: unusable spawn working directory")

// spawnPlan is the resolved, platform-independent part of a spawn decision: what
// the darwin spawner encodes into posix_spawn file actions. It exists so the
// working-directory decision is observable — and mutation-testable — as a value,
// independently of the cgo call that consumes it.
type spawnPlan struct {
	// ChangeDir is the absolute directory the child chdirs into before exec, or
	// "" for "inherit the caller's cwd" (SpawnSpec.Dir unset).
	//
	// "" is not a pod-safe default and is not meant as one: pkg/runtime defaults
	// every container's Dir to the pod data volume before a SpawnSpec ever
	// reaches this package (its TestPodLaunchDefaultsWorkingDirToDataVolume pins
	// that). This package has no notion of a pod data volume, so inheriting is
	// the only honest meaning an unset Dir can carry at this layer.
	ChangeDir string
}

// planSpawn resolves spec's working directory, refusing a Dir that is set but
// unusable with ErrWorkingDir.
//
// The directory is checked here, in Go, rather than left to the kernel.
// posix_spawn does surface a failed chdir file-action as its own errno (probed
// on macOS 26.5: ENOENT for a missing directory, ENOTDIR for a plain file), so
// the spawn fails either way — but that errno is indistinguishable from the same
// errno raised by the exec of spec.Path, and an operator cannot tell "your
// workingDir does not exist" from "your binary does not exist". The kernel's own
// refusal still stands behind this one as the TOCTOU backstop for a directory
// removed between this check and the exec; nothing downgrades either refusal to
// a fallback.
func planSpawn(spec SpawnSpec) (spawnPlan, error) {
	dir := spec.Dir
	if dir == "" {
		return spawnPlan{}, nil
	}
	// A relative Dir is refused rather than resolved: resolving it would resolve
	// it against the DAEMON's cwd, which is precisely the inheritance this whole
	// mechanism exists to stop.
	if !filepath.IsAbs(dir) {
		return spawnPlan{}, fmt.Errorf("%w: %q is not an absolute path", ErrWorkingDir, dir)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return spawnPlan{}, fmt.Errorf("%w: stat %q: %w", ErrWorkingDir, dir, err)
	}
	if !fi.IsDir() {
		return spawnPlan{}, fmt.Errorf("%w: %q is not a directory", ErrWorkingDir, dir)
	}
	return spawnPlan{ChangeDir: dir}, nil
}
