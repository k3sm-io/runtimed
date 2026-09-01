//go:build darwin && cgo

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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// spawnedCwd runs /bin/pwd through the PRODUCTION PosixSpawner + KqueueReaper
// with dir as SpawnSpec.Dir and returns the cwd the child actually reported.
//
// It is a real spawn, in the unit tier, deliberately: the whole subject of B202
// is a posix_spawn FILE ACTION, and a spawner that quietly dropped the action
// (the pre-B202 behaviour, and the first mutant this gate must kill) is
// indistinguishable from a correct one at every seam short of the child's own
// getcwd. /bin/pwd is a stock platform binary, takes no privilege, needs no
// network, and exits immediately.
func spawnedCwd(t *testing.T, dir string) string {
	t.Helper()

	var mu sync.Mutex
	var out []string
	sink := func(b []byte) { mu.Lock(); out = append(out, string(b)); mu.Unlock() }

	p := NewProcess(PosixSpawner{}, KqueueReaper{},
		SpawnSpec{Path: "/bin/pwd", Argv: []string{"/bin/pwd"}, Env: []string{}, Dir: dir}, sink)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start with Dir=%q: %v", dir, err)
	}
	code, _, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait with Dir=%q: %v", dir, err)
	}
	if code != 0 {
		t.Fatalf("/bin/pwd exited %d with Dir=%q", code, dir)
	}
	p.LogsDrained()

	mu.Lock()
	defer mu.Unlock()
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// realPath resolves every symlink in path, so a comparison against a child's
// getcwd is not defeated by macOS's /var -> /private/var firmlink (t.TempDir()
// hands back the /var spelling; the kernel reports the /private/var one).
func realPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	return resolved
}

// TestSpawnHonorsWorkingDir is the B202 gate. It pins the three halves of the
// SpawnSpec.Dir contract at the spawn seam:
//
//   - a set Dir is HONORED — the child's own getcwd is that directory, not the
//     daemon's inherited cwd (red before B202: Dir was documented on SpawnSpec
//     and set by pkg/runtime, but spawn_darwin.go referenced it nowhere, so every
//     pod on every node ran in the daemon's cwd);
//   - an unset Dir INHERITS, and says so — the pod-safe default (the pod data
//     volume) belongs to pkg/runtime, which has the data volume; it is pinned
//     there by TestPodLaunchDefaultsWorkingDirToDataVolume;
//   - a set-but-unusable Dir FAILS typed (ErrWorkingDir) and spawns nothing —
//     never a silent fallback to the inherited cwd.
func TestSpawnHonorsWorkingDir(t *testing.T) {
	t.Run("set dir is honored", func(t *testing.T) {
		dir := realPath(t, t.TempDir())
		if got := spawnedCwd(t, dir); got != dir {
			t.Errorf("child cwd = %q, want the requested Dir %q", got, dir)
		}
		// A second, unrelated directory: a spawner that hard-coded any single
		// path (or chdir'd the daemon once) passes the case above and fails here.
		other := realPath(t, t.TempDir())
		if got := spawnedCwd(t, other); got != other {
			t.Errorf("child cwd = %q, want the requested Dir %q", got, other)
		}
	})

	t.Run("unset dir inherits the caller cwd", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("Getwd: %v", err)
		}
		plan, err := planSpawn(SpawnSpec{Path: "/bin/pwd"})
		if err != nil {
			t.Fatalf("planSpawn with no Dir: %v", err)
		}
		if plan.ChangeDir != "" {
			t.Errorf("ChangeDir = %q, want %q (no chdir file action)", plan.ChangeDir, "")
		}
		if got, want := spawnedCwd(t, ""), realPath(t, wd); got != want {
			t.Errorf("child cwd = %q, want the inherited cwd %q", got, want)
		}
	})

	t.Run("unusable dir fails typed", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cases := []struct {
			name string
			dir  string
		}{
			{"missing", filepath.Join(t.TempDir(), "absent")},
			{"not a directory", file},
			{"relative", "relative/dir"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// planSpawn is the decision; PosixSpawner.Spawn is the seam that
				// must carry it. Both are asserted, so a spawner that dropped the
				// refusal (mutant: ignore planSpawn's error and spawn anyway)
				// cannot pass on planSpawn's verdict alone.
				if _, err := planSpawn(SpawnSpec{Path: "/bin/pwd", Dir: tc.dir}); !errors.Is(err, ErrWorkingDir) {
					t.Errorf("planSpawn error = %v, want ErrWorkingDir", err)
				}
				pid, err := PosixSpawner{}.Spawn(context.Background(),
					SpawnSpec{Path: "/bin/pwd", Argv: []string{"/bin/pwd"}, Dir: tc.dir})
				if !errors.Is(err, ErrWorkingDir) {
					t.Fatalf("Spawn error = %v, want ErrWorkingDir", err)
				}
				if pid != 0 {
					t.Errorf("Spawn returned pid %d; a refused working directory must start nothing", pid)
				}
			})
		}
	})
}
