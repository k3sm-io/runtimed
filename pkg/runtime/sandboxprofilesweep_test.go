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

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestStartupSweepsStaleSandboxProfiles is the B275 leak contract: a daemon
// killed without teardown leaves one staged per-pod SBPL file per live pod, and
// nothing on the node ever removed them. The startup reap now sweeps them.
//
// The test drives the REAL sandbox backend (not a fake) through the production
// startup hook, because the leak is a property of where the staging happens and
// where the sweep is called — a fake sweeper would assert only that the hook
// calls something. It seeds both layouts: the current <root>/sbpl/ staging dir
// and the legacy top-level <root>/ files older hosts still carry. It also pins
// the two halves the sweep must NOT do: touch a non-profile file at either
// level, and run late enough to eat a profile this daemon staged.
func TestStartupSweepsStaleSandboxProfiles(t *testing.T) {
	root := t.TempDir()

	// A fake shim file is enough: Available() stats it, and this test never
	// spawns. The real helper is exercised by the darwin integration tier.
	shim := filepath.Join(root, sandbox.ExecShimName)
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	backend, err := sandbox.NewExecShimBackend(shim, root)
	if err != nil {
		t.Fatal(err)
	}

	sbplDir := filepath.Join(root, sandbox.ProfileSubdir)
	if err := os.MkdirAll(sbplDir, 0o700); err != nil {
		t.Fatal(err)
	}
	staleTop := filepath.Join(root, "k3sm-sbpl-aaa.sb")
	staleDir := filepath.Join(sbplDir, "k3sm-sbpl-bbb.sb")
	// The negative controls: one unrelated file at each level. Without them a
	// sweep that deleted the whole directory would pass.
	keepTop := filepath.Join(root, "keep-me.txt")
	keepDir := filepath.Join(sbplDir, "keep-me.txt")
	for _, p := range []string{staleTop, staleDir, keepTop, keepDir} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	rt := newTestRuntimeCfg(t, Config{Root: root}, Deps{Backend: backend})
	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}

	for _, p := range []string{staleTop, staleDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale profile %s survived the startup sweep (stat err = %v)", p, err)
		}
	}
	for _, p := range []string{keepTop, keepDir} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("unrelated file %s was removed by the sweep: %v", p, err)
		}
	}

	// The sweep ran exactly once, BEFORE any pod could be served: a profile
	// staged after it must survive under <root>/sbpl. This is the ordering the
	// "everything present is stale" argument rests on — a sweep called from a
	// later hook would delete a live pod's profile out from under its shim.
	t.Run("a profile staged after the sweep survives", func(t *testing.T) {
		if !backend.Available() {
			t.Skip("exec-shim backend unavailable on this host (darwin + macOS 26 gate)")
		}
		profile, err := sandbox.Generate(&runtimev1.SandboxProfile{
			DataVolumePath: filepath.Join(root, "pods", "p1", "rootfs"),
		}, sandbox.GenerateOptions{Posture: sandbox.Posture{
			WorkDir:    root,
			PodLogsDir: filepath.Join(root, "podlogs"),
		}})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		_, argv, cleanup, err := backend.WrapCommand(context.Background(), profile, []string{"/bin/echo"}, supervisor.LaunchSpec{})
		if err != nil {
			t.Fatalf("WrapCommand: %v", err)
		}
		defer func() { _ = cleanup() }()
		staged := argv[len(argv)-2]
		if got := filepath.Dir(staged); got != sbplDir {
			t.Errorf("profile staged at %s, want a file under %s", staged, sbplDir)
		}
		if _, err := os.Stat(staged); err != nil {
			t.Errorf("freshly staged profile %s is missing: %v", staged, err)
		}
		// 0600: hygiene against other local users, not a pod boundary (the
		// Seatbelt deny on <root>/sbpl is the boundary).
		fi, err := os.Stat(staged)
		if err == nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("staged profile mode = %v, want 0600", fi.Mode().Perm())
		}
	})
}
