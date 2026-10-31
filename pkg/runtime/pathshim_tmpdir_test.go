//go:build darwin

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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPathShimBuildLeavesNoTempDirs runs hack/build-pathshim.sh with TMPDIR
// pointed at a fresh empty directory and asserts the directory is still empty
// afterwards. Apple clang's driver leaves one empty "<source>-<hex>" directory
// per -arch in TMPDIR on a multi-arch compile, so without the script's own
// scratch TMPDIR every shim build leaks them into the caller's temp dir.
func TestPathShimBuildLeavesNoTempDirs(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Fatalf("clang not on PATH, the path shim cannot be built (this gate must not be skipped): %v", err)
	}
	root := pathShimRepoRoot(t)
	tmp := t.TempDir()
	outDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "hack", "build-pathshim.sh"), outDir)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-pathshim.sh failed: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read TMPDIR %s: %v", tmp, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("build-pathshim.sh left %d entries in TMPDIR: %v", len(names), names)
	}
}
