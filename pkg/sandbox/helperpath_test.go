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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realPath resolves p through every symlink so two spellings of one file
// compare equal (macOS temp dirs sit behind /var -> /private/var).
func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", p, err)
	}
	return r
}

// findHelperEnv makes a re-exec of the test binary print FindExecShim's result
// instead of running the gate (see TestFindExecShimThroughSymlink).
const findHelperEnv = "K3SM_SANDBOX_TEST_PRINT_FIND_EXECSHIM"

// TestFindExecShimThroughSymlink pins that the helper lookup resolves the
// executable through symlinks. On darwin os.Executable reports the path as
// invoked, so a binary run via an install symlink (/usr/local/bin/k3sm) must
// still find the helpers beside its real location.
func TestFindExecShimThroughSymlink(t *testing.T) {
	if os.Getenv(findHelperEnv) == "1" {
		p, err := FindExecShim()
		if err != nil {
			os.Stdout.WriteString("ERR " + err.Error() + "\n")
			return
		}
		os.Stdout.WriteString("FOUND " + p + "\n")
		return
	}

	for _, name := range []string{ExecShimName, VMHostName} {
		t.Run(name, func(t *testing.T) {
			realDir := t.TempDir()
			linkDir := t.TempDir()
			realExe := filepath.Join(realDir, "k3sm")
			writeFile(t, realExe, "x")
			writeFile(t, filepath.Join(realDir, name), "x")

			linkExe := filepath.Join(linkDir, "k3sm")
			if err := os.Symlink(realExe, linkExe); err != nil {
				t.Fatal(err)
			}
			dangling := filepath.Join(linkDir, "dangling")
			if err := os.Symlink(filepath.Join(realDir, "gone"), dangling); err != nil {
				t.Fatal(err)
			}

			// The naive (pre-fix) candidate beside the link must not exist, or
			// the symlinked case below would pass without exercising resolution.
			if _, err := os.Stat(filepath.Join(filepath.Dir(linkExe), name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("naive candidate beside the link exists (err=%v): fixture does not exercise symlinks", err)
			}

			want := realPath(t, filepath.Join(realDir, name))
			cases := []struct {
				desc   string
				exe    string
				helper string
				found  bool
			}{
				{"direct invocation", realExe, name, true},
				{"symlinked invocation", linkExe, name, true},
				{"dangling symlink falls back and misses", dangling, name, false},
				{"helper missing", linkExe, name + "-missing", false},
			}
			for _, tc := range cases {
				t.Run(tc.desc, func(t *testing.T) {
					got, ok := siblingOf(tc.exe, tc.helper)
					if ok != tc.found {
						t.Fatalf("siblingOf(%s, %s) found = %v (cand %q), want %v", tc.exe, tc.helper, ok, got, tc.found)
					}
					if tc.found && realPath(t, got) != want {
						t.Errorf("siblingOf(%s, %s) = %q, want %q", tc.exe, tc.helper, got, want)
					}
				})
			}
		})
	}

	t.Run("end to end through a symlinked test binary", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Skipf("os.Executable: %v", err)
		}
		realExe := realPath(t, exe)
		shim := filepath.Join(filepath.Dir(realExe), ExecShimName)
		if _, err := os.Lstat(shim); err == nil {
			t.Skipf("%s already exists beside the test binary; refusing to clobber it", shim)
		}
		if err := os.WriteFile(shim, []byte("x"), 0o755); err != nil {
			t.Skipf("test binary dir not writable: %v", err)
		}
		t.Cleanup(func() { _ = os.Remove(shim) })

		linkExe := filepath.Join(t.TempDir(), "k3sm")
		if err := os.Symlink(realExe, linkExe); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(linkExe, "-test.run=^TestFindExecShimThroughSymlink$")
		// An empty PATH rules out the LookPath fallback, so only the
		// beside-the-executable candidate can satisfy the lookup.
		cmd.Env = append(os.Environ(), findHelperEnv+"=1", "PATH="+t.TempDir())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("re-exec through symlink: %v\n%s", err, out)
		}
		var got string
		for _, line := range strings.Split(string(out), "\n") {
			if p, ok := strings.CutPrefix(line, "FOUND "); ok {
				got = p
			}
		}
		if got == "" {
			t.Fatalf("FindExecShim did not find the helper through the symlink:\n%s", out)
		}
		if realPath(t, got) != realPath(t, shim) {
			t.Errorf("FindExecShim() = %q, want %q", got, shim)
		}
	})
}
