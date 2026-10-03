//go:build integration && darwin && cgo

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

package supervisor_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// buildPathShim builds the path-rebase shim from this tree's source into dir,
// with the arm64 and arm64e slices (an arm64e re-signed copy refuses an
// inserted library without one).
func buildPathShim(t *testing.T, dir string) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "shim", "pathrebase_shim.c"))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "libk3sm_pathrebase_shim.dylib")
	if b, err := exec.Command("clang", "-arch", "arm64", "-arch", "arm64e", "-dynamiclib", "-fPIC", "-O2",
		"-Wall", "-Wextra", "-o", out, src).CombinedOutput(); err != nil {
		t.Fatalf("build the path shim: %v\n%s", err, b)
	}
	return out
}

// buildSpawner builds an ordinary (ad-hoc signed, not platform, not hardened)
// arm64 main that posix_spawns argv[1:] with its own environment and exits
// with the child's status: the pod process that spawns a platform child.
func buildSpawner(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "spawner.c")
	const prog = `#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc, char **argv) {
	if (argc < 2) return 2;
	pid_t pid;
	int rc = posix_spawn(&pid, argv[1], NULL, NULL, argv + 1, environ);
	if (rc != 0) { fprintf(stderr, "posix_spawn: %d\n", rc); return 126; }
	int st = 0;
	if (waitpid(pid, &st, 0) < 0) return 125;
	return WIFEXITED(st) ? WEXITSTATUS(st) : 124;
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "spawner")
	if b, err := exec.Command("clang", "-arch", "arm64", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("build the spawner: %v\n%s", err, b)
	}
	return bin
}

// TestUnloadedShimChildIsDetected is the gate for restricted-child reporting.
// A pod process with the path shim inserted and /mnt/sec mounted (materialized
// at <dataVol>/mnt/sec) posix_spawns `/bin/cat /mnt/sec/key`. /bin/cat is a
// platform binary: dyld scrubs DYLD_* from it, so it reads the HOST path. The
// gate fails only on SILENCE: either cat printed the key (it was rebased after
// all) or the supervisor's reader returns "/bin/cat".
//
// The spawner runs under the production pod Seatbelt profile, launched through
// the real exec-shim (podProfile/buildShim/shimArgv), with the DYLD and shim
// configuration in the exec-shim's environment, exactly as a container gets
// it. Controls: an ad-hoc re-signed copy of cat as the child keeps the shim,
// reads the key and reports nothing (the predicate is not "every exec"); with
// no K3SM_MOUNT_PATHS nothing is reported (no mount, no divergence).
func TestUnloadedShimChildIsDetected(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Fatalf("clang is required to build the path shim and the spawner: %v", err)
	}
	execShim := buildShim(t)
	profile, dataVol := podProfile(t, "pod-childreport")
	dylib := buildPathShim(t, dataVol)
	spawner := buildSpawner(t, dataVol)
	const secret = "k3sm-childreport-secret"
	if err := os.MkdirAll(filepath.Join(dataVol, "mnt", "sec"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataVol, "mnt", "sec", "key"), []byte(secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, err := supervisor.ChildReportName("app")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dataVol, name)

	// run launches the spawner, under the pod profile, spawning child on
	// /mnt/sec/key, and returns its combined output and what a fresh reader
	// returns from the report afterwards. extra is appended to the env.
	run := func(t *testing.T, child string, mounts bool, extra ...string) (string, []string) {
		t.Helper()
		if err := os.Remove(reportPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		argv := shimArgv(execShim, profile, spawner, child, "/mnt/sec/key")
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = []string{
			"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
			"DYLD_INSERT_LIBRARIES=" + dylib,
			"K3SM_ROOTFS=" + dataVol,
			supervisor.ChildReportEnv + "=" + reportPath,
		}
		if mounts {
			cmd.Env = append(cmd.Env, "K3SM_MOUNT_PATHS=/mnt/sec")
		}
		cmd.Env = append(cmd.Env, extra...)
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		err := cmd.Run()
		t.Logf("%s (mounts=%v): err=%v output=%q", child, mounts, err, buf.String())
		names, perr := supervisor.NewChildReport(dataVol, name, nil).Poll()
		if perr != nil {
			t.Fatalf("Poll: %v", perr)
		}
		t.Logf("reader returned %q", names)
		return buf.String(), names
	}

	t.Run("platform child is read or reported", func(t *testing.T) {
		out, names := run(t, "/bin/cat", true)
		read := strings.Contains(out, secret)
		reported := slices.Contains(names, "/bin/cat")
		if !read && !reported {
			t.Fatalf("SILENT: /bin/cat neither read the mounted key nor was reported (output %q, report %q)", out, names)
		}
		if !read {
			t.Logf("observation: /bin/cat ran without the shim and read the host path; reported as %q", names)
		}
	})

	t.Run("re-signed copy keeps the shim and is not reported", func(t *testing.T) {
		cat := filepath.Join(dataVol, "cat")
		_ = os.Remove(cat)
		if b, err := exec.Command("cp", "-c", "/bin/cat", cat).CombinedOutput(); err != nil {
			t.Fatalf("cp -c: %v\n%s", err, b)
		}
		if b, err := exec.Command("codesign", "-f", "-s", "-", cat).CombinedOutput(); err != nil {
			t.Fatalf("codesign: %v\n%s", err, b)
		}
		out, names := run(t, cat, true)
		if !strings.Contains(out, secret) {
			t.Fatalf("the re-signed copy did not read the mounted key (output %q): the shim did not load into it", out)
		}
		if len(names) != 0 {
			t.Fatalf("the re-signed copy was reported: %q", names)
		}
	})

	t.Run("a full report file is not grown", func(t *testing.T) {
		const full = 64 << 10 // the shim's K3SM_REPORT_MAX_BYTES
		fill := func() {
			if err := os.WriteFile(reportPath, bytes.Repeat([]byte("x"), full), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		argv := shimArgv(execShim, profile, spawner, "/bin/cat", "/mnt/sec/key")
		fill()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = []string{
			"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
			"DYLD_INSERT_LIBRARIES=" + dylib,
			"K3SM_ROOTFS=" + dataVol,
			"K3SM_MOUNT_PATHS=/mnt/sec",
			supervisor.ChildReportEnv + "=" + reportPath,
		}
		_ = cmd.Run() // cat fails on the host path; only the file size matters
		st, err := os.Stat(reportPath)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != full {
			t.Fatalf("report grew past the cap: %d bytes, want %d", st.Size(), full)
		}
	})

	// /bin/cat is on the shadow list, but a copy the interposer will not use
	// (absent, or failing its ownership/mode check) means cat really runs as
	// the platform binary: it must be reported exactly as if it were unlisted.
	t.Run("listed binary with no usable copy is still reported", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			setup func(dir string)
		}{
			{"missing copy", func(string) {}},
			{"group-writable copy", func(dir string) {
				cat := filepath.Join(dir, "cat")
				if b, err := exec.Command("cp", "-c", "/bin/cat", cat).CombinedOutput(); err != nil {
					t.Fatalf("cp -c: %v\n%s", err, b)
				}
				if b, err := exec.Command("codesign", "-f", "-s", "-", cat).CombinedOutput(); err != nil {
					t.Fatalf("codesign: %v\n%s", err, b)
				}
				if err := os.Chmod(cat, 0o775); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := filepath.Join(dataVol, "shadow-"+strings.ReplaceAll(tc.name, " ", "-"))
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				tc.setup(dir)
				out, names := run(t, "/bin/cat", true, "K3SM_SHADOW_DIR="+dir)
				if strings.Contains(out, secret) {
					t.Fatalf("cat read the mounted key: a copy that must not be used was used (output %q)", out)
				}
				if !slices.Contains(names, "/bin/cat") {
					t.Fatalf("SILENT: /bin/cat ran unshimmed with an unusable copy and was not reported (report %q)", names)
				}
			})
		}
	})

	t.Run("no mounts reports nothing", func(t *testing.T) {
		_, names := run(t, "/bin/cat", false)
		if len(names) != 0 {
			t.Fatalf("reported with no K3SM_MOUNT_PATHS: %q", names)
		}
		if _, err := os.Lstat(reportPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("report file created with no mounts: %v", err)
		}
	})
}
