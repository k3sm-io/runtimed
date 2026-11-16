//go:build integration && darwin

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
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The per-pod Darwin user dirs, run for real: confined processes under the
// SHIPPED generator's profile, real links in this user's /var/folders trees, the
// real path-rebase shim. Integration-tagged because it writes (and removes) two
// symlinks per case in the shared trees.
//
// Every case makes the links BEFORE any confined process carries the suffix:
// dirhelper mkdirs a missing suffix dir even for a confined caller, as a
// SIP-protected directory nobody can remove (userdirs.go). Each run uses fresh
// random pod ids, so a leak from an aborted run never collides with the next.

const userDirProbeSrc = `
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
/* write: write a file into the confstr temp dir and print the dir.
 * spawn: posix_spawn "write" with a CURATED envp that lacks the suffix, the
 * way Swift Build launches its link step. */
int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "spawn") == 0) {
		char *cargv[] = {argv[0], "write", NULL};
		char *cenv[] = {"LLBUILD_TASK_ID=1", NULL};
		pid_t pid;
		if (posix_spawn(&pid, argv[0], NULL, NULL, cargv, cenv) != 0) return 3;
		int st = 0;
		waitpid(pid, &st, 0);
		return WIFEXITED(st) ? WEXITSTATUS(st) : 4;
	}
	char dir[1024], path[1100];
	if (confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof dir) == 0) return 5;
	printf("%s\n", dir);
	snprintf(path, sizeof path, "%sprobe.txt", dir);
	FILE *f = fopen(path, "w");
	if (f == NULL) { perror(path); return 1; }
	fputs("ok\n", f);
	return fclose(f) == 0 ? 0 : 2;
}
`

type userDirPod struct {
	id, dataVol, profile, profileNoGrant string
}

func TestConfinedPodUserDirs(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not on PATH")
	}
	temp, cache, err := sandbox.DarwinUserDirs()
	if err != nil {
		t.Skipf("no darwin user dirs: %v", err)
	}
	dirs := resolveDarwinUserDirs(func() (string, string, error) { return temp, cache, nil }, discardInfo{})
	if !dirs.on() {
		t.Fatal("could not resolve the darwin user dirs")
	}
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(work, "/Users/") {
		t.Skipf("TMPDIR resolves under /Users (%s), which the pod profile denies", work)
	}

	newPod := func(t *testing.T) userDirPod {
		t.Helper()
		var b [6]byte
		_, _ = rand.Read(b[:])
		id := "udtest-" + hex.EncodeToString(b[:])
		dataVol := filepath.Join(work, "pods", id, "rootfs")
		if err := provisionPodTmpDir(dataVol); err != nil {
			t.Fatal(err)
		}
		if err := provisionPodUserDirs(dataVol); err != nil {
			t.Fatal(err)
		}
		sfx, _ := sandbox.UserDirSuffix(id)
		tt, ct := podUserDirTargets(dataVol)
		for _, l := range [][2]string{{filepath.Join(dirs.temp, sfx), tt}, {filepath.Join(dirs.cache, sfx), ct}} {
			if err := ensureSymlink(l[0], l[1]); err != nil {
				t.Fatal(err)
			}
			link := l[0]
			t.Cleanup(func() { _ = os.Remove(link) })
		}
		gen := func(name string, u sandbox.UserDirs) string {
			p, err := sandbox.Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol},
				sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: work}, PodUID: id, UserDirs: u})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(work, id+"-"+name+".sb")
			if err := os.WriteFile(path, []byte(p), 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}
		return userDirPod{
			id: id, dataVol: dataVol,
			profile:        gen("grant", sandbox.UserDirs{Temp: dirs.temp, Cache: dirs.cache}),
			profileNoGrant: gen("nogrant", sandbox.UserDirs{}),
		}
	}

	a := newPod(t)
	probe := filepath.Join(a.dataVol, "probe")
	src := filepath.Join(work, "probe.c")
	if err := os.WriteFile(src, []byte(userDirProbeSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-o", probe, src).CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}

	run := func(t *testing.T, profile string, env []string, mode string) (string, error) {
		t.Helper()
		// The env goes through /usr/bin/env, never sandbox-exec's own environ:
		// sandbox-exec is a platform binary, so dyld strips DYLD_* from it and
		// the shim would never reach the probe.
		argv := append([]string{"-f", profile, "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "TMPDIR=" + podTmpDir(a.dataVol)}, env...)
		cmd := exec.Command("/usr/bin/sandbox-exec", append(argv, probe, mode)...)
		cmd.Dir = a.dataVol
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	suffixA, _ := sandbox.UserDirSuffix(a.id)
	tempTargetA, _ := podUserDirTargets(a.dataVol)

	t.Run("green: the suffix resolves into the pod's own data volume", func(t *testing.T) {
		_ = os.Remove(filepath.Join(tempTargetA, "probe.txt"))
		out, err := run(t, a.profile, []string{userDirSuffixEnv + "=" + suffixA}, "write")
		if err != nil {
			t.Fatalf("a confined write through the pod's own link failed: %v\n%s", err, out)
		}
		if _, err := os.Stat(filepath.Join(tempTargetA, "probe.txt")); err != nil {
			t.Errorf("the write did not land in the data volume: %v", err)
		}
	})

	t.Run("red: no suffix, the shared tree stays denied", func(t *testing.T) {
		if out, err := run(t, a.profile, nil, "write"); err == nil {
			t.Fatalf("a confined write to the shared temp tree succeeded; this test no longer proves anything:\n%s", out)
		}
	})

	t.Run("red: no metadata literal, the link does not resolve", func(t *testing.T) {
		if out, err := run(t, a.profileNoGrant, []string{userDirSuffixEnv + "=" + suffixA}, "write"); err == nil {
			t.Fatalf("a confined write through the link succeeded without its grant:\n%s", out)
		}
	})

	t.Run("cross-pod: another pod's suffix reaches nothing", func(t *testing.T) {
		b := newPod(t)
		suffixB, _ := sandbox.UserDirSuffix(b.id)
		if out, err := run(t, a.profile, []string{userDirSuffixEnv + "=" + suffixB}, "write"); err == nil {
			t.Fatalf("pod A wrote through pod B's link:\n%s", out)
		}
		tempTargetB, _ := podUserDirTargets(b.dataVol)
		if _, err := os.Stat(filepath.Join(tempTargetB, "probe.txt")); err == nil {
			t.Error("a file appeared in pod B's data volume")
		}
	})

	t.Run("the shim keeps the suffix across a curated envp", func(t *testing.T) {
		shim := buildPathShim(t)
		// The shim must be readable by the confined process: copy it into the
		// data volume, where a real node's would be under /Library.
		inPod := filepath.Join(a.dataVol, "shim.dylib")
		b, err := os.ReadFile(shim)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inPod, b, 0o644); err != nil {
			t.Fatal(err)
		}
		env := []string{userDirSuffixEnv + "=" + suffixA}
		if out, err := run(t, a.profile, env, "spawn"); err == nil {
			t.Fatalf("the curated child succeeded WITHOUT the shim; the stickiness is not what this measures:\n%s", out)
		}
		if out, err := run(t, a.profile, append(env, dyldInsertEnv+"="+inPod), "spawn"); err != nil {
			t.Fatalf("the curated child failed WITH the shim: %v\n%s", err, out)
		}
	})
}

// TestConfinedSwiftBuildDefaultBuildSystem is the named gate at the
// runtime tier: the default `swift build` (Swift Build) under the shipped
// profile, the pod's links and the real shim, with the Command Line Tools and,
// when present, the Xcode toolchain under its xcode_toolchain_dir grant, where
// `swift test` runs an XCTest target too. The full native-pod run is the lab
// slice.
//
// Swift Testing targets are not used: their macro plugin server looks for
// swift-plugin-server under the host's xcode-select'ed Xcode, outside any
// grant, which is a macro-plugin question and not this one.
func TestConfinedSwiftBuildDefaultBuildSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: Swift Build runs")
	}
	temp, cache, err := sandbox.DarwinUserDirs()
	if err != nil {
		t.Skipf("no darwin user dirs: %v", err)
	}
	dirs := resolveDarwinUserDirs(func() (string, string, error) { return temp, cache, nil }, discardInfo{})
	shimBytes, err := os.ReadFile(buildPathShim(t))
	if err != nil {
		t.Fatal(err)
	}

	const clt = "/Library/Developer/CommandLineTools"
	const xcode = "/Applications/Xcode.app/Contents/Developer"
	for _, tc := range []struct {
		name, devDir, bin string
		grant             bool // the xcode_toolchain_dir grant
		test              bool // also run `swift test` (XCTest)
	}{
		{"command line tools", clt, clt + "/usr/bin", false, false},
		{"xcode toolchain", xcode, xcode + "/Toolchains/XcodeDefault.xctoolchain/usr/bin", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.bin + "/swift-build"); err != nil {
				t.Skipf("no swift-build under %s", tc.bin)
			}
			work, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(work, "/Users/") {
				t.Skipf("TMPDIR resolves under /Users (%s)", work)
			}
			var nb [6]byte
			_, _ = rand.Read(nb[:])
			id := "udswift-" + hex.EncodeToString(nb[:])
			dataVol := filepath.Join(work, "pods", id, "rootfs")
			if err := provisionPodTmpDir(dataVol); err != nil {
				t.Fatal(err)
			}
			if err := provisionPodUserDirs(dataVol); err != nil {
				t.Fatal(err)
			}
			sfx, _ := sandbox.UserDirSuffix(id)
			tt, ct := podUserDirTargets(dataVol)
			for _, l := range [][2]string{{filepath.Join(dirs.temp, sfx), tt}, {filepath.Join(dirs.cache, sfx), ct}} {
				if err := ensureSymlink(l[0], l[1]); err != nil {
					t.Fatal(err)
				}
				link := l[0]
				t.Cleanup(func() { _ = os.Remove(link) })
			}
			sp := &runtimev1.SandboxProfile{DataVolumePath: dataVol}
			if tc.grant {
				sp.XcodeToolchainDir = tc.devDir
			}
			prof, err := sandbox.Generate(sp, sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: work}, PodUID: id,
				UserDirs: sandbox.UserDirs{Temp: dirs.temp, Cache: dirs.cache}})
			if err != nil {
				t.Fatal(err)
			}
			profPath := filepath.Join(work, "pod.sb")
			if err := os.WriteFile(profPath, []byte(prof), 0o644); err != nil {
				t.Fatal(err)
			}
			shim := filepath.Join(dataVol, "shim.dylib")
			if err := os.WriteFile(shim, shimBytes, 0o644); err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Join(dataVol, "hello")
			files := map[string]string{
				"Package.swift":            "// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: \"hello\", targets: [.executableTarget(name: \"hello\"), .testTarget(name: \"helloTests\")])\n",
				"Sources/hello/main.swift": "import Foundation\ntry! \"ok\".write(to: URL(fileURLWithPath: \"atomic.txt\"), atomically: true, encoding: .utf8)\nprint(\"hi from pod\")\n",
				"Tests/helloTests/t.swift": "import XCTest\nfinal class T: XCTestCase { func testTwo() { XCTAssertEqual(1 + 1, 2) } }\n",
			}
			for name, body := range files {
				p := filepath.Join(pkg, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// PATH starts at the toolchain's own bin: /usr/bin/swift is the
			// xcrun shim, a platform binary dyld strips the shim from.
			env := []string{
				"PATH=" + tc.bin + ":/usr/bin:/bin:/usr/sbin:/sbin",
				"HOME=" + dataVol,
				"DEVELOPER_DIR=" + tc.devDir,
				tmpDirEnv + "=" + podTmpDir(dataVol),
				clangModuleCacheEnv + "=" + podModuleCacheDir(dataVol),
				userDirSuffixEnv + "=" + sfx,
				dyldInsertEnv + "=" + shim,
			}
			swift := func(args ...string) (string, error) {
				// Through /usr/bin/env: DYLD_* given to sandbox-exec itself
				// (a platform binary) is stripped.
				argv := append(append([]string{"-f", profPath, "/usr/bin/env", "-i"}, env...), tc.bin+"/swift")
				cmd := exec.Command("/usr/bin/sandbox-exec", append(argv, args...)...)
				cmd.Dir = pkg
				out, err := cmd.CombinedOutput()
				return string(out), err
			}
			if out, err := swift("build", "--disable-sandbox"); err != nil {
				t.Fatalf("confined swift build (default build system) failed: %v\n%s", err, out)
			}
			if tc.test {
				if out, err := swift("test", "--disable-sandbox"); err != nil {
					t.Fatalf("confined swift test failed: %v\n%s", err, out)
				}
			}
		})
	}
}

// discardInfo satisfies resolveDarwinUserDirs' logger.
type discardInfo struct{}

func (discardInfo) Info(string, ...any) {}
