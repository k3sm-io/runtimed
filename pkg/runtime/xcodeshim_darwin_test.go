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
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/shadowset"
)

// fillArgvHarness is a C program that compiles the interposer's own source
// in and drives its DIRECT argv fill for one copy name: it prints the
// rewritten argv, one argument per line. Including the .c file reaches the
// static k3sm_fill_argv without a test hook in the product; the interposer
// table in a main executable is inert (dyld applies __interpose only from a
// loaded library).
const fillArgvHarness = `#include "pathrebase_shim.c"
int main(int argc, char **argv) {
    k3sm_exec_plan_t pl;
    memset(&pl, 0, sizeof pl);
    pl.kind = K3SM_EXEC_DIRECT;
    pl.copy = argv[1];
    char *nargv[argc + 3 + K3SM_SHADOW_APPEND_MAX];
    k3sm_fill_argv(&pl, argv + 2, (size_t)(argc - 2), nargv);
    for (size_t i = 0; nargv[i] != NULL; i++) {
        printf("%s\n", nargv[i]);
    }
    return 0;
}
`

// TestShimAppendsTheCopysArgs is the gate on the interposer half of the
// xcodebuild nested-sandbox defaults, and on its parity with the Go twin: for
// each case the C fill and shadowset.AppendFor (which shadowRewrite applies on
// the runtime's own spawn) give the same argv, and the expected one.
func TestShimAppendsTheCopysArgs(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH: %v", err)
	}
	root := pathShimRepoRoot(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(src, []byte(fillArgvHarness), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "harness")
	build := exec.Command("clang", "-w", "-I", filepath.Join(root, "shim"), "-o", bin, src)
	build.Env = append(os.Environ(), "TMPDIR="+dir)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the fill harness: %v\n%s", err, out)
	}
	const (
		manifest = "-IDEPackageSupportDisableManifestSandbox=YES"
		plugins  = "-IDEPackageSupportDisablePluginExecutionSandbox=YES"
		swiftc   = "SWIFTC_DISABLE_SANDBOX=YES"
	)
	for _, tc := range []struct {
		name string
		copy string
		argv []string
		want []string
	}{
		{"a build gets all three", "xcodebuild",
			[]string{"xcodebuild", "-scheme", "App", "build"},
			[]string{"xcodebuild", "-scheme", "App", "build", manifest, plugins, swiftc}},
		{"a bare xcodebuild builds too", "xcodebuild",
			[]string{"xcodebuild"},
			[]string{"xcodebuild", manifest, plugins, swiftc}},
		{"the caller's own values win", "xcodebuild",
			[]string{"xcodebuild", "-IDEPackageSupportDisableManifestSandbox=NO", "SWIFTC_DISABLE_SANDBOX=NO", "-list"},
			[]string{"xcodebuild", "-IDEPackageSupportDisableManifestSandbox=NO", "SWIFTC_DISABLE_SANDBOX=NO", "-list", plugins}},
		{"a tool mode gets no build setting", "xcodebuild",
			[]string{"xcodebuild", "-create-xcframework", "-output", "x"},
			[]string{"xcodebuild", "-create-xcframework", "-output", "x", manifest, plugins}},
		{"a key in argv[0] does not count", "xcodebuild",
			[]string{"SWIFTC_DISABLE_SANDBOX=NO"},
			[]string{"SWIFTC_DISABLE_SANDBOX=NO", manifest, plugins, swiftc}},
		{"another copy gets nothing", "bash",
			[]string{"sh", "-c", "true"},
			[]string{"sh", "-c", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(bin, append([]string{tc.copy}, tc.argv...)...).Output()
			if err != nil {
				t.Fatalf("harness: %v", err)
			}
			gotC := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
			if strings.Join(gotC, "\x00") != strings.Join(tc.want, "\x00") {
				t.Errorf("interposer argv = %q, want %q", gotC, tc.want)
			}
			if gotGo := shadowset.AppendFor(tc.copy, tc.argv); strings.Join(gotGo, "\x00") != strings.Join(tc.want, "\x00") {
				t.Errorf("shadowset.AppendFor = %q, want %q (the twins disagree)", gotGo, tc.want)
			}
		})
	}
}

// TestShimRefusesARequiredHostWithoutItsCopy: on a node with a shadow set, an
// exec of Xcode's xcodebuild whose copy is not usable (here: a shadow dir that
// fails the trust check, as a missing copy does) is refused with a message
// naming sudo k3sm install, instead of running the original, which in a pod
// hangs or fails without naming the cause. A required host's exec is refused
// before the kernel sees it, so the test needs no Xcode.
func TestShimRefusesARequiredHostWithoutItsCopy(t *testing.T) {
	shim := buildPathShim(t)
	// The caller is built here, ad hoc signed by the linker, so dyld keeps
	// the inserted shim in it (a platform binary such as /bin/sh would drop
	// it and prove nothing).
	dir := t.TempDir()
	src := filepath.Join(dir, "caller.c")
	if err := os.WriteFile(src, []byte(`#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) { execv(argv[1], argv + 1); perror("exec"); return 127; }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	caller := filepath.Join(dir, "caller")
	build := exec.Command("clang", "-o", caller, src)
	build.Env = append(os.Environ(), "TMPDIR="+dir)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the exec caller: %v\n%s", err, out)
	}
	cmd := exec.Command(caller, shadowset.XcodebuildSource, "-version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", dyldInsertEnv + "=" + shim, shadowDirEnv + "=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the exec ran:\n%s", out)
	}
	if !strings.Contains(string(out), "k3sm: refusing to run "+shadowset.XcodebuildSource) ||
		!strings.Contains(string(out), "sudo k3sm install") {
		t.Errorf("no refusal naming the fix:\n%s", out)
	}

	// The contrast: an exec of a host that is not Required falls through to
	// the host binary as before (here /usr/bin/true, which has no copy).
	ok := exec.Command(caller, "/usr/bin/true")
	ok.Env = cmd.Env
	if out, err := ok.CombinedOutput(); err != nil {
		t.Errorf("a non-required exec was refused: %v\n%s", err, out)
	}
}
