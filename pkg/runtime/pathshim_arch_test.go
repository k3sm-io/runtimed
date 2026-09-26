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
	"context"
	"debug/macho"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"
)

// pathShimRepoRoot returns the runtimed repo root from this file's location.
func pathShimRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	// .../runtimed/pkg/runtime/pathshim_arch_test.go -> .../runtimed
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// requireX86_64Capable skips the test when this toolchain cannot emit an x86_64
// slice at all (no clang, or no x86_64 SDK support). It compiles a throwaway
// dylib rather than assuming, so the difference between "the environment cannot
// build the slice" (legible skip) and "the build script did not ask for the
// slice" (failure) is decided by evidence, not by inference.
func requireX86_64Capable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH, cannot build the shim at all: %v", err)
	}
	src := filepath.Join(t.TempDir(), "probe.c")
	if err := os.WriteFile(src, []byte("int k3sm_arch_probe(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatalf("write arch probe source: %v", err)
	}
	out := filepath.Join(filepath.Dir(src), "probe.dylib")
	cmd := exec.Command("clang", "-arch", "x86_64", "-dynamiclib", "-o", out, src)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("SKIP: this toolchain cannot emit an x86_64 slice (no x86_64 SDK support?), "+
			"so the universal-shim assertion is untestable here: %v\n%s", err, combined)
	}
}

// machoArches returns the CPU architectures present in the Mach-O at path,
// whether it is a fat (universal) file or a single-arch one.
func machoArches(t *testing.T, path string) []macho.Cpu {
	t.Helper()
	fat, err := macho.OpenFat(path)
	if err == nil {
		defer func() { _ = fat.Close() }()
		arches := make([]macho.Cpu, 0, len(fat.Arches))
		for _, a := range fat.Arches {
			arches = append(arches, a.Cpu)
		}
		return arches
	}
	if !errors.Is(err, macho.ErrNotFat) {
		t.Fatalf("read %s as a fat Mach-O: %v", path, err)
	}
	thin, err := macho.Open(path)
	if err != nil {
		t.Fatalf("read %s as a Mach-O: %v", path, err)
	}
	defer func() { _ = thin.Close() }()
	return []macho.Cpu{thin.Cpu}
}

// TestPathShimIsUniversalBinary asserts the built path-rebase shim carries both
// an arm64 and an x86_64 slice, by reading the Mach-O headers of the artifact
// hack/build-pathshim.sh actually produces.
//
// It reads the artifact and never greps the build script, on purpose: the bug
// this gate fixes (B166) was a build script whose prose promised a fat dylib
// while its flags passed only -arch arm64. A script-grep gate would have passed
// for the whole life of that bug, and would pass again the moment someone edits
// the comment back. The artifact cannot lie.
//
// Why it matters: dyld HARD-TERMINATES a process whose DYLD_INSERT_LIBRARIES
// library has no slice for that process's architecture, so an arm64-only shim
// kills a darwin/amd64 pod payload under Rosetta rather than merely dropping
// path rebasing.
func TestPathShimIsUniversalBinary(t *testing.T) {
	requireX86_64Capable(t)

	root := pathShimRepoRoot(t)
	outDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "hack", "build-pathshim.sh"), outDir)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-pathshim.sh failed: %v\n%s", err, out)
	}
	dylib := filepath.Join(outDir, "libk3sm_pathrebase_shim.dylib")
	if _, err := os.Stat(dylib); err != nil {
		t.Fatalf("path-rebase shim dylib not produced: %v", err)
	}

	arches := machoArches(t, dylib)
	want := map[macho.Cpu]bool{macho.CpuArm64: false, macho.CpuAmd64: false}
	for _, a := range arches {
		if _, ok := want[a]; ok {
			want[a] = true
		}
	}
	for cpu, found := range want {
		if !found {
			t.Errorf("built shim %s is missing the %s slice; it has %v. "+
				"dyld hard-terminates a process whose inserted library lacks its arch — "+
				"hack/build-pathshim.sh must pass both -arch arm64 and -arch x86_64",
				filepath.Base(dylib), cpu, arches)
		}
	}
}

// buildPathShim builds the path-rebase shim with hack/build-pathshim.sh into a
// temp dir and returns the dylib, skipping (never passing) when clang is
// absent, since then there is no artifact to test.
func buildPathShim(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("SKIP: clang not on PATH, the path shim cannot be built: %v", err)
	}
	root := pathShimRepoRoot(t)
	outDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "hack", "build-pathshim.sh"), outDir)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-pathshim.sh failed: %v\n%s", err, out)
	}
	dylib := filepath.Join(outDir, "libk3sm_pathrebase_shim.dylib")
	if _, err := os.Stat(dylib); err != nil {
		t.Fatalf("path-rebase shim dylib not produced: %v", err)
	}
	return dylib
}

// TestPathShimLoadsIntoArm64e is the arm64e canary: it builds a tiny arm64e
// executable at test time, ad-hoc signs it, and runs it with the BUILT shim in
// DYLD_INSERT_LIBRARIES, asserting dyld loads the shim instead of terminating
// the process for a missing architecture.
//
// Why a live load and not the header check TestPathShimIsUniversalBinary
// makes: debug/macho exposes a fat slice's Cpu but not its SubCpu, and arm64
// and arm64e share Cpu (CPU_TYPE_ARM64), differing only in the subtype, so the
// headers cannot tell the two apart from Go. And a present slice is not a
// loadable one: Apple does not promise a stable arm64e ABI for third-party
// code, so a toolchain or OS change could leave a slice dyld rejects. Only a
// load answers that. Why it matters: Apple ships /bin/bash, /bin/zsh,
// /bin/dash and /usr/bin/env as arm64e, so the node's re-signed shell copies
// are arm64e processes, and an arm64e process refuses an arm64-only inserted
// library by SIGABRT: every shadow-shell exec would die.
func TestPathShimLoadsIntoArm64e(t *testing.T) {
	if goruntime.GOARCH != "arm64" {
		t.Skipf("SKIP: arm64e processes need an Apple silicon host (GOARCH=%s)", goruntime.GOARCH)
	}
	dylib := buildPathShim(t)

	dir := t.TempDir()
	src := filepath.Join(dir, "probe.c")
	if err := os.WriteFile(src, []byte("int main(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "probe-arm64e")
	if out, err := exec.Command("clang", "-arch", "arm64e", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("SKIP: this toolchain cannot emit an arm64e executable: %v\n%s", err, out)
	}
	if err := image.AdHocSign(context.Background(), bin); err != nil {
		t.Fatalf("ad-hoc sign the arm64e probe: %v", err)
	}
	// Control: the probe itself must run, or a failure below would be about
	// the probe, not the shim.
	if out, err := exec.Command(bin).CombinedOutput(); err != nil {
		t.Skipf("SKIP: this host will not run an ad-hoc arm64e executable at all: %v\n%s", err, out)
	}

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), dyldInsertEnv+"="+dylib)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "incompatible architecture") || strings.Contains(string(out), "missing compatible architecture") {
		t.Fatalf("dyld refused the shim in an arm64e process (hack/build-pathshim.sh must pass -arch arm64e):\n%s", out)
	}
	if err != nil {
		t.Fatalf("arm64e probe with the shim inserted failed: %v\n%s", err, out)
	}
}
