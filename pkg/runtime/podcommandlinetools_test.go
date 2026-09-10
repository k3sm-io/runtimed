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
)

// TestConfinedCommandLineToolsNeedNoToolchainGrant pins the dependency the
// developer-dir decision rests on: a pod whose DEVELOPER_DIR names the Command
// Line Tools compiles and links with NO xcode_toolchain_dir grant of any kind.
//
// That is why a node whose active selection is the Command Line Tools stamps no
// grant at all instead of stamping a value the generator refuses. The reason it
// works is NOT a scoped exception for the toolchain: the base profile grants
// file-read* over /System, /usr, /bin and /Library wholesale (sandbox.Generate's
// read set), and /Library/Developer/CommandLineTools falls inside the last of
// those. A future pass narrowing that read set — a reasonable thing to want,
// since it is broader than DESIGN.md's stated baseline — would silently take
// the Command Line Tools away from every pod, and the only visible symptom
// would be annotated pods failing on nodes without Xcode.
//
// So this test is a regression pin rather than a proof of new behaviour: it is
// green before and after the change it accompanies, and its job is to go red
// the day that read set narrows. Its non-vacuity was checked by mutation —
// dropping "/Library" from the base read set turns it red.
func TestConfinedCommandLineToolsNeedNoToolchainGrant(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	const cltDir = "/Library/Developer/CommandLineTools"
	if _, err := os.Stat(filepath.Join(cltDir, "usr", "bin", "swiftc")); err != nil {
		t.Skipf("no Command Line Tools install at %s", cltDir)
	}
	// The /usr/bin shim, not the Command Line Tools binary directly: it is what
	// a pod finds on its PATH, and it is the thing that consults DEVELOPER_DIR
	// to pick a toolchain and an SDK. Invoking the CLT swiftc directly skips
	// that resolution and needs an explicit -sdk, which would make this test
	// about a flag rather than about what a pod can reach.
	const swiftc = "/usr/bin/swiftc"
	if _, err := os.Stat(swiftc); err != nil {
		t.Skipf("no %s on this host", swiftc)
	}

	work := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(work); err == nil {
		work = resolved
	}
	if strings.HasPrefix(work, "/Users/") {
		t.Skipf("TMPDIR resolves under /Users (%s), which the pod profile denies", work)
	}
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	if err := os.MkdirAll(podModuleCacheDir(dataVol), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataVol, "main.swift"), []byte("print(\"hello from a pod\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// No XcodeToolchainDir: the profile carries no toolchain stanza at all.
	profile, err := generateTestPodProfile(dataVol, work)
	if err != nil {
		t.Fatalf("generate profile: %v", err)
	}
	if strings.Contains(profile, cltDir) {
		t.Fatalf("the profile names %s; this test only means something when nothing granted it:\n%s", cltDir, profile)
	}
	profPath := filepath.Join(work, "pod.sb")
	if err := os.WriteFile(profPath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/usr/bin/sandbox-exec", "-f", profPath, swiftc, "-o", "clt", "main.swift")
	cmd.Dir = dataVol
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + dataVol,
		developerDirEnv + "=" + cltDir,
		tmpDirEnv + "=" + podTmpDir(dataVol),
		clangModuleCacheEnv + "=" + podModuleCacheDir(dataVol),
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("a confined swiftc with %s=%s and no toolchain grant failed (%v):\n%s", developerDirEnv, cltDir, err, out)
	}
	if _, err := os.Stat(filepath.Join(dataVol, "clt")); err != nil {
		t.Fatalf("the compile reported success but produced no binary: %v", err)
	}
}
