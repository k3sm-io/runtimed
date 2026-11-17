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

// foundationAtomicProbeSrc writes the two ways Foundation reaches the
// replacement directory, in the order swift build does: an atomic Data write,
// then an explicit itemReplacementDirectory request, for a file in the pod's
// own tree. It prints the directory Foundation chose and exits non-zero on the
// first failure.
const foundationAtomicProbeSrc = `
import Foundation
let dir = URL(fileURLWithPath: CommandLine.arguments[1])
do {
	try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
	try Data("one".utf8).write(to: dir.appendingPathComponent("atomic.json"), options: .atomic)
	print("atomic ok")
	let r = try FileManager.default.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: dir, create: true)
	print("replacement \(r.path)")
	let tmp = r.appendingPathComponent("manifest.json")
	try Data("two".utf8).write(to: tmp)
	_ = try FileManager.default.replaceItemAt(dir.appendingPathComponent("atomic.json"), withItemAt: tmp)
	print("replace ok")
} catch {
	print("FAIL \(error)")
	exit(1)
}
`

// attachScratchVolume creates and mounts a small APFS volume under dir, which
// is what /var/lib/k3sm is on a node (the k3sm-pods volume): a path there is on
// a different volume from the user temp dir, so Foundation puts its replacement
// directory at THAT volume's root. hdiutil needs no root for an image the user
// owns.
func attachScratchVolume(t *testing.T, dir string) string {
	t.Helper()
	img := filepath.Join(dir, "vol")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-size", "64m", "-fs", "APFS", "-type", "SPARSE", "-volname", "k3smtest", img).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create: %v: %s", err, out)
	}
	mnt := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("hdiutil", "attach", "-quiet", "-nobrowse", "-mountpoint", mnt, img+".sparseimage").CombinedOutput(); err != nil {
		t.Skipf("hdiutil attach: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("hdiutil", "detach", "-quiet", "-force", mnt).Run() })
	return mnt
}

// TestConfinedFoundationAtomicWriteOnSeparateVolume is the gate for a confined
// atomic write on a separate volume. A pod data volume on its own APFS volume
// (as /var/lib/k3sm is) runs a Foundation probe under the SHIPPED profile with
// the real path-rebase shim and the env the runtime gives every container.
// Foundation's replacement directory for a file there is <volume
// root>/.TemporaryItems/folders.<uid>, one directory per uid that every pod of
// the node would share, so the profile denies it and an atomic write failed
// EPERM (swift build's "unable to write manifest"). The shim redirects that
// directory into the pod's own data volume, and the test asserts the probe
// succeeds, that the directory it was given is the pod's, and that nothing was
// created in the shared one.
func TestConfinedFoundationAtomicWriteOnSeparateVolume(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	if _, err := exec.LookPath("swiftc"); err != nil {
		t.Skip("swiftc not on PATH")
	}
	temp, cache, err := sandbox.DarwinUserDirs()
	if err != nil {
		t.Skipf("no darwin user dirs: %v", err)
	}
	dirs := resolveDarwinUserDirs(func() (string, string, error) { return temp, cache, nil }, discardInfo{})
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(base, "/Users/") {
		t.Skipf("TMPDIR resolves under /Users (%s)", base)
	}
	shim := buildPathShim(t)
	probe := filepath.Join(base, "foundation-probe")
	src := filepath.Join(base, "probe.swift")
	if err := os.WriteFile(src, []byte(foundationAtomicProbeSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("swiftc", "-o", probe, src).CombinedOutput(); err != nil {
		t.Fatalf("swiftc: %v: %s", err, out)
	}

	work := attachScratchVolume(t, base)
	var nb [6]byte
	_, _ = rand.Read(nb[:])
	id := "fdnatomic-" + hex.EncodeToString(nb[:])
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
	vol, err := statfsMountPoint(work)
	if err != nil {
		t.Fatal(err)
	}
	shared, ok := sandbox.SharedVolumeTempDir(vol)
	if !ok {
		t.Fatalf("no shared replacement dir for a data volume on its own APFS volume (%s)", vol)
	}
	prof, err := sandbox.Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol},
		sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: work, WorkVolume: vol}, PodUID: id,
			UserDirs: sandbox.UserDirs{Temp: dirs.temp, Cache: dirs.cache}})
	if err != nil {
		t.Fatal(err)
	}
	profPath := filepath.Join(base, "pod.sb")
	if err := os.WriteFile(profPath, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	inPod := filepath.Join(dataVol, "probe")
	if b, err := os.ReadFile(probe); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(inPod, b, 0o755); err != nil {
		t.Fatal(err)
	}

	// The shim is read from inside the data volume, which the profile grants,
	// as the node stages it under a granted path.
	insert := filepath.Join(dataVol, "shim.dylib")
	copyFile := func(src, dst string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(shim, insert)
	if tr := os.Getenv("K3SM_TEST_TRACE_DYLIB"); tr != "" {
		copyFile(tr, filepath.Join(dataVol, "trace.dylib"))
		insert += ":" + filepath.Join(dataVol, "trace.dylib")
	}
	env := []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + dataVol,
		tmpDirEnv + "=" + podTmpDir(dataVol),
		userDirSuffixEnv + "=" + sfx,
		dyldInsertEnv + "=" + insert,
		// What containerEnv gives a container with no volume mount.
		pathShimRootfsEnv + "=" + dataVol,
		pathShimMountsEnv + "=" + shared,
	}
	// Through /usr/bin/env: DYLD_* given to sandbox-exec itself (a platform
	// binary) is stripped.
	argv := append(append([]string{"-f", profPath, "/usr/bin/env", "-i"}, env...), inPod, filepath.Join(dataVol, "work"))
	cmd := exec.Command("/usr/bin/sandbox-exec", argv...)
	cmd.Dir = dataVol
	out, err := cmd.CombinedOutput()
	t.Logf("probe:\n%s", out)
	if err != nil {
		t.Fatalf("confined Foundation atomic write on a separate volume failed: %v", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if p, ok := strings.CutPrefix(l, "replacement "); ok && !strings.HasPrefix(p, dataVol+"/") {
			t.Fatalf("replacement directory %s is outside the pod data volume %s", p, dataVol)
		}
	}
	if ents, err := os.ReadDir(filepath.Join(work, ".TemporaryItems")); err == nil && len(ents) > 0 {
		t.Fatalf("the shared %s/.TemporaryItems was used: %v", work, ents)
	}
}
