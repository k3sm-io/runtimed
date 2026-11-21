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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPodHardLinkFromReadableSourcesUnderSandboxExec measures, under a
// generated pod profile run with sandbox-exec, whether a pod process can make
// a hard link inside its own rootfs to a file it may read but not write. Such
// a link is how a pod would get the daemon, which reads and writes the pod
// tree as root or as the service user, to act on a file the pod cannot act on
// itself (pkg/mount refuses any multiply-linked file it reads or writes; the
// test pins what the profile does underneath that). The sources are a file
// in a read-only host share, in a read-only persistent volume, in an image
// volume's shared artifact view, in one of the pod's own credential mounts
// (granted read-only inside the writable rootfs), a system file the profile
// grants read (on the data volume's volume, so EXDEV is not the answer), and
// in another pod's rootfs; and, as controls the pod may write anyway, a file
// in a read-write host share and in a read-write persistent volume. Each
// attempt links to a fresh name. The results are what was measured on macOS
// 27.2.1 (arm64) and are pinned, so a profile change that moves one is seen.
// The profile is sandbox.Generate's with the options compileProfile passes
// for these grants and a minimal posture; building it through
// Runtime.compileProfile itself needs a Runtime and a host-shares file.
func TestPodHardLinkFromReadableSourcesUnderSandboxExec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Fatalf("sandbox-exec is missing, so nothing can be measured: %v", err)
	}
	base := filepath.Join("/private/tmp", "k3sm-rl-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	otherPod := filepath.Join(work, "pods", "p2", "rootfs")
	roShare := filepath.Join(base, "ro-share")
	rwShare := filepath.Join(base, "rw-share")
	roPV := filepath.Join(base, "storage", "ro-pv")
	rwPV := filepath.Join(base, "storage", "rw-pv")
	view := filepath.Join(work, ArtifactViewsSubdir, strings64("a"), strings64("c"))
	cred := filepath.Join(dataVol, "var", "run", "secrets", "token")
	for _, d := range []string{dataVol, otherPod, roShare, rwShare, roPV, rwPV, view, cred} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:           Posture{WorkDir: work},
		HostShares:        []HostShare{{Path: roShare, ReadOnly: true}, {Path: rwShare}},
		ReadPaths:         []string{roPV},
		WritePaths:        []string{rwPV},
		ArtifactViewPaths: []string{view},
		ReadOnlyPaths:     []string{cred},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "rl.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) error {
		return exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, args...)...).Run()
	}
	link := func(src, name string) bool {
		dst := filepath.Join(dataVol, name)
		if _, err := os.Lstat(dst); err == nil {
			t.Fatalf("%s exists before the attempt; the measurement would be void", dst)
		}
		_ = run("/bin/ln", src, dst)
		fi, err := os.Lstat(dst)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		return ok && st.Nlink > 1
	}
	if !link(filepath.Join(dataVol, "f"), "own-link") {
		t.Fatal("a hard link inside the pod's own rootfs was refused; the measurement is void")
	}
	// A system file the pod may read, on the same volume as the data volume
	// (a link across volumes fails with EXDEV whatever the profile says).
	const system = "/private/etc/ssl/cert.pem" // the system TLS grant
	var sst, dst syscall.Stat_t
	if err := syscall.Stat(system, &sst); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(dataVol, &dst); err != nil {
		t.Fatal(err)
	}
	if sst.Dev != dst.Dev {
		t.Fatalf("%s is on device %d and the data volume on %d; the system case would measure EXDEV", system, sst.Dev, dst.Dev)
	}
	for i, tc := range []struct {
		name, src             string
		wantReadable, wantLnk bool
	}{
		{"a file in a read-only host share", filepath.Join(roShare, "f"), true, false},
		{"a file in a read-write host share", filepath.Join(rwShare, "f"), true, true},
		{"a file in a read-only persistent volume", filepath.Join(roPV, "f"), true, false},
		{"a file in a read-write persistent volume", filepath.Join(rwPV, "f"), true, true},
		{"a system file on the data volume's volume", system, true, false},
		{"a file in an image volume's artifact view", filepath.Join(view, "f"), true, false},
		{"a file in the pod's own credential mount", filepath.Join(cred, "f"), true, false},
		{"a file in another pod's rootfs", filepath.Join(otherPod, "f"), false, false},
	} {
		i := i
		t.Run(tc.name, func(t *testing.T) {
			readable := run("/bin/cat", tc.src) == nil
			linked := link(tc.src, "in-"+strconv.Itoa(i))
			t.Logf("%s: readable under the profile=%v, hard-linked into the rootfs=%v", tc.src, readable, linked)
			if readable != tc.wantReadable {
				t.Errorf("readable = %v, want %v (the case does not set up what it names)", readable, tc.wantReadable)
			}
			if linked != tc.wantLnk {
				t.Errorf("linked = %v, want %v", linked, tc.wantLnk)
			}
		})
	}
}

// strings64 is c repeated to a 64-character hex name.
func strings64(c string) string {
	out := ""
	for len(out) < 64 {
		out += c
	}
	return out
}
