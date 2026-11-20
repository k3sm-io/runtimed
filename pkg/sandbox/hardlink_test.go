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

// TestPodHardLinkIntoItsRootfsUnderSandboxExec measures, under a generated pod
// profile, whether a pod process can hard-link a file that lies outside its
// rootfs into it: a file in a directory it has no grant on, a file in another
// pod's rootfs, and a file in a host share it may only read. The root-side
// fsGroup walk (supervisor.ChownForFSGroup) changes what it finds in the
// rootfs, so each of these the profile allows is a file the walk must refuse
// on its own. The walk skips every multiply-linked file whatever this test
// measures; the test pins the facts so a profile change that moves them is
// seen.
func TestPodHardLinkIntoItsRootfsUnderSandboxExec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/private/tmp", "k3sm-hl-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	otherPod := filepath.Join(work, "pods", "p2", "rootfs")
	ungranted := filepath.Join(base, "ungranted")
	roShare := filepath.Join(base, "ro")
	for _, d := range []string{dataVol, otherPod, ungranted, roShare} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:    Posture{WorkDir: work},
		HostShares: []HostShare{{Path: roShare, ReadOnly: true}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "hl.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	link := func(src, name string) (linked bool) {
		dst := filepath.Join(dataVol, name)
		_ = exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/ln", src, dst).Run()
		fi, err := os.Lstat(dst)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		return ok && st.Nlink > 1
	}
	// The control: a link between two names inside the pod's own rootfs. If
	// this fails the measurement below proves nothing.
	if !link(filepath.Join(dataVol, "f"), "own-link") {
		t.Fatal("a hard link inside the pod's own rootfs was refused; the measurement is void")
	}
	for _, tc := range []struct {
		name, src  string
		wantDenied bool
	}{
		{"a file in a directory with no grant", filepath.Join(ungranted, "f"), true},
		{"a file in another pod's rootfs", filepath.Join(otherPod, "f"), true},
		{"a file in a read-only host share", filepath.Join(roShare, "f"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			linked := link(tc.src, "in-"+strconv.Itoa(len(tc.name)))
			t.Logf("link %s into the rootfs under the pod profile: linked=%v", tc.src, linked)
			if linked == tc.wantDenied {
				t.Errorf("linked = %v, want denied = %v", linked, tc.wantDenied)
			}
		})
	}
}
