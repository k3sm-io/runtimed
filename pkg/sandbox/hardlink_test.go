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
	"strings"
	"syscall"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPodHardLinkIntoItsRootfsUnderSandboxExec measures, under a generated pod
// profile, whether a pod process can hard-link a file that lies outside its
// rootfs into it: a file in a directory it has no grant on, a file in another
// pod's rootfs, a file in a host share it may only read, and a file in a host
// share it may write (allowed: measured, the link is made). The root-side
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
	rwShare := filepath.Join(base, "rw")
	for _, d := range []string{dataVol, otherPod, ungranted, roShare, rwShare} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:    Posture{WorkDir: work},
		HostShares: []HostShare{{Path: roShare, ReadOnly: true}, {Path: rwShare}},
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
		{"a file in a read-write host share", filepath.Join(rwShare, "f"), false},
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

// TestPodRenameIntoItsRootfsUnderSandboxExec measures, under a generated pod
// profile, whether a pod process can rename a file or a directory that lies
// outside its rootfs into it. A renamed entry keeps one link, so the fsGroup
// walk's hard-link skip does not see it; the walk's owner check
// (supervisor.ChownForFSGroup) is what keeps another tenant's entry from
// being regrouped. The test records what the profile does and pins it, so a
// profile change that moves a case is seen.
func TestPodRenameIntoItsRootfsUnderSandboxExec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/private/tmp", "k3sm-rn-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	otherPod := filepath.Join(work, "pods", "p2", "rootfs")
	ungranted := filepath.Join(base, "ungranted")
	roShare := filepath.Join(base, "ro")
	rwShare := filepath.Join(base, "rw")
	for _, d := range []string{dataVol, otherPod, ungranted, roShare, rwShare} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A file straight in /private/tmp, outside every directory the test
	// grants or names.
	tmpTop := filepath.Join("/private/tmp", "k3sm-rn-"+strconv.Itoa(os.Getpid())+"-top")
	t.Cleanup(func() { _ = os.RemoveAll(tmpTop) })
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:    Posture{WorkDir: work},
		HostShares: []HostShare{{Path: roShare, ReadOnly: true}, {Path: rwShare}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "rn.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	// rename moves src into the rootfs under the profile and reports whether
	// it arrived and left its old name.
	rename := func(t *testing.T, src, name string) (moved bool) {
		t.Helper()
		dst := filepath.Join(dataVol, name)
		_ = exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/mv", src, dst).Run()
		_, errDst := os.Lstat(dst)
		_, errSrc := os.Lstat(src)
		return errDst == nil && errSrc != nil
	}
	make := func(t *testing.T, path string, dir bool) {
		t.Helper()
		if dir {
			if err := os.MkdirAll(filepath.Join(path, "inner"), 0o755); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The control: a rename inside the pod's own rootfs.
	make(t, filepath.Join(dataVol, "own"), false)
	if !rename(t, filepath.Join(dataVol, "own"), "own-moved") {
		t.Fatal("a rename inside the pod's own rootfs was refused; the measurement is void")
	}
	for _, tc := range []struct {
		name      string
		src       string
		wantMoved bool
	}{
		{"a file in a read-write host share", filepath.Join(rwShare, "f"), true},
		{"a directory in a read-write host share", filepath.Join(rwShare, "d"), true},
		{"a file straight in /private/tmp", tmpTop + "-f", false},
		{"a directory straight in /private/tmp", tmpTop, false},
		{"a file in a directory with no grant", filepath.Join(ungranted, "f"), false},
		{"a file in another pod's rootfs", filepath.Join(otherPod, "f"), false},
		{"a file in a read-only host share", filepath.Join(roShare, "f"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			make(t, tc.src, strings.HasPrefix(filepath.Base(tc.src), "d") || tc.src == tmpTop)
			moved := rename(t, tc.src, "in-"+strconv.Itoa(len(tc.name)))
			t.Logf("rename %s into the rootfs under the pod profile: moved=%v", tc.src, moved)
			if moved != tc.wantMoved {
				t.Errorf("moved = %v, want %v", moved, tc.wantMoved)
			}
		})
	}
}
