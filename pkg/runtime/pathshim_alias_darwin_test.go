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
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/mount"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPathShimReachesSharedVolumeAlias runs the pod shape "sh -c" in a
// re-signed bash with the built path shim against a data volume
// mount.Materialize rendered for one emptyDir mounted at /yurei-project-tools
// by an init container and at a nested path under an existing host parent by
// the main container. The main container's shell, configured with only its own
// mount path, cds into that path and reads the init container's file: the
// second mount path is an alias of the one directory, and the shim plus the
// kernel's link follow reach it.
//
// It also pins where "cd: <path>: Not a directory" comes from: a nested mount
// path under an existing host parent cds fine, and the shell reports ENOTDIR
// only when the rebased entry is not a directory.
func TestPathShimReachesSharedVolumeAlias(t *testing.T) {
	shim := buildPathShim(t)
	bin := t.TempDir()
	cloneSigned(t, "/bin/bash", filepath.Join(bin, "sh"))

	for _, parent := range []string{"/opt", "/usr"} {
		if fi, err := os.Stat(parent); err != nil || !fi.IsDir() {
			continue
		}
		mainPath := parent + "/k3sm-b1927-yurei"
		if _, err := os.Lstat(mainPath); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("host path %s exists (err=%v); the test needs it absent", mainPath, err)
		}
		run := func(t *testing.T, rootfs, mounts, script string) (string, error) {
			t.Helper()
			cmd := &exec.Cmd{Path: filepath.Join(bin, "sh"), Args: []string{"sh", "-c", script}, Dir: "/"}
			cmd.Env = []string{
				"PATH=/usr/bin:/bin",
				pathShimRootfsEnv + "=" + rootfs,
				pathShimMountsEnv + "=" + mounts,
				dyldInsertEnv + "=" + shim,
			}
			out, err := cmd.CombinedOutput()
			return string(out), err
		}

		t.Run("alias at "+mainPath, func(t *testing.T) {
			rootfs := filepath.Join(t.TempDir(), "rootfs")
			vol := &runtimev1.Volume{Name: "tools", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}
			box := &runtimev1.PodBox{
				PodId:          "pod-1",
				Volumes:        []*runtimev1.Volume{vol},
				InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{{Name: "tools", MountPath: "/yurei-project-tools"}}}},
				Containers:     []*runtimev1.Container{{Name: "main", VolumeMounts: []*runtimev1.VolumeMount{{Name: "tools", MountPath: mainPath}}}},
			}
			if _, err := mount.Materialize(context.Background(), box, rootfs, "", nil); err != nil {
				t.Fatalf("Materialize: %v", err)
			}
			// The init container writes through its own mount path.
			out, err := run(t, rootfs, "/yurei-project-tools", "echo TOOL > /yurei-project-tools/tool")
			if err != nil {
				t.Fatalf("init write: %v\n%s", err, out)
			}
			// The main container reads it at its own.
			out, err = run(t, rootfs, mainPath, "cd "+mainPath+" && pwd && read l < tool && echo \"$l\" && read m < "+mainPath+"/tool && echo \"$m\"")
			if err != nil {
				t.Fatalf("main cd and read: %v\n%s", err, out)
			}
			if want := mainPath + "\nTOOL\nTOOL\n"; out != want {
				t.Fatalf("main output = %q, want %q", out, want)
			}
			if _, err := os.Lstat(mainPath); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("host path %s exists (err=%v): a call reached the host", mainPath, err)
			}
		})

		t.Run("ENOTDIR only from a non-directory at "+mainPath, func(t *testing.T) {
			rootfs := filepath.Join(t.TempDir(), "rootfs")
			if err := os.MkdirAll(filepath.Join(rootfs, parent), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootfs, mainPath), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := run(t, rootfs, mainPath, "cd "+mainPath)
			if err == nil || !strings.Contains(out, "Not a directory") {
				t.Fatalf("cd into a file at the rebased path: err=%v, want ENOTDIR\n%s", err, out)
			}
			if err := os.Remove(filepath.Join(rootfs, mainPath)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(rootfs, mainPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if out, err := run(t, rootfs, mainPath, "cd "+mainPath+" && pwd"); err != nil || out != mainPath+"\n" {
				t.Fatalf("cd into a nested directory under existing %s: err=%v\n%s", parent, err, out)
			}
		})
	}
}
