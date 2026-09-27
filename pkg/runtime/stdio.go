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
	"fmt"
	"os"
	"path/filepath"

	"k3sm.io/runtimed/pkg/supervisor"
)

// podStdioSubdir is the directory, directly under a pod's own dir, that holds
// each container's raw stdout/stderr capture files:
// <podDir>/stdio/<container>/{stdout,stderr}.raw (+ .offset).
//
// It is a fixed sibling of <podDir>/rootfs, never <podDir>/<container>: a
// container may legally be NAMED "rootfs", and <podDir>/rootfs is the pod's
// writable data volume, so the per-container spelling would let a pod plant a
// symlink where this daemon creates and truncates files. Nothing under the pod
// dir outside rootfs is writable by the pod (its profile re-allows only the
// data volume); the child writes these files only through the descriptors it is
// handed. DeletePod's removePodDir takes them with the rest of the pod dir.
const podStdioSubdir = "stdio"

// containerCapture returns the raw capture files for one container of a pod.
func (r *Runtime) containerCapture(podID, container string) (supervisor.FileCapture, error) {
	podDir, err := r.podDir(podID)
	if err != nil {
		return supervisor.FileCapture{}, err
	}
	if container == "" || container == "." || container == ".." || container != filepath.Base(container) {
		return supervisor.FileCapture{}, fmt.Errorf("container name %q is not a path component", container)
	}
	dir := filepath.Join(podDir, podStdioSubdir, container)
	return supervisor.FileCapture{
		Stdout: filepath.Join(dir, "stdout.raw"),
		Stderr: filepath.Join(dir, "stderr.raw"),
	}, nil
}

// captureResumable reports whether a container's output was file-captured by
// the daemon that spawned it: both raw files and both offset files exist. A
// pod spawned before file capture wrote to pipes and has none of them.
func captureResumable(c supervisor.FileCapture) bool {
	for _, raw := range []string{c.Stdout, c.Stderr} {
		for _, p := range []string{raw, supervisor.OffsetPath(raw)} {
			if _, err := os.Lstat(p); err != nil {
				return false
			}
		}
	}
	return true
}
