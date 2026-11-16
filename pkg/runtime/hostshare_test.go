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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
)

func hostPathPod(path string, mounted bool) *runtimev1.PodBox {
	box := &runtimev1.PodBox{
		PodId:      "p1",
		Volumes:    []*runtimev1.Volume{{Name: "code", HostPath: &runtimev1.HostPathVolumeSource{Path: path}}},
		Containers: []*runtimev1.Container{{Name: "c"}},
	}
	if mounted {
		box.Containers[0].VolumeMounts = []*runtimev1.VolumeMount{{Name: "code", MountPath: path}}
	}
	return box
}

// TestHostSharesAreTheNodesDecision pins that the runtime decides a hostPath
// volume itself, from its configured allowlist file, and never from the
// request: with no file configured, a missing file or a file the daemon user
// could have written, a mounted hostPath volume is refused, so a CreatePod
// sent straight to the socket gets nothing the provider would not give.
func TestHostSharesAreTheNodesDecision(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	userFile := filepath.Join(dir, "shares")
	if err := os.WriteFile(userFile, []byte("rw "+share+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, file string
		want       error
	}{
		{"no_file_configured", "", hostshare.ErrNotShared},
		{"missing_file", filepath.Join(dir, "absent"), hostshare.ErrNotShared},
		{"user_written_file", userFile, hostshare.ErrUnsafeFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &Runtime{cfg: Config{HostSharesFile: tc.file}, log: slog.New(slog.DiscardHandler)}
			if os.Geteuid() == 0 && tc.want == hostshare.ErrUnsafeFile {
				t.Skip("running as root: the test's own file is root-owned")
			}
			if _, err := r.hostShares(hostPathPod(share, true)); !errors.Is(err, tc.want) {
				t.Errorf("hostShares = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("unmounted_reads_nothing", func(t *testing.T) {
		t.Parallel()
		r := &Runtime{cfg: Config{HostSharesFile: userFile}, log: slog.New(slog.DiscardHandler)}
		if got, err := r.hostShares(hostPathPod(share, false)); err != nil || got != nil {
			t.Errorf("hostShares(unmounted) = %v, %v, want nil, nil", got, err)
		}
	})
}

// TestHostShareMountIsNeverRebased pins that a host share's mount path is
// left out of the path-rebase shim's prefixes: the pod reaches the real host
// path, and rebasing it into the pod's data volume would hide the share.
func TestHostShareMountIsNeverRebased(t *testing.T) {
	t.Parallel()
	box := hostPathPod("/Users/dev/Code/app", true)
	box.Volumes = append(box.Volumes, &runtimev1.Volume{Name: "cfg", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
	box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts, &runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/app"})
	got := strings.Join(containerMountPaths(box, box.Containers[0]), ":")
	if got != "/etc/app" {
		t.Errorf("containerMountPaths = %q, want only the emptyDir mount", got)
	}
}
