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
	"errors"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestSharedVolumeTempDir pins which mount points have a shared replacement
// directory: any volume but the root and data volumes.
func TestSharedVolumeTempDir(t *testing.T) {
	for mnt, want := range map[string]string{
		"/private/var/lib/k3sm": "/private/var/lib/k3sm/.TemporaryItems",
		"/Volumes/K3SM":         "/Volumes/K3SM/.TemporaryItems",
		"/System/Volumes/Data":  "",
		"/":                     "",
		"":                      "",
	} {
		got, ok := SharedVolumeTempDir(mnt)
		if got != want || ok != (want != "") {
			t.Errorf("SharedVolumeTempDir(%q) = %q, %v; want %q", mnt, got, ok, want)
		}
	}
}

// TestGenerateDeniesTheWorkVolumeSharedTempDir proves the shared replacement
// directory is denied where Foundation really puts it: under the work-dir
// always, and under the work volume's mount point when the work-dir is below
// it. Both are protected roots, so a caller path at or under one is refused,
// and a malformed work volume refuses the profile.
func TestGenerateDeniesTheWorkVolumeSharedTempDir(t *testing.T) {
	const workDir = "/Volumes/K3SM/k3sm"
	const dataVol = workDir + "/pods/pod-abc/rootfs"
	sp := &runtimev1.SandboxProfile{DataVolumePath: dataVol}

	out, err := Generate(sp, GenerateOptions{Posture: Posture{WorkDir: workDir, WorkVolume: "/Volumes/K3SM", PodLogsDir: "/var/log/pods"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, d := range []string{workDir + "/.TemporaryItems", "/Volumes/K3SM/.TemporaryItems"} {
		if !strings.Contains(out, "  (subpath \""+d+"\")\n") {
			t.Errorf("no protected deny for %s:\n%s", d, out)
		}
	}
	iDeny := strings.Index(out, "(subpath \"/Volumes/K3SM/.TemporaryItems\")")
	iReallow := strings.Index(out, "(allow file-read* file-write*\n  (subpath \""+dataVol+"\")")
	if iDeny < 0 || iReallow < 0 || iDeny > iReallow {
		t.Errorf("work-volume deny (%d) must sit in the protected tier, before the data-vol re-allow (%d)", iDeny, iReallow)
	}

	// The default node: the work-dir is the mount point, one deny, and the
	// same profile as with no work volume at all (no drift on re-attach).
	const nodeVol = "/var/lib/k3sm/pods/pod-abc/rootfs"
	nodeSP := &runtimev1.SandboxProfile{DataVolumePath: nodeVol}
	without, err := Generate(nodeSP, GenerateOptions{Posture: Posture{PodLogsDir: "/var/log/pods"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Both spellings: statfs reports /private/var/lib/k3sm on a node.
	for _, vol := range []string{"/var/lib/k3sm", "/private/var/lib/k3sm"} {
		with, err := Generate(nodeSP, GenerateOptions{Posture: Posture{WorkVolume: vol, PodLogsDir: "/var/log/pods"}})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if with != without {
			t.Errorf("a work volume %s equal to the work-dir changed the profile", vol)
		}
	}
	if n := strings.Count(without, "(subpath \"/private/var/lib/k3sm/.TemporaryItems\")"); n != 1 {
		t.Errorf("the node's shared temp dir is denied %d times, want once", n)
	}

	for _, grant := range []string{"/Volumes/K3SM/.TemporaryItems", "/Volumes/K3SM/.TemporaryItems/folders.501"} {
		_, err := Generate(sp, GenerateOptions{
			Posture:    Posture{WorkDir: workDir, WorkVolume: "/Volumes/K3SM", PodLogsDir: "/var/log/pods"},
			WritePaths: []string{grant},
		})
		if err == nil {
			t.Errorf("a write grant of %s was accepted", grant)
		}
	}
	for _, bad := range []string{"relative", "/Volumes/K3SM/", "/Volumes/\"x"} {
		_, err := Generate(sp, GenerateOptions{Posture: Posture{WorkDir: workDir, WorkVolume: bad, PodLogsDir: "/var/log/pods"}})
		if !errors.Is(err, ErrInvalidWorkVolume) {
			t.Errorf("WorkVolume %q: err = %v, want ErrInvalidWorkVolume", bad, err)
		}
	}
}
