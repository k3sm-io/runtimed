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
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestReadOnlyMountsCreateMatchesReattach pins the read-only sub-scope a
// native pod's profile carries for its read_only mounts, and that a daemon
// re-attaching to the pod derives the same profile from the spec alone
// (boxProfile, which reads mount.ScopeFor). An emptyDir every container
// mounts read_only and a downwardAPI volume mounted without it are in the
// sub-scope; an
// emptyDir one container mounts read-only and another read-write is not, and
// the create warns once, naming it.
func TestReadOnlyMountsCreateMatchesReattach(t *testing.T) {
	var logs bytes.Buffer
	rt := newTestRuntimeCfg(t, Config{Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}, Deps{})
	const podID = "pod-ro-mounts"
	box := hostBinBox(rt, podID)
	box.Volumes = []*runtimev1.Volume{
		{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		{Name: "info", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: []*runtimev1.DownwardAPIVolumeFile{
			{Path: "name", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
		}}},
		{Name: "shared", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		{Name: "tmp", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
	}
	box.Containers[0].VolumeMounts = []*runtimev1.VolumeMount{
		{Name: "scratch", MountPath: "/scratch", ReadOnly: true},
		{Name: "info", MountPath: "/etc/info"}, // API data: read-only without the flag
		{Name: "shared", MountPath: "/shared", ReadOnly: true},
		{Name: "tmp", MountPath: "/etc/info/tmp"}, // writable, nested in read-only info
	}
	box.Containers = append(box.Containers, &runtimev1.Container{
		Name: "writer", Image: "/bin/sleep",
		VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "shared", MountPath: "/shared"},
			{Name: "scratch", MountPath: "/scratch-alias", ReadOnly: true}, // an alias of /scratch
		},
	})
	mustCreatePod(t, rt, box)

	rt.mu.Lock()
	profile := rt.pods[podID].profile
	rt.mu.Unlock()
	rootfs := derivedRootfs(t, rt, podID)
	at := strings.Index(profile, ";; credentials (secrets / SA-token)")
	if at < 0 {
		t.Fatalf("the profile has no read-only sub-scope:\n%s", profile)
	}
	stanza := profile[at:]
	for _, p := range []string{filepath.Join(rootfs, "scratch"), filepath.Join(rootfs, "etc", "info")} {
		if !strings.Contains(stanza, "(subpath \""+p+"\")") {
			t.Errorf("read-only mount %s is not in the profile's read-only sub-scope:\n%s", p, stanza)
		}
	}
	if a := filepath.Join(rootfs, "scratch-alias"); strings.Contains(stanza, a) {
		t.Errorf("alias link %s carries a rule; the directory at /scratch does:\n%s", a, stanza)
	}
	if shared := filepath.Join(rootfs, "shared"); strings.Contains(stanza, shared) {
		t.Errorf("mixed mount %s is in the read-only sub-scope; one container mounts it read-write:\n%s", shared, stanza)
	}
	// The writable emptyDir nested in info gets its write back, and /etc, the
	// ancestor of info, may not be renamed.
	if p := filepath.Join(rootfs, "etc", "info", "tmp"); !strings.Contains(stanza, "(allow file-write*\n  (subpath \""+p+"\")") {
		t.Errorf("nested writable mount %s is not re-allowed:\n%s", p, stanza)
	}
	if p := filepath.Join(rootfs, "etc"); !strings.Contains(stanza, "(literal \""+p+"\")") {
		t.Errorf("ancestor %s of a read-only mount is not guarded:\n%s", p, stanza)
	}
	// The re-attach derivation is the create's: the same profile, byte for byte.
	if again, err := rt.boxProfile(box); err != nil || again != profile {
		t.Errorf("boxProfile differs from the create's profile (err %v)", err)
	}
	if n := strings.Count(logs.String(), "stays writable for the whole pod"); n != 1 || !strings.Contains(logs.String(), "volumes=[shared]") {
		t.Errorf("want one Warn naming volume shared, got %d in:\n%s", n, logs.String())
	}
}
