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

package mount

import (
	"context"
	"path/filepath"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRefreshUpdatesReadOnlyConfigMap pins that a read-only configMap mount
// still refreshes: read-only is the pod's profile, and the refresh runs as the
// daemon, so the mount's verdict changes nothing about it.
func TestRefreshUpdatesReadOnlyConfigMap(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	r := newRefreshResolver()
	r.set("app", false, "a", "1")
	box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "app")},
		&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg", ReadOnly: true})
	layout, err := Materialize(ctx, box, root, "", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	dir := filepath.Join(root, "etc/cfg")
	if got := layout.ReadOnlyPaths(); len(got) != 1 || got[0] != dir {
		t.Fatalf("ReadOnlyPaths = %v, want [%s]", got, dir)
	}
	oldGen := liveGen(t, dir)

	r.set("app", false, "a", "2")
	res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := res.Volumes; len(got) != 1 || got[0].Outcome != RefreshUpdated {
		t.Fatalf("outcomes = %+v, want one Updated", got)
	}
	if got := readString(t, filepath.Join(dir, "a")); got != "2" {
		t.Errorf("a after refresh = %q, want 2", got)
	}
	if liveGen(t, dir) == oldGen {
		t.Errorf("..data still names %s after a change", oldGen)
	}
}
