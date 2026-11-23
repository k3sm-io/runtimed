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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// twoPathBox is a pod mounting vol at initPath in an init container and at
// mainPath in the main container.
func twoPathBox(vol *runtimev1.Volume, initPath, mainPath string) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:          "pod-1",
		Namespace:      "default",
		Name:           "demo",
		Volumes:        []*runtimev1.Volume{vol},
		InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{{Name: vol.GetName(), MountPath: initPath}}}},
		Containers:     []*runtimev1.Container{{Name: "main", VolumeMounts: []*runtimev1.VolumeMount{{Name: vol.GetName(), MountPath: mainPath}}}},
	}
}

// rebased is the host path the path-rebase shim turns mountPath/rel into for a
// pod whose data volume is dataVol ("<rootfs><path>", shim/pathrebase_shim.c).
func rebased(dataVol, mountPath, rel string) string {
	return filepath.Join(dataVol, mountPath, rel)
}

// TestSameVolumeDifferentMountPathsShareOneDir pins kubelet parity for one
// volume mounted at different mount paths in different containers: it is ONE
// directory per pod, reached at each container's mount path. A file written
// through the first rebased mount path is read back through the second, every
// path of a credential is in the read-only sub-scope (from the render and from
// the pure CredentialPaths alike), and a refresh of a configMap or secret
// reaches every path.
func TestSameVolumeDifferentMountPathsShareOneDir(t *testing.T) {
	ctx := context.Background()

	emptyDirCase := func(t *testing.T, mainPath string, prepare func(t *testing.T, dataVol string)) {
		t.Helper()
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		if prepare != nil {
			prepare(t, dataVol)
		}
		box := twoPathBox(&runtimev1.Volume{Name: "tools", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, "/yurei-project-tools", mainPath)
		layout, err := Materialize(ctx, box, dataVol, "", nil)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		// The init container fills the emptyDir through its own mount path...
		if err := os.WriteFile(rebased(dataVol, "/yurei-project-tools", "bin-tool"), []byte("TOOL"), 0o755); err != nil {
			t.Fatalf("write through the init container's mount path: %v", err)
		}
		// ...and the main container sees it at its own.
		got, err := os.ReadFile(rebased(dataVol, mainPath, "bin-tool"))
		if err != nil || string(got) != "TOOL" {
			t.Fatalf("read through the main container's mount path %s = %q, %v; want the init container's file", mainPath, got, err)
		}
		// And the reverse direction.
		if err := os.WriteFile(rebased(dataVol, mainPath, "from-main"), []byte("M"), 0o644); err != nil {
			t.Fatalf("write through %s: %v", mainPath, err)
		}
		if got, err := os.ReadFile(rebased(dataVol, "/yurei-project-tools", "from-main")); err != nil || string(got) != "M" {
			t.Fatalf("read back through the init path = %q, %v", got, err)
		}
		// The mount path is a directory once followed (cd into it works).
		if fi, err := os.Stat(rebased(dataVol, mainPath, "")); err != nil || !fi.IsDir() {
			t.Fatalf("stat %s through the data volume = %v, %v; want a directory", mainPath, fi, err)
		}
		paths := map[string]bool{}
		for _, m := range layout.Mounts {
			paths[m.Path] = true
		}
		for _, p := range []string{"/yurei-project-tools", mainPath} {
			if !paths[filepath.Join(dataVol, p)] {
				t.Errorf("Layout.Mounts = %+v, missing %s", layout.Mounts, p)
			}
		}
	}

	t.Run("emptyDir at two top-level paths", func(t *testing.T) {
		emptyDirCase(t, "/opt/tools", nil)
	})

	// The node's /opt exists and the image rootfs has its own /opt with
	// content: the nested mount path is still a directory reached through
	// the existing parent, and the parent's content is left alone.
	t.Run("emptyDir at a nested path under an existing parent", func(t *testing.T) {
		emptyDirCase(t, "/opt/yurei", func(t *testing.T, dataVol string) {
			if err := os.MkdirAll(filepath.Join(dataVol, "opt", "other"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dataVol, "opt", "keep"), []byte("K"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if b, err := os.ReadFile(filepath.Join(dataVol, "opt", "keep")); err != nil || string(b) != "K" {
					t.Errorf("the existing parent's content changed: %q, %v", b, err)
				}
			})
		})
	})

	// An empty directory the image rootfs already has at the second path is
	// replaced by the alias, as a mount would cover it.
	t.Run("emptyDir alias over an empty image directory", func(t *testing.T) {
		emptyDirCase(t, "/opt/tools", func(t *testing.T, dataVol string) {
			if err := os.MkdirAll(filepath.Join(dataVol, "opt", "tools"), 0o755); err != nil {
				t.Fatal(err)
			}
		})
	})

	refreshable := func(t *testing.T, vol *runtimev1.Volume, r fakeResolver, update func(), wantCred bool) {
		t.Helper()
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		box := twoPathBox(vol, "/etc/first", "/srv/second")
		layout, err := Materialize(ctx, box, dataVol, "", &r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		for _, p := range []string{"/etc/first", "/srv/second"} {
			if got, err := os.ReadFile(rebased(dataVol, p, "k")); err != nil || string(got) != "v1" {
				t.Fatalf("read k at %s = %q, %v; want v1", p, got, err)
			}
		}
		var wantCreds []string
		if wantCred {
			wantCreds = []string{filepath.Join(dataVol, "etc/first"), filepath.Join(dataVol, "srv/second")}
		}
		if got := layout.CredentialPaths(); !reflect.DeepEqual(got, wantCreds) {
			t.Errorf("Layout.CredentialPaths() = %v, want %v", got, wantCreds)
		}
		pure, err := CredentialPaths(box, dataVol)
		if err != nil {
			t.Fatalf("CredentialPaths: %v", err)
		}
		if !reflect.DeepEqual(pure, wantCreds) {
			t.Errorf("CredentialPaths() = %v, want %v", pure, wantCreds)
		}
		for _, m := range layout.Mounts {
			if m.ReadOnly != wantCred || m.Credential != wantCred {
				t.Errorf("mount %+v: want ReadOnly and Credential = %v", m, wantCred)
			}
		}

		update()
		res, err := Refresh(ctx, dataVol, box, &r, RefreshOptions{State: layout.State})
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if len(res.Volumes) != 1 || res.Volumes[0].Outcome != RefreshUpdated {
			t.Fatalf("Refresh volumes = %+v, want one Updated", res.Volumes)
		}
		for _, p := range []string{"/etc/first", "/srv/second"} {
			if got, err := os.ReadFile(rebased(dataVol, p, "k")); err != nil || string(got) != "v2" {
				t.Errorf("after refresh, k at %s = %q, %v; want v2", p, got, err)
			}
		}
	}

	t.Run("configMap at two paths", func(t *testing.T) {
		r := fakeResolver{cms: map[string]map[string][]byte{"cm": {"k": []byte("v1")}}}
		refreshable(t, &runtimev1.Volume{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}, r,
			func() { r.cms["cm"]["k"] = []byte("v2") }, false)
	})

	t.Run("secret at two paths, both read-only scoped", func(t *testing.T) {
		r := fakeResolver{secrets: map[string]map[string][]byte{"sec": {"k": []byte("v1")}}}
		refreshable(t, &runtimev1.Volume{Name: "creds", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}, r,
			func() { r.secrets["sec"]["k"] = []byte("v2") }, true)
	})

	t.Run("two different volumes at one path is still an error", func(t *testing.T) {
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		box := &runtimev1.PodBox{
			PodId: "pod-1",
			Volumes: []*runtimev1.Volume{
				{Name: "a", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
				{Name: "b", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
			},
			InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{{Name: "a", MountPath: "/opt/tools"}}}},
			Containers:     []*runtimev1.Container{{Name: "main", VolumeMounts: []*runtimev1.VolumeMount{{Name: "b", MountPath: "/opt/tools"}}}},
		}
		_, err := Materialize(ctx, box, dataVol, "", nil)
		if err == nil || !strings.Contains(err.Error(), "both target") {
			t.Fatalf("Materialize = %v, want the destination conflict error", err)
		}
		if _, err := CredentialPaths(box, dataVol); err == nil {
			t.Fatal("CredentialPaths accepted two volumes at one path")
		}
	})

	t.Run("one volume at a path and its own descendant is refused", func(t *testing.T) {
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		box := twoPathBox(&runtimev1.Volume{Name: "tools", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, "/opt/tools", "/opt/tools/nested")
		if _, err := Materialize(ctx, box, dataVol, "", nil); err == nil {
			t.Fatal("Materialize accepted a volume mounted inside itself")
		}
	})

	t.Run("a non-empty directory at the second path is refused", func(t *testing.T) {
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		if err := os.MkdirAll(filepath.Join(dataVol, "opt", "tools"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataVol, "opt", "tools", "image-file"), []byte("I"), 0o644); err != nil {
			t.Fatal(err)
		}
		box := twoPathBox(&runtimev1.Volume{Name: "tools", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, "/yurei-project-tools", "/opt/tools")
		if _, err := Materialize(ctx, box, dataVol, "", nil); err == nil {
			t.Fatal("Materialize replaced a non-empty directory with the alias")
		}
		if b, err := os.ReadFile(filepath.Join(dataVol, "opt", "tools", "image-file")); err != nil || string(b) != "I" {
			t.Fatalf("the refused directory's content changed: %q, %v", b, err)
		}
	})
}
