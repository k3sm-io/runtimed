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
	"sort"
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
		pure, err := planCredentialPaths(box, dataVol)
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
		if _, err := planCredentialPaths(box, dataVol); err == nil {
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

// nestBox is a pod whose init container mounts initMounts and whose main
// container mounts mainMounts, over vols.
func nestBox(vols []*runtimev1.Volume, initMounts, mainMounts []*runtimev1.VolumeMount) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:          "pod-1",
		Namespace:      "default",
		Name:           "demo",
		Volumes:        vols,
		InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: initMounts}},
		Containers:     []*runtimev1.Container{{Name: "main", VolumeMounts: mainMounts}},
	}
}

// TestNestedMountsUnderLinksAndCredentialsRefused pins the plan-time nesting
// check: a mount path under an alias, under a selection that has aliases,
// under an image / PVC / exposure link, or under a credential directory is
// refused, by the pure walk and by Materialize alike. A mount nested in a
// plain directory with no alias is kept as main allowed it.
func TestNestedMountsUnderLinksAndCredentialsRefused(t *testing.T) {
	vm := func(name, path string) *runtimev1.VolumeMount {
		return &runtimev1.VolumeMount{Name: name, MountPath: path}
	}
	empty := func(name string) *runtimev1.Volume {
		return &runtimev1.Volume{Name: name, EmptyDir: &runtimev1.EmptyDirVolumeSource{}}
	}
	pvc := &runtimev1.Volume{Name: "data", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}}
	expose := &runtimev1.Volume{Name: "share", Expose: &runtimev1.ExposeVolumeSource{}}
	secret := &runtimev1.Volume{Name: "creds", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}
	cm := &runtimev1.Volume{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}
	r := fakeResolver{
		cms:     map[string]map[string][]byte{"cm": {"k": []byte("v")}},
		secrets: map[string]map[string][]byte{"sec": {"k": []byte("s")}},
	}

	refused := []struct {
		name string
		box  *runtimev1.PodBox
	}{
		{"PVC under an aliased destination", nestBox([]*runtimev1.Volume{empty("tools"), pvc},
			[]*runtimev1.VolumeMount{vm("tools", "/a")}, []*runtimev1.VolumeMount{vm("tools", "/b"), vm("data", "/a/data")})},
		{"PVC under an alias path", nestBox([]*runtimev1.Volume{empty("tools"), pvc},
			[]*runtimev1.VolumeMount{vm("tools", "/a")}, []*runtimev1.VolumeMount{vm("tools", "/b"), vm("data", "/b/data")})},
		{"alias under another selection's destination", nestBox([]*runtimev1.Volume{empty("tools"), empty("outer")},
			[]*runtimev1.VolumeMount{vm("tools", "/t"), vm("outer", "/x")}, []*runtimev1.VolumeMount{vm("tools", "/x/t")})},
		{"emptyDir under a credential", nestBox([]*runtimev1.Volume{secret, empty("scratch")},
			nil, []*runtimev1.VolumeMount{vm("creds", "/s"), vm("scratch", "/s/sub")})},
		{"emptyDir under a PVC", nestBox([]*runtimev1.Volume{pvc, empty("scratch")},
			nil, []*runtimev1.VolumeMount{vm("data", "/d"), vm("scratch", "/d/sub")})},
		{"emptyDir under an exposure", nestBox([]*runtimev1.Volume{expose, empty("scratch")},
			nil, []*runtimev1.VolumeMount{vm("share", "/e"), vm("scratch", "/e/sub")})},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			dataVol := filepath.Join(t.TempDir(), "rootfs")
			if _, err := planCredentialPaths(tc.box, dataVol); err == nil || !strings.Contains(err.Error(), "is nested under") {
				t.Fatalf("CredentialPaths = %v, want the nesting refusal", err)
			}
			if _, err := Materialize(context.Background(), tc.box, dataVol, "", &r); err == nil || !strings.Contains(err.Error(), "is nested under") {
				t.Fatalf("Materialize = %v, want the nesting refusal", err)
			}
			if _, err := os.Lstat(dataVol); err == nil {
				t.Errorf("Materialize wrote %s before refusing the plan", dataVol)
			}
		})
	}

	// Kept as main allowed it: distinct volumes nested in a plain directory,
	// no alias and no credential outside.
	allowed := []struct {
		name string
		box  *runtimev1.PodBox
	}{
		{"configMap inside an emptyDir", nestBox([]*runtimev1.Volume{empty("scratch"), cm},
			nil, []*runtimev1.VolumeMount{vm("scratch", "/a"), vm("cfg", "/a/cfg")})},
		{"secret inside an emptyDir", nestBox([]*runtimev1.Volume{empty("scratch"), secret},
			nil, []*runtimev1.VolumeMount{vm("scratch", "/a"), vm("creds", "/a/creds")})},
		{"PVC inside an emptyDir", nestBox([]*runtimev1.Volume{empty("scratch"), pvc},
			nil, []*runtimev1.VolumeMount{vm("scratch", "/a"), vm("data", "/a/data")})},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			dataVol := filepath.Join(t.TempDir(), "rootfs")
			if _, err := Materialize(context.Background(), tc.box, dataVol, "", &r); err != nil {
				t.Fatalf("Materialize: %v", err)
			}
		})
	}
}

// TestCredentialPathsEqualsLayoutWithAliases pins the pure credential verdict
// against the render's with aliases present: a re-attaching daemon recompiles
// the profile from CredentialPaths, and its digest must equal the create's.
func TestCredentialPathsEqualsLayoutWithAliases(t *testing.T) {
	r := fakeResolver{
		cms:     map[string]map[string][]byte{"cm": {"k": []byte("v")}},
		secrets: map[string]map[string][]byte{"sec": {"k": []byte("s")}},
		token:   "TOKEN",
	}
	vm := func(name, path, sub string) *runtimev1.VolumeMount {
		return &runtimev1.VolumeMount{Name: name, MountPath: path, SubPath: sub}
	}
	box := nestBox([]*runtimev1.Volume{
		{Name: "creds", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}},
		{Name: "tok", Projected: &runtimev1.ProjectedVolumeSource{Sources: []*runtimev1.VolumeProjection{
			{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Audience: "api", ExpirationSeconds: 3600, Path: "token"}},
		}}},
		{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}},
		{Name: "tools", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
	}, []*runtimev1.VolumeMount{
		vm("creds", "/etc/creds", ""), vm("tok", "/var/run/tok", ""), vm("cfg", "/etc/cfg", ""),
		vm("creds", "/etc/one-key", "k"), vm("tools", "/tools", ""),
	}, []*runtimev1.VolumeMount{
		vm("creds", "/srv/creds", ""), vm("tok", "/srv/tok", ""), vm("cfg", "/srv/cfg", ""),
		vm("creds", "/srv/one-key", "k"), vm("tools", "/opt/tools", ""),
	})
	dataVol := filepath.Join(t.TempDir(), "rootfs")
	layout, err := Materialize(context.Background(), box, dataVol, "", &r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	pure, err := planCredentialPaths(box, dataVol)
	if err != nil {
		t.Fatalf("CredentialPaths: %v", err)
	}
	if got := layout.CredentialPaths(); !reflect.DeepEqual(pure, got) {
		t.Fatalf("CredentialPaths() = %v, Layout.CredentialPaths() = %v; want equal", pure, got)
	}
	var want []string
	for _, p := range []string{"/etc/creds", "/etc/one-key", "/srv/creds", "/srv/one-key", "/srv/tok", "/var/run/tok"} {
		want = append(want, filepath.Join(dataVol, p))
	}
	if !reflect.DeepEqual(pure, want) {
		t.Fatalf("CredentialPaths() = %v, want %v", pure, want)
	}
}

// TestPlaceAliasReplacesStaleLinkAtomically pins that a stale alias link is
// swapped for the new one by a rename (the name never goes missing) and leaves
// no temporary entry behind.
func TestPlaceAliasReplacesStaleLinkAtomically(t *testing.T) {
	dataVol := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(dataVol, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("stale", filepath.Join(dataVol, "opt", "tools")); err != nil {
		t.Fatal(err)
	}
	if err := placeAlias(dataVol, filepath.Join(dataVol, "opt", "tools"), filepath.Join(dataVol, "first")); err != nil {
		t.Fatalf("placeAlias: %v", err)
	}
	if got, err := os.Readlink(filepath.Join(dataVol, "opt", "tools")); err != nil || got != "../first" {
		t.Fatalf("alias link = %q, %v; want ../first", got, err)
	}
	names, err := os.ReadDir(filepath.Join(dataVol, "opt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Fatalf("entries under opt = %v, want only the alias", names)
	}
}

// planCredentialPaths is the credential paths a pure walk of box derives: each
// credential selection's directory and its aliases, sorted. It is what
// Layout.CredentialPaths reports after a render.
func planCredentialPaths(box *runtimev1.PodBox, dataVol string) ([]string, error) {
	plans, err := planMounts(box, filepath.Clean(dataVol))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pm := range plans {
		if credentialSource(pm.vol) {
			out = append(out, pm.dest)
			out = append(out, aliasDests(pm.aliases)...)
		}
	}
	sort.Strings(out)
	return out, nil
}
