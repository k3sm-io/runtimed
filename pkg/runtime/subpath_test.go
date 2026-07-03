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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/mount"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// subPathResolver is a mount.Resolver serving multi-key ConfigMap/Secret data so
// the sibling-absence assertion (only the selected key materializes) is meaningful.
type subPathResolver struct {
	cms     map[string]map[string][]byte
	secrets map[string]map[string][]byte
}

func (s subPathResolver) ConfigMap(_ context.Context, _, name string) (map[string][]byte, error) {
	if d, ok := s.cms[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("configMap %q: %w", name, os.ErrNotExist)
}

func (s subPathResolver) Secret(_ context.Context, _, name string) (map[string][]byte, error) {
	if d, ok := s.secrets[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("secret %q: %w", name, os.ErrNotExist)
}

func (s subPathResolver) ServiceAccountToken(_ context.Context, _, _ string, _ int64) (string, error) {
	return "TOKEN", nil
}

// subPathBox builds a one-container PodBox mounting vol at mountPath with subPath.
func subPathBox(vol *runtimev1.Volume, mountPath, subPath string) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:      "pod-1",
		Namespace:  "default",
		Name:       "demo",
		Volumes:    []*runtimev1.Volume{vol},
		Containers: []*runtimev1.Container{{Name: "main", VolumeMounts: []*runtimev1.VolumeMount{{Name: vol.GetName(), MountPath: mountPath, SubPath: subPath}}}},
	}
}

// regularFilesUnder returns every regular-file path (relative to root) in root's
// subtree — used to prove no un-selected sibling is left readable under dataVol.
func regularFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestVolumeSubPathMaterialization is the B77 gate: subPath materialization exposes
// ONLY the volume's <subPath> element at the mount path (a file or a subdir), never
// the whole volume, with the escape/fail-closed guards — and leaves the no-subPath
// path unchanged. It drives mount.Materialize with a fake Resolver + a temp dataVol
// and asserts the on-disk result.
func TestVolumeSubPathMaterialization(t *testing.T) {
	ctx := context.Background()
	r := subPathResolver{
		cms: map[string]map[string][]byte{
			"cfg": {"a": []byte("AA"), "b": []byte("BB"), "c": []byte("CC")},
		},
		secrets: map[string]map[string][]byte{
			"sec": {"id_rsa": []byte("PRIVATE"), "id_pub": []byte("PUBLIC")},
		},
	}

	// (a) configMap subPath=<key> → the mount path IS that key's file with its bytes.
	t.Run("a_configmap_key_is_file", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}, "/etc/config", "b")
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		placed := filepath.Join(dataVol, "etc/config")
		fi, err := os.Lstat(placed)
		if err != nil {
			t.Fatalf("lstat placed: %v", err)
		}
		if fi.IsDir() {
			t.Fatalf("mount path is a directory, want the selected file (subPath inversion / EISDIR bug)")
		}
		got, err := os.ReadFile(placed)
		if err != nil {
			t.Fatalf("read placed: %v", err)
		}
		if string(got) != "BB" {
			t.Errorf("placed = %q, want %q", got, "BB")
		}
	})

	// (b) SIBLING-ABSENCE (anti-inversion): the OTHER keys are not at the mount path
	// AND not left readable anywhere under dataVol (staging removed). This is the
	// load-bearing check: it FAILS against the broken whole-volume behavior.
	t.Run("b_sibling_absence", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}, "/etc/config", "b")
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		files := regularFilesUnder(t, dataVol)
		if len(files) != 1 || files[0] != filepath.FromSlash("etc/config") {
			t.Fatalf("readable regular files under dataVol = %v, want exactly [etc/config] (siblings a,c must be absent)", files)
		}
		for _, sib := range []string{"a", "c"} {
			if b, err := os.ReadFile(filepath.Join(dataVol, "etc/config", sib)); err == nil {
				t.Errorf("sibling key %q leaked under mount path: %q", sib, b)
			}
		}
	})

	// (c) a subPath naming a non-existent element fails closed.
	t.Run("c_missing_element_errors", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}, "/etc/config", "does-not-exist")
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err == nil {
			t.Fatal("subPath naming a non-existent element must fail closed")
		}
	})

	// (d) no-subPath UNCHANGED: the whole volume materializes at the mount path
	// (regression guard for the common case).
	t.Run("d_no_subpath_unchanged", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}, "/etc/config", "")
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		if fi, err := os.Stat(filepath.Join(dataVol, "etc/config")); err != nil || !fi.IsDir() {
			t.Fatalf("no-subPath mount path should be the whole-volume dir: %v", err)
		}
		for k, want := range map[string]string{"a": "AA", "b": "BB", "c": "CC"} {
			got, err := os.ReadFile(filepath.Join(dataVol, "etc/config", k))
			if err != nil || string(got) != want {
				t.Errorf("key %s = %q (err %v), want %q", k, got, err, want)
			}
		}
	})

	// (e) emptyDir subPath=<subdir> → that subdir is the mount path (dir case).
	t.Run("e_emptydir_subdir_is_dir", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, "/data", "sub")
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		fi, err := os.Lstat(filepath.Join(dataVol, "data"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("emptyDir subPath mount path should be a directory: %v", err)
		}
	})

	// (f) a secret subPath → the returned Mount reports Credential + ReadOnly so the
	// live mount-path file lands in the SBPL read-only sub-scope.
	t.Run("f_secret_subpath_is_credential", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "tok", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}, "/etc/token", "id_rsa")
		layout, err := mount.Materialize(ctx, box, dataVol, "", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		if len(layout.Mounts) != 1 {
			t.Fatalf("mounts = %d, want 1", len(layout.Mounts))
		}
		m := layout.Mounts[0]
		if !m.Credential || !m.ReadOnly {
			t.Errorf("secret subPath mount Credential=%v ReadOnly=%v, want both true", m.Credential, m.ReadOnly)
		}
		placed := filepath.Join(dataVol, "etc/token")
		if m.Path != placed {
			t.Errorf("Mount.Path = %q, want the placed mount path %q (never the staging dir)", m.Path, placed)
		}
		creds := layout.CredentialPaths()
		if len(creds) != 1 || creds[0] != placed {
			t.Errorf("CredentialPaths = %v, want [%s]", creds, placed)
		}
	})

	// (g) a "../"-escaping subPath is rejected.
	t.Run("g_escaping_subpath_errors", func(t *testing.T) {
		dataVol := t.TempDir()
		box := subPathBox(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}, "/etc/config", "../../etc/passwd")
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err == nil {
			t.Fatal("a subPath escaping the volume root via .. must be rejected")
		}
	})

	// (h) two containers mounting one volume at the SAME mount path with DIFFERENT
	// subPaths cannot both be materialized on the shared tree — a hard error, not a
	// silent first-wins. (An identical (volume, subPath) into two containers is fine.)
	t.Run("h_conflicting_subpaths_error", func(t *testing.T) {
		dataVol := t.TempDir()
		vol := &runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}
		box := &runtimev1.PodBox{
			PodId: "pod-1", Namespace: "default", Name: "demo",
			Volumes: []*runtimev1.Volume{vol},
			Containers: []*runtimev1.Container{
				{Name: "a", VolumeMounts: []*runtimev1.VolumeMount{{Name: "cm", MountPath: "/etc/config", SubPath: "b"}}},
				{Name: "b", VolumeMounts: []*runtimev1.VolumeMount{{Name: "cm", MountPath: "/etc/config", SubPath: "c"}}},
			},
		}
		if _, err := mount.Materialize(ctx, box, dataVol, "", r); err == nil {
			t.Fatal("two different subPaths of one volume at the same mount path must conflict, not silently first-win")
		}
	})
}
