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
	"reflect"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestCredentialPathsMatchesMaterialize pins CredentialPaths as the pure half
// of Materialize's credential verdict: over every volume source kind, with and
// without a subPath, the paths it derives from the spec alone equal the ones a
// real render reports. A daemon re-attaching to a pod recompiles the pod's SBPL
// read-only sub-scope from this, so a disagreement would compile a different
// profile than the create did.
func TestCredentialPathsMatchesMaterialize(t *testing.T) {
	r := fakeResolver{
		cms:     map[string]map[string][]byte{"cm": {"k": []byte("v")}},
		secrets: map[string]map[string][]byte{"sec": {"k": []byte("s")}},
		token:   "TOKEN",
	}
	projected := func(p ...*runtimev1.VolumeProjection) *runtimev1.Volume {
		return &runtimev1.Volume{Name: "v", Projected: &runtimev1.ProjectedVolumeSource{Sources: p}}
	}
	cmProj := &runtimev1.VolumeProjection{ConfigMap: &runtimev1.ConfigMapProjection{Name: "cm"}}
	secProj := &runtimev1.VolumeProjection{Secret: &runtimev1.SecretProjection{Name: "sec"}}
	tokProj := &runtimev1.VolumeProjection{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Audience: "api", ExpirationSeconds: 3600, Path: "token"}}
	downProj := &runtimev1.VolumeProjection{DownwardApi: &runtimev1.DownwardAPIProjection{Items: []*runtimev1.DownwardAPIVolumeFile{
		{Path: "name", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
	}}}

	cases := []struct {
		name       string
		vol        *runtimev1.Volume
		subPath    string
		credential bool
	}{
		{name: "configMap", vol: &runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}},
		{name: "secret", vol: &runtimev1.Volume{Name: "v", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}, credential: true},
		{name: "emptyDir", vol: &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
		{name: "downwardAPI", vol: &runtimev1.Volume{Name: "v", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: []*runtimev1.DownwardAPIVolumeFile{
			{Path: "name", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
		}}}},
		{name: "projected configMap", vol: projected(cmProj)},
		{name: "projected downwardAPI", vol: projected(downProj)},
		{name: "projected secret", vol: projected(cmProj, secProj), credential: true},
		{name: "projected token", vol: projected(tokProj, cmProj), credential: true},
		{name: "persistentVolumeClaim is not materialized here", vol: &runtimev1.Volume{Name: "v", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}}},
		{name: "subPath of a configMap", vol: &runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}, subPath: "k"},
		{name: "subPath of a secret", vol: &runtimev1.Volume{Name: "v", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}, subPath: "k", credential: true},
		{name: "subPath of an emptyDir", vol: &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, subPath: "d"},
		{name: "subPath of a projected token", vol: projected(tokProj), subPath: "token", credential: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataVol := filepath.Join(t.TempDir(), "rootfs")
			box := boxWith(tc.vol)
			box.Containers[0].VolumeMounts[0].SubPath = tc.subPath
			layout, err := Materialize(context.Background(), box, dataVol, "10.1.2.3", r)
			if err != nil {
				t.Fatalf("Materialize: %v", err)
			}
			pure, err := CredentialPaths(box, dataVol)
			if err != nil {
				t.Fatalf("CredentialPaths: %v", err)
			}
			rendered := layout.CredentialPaths()
			if !reflect.DeepEqual(pure, rendered) {
				t.Fatalf("CredentialPaths = %v, Materialize reported %v", pure, rendered)
			}
			var want []string
			if tc.credential {
				want = []string{filepath.Join(dataVol, "etc", "v")}
			}
			if !reflect.DeepEqual(pure, want) {
				t.Fatalf("CredentialPaths = %v, want %v", pure, want)
			}
		})
	}

	t.Run("every source in one box", func(t *testing.T) {
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		box := boxWith(
			&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}},
			&runtimev1.Volume{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}},
			&runtimev1.Volume{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
			&runtimev1.Volume{Name: "tok", Projected: &runtimev1.ProjectedVolumeSource{Sources: []*runtimev1.VolumeProjection{tokProj}}},
			&runtimev1.Volume{Name: "pvc", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}},
		)
		layout, err := Materialize(context.Background(), box, dataVol, "10.1.2.3", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		pure, err := CredentialPaths(box, dataVol)
		if err != nil {
			t.Fatalf("CredentialPaths: %v", err)
		}
		want := []string{filepath.Join(dataVol, "etc", "sec"), filepath.Join(dataVol, "etc", "tok")}
		if !reflect.DeepEqual(pure, layout.CredentialPaths()) || !reflect.DeepEqual(pure, want) {
			t.Fatalf("CredentialPaths = %v, Materialize = %v, want %v", pure, layout.CredentialPaths(), want)
		}
	})

	t.Run("an undefined volume is refused by both halves", func(t *testing.T) {
		box := boxWith(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}})
		box.Volumes = nil
		if _, err := CredentialPaths(box, t.TempDir()); err == nil {
			t.Fatal("CredentialPaths accepted a mount of an undefined volume")
		}
	})
}
