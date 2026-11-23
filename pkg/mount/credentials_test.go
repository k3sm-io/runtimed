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
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestReadOnlyPathsMatchesMaterialize pins ReadOnlyPaths as the pure half of
// Materialize's read-only verdict: over every volume source kind, with and
// without a subPath, and with and without read_only on the mount, the paths it
// derives from the spec alone equal the ones a real render reports: every
// API-data volume, credentials included, whatever its flag, and an emptyDir
// only when read_only. A daemon re-attaching to a pod recompiles the pod's
// SBPL read-only sub-scope from this, so a disagreement would compile a
// different profile than the create did.
func TestReadOnlyPathsMatchesMaterialize(t *testing.T) {
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
		// apiData is a configMap / secret / downwardAPI / projected volume:
		// read-only whatever the mount says (kubelet parity).
		apiData bool
	}{
		{name: "configMap", vol: &runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}, apiData: true},
		{name: "secret", vol: &runtimev1.Volume{Name: "v", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}, credential: true, apiData: true},
		{name: "emptyDir", vol: &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
		{name: "downwardAPI", vol: &runtimev1.Volume{Name: "v", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: []*runtimev1.DownwardAPIVolumeFile{
			{Path: "name", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
		}}}, apiData: true},
		{name: "projected configMap", vol: projected(cmProj), apiData: true},
		{name: "projected downwardAPI", vol: projected(downProj), apiData: true},
		{name: "projected secret", vol: projected(cmProj, secProj), credential: true, apiData: true},
		{name: "projected token", vol: projected(tokProj, cmProj), credential: true, apiData: true},
		{name: "persistentVolumeClaim is not materialized here", vol: &runtimev1.Volume{Name: "v", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}}},
		{name: "subPath of a configMap", vol: &runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}, subPath: "k", apiData: true},
		{name: "subPath of a secret", vol: &runtimev1.Volume{Name: "v", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}}, subPath: "k", credential: true, apiData: true},
		{name: "subPath of an emptyDir", vol: &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, subPath: "d"},
		{name: "subPath of a projected token", vol: projected(tokProj), subPath: "token", credential: true, apiData: true},
	}
	for _, tc := range cases {
		for _, readOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/readOnly=%v", tc.name, readOnly), func(t *testing.T) {
				dataVol := filepath.Join(t.TempDir(), "rootfs")
				box := boxWith(tc.vol)
				box.Containers[0].VolumeMounts[0].SubPath = tc.subPath
				box.Containers[0].VolumeMounts[0].ReadOnly = readOnly
				layout, err := Materialize(context.Background(), box, dataVol, "10.1.2.3", r)
				if err != nil {
					t.Fatalf("Materialize: %v", err)
				}
				sc, err := ScopeFor(box, dataVol)
				if err != nil {
					t.Fatalf("ScopeFor: %v", err)
				}
				if !reflect.DeepEqual(sc, layout.Scope()) {
					t.Fatalf("ScopeFor = %+v, Materialize reported %+v", sc, layout.Scope())
				}
				pure, mixed := sc.ReadOnly, sc.Mixed
				if !reflect.DeepEqual(pure, layout.ReadOnlyPaths()) {
					t.Fatalf("ReadOnlyPaths = %v, Materialize reported %v", pure, layout.ReadOnlyPaths())
				}
				if len(mixed) != 0 || len(layout.MixedReadOnly) != 0 {
					t.Fatalf("one container reported mixed volumes: pure %v, Materialize %v", mixed, layout.MixedReadOnly)
				}
				placed := filepath.Join(dataVol, "etc", "v")
				var wantCreds, wantRO []string
				if tc.credential {
					wantCreds = []string{placed}
				}
				materialized := tc.vol.GetPersistentVolumeClaim() == nil
				if materialized && (tc.apiData || readOnly) {
					wantRO = []string{placed}
				}
				if got := layout.CredentialPaths(); !reflect.DeepEqual(got, wantCreds) {
					t.Fatalf("CredentialPaths = %v, want %v", got, wantCreds)
				}
				if !reflect.DeepEqual(pure, wantRO) {
					t.Fatalf("ReadOnlyPaths = %v, want %v", pure, wantRO)
				}
			})
		}
	}

	t.Run("an emptyDir's read_only is per selection, over every container and path", func(t *testing.T) {
		vol := func(name string) *runtimev1.Volume {
			return &runtimev1.Volume{Name: name, EmptyDir: &runtimev1.EmptyDirVolumeSource{}}
		}
		cm := &runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}}
		mnt := func(name, path string, ro bool) *runtimev1.VolumeMount {
			return &runtimev1.VolumeMount{Name: name, MountPath: path, ReadOnly: ro}
		}
		dataVol := filepath.Join(t.TempDir(), "rootfs")
		box := &runtimev1.PodBox{
			PodId: "pod-1", Namespace: "default", Name: "demo",
			Volumes: []*runtimev1.Volume{vol("scratch"), vol("logs"), cm},
			InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{
				mnt("scratch", "/work", false), // read-write here: the selection stays writable everywhere
				mnt("logs", "/logs", true),
				mnt("cm", "/etc/cm", false), // an API-data volume: read-only whatever the flag says
			}}},
			Containers: []*runtimev1.Container{{Name: "main", VolumeMounts: []*runtimev1.VolumeMount{
				mnt("scratch", "/work", true),
				mnt("scratch", "/ro-work", true), // an alias of /work: still mixed
				mnt("logs", "/var/logs", true),   // an alias of /logs: read-only everywhere
			}}},
		}
		layout, err := Materialize(context.Background(), box, dataVol, "10.1.2.3", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		sc, err := ScopeFor(box, dataVol)
		if err != nil {
			t.Fatalf("ScopeFor: %v", err)
		}
		if !reflect.DeepEqual(sc, layout.Scope()) {
			t.Fatalf("ScopeFor = %+v, Materialize reported %+v", sc, layout.Scope())
		}
		// /ro-work is a link to scratch's writable /work and carries nothing;
		// /var/logs is one to logs' read-only /logs and carries the rule.
		if want := []string{filepath.Join(dataVol, "work")}; !reflect.DeepEqual(sc.Writable, want) {
			t.Fatalf("Writable = %v, want %v", sc.Writable, want)
		}
		pure, mixed := sc.ReadOnly, sc.Mixed
		want := []string{filepath.Join(dataVol, "etc", "cm"), filepath.Join(dataVol, "logs"), filepath.Join(dataVol, "var", "logs")}
		if !reflect.DeepEqual(pure, layout.ReadOnlyPaths()) || !reflect.DeepEqual(pure, want) {
			t.Fatalf("ReadOnlyPaths = %v, Materialize = %v, want %v", pure, layout.ReadOnlyPaths(), want)
		}
		if wantMixed := []string{"scratch"}; !reflect.DeepEqual(mixed, wantMixed) || !reflect.DeepEqual(layout.MixedReadOnly, wantMixed) {
			t.Fatalf("mixed = %v, Materialize = %v, want %v", mixed, layout.MixedReadOnly, wantMixed)
		}
	})

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
		sc, err := ScopeFor(box, dataVol)
		if err != nil {
			t.Fatalf("ScopeFor: %v", err)
		}
		if !reflect.DeepEqual(sc, layout.Scope()) {
			t.Fatalf("ScopeFor = %+v, Materialize reported %+v", sc, layout.Scope())
		}
		pure := sc.ReadOnly
		want := []string{filepath.Join(dataVol, "etc", "cm"), filepath.Join(dataVol, "etc", "sec"), filepath.Join(dataVol, "etc", "tok")}
		if !reflect.DeepEqual(pure, layout.ReadOnlyPaths()) || !reflect.DeepEqual(pure, want) {
			t.Fatalf("ReadOnlyPaths = %v, Materialize = %v, want %v", pure, layout.ReadOnlyPaths(), want)
		}
	})

	t.Run("an undefined volume is refused by both halves", func(t *testing.T) {
		box := boxWith(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cm"}})
		box.Volumes = nil
		if _, err := ScopeFor(box, t.TempDir()); err == nil {
			t.Fatal("ScopeFor accepted a mount of an undefined volume")
		}
	})
}
