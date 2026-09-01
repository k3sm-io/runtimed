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
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// saTokenVolume is the projected volume every pod gets by default when its
// ServiceAccount token is automounted — the exact shape whose missing host
// directory killed guest init ("mount /run/k3sm/shares/k3sm.proj/
// kube-api-access-6t9pz at /var/run/secrets/kubernetes.io/serviceaccount: no
// such file or directory").
func saTokenVolume(name string) *runtimev1.Volume {
	return &runtimev1.Volume{Name: name, Projected: &runtimev1.ProjectedVolumeSource{
		Sources: []*runtimev1.VolumeProjection{
			{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{ExpirationSeconds: 3607, Path: "token"}},
			{ConfigMap: &runtimev1.ConfigMapProjection{Name: "kube-root-ca.crt", Items: []*runtimev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
			{DownwardApi: &runtimev1.DownwardAPIProjection{Items: []*runtimev1.DownwardAPIVolumeFile{
				{Path: "namespace", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}},
			}}},
		},
	}}
}

// shareBox builds a vm PodBox from the given volumes and one volumeMount list
// per container name, in the order the names appear.
func shareBox(volumes []*runtimev1.Volume, mounts map[string][]*runtimev1.VolumeMount, order ...string) *runtimev1.PodBox {
	containers := make([]*runtimev1.Container, 0, len(order))
	for _, name := range order {
		containers = append(containers, &runtimev1.Container{Name: name, Image: "docker.io/library/busybox", VolumeMounts: mounts[name]})
	}
	return &runtimev1.PodBox{
		PodId:      "pod-1",
		Namespace:  "default",
		Name:       "demo",
		Volumes:    volumes,
		Containers: containers,
	}
}

// TestMaterializeShares is the vm-path counterpart of TestMaterializeAllSources:
// the pooled proj/vols share content the guest binds must exist on the host
// BEFORE the VM boots. ComputeSharePlan alone (the pure-data planner) creates
// nothing, so every want below fails on a plan-only path.
func TestMaterializeShares(t *testing.T) {
	res := fakeResolver{
		cms: map[string]map[string][]byte{
			"kube-root-ca.crt": {"ca.crt": []byte("CERT")},
			"app-config":       {"app.conf": []byte("k=v")},
		},
		secrets: map[string]map[string][]byte{
			"registry": {"dockerconfigjson": []byte("{}")},
		},
		token: "BOUND-TOKEN",
	}
	const saVol = "kube-api-access-6t9pz"
	const saPath = "/var/run/secrets/kubernetes.io/serviceaccount"

	cases := []struct {
		name    string
		volumes []*runtimev1.Volume
		mounts  map[string][]*runtimev1.VolumeMount
		order   []string
		podIP   string
		files   map[string]string // path under podDir -> content
		dirs    []string          // paths under podDir that must be dirs
		absent  []string          // paths under podDir that must not exist
		modes   map[string]os.FileMode
	}{
		{
			name:    "automounted-sa-token-and-emptydir",
			volumes: []*runtimev1.Volume{saTokenVolume(saVol), {Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
			mounts: map[string][]*runtimev1.VolumeMount{"main": {
				{Name: saVol, MountPath: saPath, ReadOnly: true},
				{Name: "scratch", MountPath: "/scratch"},
			}},
			order: []string{"main"},
			files: map[string]string{
				"k3sm.proj/" + saVol + "/token":     "BOUND-TOKEN",
				"k3sm.proj/" + saVol + "/ca.crt":    "CERT",
				"k3sm.proj/" + saVol + "/namespace": "default",
			},
			dirs:  []string{"rootfs", "k3sm.proj", "k3sm.proj/" + saVol, "k3sm.vols", "k3sm.vols/scratch"},
			modes: map[string]os.FileMode{"k3sm.proj": 0o700},
		},
		{
			name: "configmap-and-secret-pool-into-one-proj-share",
			volumes: []*runtimev1.Volume{
				{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-config"}},
				{Name: "reg", Secret: &runtimev1.SecretVolumeSource{SecretName: "registry"}},
			},
			mounts: map[string][]*runtimev1.VolumeMount{"main": {
				{Name: "cfg", MountPath: "/etc/app"},
				{Name: "reg", MountPath: "/etc/reg"},
			}},
			order: []string{"main"},
			files: map[string]string{
				"k3sm.proj/cfg/app.conf":         "k=v",
				"k3sm.proj/reg/dockerconfigjson": "{}",
			},
			dirs:   []string{"k3sm.proj/cfg", "k3sm.proj/reg"},
			absent: []string{"k3sm.vols"},
		},
		{
			name:    "memory-emptydir-is-a-guest-tmpfs-not-a-share",
			volumes: []*runtimev1.Volume{{Name: "shm", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "Memory"}}},
			mounts:  map[string][]*runtimev1.VolumeMount{"main": {{Name: "shm", MountPath: "/dev/shm"}}},
			order:   []string{"main"},
			dirs:    []string{"rootfs"},
			absent:  []string{"k3sm.vols", "k3sm.proj", "k3sm.vols/shm"},
		},
		{
			name:    "one-volume-mounted-by-two-containers-materializes-once",
			volumes: []*runtimev1.Volume{saTokenVolume(saVol)},
			mounts: map[string][]*runtimev1.VolumeMount{
				"init": {{Name: saVol, MountPath: saPath}},
				"main": {{Name: saVol, MountPath: saPath}},
			},
			order: []string{"init", "main"},
			files: map[string]string{"k3sm.proj/" + saVol + "/token": "BOUND-TOKEN"},
			dirs:  []string{"k3sm.proj/" + saVol},
		},
		{
			name: "downward-api-projects-the-pod-ip-it-is-given",
			volumes: []*runtimev1.Volume{{Name: "podinfo", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: []*runtimev1.DownwardAPIVolumeFile{
				{Path: "ip", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "status.podIP"}},
				{Path: "name", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}},
			}}}},
			mounts: map[string][]*runtimev1.VolumeMount{"main": {{Name: "podinfo", MountPath: "/etc/podinfo"}}},
			order:  []string{"main"},
			podIP:  "10.42.0.7",
			files: map[string]string{
				"k3sm.proj/podinfo/ip":   "10.42.0.7",
				"k3sm.proj/podinfo/name": "demo",
			},
		},
		{
			name: "subpath-is-applied-guest-side-so-the-whole-volume-is-rendered",
			volumes: []*runtimev1.Volume{
				{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-config"}},
			},
			mounts: map[string][]*runtimev1.VolumeMount{"main": {
				{Name: "cfg", MountPath: "/etc/app.conf", SubPath: "app.conf"},
			}},
			order: []string{"main"},
			files: map[string]string{"k3sm.proj/cfg/app.conf": "k=v"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workRoot := t.TempDir()
			podDir := filepath.Join(workRoot, "pods", "pod-1")
			box := shareBox(tc.volumes, tc.mounts, tc.order...)

			plan, err := ComputeSharePlan(box, podDir, workRoot, planClass(workRoot))
			if err != nil {
				t.Fatalf("ComputeSharePlan: %v", err)
			}
			if err := MaterializeShares(context.Background(), box, plan, tc.podIP, res); err != nil {
				t.Fatalf("MaterializeShares: %v", err)
			}

			for rel, want := range tc.files {
				got, rerr := os.ReadFile(filepath.Join(podDir, rel))
				if rerr != nil {
					t.Errorf("read %s: %v", rel, rerr)
					continue
				}
				if string(got) != want {
					t.Errorf("%s = %q, want %q", rel, got, want)
				}
			}
			for _, rel := range tc.dirs {
				fi, serr := os.Stat(filepath.Join(podDir, rel))
				if serr != nil {
					t.Errorf("stat %s: %v", rel, serr)
					continue
				}
				if !fi.IsDir() {
					t.Errorf("%s is not a directory", rel)
				}
			}
			for _, rel := range tc.absent {
				if _, serr := os.Stat(filepath.Join(podDir, rel)); !errors.Is(serr, os.ErrNotExist) {
					t.Errorf("%s should not exist, stat err = %v", rel, serr)
				}
			}
			for rel, want := range tc.modes {
				fi, serr := os.Stat(filepath.Join(podDir, rel))
				if serr != nil {
					t.Errorf("stat %s: %v", rel, serr)
					continue
				}
				if got := fi.Mode().Perm(); got != want {
					t.Errorf("%s mode = %o, want %o", rel, got, want)
				}
			}
		})
	}
}

// TestMaterializeSharesSkipsPVCShares pins the ownership boundary: a PVC's data
// dir belongs to pkg/volume, so the share materializer must not create it (the
// native spine's Materialize skips PVC sources for the same reason).
func TestMaterializeSharesSkipsPVCShares(t *testing.T) {
	workRoot := t.TempDir()
	podDir := filepath.Join(workRoot, "pods", "pod-1")
	box := shareBox(
		[]*runtimev1.Volume{{Name: "data", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-1"}}},
		map[string][]*runtimev1.VolumeMount{"main": {{Name: "data", MountPath: "/data"}}},
		"main",
	)
	class := planClass(workRoot)
	plan, err := ComputeSharePlan(box, podDir, workRoot, class)
	if err != nil {
		t.Fatalf("ComputeSharePlan: %v", err)
	}
	if err := MaterializeShares(context.Background(), box, plan, "", nil); err != nil {
		t.Fatalf("MaterializeShares: %v", err)
	}
	pvcRoot, err := class.DataDir("default", "pvc-1")
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	if _, err := os.Stat(pvcRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pvc root %s should be left to pkg/volume, stat err = %v", pvcRoot, err)
	}
}

// TestMaterializeSharesRejectsTraversingVolumeName is the fail-closed guard on
// the one PodBox string that becomes a path component here: a volume name that
// would address a sibling of the share root is refused, not rendered.
func TestMaterializeSharesRejectsTraversingVolumeName(t *testing.T) {
	workRoot := t.TempDir()
	podDir := filepath.Join(workRoot, "pods", "pod-1")
	box := shareBox(
		[]*runtimev1.Volume{{Name: "../escape", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
		map[string][]*runtimev1.VolumeMount{"main": {{Name: "../escape", MountPath: "/x"}}},
		"main",
	)
	plan, err := ComputeSharePlan(box, podDir, workRoot, planClass(workRoot))
	if err != nil {
		t.Fatalf("ComputeSharePlan: %v", err)
	}
	if err := MaterializeShares(context.Background(), box, plan, "", nil); err == nil {
		t.Fatal("a traversing volume name must be rejected")
	}
	if _, err := os.Stat(filepath.Join(workRoot, "pods", "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the traversing name must not have been materialized")
	}
}
