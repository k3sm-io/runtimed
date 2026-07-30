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
	"reflect"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// planClass returns a defaulted local-path class rooted under root/storage,
// the shape createVMPod hands the planner in production.
func planClass(root string) storagev1.LocalPathClass {
	return storagev1.LocalPathClass{BasePath: root + "/storage"}.WithDefaults()
}

// planBox builds a vm PodBox with the given volumes and one "main" container
// mounting each volume at /mnt/<name> (no subPath).
func planBox(volumes ...*runtimev1.Volume) *runtimev1.PodBox {
	mounts := make([]*runtimev1.VolumeMount, 0, len(volumes))
	for _, v := range volumes {
		mounts = append(mounts, &runtimev1.VolumeMount{Name: v.GetName(), MountPath: "/mnt/" + v.GetName()})
	}
	return &runtimev1.PodBox{
		PodId:     "pod-1",
		Namespace: "default",
		Name:      "p",
		Volumes:   volumes,
		Containers: []*runtimev1.Container{{
			Name:         "main",
			Image:        "/bin/sleep",
			VolumeMounts: mounts,
		}},
	}
}

// TestIsStrictlyUnder pins the strict, separator-aware containment helper the
// share-plan guards depend on: equality is FALSE (the difference from isUnder)
// and a sibling sharing a name prefix is NOT a descendant.
func TestIsStrictlyUnder(t *testing.T) {
	cases := []struct {
		name       string
		path, base string
		want       bool
	}{
		{"child", "/a/b", "/a", true},
		{"deep-descendant", "/a/b/c/d", "/a/b", true},
		{"equal-is-false", "/a/b", "/a/b", false},
		{"equal-after-clean-is-false", "/a/b/", "/a/b", false},
		{"sibling-prefix-not-under", "/a/bc", "/a/b", false},
		{"sibling-prefix-deep-not-under", "/a/bc/d", "/a/b", false},
		{"parent-not-under-child", "/a", "/a/b", false},
		{"unrelated", "/x/y", "/a/b", false},
		{"root-base-child", "/a", "/", true},
		{"root-base-equal-is-false", "/", "/", false},
		{"cleans-inputs", "/a/./b/../b/c", "/a/b", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStrictlyUnder(tc.path, tc.base); got != tc.want {
				t.Errorf("isStrictlyUnder(%q, %q) = %v, want %v", tc.path, tc.base, got, tc.want)
			}
		})
	}
}

// TestValidateVMSubPath pins the lexical sub_path validation: relative, clean,
// and no ".." segment — including the "../x" case that IS clean-invariant and
// only the segment scan catches.
func TestValidateVMSubPath(t *testing.T) {
	cases := []struct {
		name    string
		subPath string
		wantErr bool
	}{
		{"simple", "conf", false},
		{"nested", "a/b/c", false},
		{"dotfile", ".hidden", false},
		{"absolute", "/etc/passwd", true},
		{"dotdot-alone", "..", true},
		{"leading-dotdot-clean-invariant", "../x", true},
		{"interior-dotdot-uncleaned", "a/../b", true},
		{"trailing-dotdot", "a/..", true},
		{"unclean-dot-segment", "a/./b", true},
		{"unclean-trailing-slash", "a/b/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVMSubPath(tc.subPath)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateVMSubPath(%q) err = %v, wantErr %v", tc.subPath, err, tc.wantErr)
			}
		})
	}
}

// TestClassifyVMVolumeArity pins the arity-checked dispatch over the volume
// source union (NOT a proto oneof): exactly one known source or reject — a
// zero-source volume (how a future unknown field like host_path presents to
// this build) and a two-source volume both fail closed.
func TestClassifyVMVolumeArity(t *testing.T) {
	cases := []struct {
		name    string
		vol     *runtimev1.Volume
		wantErr bool
	}{
		{"configmap-ok", &runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}}, false},
		{"secret-ok", &runtimev1.Volume{Name: "v", Secret: &runtimev1.SecretVolumeSource{SecretName: "s"}}, false},
		{"emptydir-ok", &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}, false},
		{"downwardapi-ok", &runtimev1.Volume{Name: "v", DownwardApi: &runtimev1.DownwardAPIVolumeSource{}}, false},
		{"projected-ok", &runtimev1.Volume{Name: "v", Projected: &runtimev1.ProjectedVolumeSource{}}, false},
		{"pvc-ok", &runtimev1.Volume{Name: "v", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}}, false},
		{"zero-sources-rejected", &runtimev1.Volume{Name: "v"}, true},
		{"two-sources-rejected", &runtimev1.Volume{
			Name:      "v",
			ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"},
			EmptyDir:  &runtimev1.EmptyDirVolumeSource{},
		}, true},
		{"three-sources-rejected", &runtimev1.Volume{
			Name:                  "v",
			Secret:                &runtimev1.SecretVolumeSource{SecretName: "s"},
			Projected:             &runtimev1.ProjectedVolumeSource{},
			PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"},
		}, true},
		{"memory-medium-ok", &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "Memory"}}, false},
		{"unknown-medium-rejected", &runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "HugePages"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := classifyVMVolume(tc.vol)
			if (err != nil) != tc.wantErr {
				t.Errorf("classifyVMVolume err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestComputeSharePlanRejects table-drives the planner's fail-closed rejects
// beyond the classification table above: undeclared mounts, duplicate
// identities, malformed inputs, and every share-root guard (storage-root
// escape via a traversing claim name, the <workRoot>/run socket tree, nested
// roots).
func TestComputeSharePlanRejects(t *testing.T) {
	const root = "/work"
	pod := root + "/pods/pod-1"
	cases := []struct {
		name     string
		box      *runtimev1.PodBox
		podDir   string
		workRoot string
		class    storagev1.LocalPathClass
		wantFrag string
	}{
		{
			name: "undeclared-volume-mount",
			box: func() *runtimev1.PodBox {
				b := planBox(&runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
				b.Containers[0].VolumeMounts = append(b.Containers[0].VolumeMounts,
					&runtimev1.VolumeMount{Name: "ghost", MountPath: "/ghost"})
				return b
			}(),
			wantFrag: "undeclared volume",
		},
		{
			name: "duplicate-mount-path-in-one-container",
			box: func() *runtimev1.PodBox {
				b := planBox(
					&runtimev1.Volume{Name: "a", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
					&runtimev1.Volume{Name: "b", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
				)
				b.Containers[0].VolumeMounts[1].MountPath = b.Containers[0].VolumeMounts[0].MountPath
				return b
			}(),
			wantFrag: "duplicate mount_path",
		},
		{
			name: "empty-mount-path",
			box: func() *runtimev1.PodBox {
				b := planBox(&runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
				b.Containers[0].VolumeMounts[0].MountPath = ""
				return b
			}(),
			wantFrag: "empty mount_path",
		},
		{
			name: "duplicate-volume-name",
			box: planBox(
				&runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
				&runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}},
			),
			wantFrag: "duplicate volume name",
		},
		{
			name: "duplicate-container-name",
			box: func() *runtimev1.PodBox {
				b := planBox(&runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
				b.Containers = append(b.Containers, &runtimev1.Container{Name: "main", Image: "/bin/true"})
				return b
			}(),
			wantFrag: "duplicate container name",
		},
		{
			name: "subpath-traversal",
			box: func() *runtimev1.PodBox {
				b := planBox(&runtimev1.Volume{Name: "v", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}})
				b.Containers[0].VolumeMounts[0].SubPath = "../creds"
				return b
			}(),
			wantFrag: "sub_path",
		},
		{
			name: "subpath-on-memory-emptydir",
			box: func() *runtimev1.PodBox {
				b := planBox(&runtimev1.Volume{Name: "v", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "Memory"}})
				b.Containers[0].VolumeMounts[0].SubPath = "sub"
				return b
			}(),
			wantFrag: "not supported on a Memory-medium emptyDir",
		},
		{
			name: "pvc-claim-traversal-escapes-storage-root",
			box: planBox(&runtimev1.Volume{
				Name:                  "v",
				PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "../../etc"},
			}),
			wantFrag: "escapes the storage base path",
		},
		{
			name: "pvc-claim-traversal-into-run-tree",
			box: planBox(&runtimev1.Volume{
				Name:                  "v",
				PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "k"},
			}),
			// Storage class mis-rooted INSIDE <workRoot>/run: the R7 guard is
			// the one that refuses (the root is fine by every other rule).
			class:    storagev1.LocalPathClass{BasePath: root + "/run/storage"}.WithDefaults(),
			wantFrag: "intersects the runtime socket tree",
		},
		{
			name: "pvc-roots-nested-via-claim-names",
			box: planBox(
				&runtimev1.Volume{Name: "a", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}},
				&runtimev1.Volume{Name: "b", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c/nested"}},
			),
			wantFrag: "are nested",
		},
		{
			name:     "relative-pod-dir",
			box:      planBox(),
			podDir:   "pods/pod-1",
			wantFrag: "must be absolute",
		},
		{
			name:     "relative-work-root",
			box:      planBox(),
			workRoot: "work",
			wantFrag: "must be absolute",
		},
		{
			name:     "nil-box",
			box:      nil,
			wantFrag: "nil pod box",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			podDir := tc.podDir
			if podDir == "" {
				podDir = pod
			}
			workRoot := tc.workRoot
			if workRoot == "" {
				workRoot = root
			}
			class := tc.class
			if class.BasePath == "" {
				class = planClass(root)
			}
			_, err := ComputeSharePlan(tc.box, podDir, workRoot, class)
			if err == nil {
				t.Fatal("want reject, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantFrag) {
				t.Errorf("error %q does not contain %q", err, tc.wantFrag)
			}
		})
	}
}

// TestComputeSharePlanShapes pins planner shapes the runtime gate does not:
// conditional pooled-share emission, the read-only derivation mirror, subPath
// carried verbatim, tag/order determinism, and same-input reproducibility.
func TestComputeSharePlanShapes(t *testing.T) {
	const root = "/work"
	pod := root + "/pods/pod-1"
	class := planClass(root)

	t.Run("no-volumes-rootfs-share-only", func(t *testing.T) {
		plan, err := ComputeSharePlan(planBox(), pod, root, class)
		if err != nil {
			t.Fatal(err)
		}
		want := SharePlan{Shares: []Share{{Tag: ShareTagRootfs, Root: pod + "/rootfs"}}}
		if !reflect.DeepEqual(plan, want) {
			t.Errorf("plan = %+v, want %+v", plan, want)
		}
	})

	t.Run("readonly-derivation-mirrors-materialize", func(t *testing.T) {
		box := planBox(
			&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}},
			&runtimev1.Volume{Name: "cm-ro", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}},
			&runtimev1.Volume{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "s"}},
			&runtimev1.Volume{Name: "proj-plain", Projected: &runtimev1.ProjectedVolumeSource{
				Sources: []*runtimev1.VolumeProjection{{ConfigMap: &runtimev1.ConfigMapProjection{Name: "c"}}},
			}},
			&runtimev1.Volume{Name: "down", DownwardApi: &runtimev1.DownwardAPIVolumeSource{}},
		)
		// cm-ro carries an explicit read_only.
		box.Containers[0].VolumeMounts[1].ReadOnly = true
		plan, err := ComputeSharePlan(box, pod, root, class)
		if err != nil {
			t.Fatal(err)
		}
		wantRO := map[string]bool{
			"cm":         false, // plain configMap: mount intent only
			"cm-ro":      true,  // volumeMount read_only
			"sec":        true,  // credential class forces RO
			"proj-plain": true,  // projected forces RO even with no credential source
			"down":       false, // downwardAPI: mount intent only
		}
		for _, b := range plan.Binds["main"] {
			if b.ReadOnly != wantRO[b.VolumeName] {
				t.Errorf("bind %s ReadOnly = %v, want %v", b.VolumeName, b.ReadOnly, wantRO[b.VolumeName])
			}
			if b.ShareTag != ShareTagProj {
				t.Errorf("bind %s on share %s, want %s", b.VolumeName, b.ShareTag, ShareTagProj)
			}
		}
		if got := len(plan.Binds["main"]); got != len(wantRO) {
			t.Errorf("main has %d binds, want %d", got, len(wantRO))
		}
	})

	t.Run("subpath-carried-verbatim", func(t *testing.T) {
		box := planBox(&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}})
		box.Containers[0].VolumeMounts[0].SubPath = "keys/tls.crt"
		plan, err := ComputeSharePlan(box, pod, root, class)
		if err != nil {
			t.Fatal(err)
		}
		if got := plan.Binds["main"][0].SubPath; got != "keys/tls.crt" {
			t.Errorf("SubPath = %q, want verbatim %q", got, "keys/tls.crt")
		}
	})

	t.Run("pvc-tags-index-sorted-volume-names", func(t *testing.T) {
		// Declared out of order; sorted-volume-name order fixes the indices.
		box := planBox(
			&runtimev1.Volume{Name: "z", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "cz", ReadOnly: true}},
			&runtimev1.Volume{Name: "a", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "ca"}},
		)
		plan, err := ComputeSharePlan(box, pod, root, class)
		if err != nil {
			t.Fatal(err)
		}
		dirA, err := class.DataDir("default", "ca")
		if err != nil {
			t.Fatal(err)
		}
		dirZ, err := class.DataDir("default", "cz")
		if err != nil {
			t.Fatal(err)
		}
		wantShares := []Share{
			{Tag: ShareTagRootfs, Root: pod + "/rootfs"},
			{Tag: ShareTagPVCPrefix + "0", Root: dirA, Writable: true},
			{Tag: ShareTagPVCPrefix + "1", Root: dirZ, Writable: false},
		}
		if !reflect.DeepEqual(plan.Shares, wantShares) {
			t.Errorf("shares = %+v, want %+v", plan.Shares, wantShares)
		}
		// A PVC bind sources the share root itself.
		for _, b := range plan.Binds["main"] {
			if b.SourceRel != "" {
				t.Errorf("pvc bind %s SourceRel = %q, want \"\"", b.VolumeName, b.SourceRel)
			}
		}
	})

	t.Run("deterministic-across-runs", func(t *testing.T) {
		mk := func() *runtimev1.PodBox {
			b := planBox(
				&runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "c"}},
				&runtimev1.Volume{Name: "ed", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
				&runtimev1.Volume{Name: "p2", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c2"}},
				&runtimev1.Volume{Name: "p1", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "c1"}},
			)
			b.InitContainers = []*runtimev1.Container{{
				Name:         "init",
				Image:        "/bin/true",
				VolumeMounts: []*runtimev1.VolumeMount{{Name: "ed", MountPath: "/init-scratch"}},
			}}
			return b
		}
		p1, err := ComputeSharePlan(mk(), pod, root, class)
		if err != nil {
			t.Fatal(err)
		}
		p2, err := ComputeSharePlan(mk(), pod, root, class)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p1, p2) {
			t.Errorf("plans differ across identical runs:\n%+v\n%+v", p1, p2)
		}
	})
}
