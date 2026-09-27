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

package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPlanIsBindWithoutIO pins Plan as the pure half of Bind: for every box
// shape it returns exactly the (VolumeName, ClaimName, DataDir, ReadOnly) Bind
// then produces, and it touches nothing on disk — the property a daemon that
// re-derives a pod's SBPL PV scope after a restart relies on.
func TestPlanIsBindWithoutIO(t *testing.T) {
	twoClaims := pvcBox("ns1", "data", "db", "/var/data", false)
	twoClaims.Volumes = append(twoClaims.Volumes, &runtimev1.Volume{
		Name:                  "ro",
		PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "seed", ReadOnly: true},
	}, &runtimev1.Volume{Name: "cm", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "x"}})
	twoClaims.Containers[0].VolumeMounts = append(twoClaims.Containers[0].VolumeMounts,
		&runtimev1.VolumeMount{Name: "ro", MountPath: "/seed"})

	cases := []struct {
		name string
		box  *runtimev1.PodBox
		want int
	}{
		{name: "no volumes", box: &runtimev1.PodBox{PodId: "p", Namespace: "ns1", Containers: []*runtimev1.Container{{Name: "main"}}}},
		{name: "one read-write claim", box: pvcBox("ns1", "data", "db", "/var/data", false), want: 1},
		{name: "one read-only claim", box: pvcBox("ns1", "data", "db", "/var/data", true), want: 1},
		{name: "two claims beside a non-PVC volume", box: twoClaims, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			b := NewBinder(testClass(root), image.ByteCopier{}, nil, nil)
			plan, err := b.Plan(tc.box)
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			if len(plan) != tc.want {
				t.Fatalf("Plan = %+v, want %d bindings", plan, tc.want)
			}
			for _, bd := range plan {
				if _, err := os.Stat(bd.DataDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("Plan created or found %s (stat err %v): it must do no I/O", bd.DataDir, err)
				}
				if bd.Seeded || len(bd.Links) != 0 {
					t.Fatalf("Plan binding %+v carries I/O results", bd)
				}
			}
			bound, err := b.Bind(context.Background(), tc.box, filepath.Join(root, "rootfs"))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if len(bound) != len(plan) {
				t.Fatalf("Bind = %+v, Plan = %+v: different binding sets", bound, plan)
			}
			for i := range plan {
				p, g := plan[i], bound[i]
				if p.VolumeName != g.VolumeName || p.ClaimName != g.ClaimName || p.DataDir != g.DataDir || p.ReadOnly != g.ReadOnly {
					t.Fatalf("binding %d: Plan %+v, Bind %+v", i, p, g)
				}
			}
		})
	}

	t.Run("an unmappable claim is ErrInvalid", func(t *testing.T) {
		b := NewBinder(testClass(t.TempDir()), image.ByteCopier{}, nil, nil)
		if _, err := b.Plan(pvcBox("ns1", "data", "../escape", "/var/data", false)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Plan = %v, want ErrInvalid", err)
		}
	})
}
