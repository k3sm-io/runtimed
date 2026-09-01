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
	"os"
	"path/filepath"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// provisionBox is a pod with one PVC volume mounted by one container.
func provisionBox(claim string) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:     "pod-1",
		Namespace: "default",
		Name:      "p",
		Volumes: []*runtimev1.Volume{{
			Name:                  "data",
			PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
		}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "data", MountPath: "/data"}},
		}},
	}
}

// TestProvisionIsBindWithoutTheLinks pins the split the vm spine depends on:
// Provision does everything Bind does to the STORAGE ROOT and nothing at all to
// the pod rootfs. A vm pod reaches its claim through a virtiofs share device, and
// its rootfs is exported to the guest read-only, so the symlink Bind plants would
// be both wrong and unreachable there.
func TestProvisionIsBindWithoutTheLinks(t *testing.T) {
	newBinder := func(t *testing.T) (*Binder, string) {
		t.Helper()
		base := t.TempDir()
		return NewBinder(storagev1.LocalPathClass{BasePath: base}, nil, nil, nil), base
	}

	t.Run("creates-the-claim-dir-and-reports-it", func(t *testing.T) {
		b, base := newBinder(t)
		got, err := b.Provision(context.Background(), provisionBox("pgdata"))
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("bindings = %+v, want exactly one", got)
		}
		want := filepath.Join(base, "default", "pgdata")
		if got[0].DataDir != want {
			t.Errorf("DataDir = %q, want %q", got[0].DataDir, want)
		}
		if fi, serr := os.Stat(want); serr != nil || !fi.IsDir() {
			t.Errorf("claim dir %s was not created: %v", want, serr)
		}
		if len(got[0].Links) != 0 {
			t.Errorf("Links = %v, want none — a vm pod reaches its claim through the share device", got[0].Links)
		}
		if got[0].Seeded {
			t.Error("Seeded = true with no template resolver; the empty-create hot path must not clone")
		}
	})

	t.Run("an-existing-claim-is-reused-untouched", func(t *testing.T) {
		b, base := newBinder(t)
		dir := filepath.Join(base, "default", "pgdata")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		payload := []byte("PG_VERSION 16\n")
		if err := os.WriteFile(filepath.Join(dir, "PG_VERSION"), payload, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := b.Provision(context.Background(), provisionBox("pgdata"))
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if got[0].Seeded {
			t.Error("Seeded = true on reuse; a PVC is seeded exactly once, on first create")
		}
		back, err := os.ReadFile(filepath.Join(dir, "PG_VERSION"))
		if err != nil || string(back) != string(payload) {
			t.Errorf("the existing claim's contents did not survive: %q, %v", back, err)
		}
	})

	t.Run("a-box-with-no-pvc-provisions-nothing", func(t *testing.T) {
		b, base := newBinder(t)
		box := &runtimev1.PodBox{
			PodId:      "pod-1",
			Namespace:  "default",
			Volumes:    []*runtimev1.Volume{{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}},
			Containers: []*runtimev1.Container{{Name: "main"}},
		}
		got, err := b.Provision(context.Background(), box)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if got != nil {
			t.Errorf("bindings = %+v, want nil", got)
		}
		if entries, _ := os.ReadDir(base); len(entries) != 0 {
			t.Errorf("the storage root gained %d entries for a pod with no claim", len(entries))
		}
	})

	t.Run("bind-still-links-what-provision-created", func(t *testing.T) {
		// The host-process spine is unchanged by the split: Bind is Provision plus
		// the links, and a refactor that lost the second half would be invisible to
		// every Provision assertion above.
		b, base := newBinder(t)
		rootfs := t.TempDir()
		got, err := b.Bind(context.Background(), provisionBox("pgdata"), rootfs)
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if len(got) != 1 || len(got[0].Links) != 1 {
			t.Fatalf("bindings = %+v, want one binding with one link", got)
		}
		link := filepath.Join(rootfs, "data")
		if got[0].Links[0] != link {
			t.Errorf("link = %q, want %q", got[0].Links[0], link)
		}
		dest, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("readlink: %v", err)
		}
		if want := filepath.Join(base, "default", "pgdata"); dest != want {
			t.Errorf("link -> %q, want %q", dest, want)
		}
	})
}
