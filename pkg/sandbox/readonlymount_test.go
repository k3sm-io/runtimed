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

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"k3sm.io/runtimed/pkg/mount"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// roResolver serves the one configMap the read-only mount test renders.
type roResolver struct{ data map[string][]byte }

func (r roResolver) ConfigMap(context.Context, string, string) (mount.SourceData, error) {
	return mount.SourceData{Data: r.data}, nil
}

func (r roResolver) Secret(context.Context, string, string) (mount.SourceData, error) {
	return mount.SourceData{}, os.ErrNotExist
}

func (r roResolver) ServiceAccountToken(context.Context, string, string, int64) (string, error) {
	return "", os.ErrNotExist
}

// roOps are the writes a pod must not make under a read-only mount, each on
// its own name so one attempt cannot void another.
var roOps = []string{"create", "write", "rename", "chmod", "unlink"}

// TestReadOnlyVolumeMountDeniesWrites runs, under sandbox-exec, a native pod
// profile built the way compileProfile builds it: materialize the pod's
// volumes (mount.Materialize) and hand the layout's read-only paths to
// Generate. An emptyDir and a configMap every container mounts read_only must
// refuse create, write, rename, chmod and unlink at the materialized path. The
// pod has one profile, so an emptyDir one container mounts read-write and
// another read-only stays writable (and is reported mixed, which the runtime
// warns about), as does the rest of the data volume.
func TestReadOnlyVolumeMountDeniesWrites(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Fatalf("sandbox-exec is missing, so nothing can be measured: %v", err)
	}
	base := filepath.Join("/private/tmp", "k3sm-ro-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")

	cmData := map[string][]byte{}
	for _, op := range roOps {
		cmData[op] = []byte("cm")
	}
	box := &runtimev1.PodBox{
		PodId: "p1", Namespace: "default", Name: "ro",
		Volumes: []*runtimev1.Volume{
			{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
			{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}},
			{Name: "shared", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		},
		InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "shared", MountPath: "/shared"},
		}}},
		Containers: []*runtimev1.Container{{Name: "build", VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "scratch", MountPath: "/scratch", ReadOnly: true},
			{Name: "cfg", MountPath: "/etc/cfg", ReadOnly: true},
			{Name: "shared", MountPath: "/shared", ReadOnly: true},
		}}},
	}
	layout, err := mount.Materialize(context.Background(), box, dataVol, "10.1.2.3", roResolver{data: cmData})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if want := []string{"shared"}; !reflect.DeepEqual(layout.MixedReadOnly, want) {
		t.Errorf("MixedReadOnly = %v, want %v (the runtime's Warn names these)", layout.MixedReadOnly, want)
	}
	scratch := filepath.Join(dataVol, "scratch")
	cfg := filepath.Join(dataVol, "etc", "cfg")
	shared := filepath.Join(dataVol, "shared")
	for _, dir := range []string{scratch, shared, dataVol} {
		for _, op := range roOps {
			if err := os.WriteFile(filepath.Join(dir, op), []byte("cm"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:       Posture{WorkDir: work},
		ReadOnlyPaths: layout.ReadOnlyPaths(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "ro.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) error {
		return exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, args...)...).Run()
	}
	if err := run("/bin/cat", filepath.Join(cfg, "write")); err != nil {
		t.Fatalf("the read-only configMap is not readable under the profile; the measurement is void: %v", err)
	}

	// attempt makes op under dir from inside the profile and reports whether
	// the filesystem shows it happened.
	attempt := func(t *testing.T, dir, op string) bool {
		t.Helper()
		f := filepath.Join(dir, op)
		switch op {
		case "create":
			_ = run("/usr/bin/touch", filepath.Join(dir, "created"))
			_, err := os.Lstat(filepath.Join(dir, "created"))
			return err == nil
		case "write":
			_ = run("/bin/sh", "-c", `printf x >> "$1"`, "sh", f)
			b, err := os.ReadFile(f)
			return err == nil && string(b) != "cm"
		case "rename":
			_ = run("/bin/mv", f, filepath.Join(dir, "renamed"))
			_, err := os.Lstat(filepath.Join(dir, "renamed"))
			return err == nil
		case "chmod":
			_ = run("/bin/chmod", "0600", f)
			fi, err := os.Stat(f)
			return err == nil && fi.Mode().Perm() == 0o600
		case "unlink":
			_ = run("/bin/rm", "-f", f)
			_, err := os.Lstat(f)
			return err != nil
		}
		t.Fatalf("unknown op %q", op)
		return false
	}
	for _, tc := range []struct {
		name, dir string
		writable  bool
	}{
		{"emptyDir mounted read_only", scratch, false},
		{"configMap mounted read_only", cfg, false},
		{"emptyDir mounted read-write by another container", shared, true},
		{"the data volume outside any mount", dataVol, true},
	} {
		for _, op := range roOps {
			t.Run(tc.name+"/"+op, func(t *testing.T) {
				if got := attempt(t, tc.dir, op); got != tc.writable {
					t.Errorf("%s under %s happened = %v, want %v", op, tc.dir, got, tc.writable)
				}
			})
		}
	}
}
