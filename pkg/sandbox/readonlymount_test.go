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
// Generate. An emptyDir and a configMap every container mounts read_only, and
// a configMap and a downwardAPI volume mounted without it (API-data volumes are
// read-only whatever the flag says, as under the kubelet), must refuse create,
// write, rename, chmod and unlink at the materialized path. The pod has one
// profile, so an emptyDir selection one container mounts read-write stays
// writable at every path it is mounted at (and is reported mixed, which the
// runtime warns about), as does the rest of the data volume.
func TestReadOnlyVolumeMountDeniesWrites(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Fatalf("sandbox-exec is missing, so nothing can be measured: %v", err)
	}
	base := filepath.Join("/private/tmp", "k3sm-ro-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")

	cmData := map[string][]byte{}
	var fields []*runtimev1.DownwardAPIVolumeFile
	for _, op := range roOps {
		cmData[op] = []byte("cm")
		fields = append(fields, &runtimev1.DownwardAPIVolumeFile{Path: op, FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.name"}})
	}
	box := &runtimev1.PodBox{
		PodId: "p1", Namespace: "default", Name: "ro",
		Volumes: []*runtimev1.Volume{
			{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
			{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}},
			{Name: "shared", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
			{Name: "cfgflagless", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}},
			{Name: "info", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: fields}},
		},
		InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "shared", MountPath: "/shared"},
		}}},
		Containers: []*runtimev1.Container{{Name: "build", VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "scratch", MountPath: "/scratch", ReadOnly: true},
			{Name: "cfg", MountPath: "/etc/cfg", ReadOnly: true},
			// The same emptyDir selection, read-only here and read-write in init.
			{Name: "shared", MountPath: "/shared", ReadOnly: true},
			{Name: "shared", MountPath: "/shared-ro", ReadOnly: true},
			// API-data volumes without read_only: read-only all the same.
			{Name: "cfgflagless", MountPath: "/etc/cfg-flagless"},
			{Name: "info", MountPath: "/etc/info"},
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
	sharedRO := filepath.Join(dataVol, "shared-ro")
	cfgFlagless := filepath.Join(dataVol, "etc", "cfg-flagless")
	info := filepath.Join(dataVol, "etc", "info")
	for _, dir := range []string{scratch, shared, sharedRO, dataVol} {
		for _, op := range roOps {
			// O_TRUNC through any link a later layout puts at sharedRO.
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
			before, _ := os.ReadFile(f)
			_ = run("/bin/sh", "-c", `printf x >> "$1"`, "sh", f)
			b, err := os.ReadFile(f)
			return err == nil && len(b) != len(before)
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
		{"configMap mounted without read_only", cfgFlagless, false},
		{"downwardAPI mounted without read_only", info, false},
		{"emptyDir mounted read-write by another container", shared, true},
		{"the same emptyDir at a path only read-only mounts use", sharedRO, true},
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

// roProfile materializes box under a fresh data volume, writes the profile
// compileProfile would build from the layout's scope, and returns the data
// volume and a runner for argv under that profile.
func roProfile(t *testing.T, tag string, box *runtimev1.PodBox, r mount.Resolver) (string, func(args ...string) error) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Fatalf("sandbox-exec is missing, so nothing can be measured: %v", err)
	}
	base := filepath.Join("/private/tmp", "k3sm-"+tag+"-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	layout, err := mount.Materialize(context.Background(), box, dataVol, "10.1.2.3", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	sc := layout.Scope()
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture:            Posture{WorkDir: work},
		ReadOnlyPaths:      sc.ReadOnly,
		WritableMountPaths: sc.Writable,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "p.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	return dataVol, func(args ...string) error {
		return exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, args...)...).Run()
	}
}

func roBox(vols []*runtimev1.Volume, mounts ...*runtimev1.VolumeMount) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId: "p1", Namespace: "default", Name: "ro", Volumes: vols,
		Containers: []*runtimev1.Container{{Name: "main", VolumeMounts: mounts}},
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// TestReadOnlyMountAncestorsDenyRename pins the ancestor guard: with a
// read-only configMap at /etc/cfg, the pod cannot rename /etc (which would
// move the mount aside and leave its files writable at the new path) nor the
// mount directory itself, but still creates files beside it in /etc and in
// the data volume root.
func TestReadOnlyMountAncestorsDenyRename(t *testing.T) {
	dataVol, run := roProfile(t, "roanc", roBox(
		[]*runtimev1.Volume{{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}},
		&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg"},
	), roResolver{data: map[string][]byte{"k": []byte("v")}})
	etc := filepath.Join(dataVol, "etc")

	_ = run("/bin/mv", etc, etc+".old")
	if !exists(filepath.Join(etc, "cfg", "k")) || exists(etc+".old") {
		t.Errorf("the pod renamed %s, an ancestor of a read-only mount", etc)
	}
	_ = run("/bin/mv", filepath.Join(etc, "cfg"), filepath.Join(etc, "cfg2"))
	if !exists(filepath.Join(etc, "cfg", "k")) || exists(filepath.Join(etc, "cfg2")) {
		t.Errorf("the pod renamed the read-only mount directory")
	}
	_ = run("/bin/rm", "-rf", etc)
	if !exists(filepath.Join(etc, "cfg", "k")) {
		t.Errorf("the pod removed %s", etc)
	}
	if err := run("/usr/bin/touch", filepath.Join(etc, "sibling")); err != nil || !exists(filepath.Join(etc, "sibling")) {
		t.Errorf("the pod could not create a sibling file in %s: %v", etc, err)
	}
	if err := run("/usr/bin/touch", filepath.Join(dataVol, "root-file")); err != nil || !exists(filepath.Join(dataVol, "root-file")) {
		t.Errorf("the data volume root is not writable: %v", err)
	}
}

// TestNestedWritableMountUnderReadOnly pins the write re-allow: an emptyDir
// at /app/tmp inside a configMap at /app stays writable while /app does not.
func TestNestedWritableMountUnderReadOnly(t *testing.T) {
	dataVol, run := roProfile(t, "ronest", roBox(
		[]*runtimev1.Volume{
			{Name: "app", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app"}},
			{Name: "tmp", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		},
		&runtimev1.VolumeMount{Name: "app", MountPath: "/app"},
		&runtimev1.VolumeMount{Name: "tmp", MountPath: "/app/tmp"},
	), roResolver{data: map[string][]byte{"k": []byte("v")}})
	app, tmp := filepath.Join(dataVol, "app"), filepath.Join(dataVol, "app", "tmp")

	if err := run("/bin/sh", "-c", `printf x > "$1/f" && mv "$1/f" "$1/g" && chmod 600 "$1/g" && rm "$1/g" && mkdir "$1/d"`, "sh", tmp); err != nil {
		t.Errorf("the nested emptyDir %s is not writable: %v", tmp, err)
	}
	if !exists(filepath.Join(tmp, "d")) {
		t.Errorf("mkdir in the nested emptyDir did not happen")
	}
	_ = run("/usr/bin/touch", filepath.Join(app, "new"))
	if exists(filepath.Join(app, "new")) {
		t.Errorf("the pod created a file in the read-only configMap %s", app)
	}
	_ = run("/bin/rm", "-f", filepath.Join(app, "k"))
	if !exists(filepath.Join(app, "k")) {
		t.Errorf("the pod unlinked a key of the read-only configMap %s", app)
	}
}

// TestReadOnlyConfigMapAtomicWriterDenied pins the atomic-writer layout of a
// read-only configMap against the pod: it cannot swap ..data to another
// generation, rename the live generation directory, or plant a symlink.
func TestReadOnlyConfigMapAtomicWriterDenied(t *testing.T) {
	dataVol, run := roProfile(t, "roaw", roBox(
		[]*runtimev1.Volume{{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "cfg"}}},
		&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg"},
	), roResolver{data: map[string][]byte{"k": []byte("v")}})
	cfg := filepath.Join(dataVol, "etc", "cfg")
	gen, err := os.Readlink(filepath.Join(cfg, "..data"))
	if err != nil {
		t.Fatalf("no ..data link in %s: %v", cfg, err)
	}

	_ = run("/bin/ln", "-sfh", "..elsewhere", filepath.Join(cfg, "..data"))
	if now, _ := os.Readlink(filepath.Join(cfg, "..data")); now != gen {
		t.Errorf("the pod swapped ..data from %q to %q", gen, now)
	}
	_ = run("/bin/mv", filepath.Join(cfg, gen), filepath.Join(cfg, "..moved"))
	if !exists(filepath.Join(cfg, gen)) || exists(filepath.Join(cfg, "..moved")) {
		t.Errorf("the pod renamed the generation directory %s", gen)
	}
	_ = run("/bin/ln", "-s", "/private/tmp", filepath.Join(cfg, "planted"))
	if exists(filepath.Join(cfg, "planted")) {
		t.Errorf("the pod planted a symlink in the read-only configMap")
	}
	if b, err := os.ReadFile(filepath.Join(cfg, "k")); err != nil || string(b) != "v" {
		t.Errorf("key k = %q, %v; want v", b, err)
	}
}
