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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestSeatbeltThroughVolumeAlias applies a generated pod profile with
// sandbox-exec to a data volume mount.Materialize rendered with a secret and
// an emptyDir each mounted at two paths, and acts through the second path (the
// alias). Through the secret's alias a write, an unlink and a rename are
// denied with EPERM and a read succeeds: the credential sub-scope covers the
// one directory whichever path reaches it. Through the emptyDir's alias all
// four succeed. The profile is built from Layout.Scope, as compileProfile
// builds it: the secret's alias link carries the rule too, so it cannot be
// unlinked and replaced.
func TestSeatbeltThroughVolumeAlias(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Fatalf("sandbox-exec is missing, so nothing can be measured: %v", err)
	}
	base := filepath.Join("/private/tmp", "k3sm-alias-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")

	box := &runtimev1.PodBox{
		PodId:     "pod-1",
		Namespace: "default",
		Name:      "demo",
		Volumes: []*runtimev1.Volume{
			{Name: "creds", Secret: &runtimev1.SecretVolumeSource{SecretName: "sec"}},
			{Name: "tools", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		},
		InitContainers: []*runtimev1.Container{{Name: "init", VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "creds", MountPath: "/etc/creds"}, {Name: "tools", MountPath: "/yurei-project-tools"},
		}}},
		Containers: []*runtimev1.Container{{Name: "main", VolumeMounts: []*runtimev1.VolumeMount{
			{Name: "creds", MountPath: "/srv/creds"}, {Name: "tools", MountPath: "/opt/tools"},
		}}},
	}
	layout, err := mount.Materialize(context.Background(), box, dataVol, "", aliasResolver{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataVol, "yurei-project-tools", "k"), []byte("tool"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The scope compileProfile passes.
	sc := layout.Scope()
	prof, err := sandbox.Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, sandbox.GenerateOptions{
		Posture:            sandbox.Posture{WorkDir: work},
		ReadOnlyPaths:      sc.ReadOnly,
		WritableMountPaths: sc.Writable,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(base, "alias.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(script string) (string, error) {
		cmd := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/bash", "-c", script)
		cmd.Dir = dataVol
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	const eperm = "Operation not permitted"

	t.Run("secret alias is read-only", func(t *testing.T) {
		alias := filepath.Join(dataVol, "srv", "creds")
		if out, err := run("cat " + alias + "/k"); err != nil || out != "secret" {
			t.Fatalf("read through the alias = %q, %v; want the secret", out, err)
		}
		for name, script := range map[string]string{
			"write":       "echo x > " + alias + "/k",
			"create":      "echo x > " + alias + "/new",
			"unlink":      "rm -f " + alias + "/k",
			"rename":      "mv " + alias + "/k " + alias + "/k2",
			"unlink link": "rm -f " + alias,
		} {
			out, err := run(script)
			if err == nil || !strings.Contains(out, eperm) {
				t.Errorf("%s through the alias: err=%v, want EPERM\n%s", name, err, out)
			}
		}
		if b, err := os.ReadFile(filepath.Join(dataVol, "etc", "creds", "k")); err != nil || string(b) != "secret" {
			t.Errorf("secret after the denied attempts = %q, %v", b, err)
		}
	})

	t.Run("emptyDir alias is writable", func(t *testing.T) {
		alias := filepath.Join(dataVol, "opt", "tools")
		// The steps build on each other, so they run in order.
		for _, step := range []struct{ name, script string }{
			{"read", "cat " + alias + "/k"},
			{"write", "echo y > " + alias + "/w"},
			{"rename", "mv " + alias + "/w " + alias + "/w2"},
			{"unlink", "rm " + alias + "/w2"},
		} {
			if out, err := run(step.script); err != nil {
				t.Fatalf("%s through the emptyDir alias: %v\n%s", step.name, err, out)
			}
		}
		if _, err := os.Lstat(filepath.Join(dataVol, "yurei-project-tools", "w2")); !os.IsNotExist(err) {
			t.Errorf("the unlink through the alias did not reach the one directory: %v", err)
		}
	})
}

// aliasResolver serves the one secret TestSeatbeltThroughVolumeAlias mounts.
type aliasResolver struct{}

func (aliasResolver) ConfigMap(context.Context, string, string) (mount.SourceData, error) {
	return mount.SourceData{}, os.ErrNotExist
}

func (aliasResolver) Secret(context.Context, string, string) (mount.SourceData, error) {
	return mount.SourceData{Data: map[string][]byte{"k": []byte("secret")}}, nil
}

func (aliasResolver) ServiceAccountToken(context.Context, string, string, int64) (string, error) {
	return "", os.ErrNotExist
}
