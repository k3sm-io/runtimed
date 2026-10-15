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
	"reflect"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestVMContainerHostnameEnv pins HOSTNAME as runtimed's LOWEST env layer on
// the vm spine (containerd's layering: the runtime default beneath the image
// env, the CRI envs above both). Every container of a vm pod gets
// HOSTNAME=<PodBox.hostname>; an image ENV HOSTNAME wins over it; a spec env
// wins over both; an empty hostname (hostNetwork) injects nothing; and the
// native spine's env does not change.
func TestVMContainerHostnameEnv(t *testing.T) {
	const (
		plainRef = "docker.io/library/plain:1"
		imgRef   = "docker.io/library/withhostname:1"
	)
	cfgs := map[string]image.ImageRunConfig{
		plainRef: {Entrypoint: []string{"/app"}, Env: []string{"PATH=/usr/bin"}},
		imgRef:   {Entrypoint: []string{"/app"}, Env: []string{"PATH=/usr/bin", "HOSTNAME=img"}},
	}
	cases := []struct {
		name     string
		hostname string
		ref      string
		specEnv  []*runtimev1.EnvVar
		want     []string
	}{
		{name: "injected below the image env", hostname: "web-0", ref: plainRef,
			want: []string{"HOSTNAME=web-0", "PATH=/usr/bin"}},
		{name: "image ENV HOSTNAME wins", hostname: "web-0", ref: imgRef,
			want: []string{"PATH=/usr/bin", "HOSTNAME=img"}},
		{name: "spec env wins over the image and the default", hostname: "web-0", ref: imgRef,
			specEnv: []*runtimev1.EnvVar{{Name: "HOSTNAME", Value: "spec"}},
			want:    []string{"PATH=/usr/bin", "HOSTNAME=spec"}},
		{name: "spec env wins over the default", hostname: "web-0", ref: plainRef,
			specEnv: []*runtimev1.EnvVar{{Name: "HOSTNAME", Value: "spec"}},
			want:    []string{"PATH=/usr/bin", "HOSTNAME=spec"}},
		{name: "setHostnameAsFQDN injects the full name", hostname: "web-0.web.ns.svc.cluster.local", ref: plainRef,
			want: []string{"HOSTNAME=web-0.web.ns.svc.cluster.local", "PATH=/usr/bin"}},
		{name: "empty hostname injects nothing", hostname: "", ref: plainRef,
			want: []string{"PATH=/usr/bin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, vmb := newVMImageRuntime(t, newImageWorld(cfgs))
			box := vmBoxWith(rt, "pod-hostname", nil,
				[]*runtimev1.Container{{Name: "c", Image: tc.ref, Env: tc.specEnv}})
			box.Hostname = tc.hostname
			got := oneVMContainer(t, createVMSpec(t, rt, vmb, box))
			if !reflect.DeepEqual(got.Env, tc.want) {
				t.Errorf("env = %q, want %q", got.Env, tc.want)
			}
		})
	}

	t.Run("every container, init included", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, newImageWorld(cfgs))
		box := vmBoxWith(rt, "pod-hostname-all",
			[]*runtimev1.Container{{Name: "init", Image: plainRef}},
			[]*runtimev1.Container{{Name: "a", Image: plainRef}, {Name: "b", Image: plainRef}})
		box.Hostname = "web-0"
		spec := createVMSpec(t, rt, vmb, box)
		if len(spec.Containers) != 3 {
			t.Fatalf("VMSpec carries %d containers, want 3", len(spec.Containers))
		}
		for _, c := range spec.Containers {
			if c.Env[0] != "HOSTNAME=web-0" {
				t.Errorf("container %s env = %q, want HOSTNAME=web-0 first", c.Name, c.Env)
			}
		}
	})

	t.Run("native box unchanged", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		box := hostBinBox(rt, "pod-native-hostname")
		c := &runtimev1.Container{Name: "app", Env: []*runtimev1.EnvVar{{Name: "POD", Value: "1"}}}
		without, err := rt.containerEnv(box, c, []string{"PATH=/usr/bin"})
		if err != nil {
			t.Fatalf("containerEnv: %v", err)
		}
		box.Hostname = "web-0"
		with, err := rt.containerEnv(box, c, []string{"PATH=/usr/bin"})
		if err != nil {
			t.Fatalf("containerEnv: %v", err)
		}
		if !reflect.DeepEqual(with, without) {
			t.Errorf("native env changed with a hostname:\n%q\nwant:\n%q", with, without)
		}
		for _, e := range with {
			if strings.HasPrefix(e, "HOSTNAME=") {
				t.Errorf("native env carries %q", e)
			}
		}
	})
}
