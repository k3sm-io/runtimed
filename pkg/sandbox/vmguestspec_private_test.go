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
	"path"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/guestinit"
)

// TestComposedSpecHidesUnmountedVolumes is the host half of the guest_private
// gate: the spec THIS composer writes, planned by the guest init it is booted
// with, never hands a container a path to a volume it does not mount, nor to
// the pooled staging root.
//
// The fixture is the shape the leak was found in: a pooled projected share
// (k3sm.proj) holding two volumes, config-a, which container x mounts, and
// secret-b, which no container mounts. Container y mounts nothing from the
// share. The verdict is read from the guest plan, not from the composer's own
// output, so a composer that stops marking the staging mount guest-private (the
// pre-fix output) is caught by what the guest would then do with it: re-expose
// the staging root inside every container root, and never detach it.
//
// "By any path" is checked as path reachability over the plan's mount steps. A
// container step whose source is the secret's path or any ancestor of it
// (staging, the shares root, the guest root, /) would put the secret inside the
// container, because the guest binds recursively; a container step mounted at or
// beneath the staging root inside the container's own root is the staging path
// re-exposed. The pod-level mount that does reach the secret is allowed only
// because the plan detaches it before any container starts.
//
// What it does NOT claim is the documented ceiling at guestShareStageRoot: a
// volume a SIBLING container mounts stays visible at the sibling's mount path,
// so the fixture keeps secret-b mounted by nobody.
func TestComposedSpecHidesUnmountedVolumes(t *testing.T) {
	t.Parallel()
	const (
		tag       = "k3sm.proj"
		mountPath = "/etc/config-a"
	)
	spec := VMSpec{
		PodID:           "pod-b239",
		PodDir:          "/var/lib/k3sm/pods/pod-b239",
		AgentSocketPath: "/var/lib/k3sm/run/vm/pod-b239/agent.sock",
		Hostname:        "leak-0",
		Containers: []VMContainer{
			{Name: "x", RootfsTag: "k3sm.rootfs.x", Argv: []string{"/bin/sleep", "1"}, UID: 1000, GID: 1000},
			{Name: "y", RootfsTag: "k3sm.rootfs.x", Argv: []string{"/bin/sleep", "1"}, UID: 0, GID: 0},
		},
		Volumes: VMVolumePlan{
			Shares: []VMShare{
				{Tag: "k3sm.rootfs.x", Root: "/var/lib/k3sm/pods/pod-b239/rootfs/x"},
				{Tag: tag, Root: "/var/lib/k3sm/pods/pod-b239/k3sm.proj"},
			},
			Binds: map[string][]VMBind{
				"x": {{VolumeName: "config-a", ShareTag: tag, SourceRel: "config-a", MountPath: mountPath, ReadOnly: true}},
			},
		},
	}
	gs, err := buildGuestSpec(spec)
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	plan, err := guestinit.Plan(gs, guestinit.Options{})
	if err != nil {
		t.Fatalf("guestinit.Plan on the composed spec: %v", err)
	}

	stage := guestShareStageDir(tag)
	secretB := path.Join(stage, "secret-b")
	// reaches reports whether a step sourced at src exposes target (the
	// source is target or one of its ancestors).
	reaches := func(src, target string) bool {
		return src != "" && strings.HasPrefix(src, "/") && (src == "/" || target == src || strings.HasPrefix(target, src+"/"))
	}
	under := func(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }

	if len(plan.Containers) != 2 {
		t.Fatalf("plan has %d containers, want 2", len(plan.Containers))
	}
	for _, c := range plan.Containers {
		root := guestinit.ContainerRootDir(c.Name)
		sawA := false
		for _, s := range c.Mounts {
			if reaches(s.Source, secretB) {
				t.Errorf("container %s: step %q -> %q reaches the unmounted volume %s", c.Name, s.Source, s.Target, secretB)
			}
			if under(s.Source, guestShareStageRoot) {
				t.Errorf("container %s: step %q -> %q is sourced from the staging root", c.Name, s.Source, s.Target)
			}
			inner := "/" + strings.TrimPrefix(strings.TrimPrefix(s.Target, root), "/")
			if under(s.Target, root) && under(inner, guestShareStageRoot) {
				t.Errorf("container %s: step mounts at %s inside its root, the staging path re-exposed", c.Name, inner)
			}
			if under(s.Target, root) && inner == mountPath {
				sawA = true
			}
		}
		// Non-vacuity: x does see its own volume, so the absence of B is
		// not the absence of every pod mount.
		if c.Name == "x" && !sawA {
			t.Errorf("container x has no step at %s; the fixture's own mount never reached it", mountPath)
		}
	}

	// The only pod-level path to the secret is the staging mount, and the plan
	// takes it out of the guest before any container starts.
	detached := map[string]bool{}
	for _, d := range plan.Detach {
		detached[d.Target] = true
	}
	for _, s := range plan.PodMounts {
		if under(secretB, s.Target) && s.Target != "/" && !detached[s.Target] {
			t.Errorf("pod mount at %s reaches %s and is never detached", s.Target, secretB)
		}
	}
	if !detached[stage] {
		t.Errorf("plan.Detach = %+v, want the staging mount %s detached", plan.Detach, stage)
	}
}
