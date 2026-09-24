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

package guestinit

import (
	"path"
	"testing"
)

// TestPlanAppliesOwnershipSidecarBeforeContainerStart pins where the ownership
// sidecar enters the boot: one step per container whose rootfs tag has a sidecar
// staged in the spec share, carrying the sidecar's guest PATH and the overlay
// root, split into the container's mounts immediately after the overlay and
// before anything is mounted inside it — and so before the container starts.
func TestPlanAppliesOwnershipSidecarBeforeContainerStart(t *testing.T) {
	t.Parallel()
	pgSidecar := OwnershipSidecarName("k3sm.rootfs.postgres")
	plan, err := Plan(goldenSpec(), Options{
		MemTotalBytes:  2 << 30,
		SpecShareFiles: []string{"guest-spec.json", pgSidecar},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pg, initDB *ContainerPlan
	for i := range plan.Containers {
		switch plan.Containers[i].Name {
		case "postgres":
			pg = &plan.Containers[i]
		case "init-db":
			initDB = &plan.Containers[i]
		}
	}
	if pg == nil || initDB == nil {
		t.Fatalf("plan lacks the golden containers: %+v", plan.Containers)
	}

	t.Run("the step is present and names the staged sidecar and the overlay", func(t *testing.T) {
		st := pg.Ownership
		if st == nil {
			t.Fatal("postgres has no ownership step though its sidecar is staged in the spec share")
		}
		if want := path.Join(SpecMountPoint, pgSidecar); st.Sidecar != want {
			t.Errorf("sidecar = %q, want %q", st.Sidecar, want)
		}
		if want := ContainerRootDir("postgres"); st.Root != want {
			t.Errorf("root = %q, want the overlay %q (never the read-only lower)", st.Root, want)
		}
	})

	t.Run("it runs after the overlay mount and before anything mounted inside it", func(t *testing.T) {
		st := pg.Ownership
		if st == nil {
			t.Fatal("no ownership step")
		}
		if st.AfterMount < 1 || st.AfterMount >= len(pg.Mounts) {
			t.Fatalf("AfterMount = %d, want within the %d mounts", st.AfterMount, len(pg.Mounts))
		}
		overlay := pg.Mounts[st.AfterMount-1]
		if overlay.FSType != "overlay" || overlay.Target != st.Root {
			t.Errorf("the mount before the step is %+v, want the overlay at %s", overlay, st.Root)
		}
		for i, m := range pg.Mounts[:st.AfterMount] {
			if m.ResolveRoot != "" {
				t.Errorf("mount %d (%s) lands inside the rootfs but precedes the step", i, m.Target)
			}
		}
		for i, m := range pg.Mounts[st.AfterMount:] {
			if m.Target == st.Root {
				t.Errorf("mount %d after the step re-targets the root %s", st.AfterMount+i, m.Target)
			}
		}
	})

	t.Run("a container whose tag has no staged sidecar gets no step", func(t *testing.T) {
		if initDB.Ownership != nil {
			t.Errorf("init-db has %+v, want none: nothing is staged for its tag", initDB.Ownership)
		}
	})

	t.Run("a spec share with no sidecar plans no step at all", func(t *testing.T) {
		bare, err := Plan(goldenSpec(), Options{SpecShareFiles: []string{"guest-spec.json"}})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		for _, c := range bare.Containers {
			if c.Ownership != nil {
				t.Errorf("%s has an ownership step with no sidecar staged", c.Name)
			}
		}
	})

	t.Run("a tag that would compose a path outside the spec share matches nothing", func(t *testing.T) {
		spec := goldenSpec()
		spec.Containers[1].RootfsTag = "../escape"
		p, err := Plan(spec, Options{SpecShareFiles: []string{OwnershipSidecarName("../escape"), "escape" + OwnershipSidecarSuffix}})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		for _, c := range p.Containers {
			if c.Ownership != nil && path.Dir(c.Ownership.Sidecar) != SpecMountPoint {
				t.Errorf("%s sidecar %q is outside %s", c.Name, c.Ownership.Sidecar, SpecMountPoint)
			}
		}
	})
}
