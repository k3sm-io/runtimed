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
	"errors"
	"reflect"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// recordingEffects records RunStart's calls and fails the one it is told to.
type recordingEffects struct {
	calls      []string
	failOn     string
	resolveFor map[string]bool // Compose settles the identity of these containers
}

func (e *recordingEffects) Compose(cp *ContainerPlan) error {
	e.calls = append(e.calls, "compose:"+cp.Name)
	if e.failOn == "compose:"+cp.Name {
		return errors.New("mount failed")
	}
	if e.resolveFor[cp.Name] {
		cp.PendingImageUser = ""
		cp.Ident = Ident{UID: 1000, GID: 1000}
	}
	return nil
}

func (e *recordingEffects) Detach(step MountStep) error {
	e.calls = append(e.calls, "detach:"+step.Target)
	if e.failOn == "detach:"+step.Target {
		return errors.New("umount2 failed")
	}
	return nil
}

func (e *recordingEffects) Start(cp ContainerPlan) error {
	e.calls = append(e.calls, "start:"+cp.Name)
	return nil
}

// TestRunStartFailsClosed pins that nothing is started when any composition,
// any detach, or any identity is not complete — the property that keeps a
// guest-private mount from being visible to a running container and an
// unresolved image user from running as uid 0.
func TestRunStartFailsClosed(t *testing.T) {
	newPlan := func() *BootPlan {
		return &BootPlan{
			Containers: []ContainerPlan{{Name: "a"}, {Name: "b", PendingImageUser: "app"}},
			Detach:     []MountStep{{Target: "/run/k3sm/shares/s", Options: []MountOption{OptionDetach}}},
		}
	}
	cases := []struct {
		name      string
		fx        *recordingEffects
		wantCalls []string
		wantErr   error
	}{
		{
			name:      "happy path: compose all, detach, start all",
			fx:        &recordingEffects{resolveFor: map[string]bool{"b": true}},
			wantCalls: []string{"compose:a", "compose:b", "detach:/run/k3sm/shares/s", "start:a", "start:b"},
		},
		{
			name:      "a compose failure starts nothing",
			fx:        &recordingEffects{failOn: "compose:b", resolveFor: map[string]bool{"b": true}},
			wantCalls: []string{"compose:a", "compose:b"},
		},
		{
			name:      "a detach failure starts nothing",
			fx:        &recordingEffects{failOn: "detach:/run/k3sm/shares/s", resolveFor: map[string]bool{"b": true}},
			wantCalls: []string{"compose:a", "compose:b", "detach:/run/k3sm/shares/s"},
		},
		{
			name:      "an identity left pending starts nothing",
			fx:        &recordingEffects{},
			wantCalls: []string{"compose:a", "compose:b"},
			wantErr:   ErrIdentityPending,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := newPlan()
			err := RunStart(plan, tc.fx)
			if !reflect.DeepEqual(tc.fx.calls, tc.wantCalls) {
				t.Errorf("calls = %v, want %v", tc.fx.calls, tc.wantCalls)
			}
			happy := tc.fx.failOn == "" && tc.wantErr == nil
			if happy && err != nil {
				t.Fatalf("RunStart: %v", err)
			}
			if !happy && err == nil {
				t.Fatal("RunStart succeeded; want a failure")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if happy && plan.Containers[1].Ident.UID != 1000 {
				t.Errorf("the resolved identity did not land on the plan element: %+v", plan.Containers[1].Ident)
			}
		})
	}

	t.Run("a detach step never reaches the mount path", func(t *testing.T) {
		if _, err := LinuxMountFlags([]MountOption{OptionDetach}); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("LinuxMountFlags(detach) err = %v, want ErrInvalidSpec", err)
		}
		if _, _, err := LinuxDetach(MountStep{Target: "/x", Options: []MountOption{OptionBind}}); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("LinuxDetach(bind) err = %v, want ErrInvalidSpec", err)
		}
		if prop, flags, err := LinuxDetach(MountStep{Target: "/x", Options: []MountOption{OptionDetach}}); err != nil ||
			prop != msPRIVATE || flags != mntDETACH {
			t.Errorf("LinuxDetach = %#x, %#x, %v", prop, flags, err)
		}
	})

	t.Run("a guest-private mount nested under another is refused", func(t *testing.T) {
		spec := unmountedVolumeSpec(true, false, 1000)
		spec.Mounts = append(spec.Mounts, &guestv1.GuestMount{
			TagOrSource: "k3sm.vols", Target: stagingRoot + "/inner",
			Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS, ReadOnly: true, GuestPrivate: true,
		})
		if _, err := Plan(spec, Options{}); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("Plan err = %v, want ErrInvalidSpec", err)
		}
	})

	t.Run("a visible mount covering a guest-private one is refused", func(t *testing.T) {
		spec := unmountedVolumeSpec(true, false, 1000)
		spec.Mounts = append(spec.Mounts, &guestv1.GuestMount{
			Target: GuestRoot + "/shares", Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS,
		})
		if _, err := Plan(spec, Options{}); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("Plan err = %v, want ErrInvalidSpec", err)
		}
	})
}
