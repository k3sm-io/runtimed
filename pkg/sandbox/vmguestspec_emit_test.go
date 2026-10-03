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
	"encoding/json"
	"strings"
	"testing"
)

// TestGuestSpecEmitsPinnedGuestFields pins what the composer now sets of
// GuestMount.guest_private, GuestContainer.sidecar and GuestContainer.image_user,
// and — as load-bearing as what it sets — where it leaves them at their zero
// value.
//
// A guest that predates a field refuses a spec that sets it, so the composer may
// set each one only where it means it: a field emitted where it is not needed
// would fail every vm pod booted against an older initramfs for nothing. So:
//
//   - every pooled-share staging mount carries guest_private, because the guest
//     must bind each volume out of it and then detach it before any container
//     starts;
//   - a per-volume bind and a whole-share (PVC) virtiofs mount do NOT, because
//     they are what a container is meant to see;
//   - sidecar and image_user are emitted only on the containers that set them,
//     and are absent from the proto-JSON (not present-and-false) everywhere else.
//
// HasGuestPrivateMounts is asserted against the same composition, so the
// runtime's capability check and the composer cannot disagree about whether a
// spec relies on the guest-private mount class.
func TestGuestSpecEmitsPinnedGuestFields(t *testing.T) {
	t.Parallel()
	spec := guestSpecFixture()
	spec.Containers = append(spec.Containers, VMContainer{
		Name: "proxy", Init: true, Sidecar: true, RootfsTag: "k3sm.rootfs.postgres",
		Argv: []string{"/proxy"}, ImageUser: "app:3000",
	})
	gs, err := buildGuestSpec(spec)
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}

	t.Run("staging mounts are guest-private and nothing else is", func(t *testing.T) {
		staged, private := 0, 0
		for _, m := range gs.GetMounts() {
			isStage := strings.HasPrefix(m.GetTarget(), guestShareStageRoot+"/")
			if isStage {
				staged++
			}
			if m.GetGuestPrivate() {
				private++
			}
			if isStage != m.GetGuestPrivate() {
				t.Errorf("mount %q (kind %v, source %q): guest_private = %v, want %v (only a staging mount is guest-private)",
					m.GetTarget(), m.GetKind(), m.GetTagOrSource(), m.GetGuestPrivate(), isStage)
			}
		}
		// The fixture stages two pooled shares (k3sm.proj for the token,
		// k3sm.vols for the cache) and mounts one PVC whole; fewer staging
		// mounts than that would make the negative half of this test vacuous.
		if staged != 2 || private != 2 {
			t.Fatalf("staged %d / guest-private %d mounts, want 2 / 2", staged, private)
		}
		if !spec.Volumes.HasGuestPrivateMounts() {
			t.Error("HasGuestPrivateMounts = false for a plan whose composition carries guest-private mounts")
		}
	})

	t.Run("a plan with no pooled-share bind carries no guest-private mount", func(t *testing.T) {
		plan := VMVolumePlan{
			Shares: []VMShare{{Tag: "k3sm.pvc0", Root: "/storage/pgdata", Writable: true}},
			Binds: map[string][]VMBind{
				"c": {{VolumeName: "pgdata", ShareTag: "k3sm.pvc0", MountPath: "/pgdata"}},
			},
			Tmpfs: map[string][]VMTmpfs{"c": {{VolumeName: "shm", MountPath: "/dev/shm"}}},
		}
		shares, err := shareIndex(plan.Shares)
		if err != nil {
			t.Fatal(err)
		}
		mounts, err := guestMounts(plan, shares, 0)
		if err != nil {
			t.Fatalf("guestMounts: %v", err)
		}
		for _, m := range mounts {
			if m.GetGuestPrivate() {
				t.Errorf("mount %q is guest-private in a plan that stages nothing", m.GetTarget())
			}
		}
		if plan.HasGuestPrivateMounts() {
			t.Error("HasGuestPrivateMounts = true for a plan that stages nothing")
		}
	})

	t.Run("sidecar and image_user are emitted only where set", func(t *testing.T) {
		for _, c := range gs.GetContainers() {
			wantSidecar, wantUser := false, ""
			if c.GetName() == "proxy" {
				wantSidecar, wantUser = true, "app:3000"
			}
			if c.GetSidecar() != wantSidecar || c.GetImageUser() != wantUser {
				t.Errorf("container %q: sidecar=%v image_user=%q, want %v %q",
					c.GetName(), c.GetSidecar(), c.GetImageUser(), wantSidecar, wantUser)
			}
		}
	})

	t.Run("an unset field is absent from the proto-JSON", func(t *testing.T) {
		data, err := marshalGuestSpec(gs)
		if err != nil {
			t.Fatalf("marshalGuestSpec: %v", err)
		}
		var doc struct {
			Containers []map[string]any `json:"containers"`
			Mounts     []map[string]any `json:"mounts"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, c := range doc.Containers {
			_, side := c["sidecar"]
			_, user := c["imageUser"]
			want := c["name"] == "proxy"
			if side != want || user != want {
				t.Errorf("container %v: sidecar key present=%v imageUser key present=%v, want %v",
					c["name"], side, user, want)
			}
		}
		for _, m := range doc.Mounts {
			v, present := m["guestPrivate"]
			if present && v != true {
				t.Errorf("mount %v carries guestPrivate=%v; a false value must be absent", m["target"], v)
			}
		}
	})
}
