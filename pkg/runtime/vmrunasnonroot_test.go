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
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	vmRootRef  = "docker.io/library/root:1"
	vmNamedRef = "docker.io/library/named:1"
	vmPlainRef = "docker.io/library/app:1"
)

func runAsNonRootWorld() *imageWorld {
	return newImageWorld(map[string]image.ImageRunConfig{
		vmRootRef:  {Entrypoint: []string{"/app"}, User: "0"},
		vmNamedRef: {Entrypoint: []string{"/app"}, User: "nobody"},
		vmPlainRef: {Entrypoint: []string{"/app"}},
	})
}

// TestVMRunAsNonRootSurfacesCreateContainerConfigError pins the kubelet's
// surface for a runAsNonRoot violation on the vm spine: a container
// configuration error (CreateContainerConfigError, the pod Pending), not a
// dead pod. The requirement is set on the POD only, so the row is also the
// proof that the pod-level field reaches the vm merge at all.
//
// On vm one guest runs the whole pod, so a container that cannot be configured
// leaves no guest to hold a per-container state: the refusal is the CreatePod
// answer, and its reason is what decides the rendering. CONTAINER_CONFIG is
// container-class (containerClassFailure), which is the class the provider
// keeps as a waiting container on a parked pod; INVALID_POD_BOX, what this path
// answered before, is a pod-level refusal the provider marks failed.
//
// A request box arguing the pod-level value back down has no vm route to the
// merge (an UpdatePod on a vm pod never re-resolves a container, and an
// ephemeral append is refused before any image work), so the "stored value
// wins" leg is pinned on the native spine in TestUpdatePodAppendsEphemeralContainer.
func TestVMRunAsNonRootSurfacesCreateContainerConfigError(t *testing.T) {
	rt, vmb := newVMImageRuntime(t, runAsNonRootWorld())
	box := vmBoxWith(rt, "pod-nonroot", nil, []*runtimev1.Container{{Name: "c", Image: vmRootRef}})
	box.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsNonRoot: true}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatal("CreatePod accepted a root image under a pod-level runAsNonRoot")
	}
	if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG {
		t.Fatalf("reason = %v, want CONTAINER_CONFIG", got)
	}
	if !containerClassFailure(resp.GetFailureReason()) {
		t.Error("CONTAINER_CONFIG must be container-class: the container waits, the pod does not fail")
	}
	if codes.Code(resp.GetError().GetCode()) == codes.InvalidArgument {
		t.Error("the refusal carries InvalidArgument, the code of a pod the caller wrote wrongly")
	}
	msg := resp.GetError().GetMessage()
	wantText := `container has runAsNonRoot and image will run as root (pod: "p_default(pod-nonroot)", container: c)`
	if !strings.Contains(msg, wantText) {
		t.Errorf("message %q does not carry the kubelet text %q", msg, wantText)
	}
	if !strings.HasPrefix(msg, "container c:") {
		t.Errorf("message %q does not lead with the container, so it cannot be attributed", msg)
	}
	if n, _ := vmb.created(); n != 0 {
		t.Errorf("CreateVM called %d times for a container that cannot be configured", n)
	}
	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: box.GetPodId()})
	if st := gs.GetStatus(); st != nil && st.GetPhase() == runtimev1.PodPhase_POD_PHASE_FAILED {
		t.Error("the runtime holds a Failed pod for a container configuration error")
	}

	t.Run("the no-command refusal keeps its pod-level reason", func(t *testing.T) {
		w := runAsNonRootWorld()
		w.cfgs["docker.io/library/bare:1"] = image.ImageRunConfig{}
		rt, _ := newVMImageRuntime(t, w)
		box := vmBoxWith(rt, "pod-bare", nil, []*runtimev1.Container{{Name: "c", Image: "docker.io/library/bare:1"}})
		_, reason, err := rt.createPod(context.Background(), box)
		if !errors.Is(err, image.ErrRunSpecInvalid) || errors.Is(err, image.ErrRunAsNonRoot) {
			t.Fatalf("err = %v, want the no-command refusal", err)
		}
		if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
			t.Errorf("reason = %v, want INVALID_POD_BOX", reason)
		}
	})

	t.Run("the same pod without the requirement boots", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, runAsNonRootWorld())
		box := vmBoxWith(rt, "pod-root-ok", nil, []*runtimev1.Container{{Name: "c", Image: vmRootRef}})
		createVMSpec(t, rt, vmb, box)
	})
}

// TestVMSidecarAndNamedUserHandedToGuest is the emit half of the native
// sidecar and named image USER hand-off.
//
// The host no longer refuses either: a native sidecar crosses as an init
// container marked sidecar, and an image whose USER is a name crosses as
// image_user for the guest to resolve against the container's own rootfs. Both
// rely on an initramfs that knows the fields, so a guest whose Health answer
// lacks the matching token fails the pod with a reason that names the fix.
//
// The runAsNonRoot leg does NOT move: a named USER under runAsNonRoot is
// refused host-side, before any hand-off, with the kubelet's non-numeric-user
// text, so in-guest resolution never decides a privilege question.
//
// A known gap, kept rather than faked: a guest that cannot resolve image_user
// fails that container's start, but guest/v1's ContainerEvent carries only
// started and exited, so there is no start-failure event the host could map to
// CONTAINER_CONFIG. The guest fails the boot with the reason on its console, and
// the host reports SANDBOX_SETUP. The console text is never parsed to fake the
// finer reason.
func TestVMSidecarAndNamedUserHandedToGuest(t *testing.T) {
	const (
		groupedRef = "docker.io/library/grouped:1"
		numericRef = "docker.io/library/numeric:1"
	)
	world := func() *imageWorld {
		w := runAsNonRootWorld()
		w.cfgs[groupedRef] = image.ImageRunConfig{Entrypoint: []string{"/app"}, User: "app:staff"}
		w.cfgs[numericRef] = image.ImageRunConfig{Entrypoint: []string{"/app"}, User: "1000:1000"}
		return w
	}

	t.Run("a native sidecar is emitted as an init container marked sidecar", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, world())
		box := vmBoxWith(rt, "pod-side",
			[]*runtimev1.Container{
				{Name: "setup", Image: vmPlainRef},
				{Name: "side", Image: vmPlainRef,
					RestartPolicy: runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS},
			},
			[]*runtimev1.Container{{Name: "c", Image: vmPlainRef}})
		spec := createVMSpec(t, rt, vmb, box)
		want := map[string][2]bool{"setup": {true, false}, "side": {true, true}, "c": {false, false}}
		if len(spec.Containers) != len(want) {
			t.Fatalf("VMSpec carries %d containers, want %d", len(spec.Containers), len(want))
		}
		for _, c := range spec.Containers {
			w := want[c.Name]
			if c.Init != w[0] || c.Sidecar != w[1] {
				t.Errorf("container %q: init=%v sidecar=%v, want init=%v sidecar=%v", c.Name, c.Init, c.Sidecar, w[0], w[1])
			}
		}
		p, _ := rt.lookupPod(box.GetPodId())
		if got := p.guestRequiredCaps; len(got) != 1 || got[0] != guestagent.CapabilitySidecarInit {
			t.Errorf("required tokens = %v, want exactly [%s]", got, guestagent.CapabilitySidecarInit)
		}
	})

	t.Run("a named image USER is handed to the guest as image_user", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			ref      string
			podSC    *runtimev1.PodSecurityContext
			sc       *runtimev1.SecurityContext
			wantUser string
		}{
			{name: "name alone", ref: vmNamedRef, wantUser: "nobody"},
			{name: "name with a pod runAsGroup", ref: vmNamedRef,
				podSC: &runtimev1.PodSecurityContext{RunAsGroup: 3000}, wantUser: "nobody:3000"},
			{name: "name with a container runAsGroup", ref: vmNamedRef,
				sc: &runtimev1.SecurityContext{RunAsGroup: 4000}, wantUser: "nobody:4000"},
			{name: "name:group is kept verbatim", ref: groupedRef, wantUser: "app:staff"},
			{name: "runAsGroup replaces the image's group", ref: groupedRef,
				podSC: &runtimev1.PodSecurityContext{RunAsGroup: 3000}, wantUser: "app:3000"},
			{name: "a runAsUser decides the uid host-side", ref: vmNamedRef,
				podSC: &runtimev1.PodSecurityContext{RunAsUser: 1234}, wantUser: ""},
			{name: "a numeric USER is decided host-side", ref: numericRef, wantUser: ""},
			{name: "no USER at all", ref: vmPlainRef, wantUser: ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rt, vmb := newVMImageRuntime(t, world())
				box := vmBoxWith(rt, "pod-user", nil, []*runtimev1.Container{{Name: "c", Image: tc.ref, SecurityContext: tc.sc}})
				box.PodSecurityContext = tc.podSC
				got := oneVMContainer(t, createVMSpec(t, rt, vmb, box))
				if got.ImageUser != tc.wantUser {
					t.Errorf("ImageUser = %q, want %q", got.ImageUser, tc.wantUser)
				}
				p, _ := rt.lookupPod(box.GetPodId())
				var want []string
				if tc.wantUser != "" {
					want = []string{guestagent.CapabilityImageUser}
				}
				if !slices.Equal(p.guestRequiredCaps, want) {
					t.Errorf("required tokens = %v, want %v for image_user %q", p.guestRequiredCaps, want, tc.wantUser)
				}
			})
		}
	})

	t.Run("a named image USER under runAsNonRoot is a container config error", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, world())
		box := vmBoxWith(rt, "pod-named-nonroot", nil, []*runtimev1.Container{{
			Name: "c", Image: vmNamedRef,
			SecurityContext: &runtimev1.SecurityContext{RunAsNonRoot: true},
		}})
		_, reason, err := rt.createPod(context.Background(), box)
		if reason != runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG || !errors.Is(err, image.ErrRunAsNonRoot) {
			t.Fatalf("err = %v reason = %v, want ErrRunAsNonRoot / CONTAINER_CONFIG", err, reason)
		}
		want := `container has runAsNonRoot and image has non-numeric user (nobody), cannot verify user is non-root (pod: "p_default(pod-named-nonroot)", container: c)`
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q does not carry the kubelet text %q", err, want)
		}
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("CreateVM called %d times", n)
		}
	})

	t.Run("a guest without the sidecar token fails the pod", func(t *testing.T) {
		agent := &capsAgent{caps: capsWithout(guestagent.CapabilitySidecarInit)}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		box := vmBoxWith(rt, "pod-side-old",
			[]*runtimev1.Container{{Name: "side", Image: vmPlainRef,
				RestartPolicy: runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS}},
			[]*runtimev1.Container{{Name: "c", Image: vmPlainRef}})
		createRunningVMPod(t, rt, box)
		assertGuestCapFailure(t, rt, vmb, box.GetPodId(), guestagent.CapabilitySidecarInit, 0)
	})

	t.Run("a guest without the image-user token fails the pod", func(t *testing.T) {
		agent := &capsAgent{caps: capsWithout(guestagent.CapabilityImageUser)}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		box := vmBoxWith(rt, "pod-user-old", nil, []*runtimev1.Container{{Name: "c", Image: vmNamedRef}})
		box.TerminationGracePeriodSeconds = 3
		createRunningVMPod(t, rt, box)
		assertGuestCapFailure(t, rt, vmb, box.GetPodId(), guestagent.CapabilityImageUser, 3*time.Second)
	})
}
