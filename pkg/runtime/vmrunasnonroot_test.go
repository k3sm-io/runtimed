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
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"

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

// TestVMSidecarAndNamedUserHandedToGuest is the host-inert half.
//
// The emit and token-check halves land with the initramfs re-pin: this build ships the guest code
// that honours GuestContainer.sidecar and image_user, but a host may not set
// either until the pinned initramfs knows them (an older guest refuses a spec
// that sets a field it does not know, so setting one early fails every vm pod
// that uses it). Until then this test pins that the host is INERT: it still
// refuses a native sidecar and a named image USER, and its carrier to the
// guest-spec composer has no field that could set either. The composer's own
// output is pinned by pkg/sandbox's TestGuestSpecSetsNoUnpinnedGuestFields.
//
// The runAsNonRoot leg is the one that does NOT change with the re-pin: a named USER
// under runAsNonRoot is refused host-side, before any hand-off, with the
// kubelet's non-numeric-user text, so in-guest resolution never decides a
// privilege question.
//
// Not here: a guest start-failure for an unresolvable image_user mapping to
// CONTAINER_CONFIG. guest/v1's ContainerEvent carries only started and exited,
// so the guest has no start-failure event to send; it fails the boot with the
// reason on the console instead.
func TestVMSidecarAndNamedUserHandedToGuest(t *testing.T) {
	t.Run("a native sidecar is still refused host-side", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, runAsNonRootWorld())
		box := vmBoxWith(rt, "pod-side",
			[]*runtimev1.Container{{Name: "side", Image: vmPlainRef,
				RestartPolicy: runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS}},
			[]*runtimev1.Container{{Name: "c", Image: vmPlainRef}})
		_, reason, err := rt.createPod(context.Background(), box)
		if !errors.Is(err, errVMSidecarUnexpressible) || reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
			t.Fatalf("err = %v reason = %v, want errVMSidecarUnexpressible / INVALID_POD_BOX", err, reason)
		}
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("CreateVM called %d times", n)
		}
	})

	t.Run("a named image USER with no runAsUser is still refused host-side", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, runAsNonRootWorld())
		box := vmBoxWith(rt, "pod-named", nil, []*runtimev1.Container{{Name: "c", Image: vmNamedRef}})
		_, reason, err := rt.createPod(context.Background(), box)
		if !errors.Is(err, errVMUnresolvableUser) || reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
			t.Fatalf("err = %v reason = %v, want errVMUnresolvableUser / INVALID_POD_BOX", err, reason)
		}
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("CreateVM called %d times", n)
		}
	})

	t.Run("a named image USER under runAsNonRoot is a container config error", func(t *testing.T) {
		rt, vmb := newVMImageRuntime(t, runAsNonRootWorld())
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

	t.Run("the host's guest carrier cannot express either field", func(t *testing.T) {
		typ := reflect.TypeOf(sandbox.VMContainer{})
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(name, "sidecar") || strings.Contains(name, "imageuser") {
				t.Errorf("sandbox.VMContainer.%s exists: a host producer for a guest field the pinned initramfs may not know",
					typ.Field(i).Name)
			}
		}
	})
}
