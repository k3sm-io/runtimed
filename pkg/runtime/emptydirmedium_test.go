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
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// mediumVolume builds a volume named name whose sole source is an emptyDir with
// the given medium (empty string is the native-served spelling).
func mediumVolume(name, medium string) *runtimev1.Volume {
	return &runtimev1.Volume{
		Name:     name,
		EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: medium},
	}
}

// wantsNativeRefusal reports whether err is (or wraps) the specific refusal
// nonEmptyEmptyDirMedium's caller in createPod produces — as opposed to any
// other error the fixture might also legitimately return.
func wantsNativeRefusal(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is not served by the native backend")
}

// TestMaterializeRefusesNonEmptyMediumNatively is B303's gate: a PodBox
// carrying an emptyDir volume whose medium is anything other than the empty
// string is refused by createPod — before the materializer (which never reads
// Medium at all — see its emptyDir comment) or any write-side sink runs —
// whenever the RESOLVED sandbox backend (sandbox.SelectBackend's output, not
// the box's requested one) is not the vm backend. This is defence in depth:
// the k3sm provider already refuses such a pod before the RPC reaches
// runtimed, and the vm backend's own planner (classifyVMVolume) legitimately
// honours "Memory" for the vm route.
//
// The check is keyed on the RESOLVED backend specifically because an
// UNSPECIFIED request that the host-capability ladder degrades to the vm rung
// (Seatbelt unavailable, vm available) legitimately honours Memory too — a
// check keyed on the REQUESTED backend would wrongly refuse that pod. Two
// rows below steer the ladder via the fake Backend/VMBackend availability to
// pin exactly that distinction.
func TestMaterializeRefusesNonEmptyMediumNatively(t *testing.T) {
	tests := []struct {
		name             string
		podID            string
		requestedBackend runtimev1.SandboxBackend
		seatbeltAvail    bool
		vmAvail          bool
		medium           string
		wantRefused      bool
		wantSucceed      bool
	}{
		{
			name:             "requested UNSPECIFIED, ladder resolves native, Memory is refused",
			podID:            "pod-native-memory",
			requestedBackend: runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			seatbeltAvail:    true,
			vmAvail:          false,
			medium:           "Memory",
			wantRefused:      true,
		},
		{
			name:             "requested UNSPECIFIED, ladder resolves native, HugePages-2Mi is refused",
			podID:            "pod-native-hugepages",
			requestedBackend: runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			seatbeltAvail:    true,
			vmAvail:          false,
			medium:           "HugePages-2Mi",
			wantRefused:      true,
		},
		{
			name:             "requested UNSPECIFIED, ladder resolves native, empty medium is accepted",
			podID:            "pod-native-empty",
			requestedBackend: runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			seatbeltAvail:    true,
			vmAvail:          false,
			medium:           "",
			wantSucceed:      true,
		},
		{
			name:             "requested VM explicitly, Memory is not refused by this check",
			podID:            "pod-vm-memory",
			requestedBackend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
			seatbeltAvail:    true,
			vmAvail:          true,
			medium:           "Memory",
		},
		{
			// Seatbelt unavailable + vm available degrades an UNSPECIFIED request
			// to the vm rung (sandbox.selectLadder) — the resolved backend is vm
			// even though the box never asked for it. Memory must not be refused.
			name:             "requested UNSPECIFIED, ladder resolves vm, Memory is not refused",
			podID:            "pod-unspecified-ladder-vm",
			requestedBackend: runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			seatbeltAvail:    false,
			vmAvail:          true,
			medium:           "Memory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{
				Backend:   fakeBackend{available: tc.seatbeltAvail},
				VMBackend: &fakeVMBackend{available: tc.vmAvail},
			})
			box := hostBinBox(rt, tc.podID)
			box.SandboxProfile.Backend = tc.requestedBackend
			box.Volumes = []*runtimev1.Volume{mediumVolume("scratch", tc.medium)}

			_, reason, err := rt.createPod(context.Background(), box)

			switch {
			case tc.wantRefused:
				if err == nil {
					t.Fatalf("createPod() = nil error, want a refusal for medium %q", tc.medium)
				}
				if !errors.Is(err, errInvalidPodBox) {
					t.Errorf("createPod() error = %v, want errInvalidPodBox in the chain", err)
				}
				if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
					t.Errorf("reason = %v, want FAILURE_REASON_INVALID_POD_BOX", reason)
				}
				if !wantsNativeRefusal(err) {
					t.Errorf("error %q does not name the native-backend refusal", err.Error())
				}
			case tc.wantSucceed:
				if err != nil {
					t.Fatalf("createPod() = %v (reason %v), want success for an empty-medium emptyDir", err, reason)
				}
			default:
				// The vm-routed rows may still fail createPod for reasons unrelated
				// to this check's fixture (host-binary image references, no real
				// VZ guest, etc.) — the assertion here is narrowly that THIS check
				// did not produce the refusal, not that pod creation succeeded.
				if wantsNativeRefusal(err) {
					t.Errorf("createPod() refused a vm-routed box on the native-only medium check: %v", err)
				}
			}
		})
	}
}

// TestCreatePodRefusesNonEmptyMediumNatively exercises the same refusal
// through the gRPC CreatePod spine, so the wire-level mapping (InvalidArgument
// + INVALID_POD_BOX) and the "no filesystem write happened" property are both
// pinned, not just createPod's direct return values.
func TestCreatePodRefusesNonEmptyMediumNatively(t *testing.T) {
	rt := newTestRuntime(t, Deps{})

	podID := "pod-native-memory-rpc"
	box := hostBinBox(rt, podID)
	box.Volumes = []*runtimev1.Volume{mediumVolume("scratch", "Memory")}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport error: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatalf("CreatePod succeeded for a native emptyDir with medium=Memory; want a refusal")
	}
	if got := codes.Code(resp.GetError().GetCode()); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
	if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
		t.Errorf("reason = %v, want FAILURE_REASON_INVALID_POD_BOX", got)
	}

	// No rootfs directory was created for the refused pod: the check runs
	// before createPod's rootfs MkdirAll, the pod tmp dir, and the GC
	// reference record.
	rootfs := derivedRootfs(t, rt, podID)
	if _, statErr := os.Stat(rootfs); !os.IsNotExist(statErr) {
		t.Errorf("rootfs %s exists after a refused CreatePod (stat err=%v); validation must run before any write", rootfs, statErr)
	}
}
