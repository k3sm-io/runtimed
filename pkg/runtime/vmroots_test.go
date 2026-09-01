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
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestVMPodRecordsItsReachabilityRootsEvenWhenThePullFails is the gate on a
// node-wide GC outage caused by one bad image reference.
//
// The host-process spine writes a pod's reachability record the moment its dir
// exists; the vm spine only ever called recordPodImage, which runs AFTER a
// successful pull. So a vm pod whose first pull failed left a pod dir with no
// record, and image.Cache.Roots reads an absent record as "this pod's references
// are unknown" and refuses to enumerate roots at all — which means the GC
// reclaims nothing, node-wide, until someone notices.
func TestVMPodRecordsItsReachabilityRootsEvenWhenThePullFails(t *testing.T) {
	const podID = "pod-vm-badimage"

	vmb := &fakeVMBackend{available: true, bootOK: true}
	cfg, d := vmPodConfig(t, Deps{
		VMBackend: vmb,
		// A puller that always fails, which is the whole point: the pod dir gets
		// created and then nothing is ever pulled into it.
		Puller: &fakePuller{err: errors.New("manifest unknown: no such image")},
	})
	rt := newTestRuntimeCfg(t, cfg, d)

	_, reason, err := rt.createPod(context.Background(), vmPodBox(rt, podID, 5))
	if err == nil {
		t.Fatal("a pod whose image cannot be pulled must fail")
	}
	if reason != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
		t.Errorf("reason = %v, want IMAGE_PULL", reason)
	}
	if n, _ := vmb.created(); n != 0 {
		t.Errorf("CreateVM called %d times after a failed pull; must be 0", n)
	}

	t.Run("the-gc-can-still-enumerate-its-roots", func(t *testing.T) {
		// The property that actually matters: the GC is not wedged. Roots is the
		// one call a reclaim makes first, and it fails CLOSED — so if the record
		// is missing this returns ErrRootsIncomplete and nothing on the node is
		// ever collected.
		roots, rerr := rt.cache.Roots()
		if errors.Is(rerr, image.ErrRootsIncomplete) {
			t.Fatalf("the image GC is wedged by one failed pull: %v", rerr)
		}
		if rerr != nil {
			t.Fatalf("Roots: %v", rerr)
		}
		// The record is well-formed and EMPTY, not absent: the pod references no
		// blobs, which is the truth, and is a different fact from "unknown".
		if len(roots) != 0 {
			t.Errorf("roots = %v, want none — the pull never succeeded, so the pod references no blobs", roots)
		}
	})

	t.Run("the-record-exists-for-this-pod", func(t *testing.T) {
		id, perr := image.ParsePodID(podID)
		if perr != nil {
			t.Fatal(perr)
		}
		got, gerr := rt.cache.PodImageRoots(id)
		if gerr != nil {
			t.Fatalf("PodImageRoots: %v; the record must exist and be readable", gerr)
		}
		if len(got) != 0 {
			t.Errorf("pod roots = %v, want an empty set", got)
		}
	})
}

// TestVMPodWithFsGroupIsRefused pins the loud replacement for a silent drop.
//
// createVMPod's VMSpec literal never set FSGroup, so a vm pod's fsGroup was
// ignored without a word. Stamping it would be worse: sandbox.idmapWanted would
// then mark the share binds Idmap and guest init refuses an idmapped mount
// outright, turning a silent drop into an unexplained boot failure. And the
// mechanism is unavailable for real — Apple's virtiofs rejects
// mount_setattr(MOUNT_ATTR_IDMAP) with EINVAL — so there is nothing to wait for
// in this release.
//
// The half that DID work is what made the drop look harmless: the fsGroup rode
// each container's supplemental group set, so a process held the group while its
// volumes were not owned by it. A half-applied security-relevant field is the
// worst outcome of the three, which is why the pod is refused.
func TestVMPodWithFsGroupIsRefused(t *testing.T) {
	t.Run("a-vm-pod-requesting-fsgroup-is-refused", func(t *testing.T) {
		for _, fsGroup := range []int64{2000, 1, -1} {
			rt, vmb := newVMPlanRuntime(t)
			box := vmPodBox(rt, "pod-vm-fsgroup", 5)
			box.PodSecurityContext = &runtimev1.PodSecurityContext{FsGroup: fsGroup}

			_, reason, err := rt.createPod(context.Background(), box)
			if err == nil {
				t.Fatalf("fsGroup %d was accepted; it cannot be applied and must not be silently ignored", fsGroup)
			}
			if !errors.Is(err, errInvalidPodBox) {
				t.Errorf("err = %v, want errInvalidPodBox in the chain", err)
			}
			if !errors.Is(err, errVMFsGroupUnsupported) {
				t.Errorf("err = %v, want errVMFsGroupUnsupported in the chain", err)
			}
			if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Errorf("reason = %v, want INVALID_POD_BOX", reason)
			}
			if n, _ := vmb.created(); n != 0 {
				t.Errorf("CreateVM called %d times; the refusal must precede the machine", n)
			}
			// The message is user-facing and is quoted in the documentation, so it
			// must keep saying what it says.
			for _, frag := range []string{
				"fsGroup is not supported on the vm RuntimeClass",
				"idmapped mounts",
				"silently ignored",
			} {
				if !strings.Contains(err.Error(), frag) {
					t.Errorf("err = %q, want it to mention %q", err, frag)
				}
			}
		}
	})

	t.Run("the-same-pod-without-fsgroup-is-admitted", func(t *testing.T) {
		// The refusal must be about fsGroup and nothing else: the identical box
		// with the field cleared reaches the backend.
		rt, vmb := newVMPlanRuntime(t)
		box := vmPodBox(rt, "pod-vm-nofsgroup", 5)
		box.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsUser: 999, RunAsGroup: 999}
		mustPlanVM(t, rt, vmb, box)
	})

	t.Run("a-host-process-pod-with-fsgroup-is-not-refused-by-this-check", func(t *testing.T) {
		// The refusal is vm-ONLY: the host-process spine applies fsGroup with
		// supervisor.ChownForFSGroup and must keep doing so.
		//
		// What this can assert unprivileged is precisely that — the pod is not
		// rejected as an invalid box, and gets as far as the chown. The chown
		// itself needs root (lchown returns EPERM in the unit tier), so the
		// assertion is on WHICH failure occurs, not on success: reaching the
		// chown at all proves the vm refusal did not fire, and the chown is the
		// step that applies the field.
		sp := &fakeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter(), Resolver: fakeResolver{}})
		box := hostBinBox(rt, "pod-host-fsgroup")
		box.PodSecurityContext = &runtimev1.PodSecurityContext{FsGroup: 2000}

		_, reason, err := rt.createPod(context.Background(), box)
		if errors.Is(err, errVMFsGroupUnsupported) {
			t.Fatalf("the vm-only fsGroup refusal fired on the host-process spine: %v", err)
		}
		if reason == runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
			t.Fatalf("a host-process pod with fsGroup was rejected as an invalid box: %v", err)
		}
		if err != nil && !strings.Contains(err.Error(), "fsGroup chown") {
			t.Fatalf("createPod failed before reaching the fsGroup chown: %v", err)
		}
	})
}
