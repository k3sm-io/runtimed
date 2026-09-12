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
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestContainerStatusReportsTheImagePullOutcome is the B119 image_pull gate: every
// container status carries how its image was obtained for the container's most
// recent RESOLVED start attempt, and carries nothing while the image question is
// still open.
//
// # Why this is not vacuous
//
// The node agent renders the kubelet's Pulled event, which has two message
// shapes — "Successfully pulled image %q in %v" and "Container image %q already
// present on machine" — and the provider sees only the resolved image, from
// which neither the choice between them nor the duration can be reconstructed.
// Before this deliverable ContainerStatus carried no such field at all, so the
// agent had to guess; and the fact is not derivable inside the provider by any
// means short of re-pulling. Each row below therefore asserts a distinction that
// nothing else in the status can express: a registry round trip against a
// local-index hit against a host binary that was never fetched, and the absence
// that must not be read as "already present".
func TestContainerStatusReportsTheImagePullOutcome(t *testing.T) {
	const podID = "pod-imagepull"

	// newPullRuntime builds a runtime whose puller reports fetched (a registry
	// round trip) or not (a local-index hit), over the fake unpacker every
	// pull-route test uses.
	newPullRuntime := func(t *testing.T, pull *fakePuller) *Runtime {
		t.Helper()
		return newTestRuntime(t, Deps{
			Puller:   pull,
			Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
			Waiter:   newBlockingWaiter(),
		})
	}

	t.Run("pulled-from-a-registry", func(t *testing.T) {
		rt := newPullRuntime(t, &fakePuller{fetched: true})
		mustCreatePod(t, rt, pullBox(rt, podID, pulledContainer("main", pullRef)))

		got := statusNamed(t, rt, podID, "main").GetImagePull()
		if got == nil {
			t.Fatal("image_pull is absent for a container whose image resolved")
		}
		if !got.GetPulled() {
			t.Error("pulled = false for an image the puller fetched from a registry")
		}
		if got.GetDuration() == nil {
			t.Error("duration is absent; the kubelet's Pulled message reports it in both shapes")
		}
	})

	t.Run("served-from-the-local-index", func(t *testing.T) {
		// The DISCRIMINATOR for the row above: the same successful resolution
		// with no registry contacted must report the other message shape.
		rt := newPullRuntime(t, &fakePuller{fetched: false})
		mustCreatePod(t, rt, pullBox(rt, podID, pulledContainer("main", pullRef)))

		got := statusNamed(t, rt, podID, "main").GetImagePull()
		if got == nil {
			t.Fatal("image_pull is absent for a container served from the local index")
		}
		if got.GetPulled() {
			t.Error("pulled = true for an image no registry was contacted for")
		}
		if got.GetDuration() == nil {
			t.Error("duration is absent for a local hit; it is the time spent proving the image was there")
		}
	})

	t.Run("host-binary-route", func(t *testing.T) {
		// A native/absolute-path container runs an executable already on this
		// machine, which is exactly the already-present claim — reported as an
		// outcome, not as an absence, because the image question IS answered.
		pull := &fakePuller{fetched: true}
		rt := newTestRuntime(t, Deps{Puller: pull, Waiter: newBlockingWaiter()})
		mustCreatePod(t, rt, hostBinBox(rt, podID))

		got := statusNamed(t, rt, podID, "main").GetImagePull()
		if got == nil {
			t.Fatal("image_pull is absent for a host-binary container")
		}
		if got.GetPulled() {
			t.Error("pulled = true on the host-binary route, which contacts no registry")
		}
		if ref := pull.ref(); ref != "" {
			t.Errorf("the host-binary route reached the puller with %q", ref)
		}
	})

	t.Run("absent-while-waiting-on-an-image-failure", func(t *testing.T) {
		const badRef = "example.com/bad:v1"
		pull := &fakePuller{fetched: true, errByRef: map[string]error{
			badRef: errors.New("manifest unknown: no such image"),
		}}
		rt := newPullRuntime(t, pull)
		mustCreatePod(t, rt, pullBox(rt, podID,
			pulledContainer("good", pullRef), pulledContainer("bad", badRef)))

		assertWaiting(t, rt, podID, "bad", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL)
		if got := statusNamed(t, rt, podID, "bad").GetImagePull(); got != nil {
			t.Errorf("image_pull = %v for a container still Waiting on its image; "+
				"an outcome here would have the agent report a pull that never resolved", got)
		}
		// Non-vacuity: the sibling container in the SAME pod does report one, so
		// the nil above is the waiting container's own state and not a field
		// nothing ever sets.
		if got := statusNamed(t, rt, podID, "good").GetImagePull(); got == nil {
			t.Error("image_pull is absent for the container that did resolve")
		}
	})

	t.Run("re-resolved-on-a-restart", func(t *testing.T) {
		// image_pull describes the MOST RECENT resolved attempt, so a restart
		// that hits the registry must replace a local-hit outcome rather than
		// carry it forward with the rest of the status.
		pull := &fakePuller{fetched: false}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{
			Puller:   pull,
			Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
			Waiter:   w,
		})
		rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
		rt.signalGroup = rec.signal
		mustCreatePod(t, rt, pullBox(rt, podID, pulledContainer("main", pullRef)))

		if got := statusNamed(t, rt, podID, "main").GetImagePull(); got.GetPulled() {
			t.Fatalf("first attempt reported pulled = true; the row's premise is gone")
		}
		pull.setFetched(true)
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: podID, Container: "main", Reason: "liveness probe failed",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("RestartContainer failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}
		if got := resp.GetStatus().GetImagePull(); !got.GetPulled() {
			t.Errorf("the restart response reports image_pull %v; the replacement was fetched", got)
		}
		if got := statusNamed(t, rt, podID, "main").GetImagePull(); !got.GetPulled() {
			t.Errorf("GetPodStatus reports image_pull %v after a fetched restart", got)
		}
	})
}
