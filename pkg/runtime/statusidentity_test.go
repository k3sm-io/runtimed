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
	"encoding/hex"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The three digests a pull resolves, kept distinguishable on purpose: only the
// CONFIG digest may ever appear in image_id. The index digest is shared by every
// platform of a multi-platform image and the layer digest names a component, so
// either one in a per-container identity field resolves the wrong artifact —
// which is the defect B132 exists to close, not a stylistic preference.
const (
	testConfigDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testIndexDigest  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testLayerDigest  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// TestContainerStatusIdentityFields is the B132 gate: ContainerStatus.image_id
// and ContainerStatus.container_id are populated by the real status-assembly path
// (CreatePod → startContainer → containerStatusOf → GetPodStatus), with the
// substrate faked at the injected seams.
//
// The two values are asserted against their SOURCES, not against literals a
// regression could drift past together with the code:
//   - image_id must equal the config digest of the manifest the pull resolved —
//     the same digest recorded as the pod's reachability root — and must not be
//     the index digest, a layer digest, or the mutable reference;
//   - container_id must equal the id derived from the pod's own reap record, so
//     the published identity and the (pgid, leader-start) pair the reap is
//     willing to SIGKILL can never be two different schemes.
func TestContainerStatusIdentityFields(t *testing.T) {
	t.Run("pulled image publishes the config digest and a record-derived id", func(t *testing.T) {
		const podID = "pod-identity"
		w := newBlockingWaiter()
		pull := &fakePuller{manifest: &runtimev1.ImageManifest{
			Reference:   "example.com/app:v1",
			MediaType:   "application/vnd.oci.image.manifest.v1+json",
			Config:      &runtimev1.Descriptor{Digest: testConfigDigest, Size: 11},
			Layers:      []*runtimev1.Descriptor{{Digest: testLayerDigest, Size: 22}},
			IndexDigest: testIndexDigest,
		}}
		rt := newTestRuntime(t, Deps{
			Waiter:        w,
			Puller:        pull,
			ProcStartTime: func(int) (int64, bool) { return 987654321, true },
		})
		mustCreatePod(t, rt, pulledImageBox(t, rt, podID))

		st := containerStatusNamed(t, rt, podID, "main")

		if got := st.GetImageId(); got != testConfigDigest {
			t.Errorf("image_id = %q, want the resolved CONFIG digest %q", got, testConfigDigest)
		}
		if got := st.GetImageId(); got == testIndexDigest || got == testLayerDigest {
			t.Errorf("image_id = %q: an index/layer digest is not the image's per-platform identity", got)
		}
		if got := st.GetImageId(); got == st.GetImage() {
			t.Errorf("image_id = %q equals the mutable reference; a tag is not a content address", got)
		}

		rec := reapRecordFor(t, rt, podID, "main")
		want := rec.containerID()
		got := st.GetContainerId()
		if got == "" {
			t.Fatal("container_id is empty; the status carries no runtime identity")
		}
		if got != want {
			t.Errorf("container_id = %q, want the id derived from the pod's reap record %q", got, want)
		}
		// The id is the one-way form, not the host pgid: a fixed-width hex digest
		// that discloses nothing about the host process table to a pods/get reader.
		if len(got) != 2*32 {
			t.Errorf("container_id %q is %d chars, want a 64-char sha256 hex digest", got, len(got))
		}
		if _, err := hex.DecodeString(got); err != nil {
			t.Errorf("container_id %q is not hex: %v", got, err)
		}
		// exact-INSTANCE binding: a recycled pgid (same pgid, different leader
		// start) must not reproduce this id, or the published identity would
		// survive an incarnation it does not describe.
		recycled := rec
		recycled.StartUnixNano++
		if recycled.containerID() == got {
			t.Error("a different leader start yields the same container_id; the id is not incarnation-bound")
		}
	})

	t.Run("host-binary route reports no image_id but still an id", func(t *testing.T) {
		const podID = "pod-hostbin"
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		mustCreatePod(t, rt, hostBinBox(rt, podID))

		st := containerStatusNamed(t, rt, podID, "main")
		// empty IS the CORRECT ANSWER here: a host binary is run in place with no
		// registry round trip and no manifest, so there is no content digest. An
		// empty image_id degrades visibly; a substitute (the image reference) would
		// be a lie in a content-addressable field.
		if got := st.GetImageId(); got != "" {
			t.Errorf("image_id = %q for a host-binary container, want empty (no manifest exists)", got)
		}
		if st.GetContainerId() == "" {
			t.Error("container_id is empty; every spawned container has a reap record to derive one from")
		}
	})

	t.Run("terminated state carries the container's own id", func(t *testing.T) {
		const podID = "pod-identity-term"
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		mustCreatePod(t, rt, hostBinBox(rt, podID))

		running := containerStatusNamed(t, rt, podID, "main")
		liveID := running.GetContainerId()
		rec := reapRecordFor(t, rt, podID, "main")
		w.release(rec.Pgid)

		var term *runtimev1.ContainerStateTerminated
		waitFor(t, 3*time.Second, "the container to terminate", func() bool {
			term = containerStatusNamed(t, rt, podID, "main").GetState().GetTerminated()
			return term != nil
		})
		if got := term.GetContainerId(); got != liveID {
			t.Errorf("terminated container_id = %q, want this container's own id %q", got, liveID)
		}
	})
}

// pulledImageBox is a PodBox whose sole container has a command, so resolveBinary
// takes the PULL route (the only route with a manifest to take an image_id from).
func pulledImageBox(t *testing.T, rt *Runtime, podID string) *runtimev1.PodBox {
	t.Helper()
	dataVol := derivedRootfs(t, rt, podID)
	return &runtimev1.PodBox{
		PodId:           podID,
		Namespace:       "default",
		Name:            "p",
		RootfsPath:      dataVol,
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: dataVol},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{{
			Name:    "main",
			Image:   "example.com/app:v1",
			Command: []string{"/app/server"}, // command set → the image is pulled
		}},
	}
}

// containerStatusNamed reads one container's status back through GetPodStatus —
// the assembled, cloned status a consumer actually sees, never the internal
// containerProc state.
func containerStatusNamed(t *testing.T, rt *Runtime, podID, name string) *runtimev1.ContainerStatus {
	t.Helper()
	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus(%s): %v", podID, err)
	}
	for _, cs := range gs.GetStatus().GetContainerStatuses() {
		if cs.GetName() == name {
			return cs
		}
	}
	t.Fatalf("pod %s has no container status named %q", podID, name)
	return nil
}

// reapRecordFor returns the durable reap record the daemon wrote for a container
// — the identity the published container_id must be derived from.
func reapRecordFor(t *testing.T, rt *Runtime, podID, container string) podProcRecord {
	t.Helper()
	recs, quarantine, err := rt.listPodProcRecords()
	if err != nil {
		t.Fatalf("listPodProcRecords: %v", err)
	}
	if len(quarantine) != 0 {
		t.Fatalf("unexpected quarantined reap records: %s", strings.Join(quarantine, ", "))
	}
	for _, rec := range recs {
		if rec.PodID == podID && rec.Container == container {
			return rec
		}
	}
	t.Fatalf("no reap record for %s/%s", podID, container)
	return podProcRecord{}
}
