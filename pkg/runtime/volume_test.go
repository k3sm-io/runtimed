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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPVCSurvivesPodTeardown is acceptance runtimed:M3.1-a2 (root-free): data
// written to a PVC-backed volume survives the pod-teardown path (the PV dir is not
// removed with the pod dir — ReclaimPolicy Retain), while the pod rootfs IS removed
// (the contrast). It also asserts the PV mount root landed in the pod's SBPL
// write-scope so the confined pod could write to it.
//
// The image cache and the runtime root share one dir (as they do in production,
// and as newTestRuntime now arranges too) so the pod rootfs (cache-derived) and
// the PV storage root (Config.Root/storage) are siblings under one root and
// removePodDir actually fires.
func TestPVCSurvivesPodTeardown(t *testing.T) {
	w := newBlockingWaiter()
	root := t.TempDir()
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{Root: root}, Deps{
		Cache:   cache,
		Backend: fakeBackend{available: true},
		Spawner: &fakeSpawner{},
		Waiter:  w,
		Puller:  &fakePuller{},
		Signer:  &fakeSigner{},
		Network: supervisor.NodeNetwork{IP: "10.1.2.3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The SIGKILL hook releases the fake reaper for the signalled pid, so the
	// fake behaves like a real process group: it dies when killed. DeletePod now
	// waits for the reaper's exit observation before returning (B40), so a fake
	// that never reports the exit would spend the full observation bound here.
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal

	const podID = "pod-pvc"
	const ns = "prod"
	const claim = "pgdata"
	rootfs := filepath.Join(root, "pods", podID, "rootfs")

	box := &runtimev1.PodBox{
		PodId:           podID,
		Namespace:       ns,
		Name:            "pg",
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: rootfs},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Volumes: []*runtimev1.Volume{{
			Name:                  "data",
			PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
		}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			Image:        "/bin/sleep",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "data", MountPath: "/var/lib/pg"}},
		}},
	}
	mustCreatePod(t, rt, box)

	// The PV dir resolves to the storage-root sibling of the pods dir.
	dataDir, err := rt.binder.Class().DataDir(ns, claim)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dataDir, filepath.Join(root, "storage")) {
		t.Fatalf("PV dir %q is not under the storage root %q", dataDir, filepath.Join(root, "storage"))
	}

	// The PV mount root is in the pod's SBPL write-scope.
	rt.mu.Lock()
	profile := rt.pods[podID].profile
	rt.mu.Unlock()
	if !strings.Contains(profile, "(allow file-write*\n  (subpath \""+dataDir+"\")") {
		t.Errorf("PV mount root %s not in SBPL write-scope:\n%s", dataDir, profile)
	}

	// Write through the pod-side symlink: it must land in the persistent dir.
	link := filepath.Join(rootfs, "var/lib/pg")
	if dst, err := os.Readlink(link); err != nil || dst != dataDir {
		t.Fatalf("pod mount link %s -> %q (err %v), want -> %q", link, dst, err, dataDir)
	}
	if err := os.WriteFile(filepath.Join(link, "state.txt"), []byte("durable"), 0o644); err != nil {
		t.Fatalf("write through PV symlink: %v", err)
	}
	persisted := filepath.Join(dataDir, "state.txt")
	if got, _ := os.ReadFile(persisted); string(got) != "durable" {
		t.Fatalf("write did not land in the persistent dir: %q", got)
	}

	// Tear the pod down (grace 0 → immediate SIGKILL; the onKill hook above lets
	// the fake reaper report the exit, as a killed group would).
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}

	// The PV dir + its contents survive teardown (lifecycle-decoupled, Retain).
	if got, err := os.ReadFile(persisted); err != nil || string(got) != "durable" {
		t.Errorf("PV data did not survive teardown: %q (err %v)", got, err)
	}

	// The pod dir (rootfs + the ephemeral symlink) IS removed — the contrast.
	if _, err := os.Stat(filepath.Join(root, "pods", podID)); !os.IsNotExist(err) {
		t.Errorf("pod dir not removed on teardown (err=%v); only the PV must persist", err)
	}

	// A fresh pod for the same claim reuses the same dir with the prior data intact.
	box2 := &runtimev1.PodBox{
		PodId:           "pod-pvc-2",
		Namespace:       ns,
		Name:            "pg",
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: filepath.Join(root, "pods", "pod-pvc-2", "rootfs")},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Volumes: []*runtimev1.Volume{{
			Name:                  "data",
			PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
		}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			Image:        "/bin/sleep",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "data", MountPath: "/var/lib/pg"}},
		}},
	}
	mustCreatePod(t, rt, box2)
	reuse := filepath.Join(root, "pods", "pod-pvc-2", "rootfs", "var/lib/pg", "state.txt")
	if got, _ := os.ReadFile(reuse); string(got) != "durable" {
		t.Errorf("re-mounted PV lost prior data: %q", got)
	}
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-pvc-2"}); err != nil {
		t.Fatalf("DeletePod 2: %v", err)
	}
}
