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
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/mount"
)

// TestRefreshProjectedVolumesIsItsOwnPath pins the split between the two
// post-create paths: UpdatePod never re-resolves volume data, and
// RefreshProjectedVolumes — a method on the concrete Runtime, not on the
// runtimev1 service — does, recording the per-volume outcome on the pod. The
// motivating path is covered end to end: a label changed by UpdatePod reaches a
// downwardAPI volume only through the refresh. An unknown pod and a vm pod are
// errors.
func TestRefreshProjectedVolumesIsItsOwnPath(t *testing.T) {
	spy := &countingResolver{}
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter(), Resolver: spy})

	const podID = "pod-refresh-own-path"
	dataVol := derivedRootfs(t, rt, podID)
	box := &runtimev1.PodBox{
		PodId:           podID,
		Namespace:       "default",
		Name:            "p",
		RootfsPath:      dataVol,
		LogDirectory:    testPodLogDir(rt, podID),
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: dataVol},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Labels:          map[string]string{"app": "before"},
		Volumes: []*runtimev1.Volume{
			{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-config"}},
			{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "git-key"}},
			{Name: "labels", DownwardApi: &runtimev1.DownwardAPIVolumeSource{Items: []*runtimev1.DownwardAPIVolumeFile{
				{Path: "app", FieldRef: &runtimev1.ObjectFieldSelector{FieldPath: "metadata.labels['app']"}},
			}}},
		},
		Containers: []*runtimev1.Container{{
			Name:  "main",
			Image: "/bin/sleep",
			VolumeMounts: []*runtimev1.VolumeMount{
				{Name: "cfg", MountPath: "/etc/cfg"},
				{Name: "sec", MountPath: "/etc/sec", ReadOnly: true},
				{Name: "labels", MountPath: "/etc/podinfo"},
			},
		}},
	}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	// The create-time render is the atomic-writer layout the refresh swaps.
	if target, err := os.Readlink(filepath.Join(dataVol, "etc/cfg/..data")); err != nil || target == "" {
		t.Fatalf("create did not write the ..data layout: %q %v", target, err)
	}
	labelFile := filepath.Join(dataVol, "etc/podinfo/app")
	if b, err := os.ReadFile(labelFile); err != nil || string(b) != "before" {
		t.Fatalf("create-time label file = %q (%v), want before", b, err)
	}
	afterCreate := spy.counts()

	// UpdatePod still never materializes.
	upd, _ := proto.Clone(box).(*runtimev1.PodBox)
	upd.Labels = map[string]string{"app": "after"}
	if ur, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: upd}); err != nil || ur.GetError() != nil {
		t.Fatalf("UpdatePod: %v / %v", err, ur.GetError())
	}
	if got := spy.counts(); got != afterCreate {
		t.Fatalf("UpdatePod re-resolved volume data: %+v -> %+v", afterCreate, got)
	}
	if b, _ := os.ReadFile(labelFile); string(b) != "before" {
		t.Fatalf("UpdatePod re-rendered the downwardAPI volume (%q); it must not materialize", b)
	}

	// RefreshProjectedVolumes does.
	res, err := rt.RefreshProjectedVolumes(context.Background(), podID)
	if err != nil {
		t.Fatalf("RefreshProjectedVolumes: %v", err)
	}
	got := spy.counts()
	if got.configMap != afterCreate.configMap+1 || got.secret != afterCreate.secret+1 {
		t.Errorf("refresh fetches = %+v after create %+v, want one more ConfigMap and one more Secret read", got, afterCreate)
	}
	if len(res.Volumes) != 3 {
		t.Fatalf("outcomes = %+v, want 3 volumes", res.Volumes)
	}
	wantOutcome := map[string]mount.RefreshOutcome{
		"cfg":    mount.RefreshUnchanged, // the data did not change
		"sec":    mount.RefreshUnchanged,
		"labels": mount.RefreshUpdated, // the label UpdatePod changed
	}
	for _, v := range res.Volumes {
		if v.Outcome != wantOutcome[v.Name] {
			t.Errorf("volume %s outcome = %s, want %s", v.Name, v.Outcome, wantOutcome[v.Name])
		}
	}
	if b, err := os.ReadFile(labelFile); err != nil || string(b) != "after" {
		t.Errorf("label file after refresh = %q (%v), want the UpdatePod value after", b, err)
	}
	rt.mu.Lock()
	p := rt.pods[podID]
	rt.mu.Unlock()
	p.mu.Lock()
	recorded := len(p.projRefresh)
	p.mu.Unlock()
	if recorded != 3 {
		t.Errorf("pod recorded %d volume outcomes, want 3", recorded)
	}

	// An unknown pod errors.
	if _, err := rt.RefreshProjectedVolumes(context.Background(), "no-such-pod"); !errors.Is(err, ErrPodNotFound) {
		t.Errorf("unknown pod err = %v, want ErrPodNotFound", err)
	}

	// A vm pod is refused: its volumes are guest shares, not generations.
	t.Run("vm-pod-refused", func(t *testing.T) {
		const vmID = "pod-refresh-vm"
		vmBox, _ := proto.Clone(box).(*runtimev1.PodBox)
		vmBox.PodId = vmID
		rt.mu.Lock()
		rt.pods[vmID] = &pod{box: vmBox, backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM}
		rt.mu.Unlock()
		t.Cleanup(func() {
			rt.mu.Lock()
			delete(rt.pods, vmID)
			rt.mu.Unlock()
		})
		before := spy.counts()
		if _, err := rt.RefreshProjectedVolumes(context.Background(), vmID); !errors.Is(err, ErrProjectedRefreshUnsupported) {
			t.Errorf("vm pod err = %v, want ErrProjectedRefreshUnsupported", err)
		}
		if after := spy.counts(); after != before {
			t.Errorf("refused vm refresh still resolved volume data: %+v -> %+v", before, after)
		}
	})
}
