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
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// countingResolver is fakeResolver with a per-method call counter. It wraps the
// ONE seam every data-backed volume source has to pass through: mount.Materialize
// reads ConfigMap/Secret bytes and mints SA tokens only through a mount.Resolver
// (pkg/mount/materialize.go, errNoResolver is returned when it is nil), so a
// resolver whose counters do not move is a proof that no volume data was
// re-resolved, whatever path the caller took to get there.
type countingResolver struct {
	mu        sync.Mutex
	inner     fakeResolver
	configMap int
	secret    int
	token     int
}

func (c *countingResolver) ConfigMap(ctx context.Context, ns, name string) (map[string][]byte, error) {
	c.mu.Lock()
	c.configMap++
	c.mu.Unlock()
	return c.inner.ConfigMap(ctx, ns, name)
}

func (c *countingResolver) Secret(ctx context.Context, ns, name string) (map[string][]byte, error) {
	c.mu.Lock()
	c.secret++
	c.mu.Unlock()
	return c.inner.Secret(ctx, ns, name)
}

func (c *countingResolver) ServiceAccountToken(ctx context.Context, ns, audience string, expirationSeconds int64) (string, error) {
	c.mu.Lock()
	c.token++
	c.mu.Unlock()
	return c.inner.ServiceAccountToken(ctx, ns, audience, expirationSeconds)
}

// resolverCounts is an immutable snapshot of a countingResolver, so a test can
// compare two moments without holding the lock across the call under test.
type resolverCounts struct {
	configMap int
	secret    int
	token     int
}

func (c *countingResolver) counts() resolverCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return resolverCounts{configMap: c.configMap, secret: c.secret, token: c.token}
}

// TestUpdatePodNeverMaterializes pins the in-place-update contract: UpdatePod
// applies labels and annotations ONLY, and volumes are materialized exactly once,
// at create — there is no re-resolution of ConfigMap/Secret/ServiceAccount-token
// data on update.
//
// This is a CHARACTERIZATION of today's behaviour, not a design requirement: a
// projected-volume refresh (the k3sm-side follow-up tracked as B234) must invert
// this test deliberately rather than trip over it. Its k3sm sibling is
// TestUpdatePodDoesNotRematerializeVolumes in pkg/provider.
//
// The contract matters outside this package: the k3sm provider decides whether an
// apiserver-side pod change can be served in place or needs a recreate, and a
// provider comment that assumes an update re-projects volume data would promise
// callers a refresh runtimed never performs (a rotated Secret or an edited
// ConfigMap does NOT reach a running pod through UpdatePod). Pinning it here means
// a future UpdatePod that grows a materialize call fails this test rather than
// silently changing what the provider may claim.
//
// Non-vacuity: the create half asserts the spy's counters MOVED, so a harness that
// never reached the materializer at all cannot make the update half pass trivially.
func TestUpdatePodNeverMaterializes(t *testing.T) {
	spy := &countingResolver{}
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w, Resolver: spy})

	const podID = "pod-upd-mat"
	dataVol := derivedRootfs(t, rt, podID)

	newBox := func() *runtimev1.PodBox {
		return &runtimev1.PodBox{
			PodId:        podID,
			Namespace:    "default",
			Name:         "p",
			RootfsPath:   dataVol,
			LogDirectory: testPodLogDir(rt, podID),
			// SBPL data volume == on-disk rootfs so the credential paths validate.
			SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: dataVol},
			SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
			Labels:          map[string]string{"app": "before"},
			Annotations:     map[string]string{"k3sm.io/note": "before"},
			Volumes: []*runtimev1.Volume{
				{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-config"}},
				{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "git-key"}},
				{Name: "tok", Projected: &runtimev1.ProjectedVolumeSource{
					Sources: []*runtimev1.VolumeProjection{
						{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Path: "token"}},
					},
				}},
			},
			Containers: []*runtimev1.Container{{
				Name:  "main",
				Image: "/bin/sleep",
				VolumeMounts: []*runtimev1.VolumeMount{
					{Name: "cfg", MountPath: "/etc/cfg"},
					{Name: "sec", MountPath: "/etc/sec", ReadOnly: true},
					{Name: "tok", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true},
				},
			}},
		}
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: newBox()})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}

	// Non-vacuity: the create path DID resolve every data-backed source.
	afterCreate := spy.counts()
	if afterCreate.configMap == 0 || afterCreate.secret == 0 || afterCreate.token == 0 {
		t.Fatalf("create did not reach the volume resolver (%+v); the rest of this test would be vacuous", afterCreate)
	}

	// The update itself: same box, new labels + annotations.
	upd := newBox()
	upd.Labels = map[string]string{"app": "after", "tier": "web"}
	upd.Annotations = map[string]string{"k3sm.io/note": "after"}

	ur, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: upd})
	if err != nil {
		t.Fatalf("UpdatePod: %v", err)
	}
	// (a) the update succeeded.
	if ur.GetError() != nil {
		t.Fatalf("UpdatePod failed: %v (reason %v)", ur.GetError(), ur.GetFailureReason())
	}

	// (b) THE CONTRACT: the update resolved nothing — no ConfigMap read, no Secret
	// read, no token minted.
	if afterUpdate := spy.counts(); afterUpdate != afterCreate {
		t.Errorf("UpdatePod re-resolved volume data: counts %+v before, %+v after; "+
			"an in-place update must apply labels/annotations only", afterCreate, afterUpdate)
	}

	// (c) the stored box carries the new labels/annotations.
	rt.mu.Lock()
	p := rt.pods[podID]
	rt.mu.Unlock()
	if p == nil {
		t.Fatalf("pod %s missing after update", podID)
	}
	p.mu.Lock()
	gotLabels := p.box.GetLabels()
	gotAnnotations := p.box.GetAnnotations()
	p.mu.Unlock()
	if gotLabels["app"] != "after" || gotLabels["tier"] != "web" {
		t.Errorf("labels = %v, want app=after tier=web", gotLabels)
	}
	if gotAnnotations["k3sm.io/note"] != "after" {
		t.Errorf("annotations = %v, want k3sm.io/note=after", gotAnnotations)
	}

	// (d) the negative arm updatableOnly still enforces: a changed container set is
	// NOT_UPDATABLE, and it too resolves nothing.
	t.Run("container-set-change-not-updatable", func(t *testing.T) {
		before := spy.counts()
		nb := newBox()
		nb.Containers = append(nb.Containers, &runtimev1.Container{Name: "extra", Image: "/bin/sleep"})
		r, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: nb})
		if err != nil {
			t.Fatalf("UpdatePod: %v", err)
		}
		if r.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("reason = %v, want NOT_UPDATABLE", r.GetFailureReason())
		}
		if after := spy.counts(); after != before {
			t.Errorf("rejected update still resolved volume data: %+v before, %+v after", before, after)
		}
	})
}
