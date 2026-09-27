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
	"fmt"

	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/mount"
)

// ErrPodNotFound reports a pod id this runtime does not hold.
var ErrPodNotFound = errors.New("pod not found")

// ErrProjectedRefreshUnsupported reports a pod whose volumes this runtime cannot
// refresh: a vm pod's volumes are pooled into guest shares (mount.MaterializeShares),
// not rendered as atomic-writer generations.
var ErrProjectedRefreshUnsupported = errors.New("projected-volume refresh is not supported for vm pods")

// RefreshProjectedVolumes re-renders the configMap / secret / downwardAPI /
// projected volume mounts of a running pod from current data — the kubelet's
// periodic projected-volume sync, driven by the provider on its own cadence.
// It is deliberately NOT part of the runtimev1 RuntimeServer contract, and
// UpdatePod never materializes: this is the one path that re-resolves volume
// data after create.
//
// Each mount is swapped by mount.Refresh's atomic ..data flip, so a container
// reads the whole old set or the whole new set. subPath, emptyDir and
// wholly-immutable volumes are skipped; a ServiceAccount token is re-minted only
// under 20% of its lifetime. Refreshes of one pod are serialized. The
// per-volume outcome is recorded on the pod; a volume that failed keeps its live
// generation, and the returned error names it.
func (r *Runtime) RefreshProjectedVolumes(ctx context.Context, podID string) (mount.RefreshResult, error) {
	r.mu.Lock()
	p, ok := r.pods[podID]
	r.mu.Unlock()
	if !ok {
		return mount.RefreshResult{}, fmt.Errorf("refresh projected volumes of pod %s: %w", podID, ErrPodNotFound)
	}
	if p.backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return mount.RefreshResult{}, fmt.Errorf("pod %s: %w", podID, ErrProjectedRefreshUnsupported)
	}

	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	// Snapshot the box: UpdatePod replaces labels/annotations under p.mu, and a
	// downward-API projection renders them.
	p.mu.Lock()
	if p.stopping {
		p.mu.Unlock()
		return mount.RefreshResult{}, fmt.Errorf("pod %s is being deleted", podID)
	}
	box, _ := proto.Clone(p.box).(*runtimev1.PodBox)
	podIP := p.podIP
	p.mu.Unlock()

	root, err := r.rootfsPath(box)
	if err != nil {
		return mount.RefreshResult{}, fmt.Errorf("pod %s data volume: %w", podID, err)
	}
	res, err := mount.Refresh(ctx, root, box, r.resolver, mount.RefreshOptions{PodIP: podIP, State: p.projState})
	if res.State.Immutable != nil {
		p.projState = res.State
	}
	p.mu.Lock()
	p.projRefresh = res.Volumes
	p.mu.Unlock()
	if err != nil {
		return res, fmt.Errorf("refresh projected volumes of pod %s: %w", podID, err)
	}
	return res, nil
}
