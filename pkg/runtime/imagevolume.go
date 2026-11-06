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

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The stable reasons a refused image volume carries, for the provider's Pod
// Event. A CreatePod error that wraps one of these begins with its text.
var (
	// ErrArtifactPullRefused: the artifact could not be fetched into the node
	// cache (a foreign registry, a refused type, a short volume, a transfer
	// failure, no cluster registry on this node).
	ErrArtifactPullRefused = errors.New("ArtifactPullRefused")
	// ErrArtifactMountRefused: the artifact is not mountable as asked (a subset
	// of paths, which this runtime does not serve) or its view could not be
	// built or linked into the pod.
	ErrArtifactMountRefused = errors.New("ArtifactMountRefused")
)

// imageVolumeViews fetches every mounted image volume of box into the node
// cache, through the same puller, IMAGE_VOLUME policy and pull credentials
// Images.PullArtifact uses, and builds each one's read-only view. A pod with no
// mounted image volume returns the zero ImageViews and touches nothing.
//
// The fetch is idempotent: an artifact the provider already pulled with
// PullArtifact resolves its manifest and finds every layer cached. A non-empty
// paths is refused before any request, never served as the whole artifact.
func (r *Runtime) imageVolumeViews(ctx context.Context, box *runtimev1.PodBox) (mount.ImageViews, runtimev1.FailureReason, error) {
	vols, err := mount.ImageVolumes(box)
	if err != nil {
		return mount.ImageViews{}, runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED,
			fmt.Errorf("%w: pod %s: %w", ErrArtifactMountRefused, box.GetPodId(), err)
	}
	if len(vols) == 0 {
		return mount.ImageViews{}, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
	}
	if r.artifacts == nil {
		return mount.ImageViews{}, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			fmt.Errorf("%w: pod %s: this node has no cluster registry configured", ErrArtifactPullRefused, box.GetPodId())
	}
	if r.views == nil {
		return mount.ImageViews{}, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("%w: pod %s: artifact views unavailable: %w", ErrArtifactMountRefused, box.GetPodId(), r.viewsErr)
	}
	views := mount.ImageViews{Root: r.views.Root(), ByVolume: make(map[string]string, len(vols))}
	for _, v := range vols {
		view, reason, err := r.imageVolumeView(ctx, box, v)
		if err != nil {
			return mount.ImageViews{}, reason, err
		}
		views.ByVolume[v.GetName()] = view
	}
	return views, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// imageVolumeView fetches vol's reference and returns its whole-artifact view.
// An error begins with its stable reason, then names the pod and the volume.
func (r *Runtime) imageVolumeView(ctx context.Context, box *runtimev1.PodBox, vol *runtimev1.Volume) (string, runtimev1.FailureReason, error) {
	ref := vol.GetImage().GetReference()
	pullRefused := func(err error) (string, runtimev1.FailureReason, error) {
		return "", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			fmt.Errorf("%w: pod %s image volume %s: %w", ErrArtifactPullRefused, box.GetPodId(), vol.GetName(), err)
	}
	if err := image.ValidateReference(ref); err != nil {
		return pullRefused(err)
	}
	// The host is checked before any credential is resolved, as the RPC does,
	// so naming a foreign registry never makes the daemon read a Secret.
	if err := r.artifacts.CheckHost(ref); err != nil {
		return pullRefused(err)
	}
	select {
	case r.artifactSem <- struct{}{}:
	case <-ctx.Done():
		return pullRefused(ctx.Err())
	}
	res, err := func() (*artifact.Result, error) {
		defer func() { <-r.artifactSem }()
		cred, err := r.pullCredential(ctx, box, ref)
		if err != nil {
			return nil, err
		}
		return r.artifacts.PullArtifact(ctx, ref, cred, runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME, nil)
	}()
	if err != nil {
		return pullRefused(err)
	}
	// The lease pins the blobs until the view's clones exist; after that the
	// artifact record is what keeps them.
	defer res.Lease.Release()
	view, err := r.views.View(ctx, res.ManifestDigest, nil)
	if err != nil {
		return "", runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("%w: pod %s image volume %s: build view of %s: %w", ErrArtifactMountRefused, box.GetPodId(), vol.GetName(), res.ManifestDigest, err)
	}
	r.log.Info("image volume view ready", "pod", box.GetPodId(), "reference", ref, "digest", res.ManifestDigest, "fetched", res.Fetched)
	return view, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// linkedImageViews re-derives a host-process pod's granted artifact views from
// its links (mount.LinkedImageViews), for a profile recompiled at attach.
func (r *Runtime) linkedImageViews(box *runtimev1.PodBox, rootfs string) ([]string, error) {
	vols, err := mount.ImageVolumes(box)
	if err != nil || len(vols) == 0 {
		return nil, err
	}
	if r.views == nil {
		return nil, fmt.Errorf("%w: artifact views unavailable: %w", ErrArtifactMountRefused, r.viewsErr)
	}
	return mount.LinkedImageViews(box, rootfs, r.views.Root())
}
