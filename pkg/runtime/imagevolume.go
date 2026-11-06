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
	// failure, no cluster registry on this node). Its FailureReason says which
	// kind (artifactPullReason).
	ErrArtifactPullRefused = errors.New("ArtifactPullRefused")
	// ErrArtifactMountRefused: the artifact is not mountable as asked (a subset
	// of paths, which this runtime does not serve) or its view could not be
	// built or linked into the pod.
	ErrArtifactMountRefused = errors.New("ArtifactMountRefused")

	// errArtifactCredential marks a failure to resolve the pod's pull
	// credential, before any registry request.
	errArtifactCredential = errors.New("resolve pull credential")
)

// artifactPullReason types an ArtifactPullRefused failure, so the provider can
// tell what a retry can fix from what it cannot without reading the message:
//
//   - IMAGE_PULL_CREDENTIAL: the pod's imagePullSecret could not be resolved,
//     as the image path reports it;
//   - RESOURCE_EXHAUSTED: the store volume would fall below its free-space
//     floor; the node, not the artifact, is short;
//   - INVALID_POD_BOX: the reference names a registry other than the cluster
//     registry, which this node never fetches from, so no retry succeeds;
//   - IMAGE_PULL: everything else, a transfer or registry failure among them.
func artifactPullReason(err error) runtimev1.FailureReason {
	switch {
	case errors.Is(err, errArtifactCredential):
		return runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL
	case errors.Is(err, artifact.ErrInsufficientSpace):
		return runtimev1.FailureReason_FAILURE_REASON_RESOURCE_EXHAUSTED
	case errors.Is(err, artifact.ErrNotClusterRegistry):
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX
	default:
		return runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL
	}
}

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
	if err := r.holdArtifacts(ctx, box, vols); err != nil {
		return mount.ImageViews{}, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("%w: pod %s: %w", ErrArtifactMountRefused, box.GetPodId(), err)
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
		return "", artifactPullReason(err),
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
			return nil, fmt.Errorf("%w: %w", errArtifactCredential, err)
		}
		return r.artifacts.PullForPod(ctx, ref, cred, runtimev1.ArtifactPolicy_ARTIFACT_POLICY_IMAGE_VOLUME, nil)
	}()
	if err != nil {
		return pullRefused(err)
	}
	// The lease pins the blobs until the pod's hold names the manifest; from
	// then on the hold keeps the manifest's blobs and views for the pod's life,
	// even if a moved tag replaces the record that names it.
	defer res.Lease.Release()
	if err := r.holdManifest(ctx, box, res); err != nil {
		return "", runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("%w: pod %s image volume %s: %w", ErrArtifactMountRefused, box.GetPodId(), vol.GetName(), err)
	}
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

// holdArtifacts records, durably and before any fetch, that box's pod holds
// the references of vols. Under holdMu, so a release pass either sees the hold
// or finishes before the fetch re-records what it forgot (see Runtime.holdMu).
func (r *Runtime) holdArtifacts(ctx context.Context, box *runtimev1.PodBox, vols []*runtimev1.Volume) error {
	id, err := image.ParsePodID(box.GetPodId())
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	refs := make([]string, 0, len(vols))
	for _, v := range vols {
		refs = append(refs, v.GetImage().GetReference())
	}
	r.holdMu.Lock()
	defer r.holdMu.Unlock()
	if err := r.index.PutArtifactHold(ctx, id, refs); err != nil {
		return fmt.Errorf("record the pod's artifact hold: %w", err)
	}
	return nil
}

// holdManifest adds the manifest res resolved, with its blobs, to box's pod's
// hold.
func (r *Runtime) holdManifest(ctx context.Context, box *runtimev1.PodBox, res *artifact.Result) error {
	id, err := image.ParsePodID(box.GetPodId())
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	r.holdMu.Lock()
	defer r.holdMu.Unlock()
	if err := r.index.AddArtifactHoldManifest(ctx, id, image.HeldManifest{
		Digest: res.ManifestDigest, Config: res.ConfigDigest, Layers: res.LayerDigests,
	}); err != nil {
		return fmt.Errorf("record the mounted manifest in the pod's hold: %w", err)
	}
	return nil
}

// hasImageVolume reports whether box declares any image volume, so may hold
// an artifact.
func hasImageVolume(box *runtimev1.PodBox) bool {
	for _, v := range box.GetVolumes() {
		if v.GetImage() != nil {
			return true
		}
	}
	return false
}

// releasePodArtifacts ends a deleted (or never created) pod's artifact hold,
// for a pod that declared an image volume. It is detached from the caller's
// cancellation: a delete that has removed the pod must not leave its hold.
func (r *Runtime) releasePodArtifacts(ctx context.Context, box *runtimev1.PodBox) {
	if !hasImageVolume(box) {
		return
	}
	r.releaseArtifactHolds(context.WithoutCancel(ctx), box.GetPodId())
}

// releaseArtifactHolds removes podID's artifact hold (none when podID is
// empty), then forgets every pod-only artifact record no remaining pod holds
// (artifact.Views.ReleasePodOnly): its views go with its last record, and its
// blobs become collectable after the store's grace. An operator-pinned record
// is never released.
//
// A hold counts unless its pod is one the daemon provably holds nothing for
// (podUntracked): a pod that was not re-attached after a restart has no live
// mount, so its stale hold is removed here. Before the startup reap every hold
// counts. It fails closed: when the holds cannot all be read, nothing is
// released.
func (r *Runtime) releaseArtifactHolds(ctx context.Context, podID string) {
	if r.index == nil {
		return
	}
	r.holdMu.Lock()
	defer r.holdMu.Unlock()
	if podID != "" {
		if id, err := image.ParsePodID(podID); err == nil {
			if err := r.index.RemoveArtifactHold(id); err != nil {
				// The hold is still there, so the read below still counts it.
				r.log.Warn("remove the pod's artifact hold", "pod", podID, "err", err)
			}
		}
	}
	if r.views == nil {
		return
	}
	holds, err := r.index.ArtifactHolds(ctx)
	if err != nil {
		r.log.Warn("artifact release skipped: the pods' holds cannot all be read, releasing nothing", "err", err)
		return
	}
	held := map[string]bool{}
	for id, h := range holds {
		if r.podUntracked(id) {
			if err := r.index.RemoveArtifactHold(id); err != nil {
				r.log.Warn("remove a gone pod's artifact hold", "pod", id.String(), "err", err)
			}
			continue
		}
		for _, ref := range h.References {
			held[ref] = true
		}
	}
	released, err := r.views.ReleasePodOnly(ctx, func(ref string) bool { return held[ref] })
	if len(released) > 0 {
		r.log.Info("released artifacts no pod holds", "keys", len(released))
	}
	if err != nil {
		r.log.Warn("artifact release", "err", err)
	}
}
