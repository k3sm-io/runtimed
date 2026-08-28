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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// imagesService serves the Images RPCs (apis/runtime/v1/images.proto) over the
// SAME *Runtime — and, critically, the same grpc.Server and therefore the same
// listener — as the Runtime service.
//
// That co-registration is the whole socket-posture control. The proto file
// records that the service inherits the daemon's single unix socket and its
// 0700-dir / 0600-socket permissions, but a proto file cannot assert what
// listener anything is registered on; only this repo can, and NewServer plus its
// gate are where it is asserted. A second listener for "just the image commands"
// would silently hand every local uid RemoveImage and PruneImages.
type imagesService struct {
	runtimev1.UnimplementedImagesServer
	rt *Runtime
}

// ListImages returns the images this node has recorded roots for.
//
// The entries are assembled from the DAEMON-AUTHORED per-pod reachability
// records, which are the only local index that exists today: a reference-to-
// digest index keyed (reference x platform) is a separate deliverable. Two
// consequences are stated rather than papered over — the listing carries no
// manifest descriptor (the store never commits a manifest blob, so there is no
// digest to report), and an image that no pod references is not listed even if
// its blobs are still cached.
func (s *imagesService) ListImages(ctx context.Context, req *runtimev1.ListImagesRequest) (*runtimev1.ListImagesResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	roots, err := s.rt.cache.Roots()
	if err != nil {
		return nil, imageStatusError(err)
	}
	seen := make(map[string]bool, len(roots))
	out := &runtimev1.ListImagesResponse{}
	for _, r := range roots {
		if req.GetReference() != "" && r.Reference != req.GetReference() {
			continue
		}
		if seen[r.Reference] {
			continue
		}
		seen[r.Reference] = true
		mfst := &runtimev1.ImageManifest{
			Reference: r.Reference,
			Config:    &runtimev1.Descriptor{Digest: r.Config},
		}
		for _, l := range r.Layers {
			mfst.Layers = append(mfst.Layers, &runtimev1.Descriptor{Digest: l})
		}
		out.Images = append(out.Images, &runtimev1.Image{Manifest: mfst})
	}
	return out, nil
}

// ImageFsInfo returns raw statfs measurements for the volume backing the image
// store, plus the store subtree's own measured size. The caller does the
// arithmetic — see FilesystemUsage in the proto, and image.StoreBytes for why
// the byte count is not a reclaim estimate.
func (s *imagesService) ImageFsInfo(ctx context.Context, _ *runtimev1.ImageFsInfoRequest) (*runtimev1.ImageFsInfoResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	root := s.rt.cache.Root()
	sample, err := image.StatfsSample(root)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	stored, err := s.rt.cache.StoreBytes()
	if err != nil {
		return nil, imageStatusError(err)
	}
	return &runtimev1.ImageFsInfoResponse{
		Filesystems: []*runtimev1.FilesystemUsage{{
			Timestamp:      timestamppb.New(time.Now()),
			Mountpoint:     sample.Mountpoint,
			UsedBytes:      sample.UsedBytes,
			CapacityBytes:  sample.CapacityBytes,
			AvailableBytes: sample.AvailableBytes,
			InodesUsed:     sample.InodesUsed,
		}},
		StoreBytes: uint64(stored),
	}, nil
}

// RemoveImage is not implemented, and the refusal is a design statement rather
// than a gap to be filled in place.
//
// A root on this node is a PER-POD record the daemon authored, not an operator
// untag: dropping one would assert that a pod no longer references content it is
// still running on, which is the exact liveness violation the image GC exists to
// make impossible. Root removal needs the reference-to-digest index (a separate
// deliverable) so an untag can drop an OPERATOR-owned root without touching any
// pod-owned one. Until that exists, refusing is the honest answer; a caller
// wanting space back calls PruneImages, which re-derives reachability first.
func (s *imagesService) RemoveImage(context.Context, *runtimev1.RemoveImageRequest) (*runtimev1.RemoveImageResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"RemoveImage: this node's image roots are per-pod records, not operator untags; "+
			"removing one would unroot a live pod's content. Use PruneImages, which re-derives reachability.")
}

// PruneImages deletes unreferenced blobs, honoring the request's dry_run.
//
// It runs the SAME code path as the daemon's disk-pressure reclaim, forced past
// the pressure check — an operator asking for a prune is asking to run the
// policy now, not to run a different, laxer policy. Every safety rule is
// therefore identical: the root set is enumerated fail-closed, live ingest
// leases are honored, and every unlink re-verifies its target.
func (s *imagesService) PruneImages(ctx context.Context, req *runtimev1.PruneImagesRequest) (*runtimev1.PruneImagesResponse, error) {
	rep, err := s.rt.cache.ReclaimUnderPressure(ctx, image.ReclaimConfig{
		Force:  true,
		DryRun: req.GetDryRun(),
		Log:    s.rt.log,
	})
	if err != nil {
		return nil, imageStatusError(err)
	}
	out := &runtimev1.PruneImagesResponse{
		RemovedDigests: rep.Removed,
		ReclaimedBytes: uint64(max(rep.ReclaimedBytes, 0)),
	}
	for _, k := range rep.Kept {
		out.Skipped = append(out.Skipped, &runtimev1.SkippedBlob{
			Digest: k.Digest,
			Reason: pruneSkipReason(k.Reason),
		})
	}
	return out, nil
}

// pruneSkipReason maps this repo's keep verdicts onto the wire enum. The mapping
// is TOTAL by construction (an unlisted verdict lands on UNSPECIFIED, which the
// proto defines as "the daemon reported no typed reason") so a new verdict can
// never be silently reported as the wrong one.
func pruneSkipReason(r image.PruneReason) runtimev1.PruneSkipReason {
	switch r {
	case image.ReasonKeptInUse:
		return runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE
	case image.ReasonKeptLeased:
		return runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_LEASED
	case image.ReasonKeptUnknownProvenance:
		// The planner's fail-closed bucket AND the executor's re-verification
		// refusals both land here; the latter is precisely UNLINK_FAILED.
		return runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_UNLINK_FAILED
	case image.ReasonKeptYoung:
		return runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_REACHABLE
	}
	return runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_UNSPECIFIED
}

// imageStatusError maps an image-store error onto a gRPC status.
//
// An incomplete root set is FAILED_PRECONDITION, not Internal: nothing is
// broken, the daemon simply refused to reason about deletion from a root set it
// could not enumerate, and the operator can act on that (find the pod dir the
// message names).
func imageStatusError(err error) error {
	if errors.Is(err, image.ErrRootsIncomplete) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, image.ErrFreeSpaceUnknown) {
		return status.Error(codes.Unavailable, err.Error())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return status.Error(codes.Internal, fmt.Sprint(err))
}

// DefaultImageGCInterval is how often the daemon re-checks the store volume for
// disk pressure.
//
// The check itself is one statfs, so the interval is chosen for the RESPONSE
// time an operator would tolerate before pulls start failing, not for the cost
// of asking. It is deliberately not a k8s-style eviction cadence: on a single
// Mac the volume this defends is shared with the kine datastore, and the useful
// property is that headroom is restored well before the control plane notices.
const DefaultImageGCInterval = 5 * time.Minute

// RunImageGC runs the daemon-side image GC on a timer until ctx is done.
//
// It is the TRIGGER — the thing that makes disk-pressure reclaim a daemon
// behavior rather than an RPC nobody calls. Each tick is a full
// ReclaimUnderPressure pass, which no-ops above the free-space floor, so the
// steady-state cost is one statfs per interval.
//
// It NEVER returns an error and never stops on one: a pass that refuses (an
// incomplete root set, an unsamplable volume) is a state to alert on and retry,
// not a reason to stop defending the volume. A pass that panics would take the
// daemon down, so the work stays inside the store's own already-tested surface.
//
// interval <= 0 selects DefaultImageGCInterval. cfg supplies the thresholds and
// the test seams; its Log defaults to the runtime's logger.
func (r *Runtime) RunImageGC(ctx context.Context, interval time.Duration, cfg image.ReclaimConfig) {
	if interval <= 0 {
		interval = DefaultImageGCInterval
	}
	if cfg.Log == nil {
		cfg.Log = r.log
	}
	// Force is a caller-facing operator verb (PruneImages); the timer is the
	// pressure trigger by definition, so it can never be forced.
	cfg.Force = false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rep, err := r.cache.ReclaimUnderPressure(ctx, cfg)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				r.log.Warn("image gc pass refused", "err", err)
				continue
			}
			if rep.Triggered {
				r.log.Info("image gc reclaimed unreferenced image content",
					"removed", len(rep.Removed), "bytes", rep.ReclaimedBytes,
					"free_before", rep.FreeBefore, "free_after", rep.FreeAfter,
					"reached_target", rep.ReachedTarget)
			}
		}
	}
}
