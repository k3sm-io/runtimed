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
	"io"
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

// ListImages returns the images this node has recorded, from the ref->digest
// index (image.FileIndex) — the record of what this daemon pulled or ingested
// and verified.
//
// It listed the per-pod REACHABILITY ROOTS until B198, which made the answer
// wrong in the one direction an operator notices: a freshly `k3sm image
// load`ed archive has no pod behind it, so it had no root, so `image ls`
// showed nothing while `image df` reported its bytes. "What is on this node"
// and "what is some pod still using" are different questions, and roots only
// ever answered the second.
//
// The GC is untouched by this. Cache.Roots remains the sole reachability
// authority; index entries are edges that no enumerator can reach, so an image
// listed here with no pod behind it is still reclaimed by the next prune (see
// image.FileIndex). That is deliberate, not a gap: a listing that pinned
// content would turn every `image ls` row into an un-reclaimable root.
//
// The listing carries no manifest_descriptor: the store commits config and
// layer blobs but never the manifest itself, so there is no digest to report
// for it. Filtering is exact-match on the request's reference and, because the
// index is keyed (reference x platform), on its platform when one is given.
func (s *imagesService) ListImages(ctx context.Context, req *runtimev1.ListImagesRequest) (*runtimev1.ListImagesResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	entries, err := s.rt.index.List(ctx)
	if err != nil {
		return nil, imageStatusError(err)
	}
	want := requestedPlatform(req.GetPlatform())
	out := &runtimev1.ListImagesResponse{}
	for _, e := range entries {
		if req.GetReference() != "" && e.Reference != req.GetReference() {
			continue
		}
		if want != nil && e.Platform != *want {
			continue
		}
		out.Images = append(out.Images, &runtimev1.Image{Manifest: e.Manifest})
	}
	return out, nil
}

// requestedPlatform converts a ListImages platform filter to the normalized
// image.Platform the index is keyed by, or nil when no filter was given.
//
// An all-empty message is "no filter" rather than "the empty platform": the
// proto has no presence for a message's emptiness beyond the message itself,
// and treating a zero-valued filter as a match target would make an unset field
// silently list nothing.
func requestedPlatform(p *runtimev1.Platform) *image.Platform {
	if p == nil || (p.GetOs() == "" && p.GetArchitecture() == "" && p.GetVariant() == "" && p.GetOsVersion() == "") {
		return nil
	}
	n := image.Platform{
		OS:           p.GetOs(),
		Architecture: p.GetArchitecture(),
		Variant:      p.GetVariant(),
		OSVersion:    p.GetOsVersion(),
	}.Normalize()
	return &n
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

// LoadImage ingests a client-streamed image archive — the `k3sm image load` /
// `import` path — and records it under the reference the first frame names.
//
// THE DAEMON IS THE SOLE STORE WRITER here (the M12 images plan, Resolution 8 as
// amended): the client opens the operator's archive, which the daemon generally
// cannot read, and streams the bytes; it never writes the content store itself.
// Everything that decides whether those bytes are admitted lives below this
// method, in image.Loader — every blob is re-hashed against the digest the
// archive's own manifest claims for it, and NOTHING is committed, leased or
// recorded until all of them have.
//
// The metadata rides the FIRST frame only. Per the wire contract a later frame's
// reference/format/digest/size are IGNORED rather than merged: a stream whose
// identity could change halfway through is one where the bytes admitted and the
// bytes described need not be the same archive.
//
// A failure is returned as a gRPC STATUS, not in the response's error field —
// the same posture as every other method on this service, and what the proto
// means by "a digest mismatch fails the call and commits nothing". No
// LoadImageResponse is sent at all in that case.
func (s *imagesService) LoadImage(stream runtimev1.Images_LoadImageServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return status.Error(codes.InvalidArgument,
			"LoadImage: the stream carried no frames; the first frame must name the reference and format")
	}
	if err != nil {
		// A transport/cancellation error from Recv is already a status.
		return err
	}
	res, err := s.rt.loader.Load(ctx, image.LoadRequest{
		Reference: first.GetReference(),
		Format:    first.GetFormat(),
		Digest:    first.GetDigest(),
		Size:      first.GetSize(),
	}, &loadStream{stream: stream, buf: first.GetChunk()})
	if err != nil {
		return loadStatusError(err)
	}
	s.rt.log.Info("ingested image archive",
		"reference", res.Manifest.GetReference(), "digest", res.Descriptor.GetDigest(),
		"platform", res.Platform.String(), "bytes", res.ReceivedBytes)
	return stream.SendAndClose(&runtimev1.LoadImageResponse{
		Images: []*runtimev1.Image{{
			ManifestDescriptor: res.Descriptor,
			Manifest:           res.Manifest,
		}},
		ReceivedBytes: res.ReceivedBytes,
	})
}

// loadStream adapts the LoadImage frame stream to the io.Reader the ingest reads
// the archive through.
//
// It is a plain sequential adapter and holds at most ONE frame's chunk: the
// archive itself is spooled by the ingest, so nothing here needs to buffer more
// than the frame in hand. Chunk boundaries carry no meaning (the proto says so);
// a frame with an empty chunk is skipped rather than read as EOF, so a client
// that sends a keepalive-shaped frame does not truncate its own upload.
type loadStream struct {
	stream runtimev1.Images_LoadImageServer
	buf    []byte
}

// Read returns the next archive bytes, pulling frames as it drains them.
func (l *loadStream) Read(p []byte) (int, error) {
	for len(l.buf) == 0 {
		req, err := l.stream.Recv()
		if err != nil {
			// io.EOF is the client's half-close: the archive is complete. Any
			// other error propagates and aborts the ingest, which commits nothing.
			return 0, err
		}
		l.buf = req.GetChunk()
	}
	n := copy(p, l.buf)
	l.buf = l.buf[n:]
	return n, nil
}

// loadStatusError maps an ingest failure onto a gRPC status.
//
// Every archive-content fault is INVALID_ARGUMENT: the caller supplied an
// archive the daemon will not admit, and the remedy is the caller's (re-export
// it, re-transfer it, split it into one image per archive). That includes
// ErrArchiveUnsupported, which is deliberately NOT reported as UNIMPLEMENTED —
// the RPC is implemented; it is the archive that is out of scope, and an
// UNIMPLEMENTED status is the one a client reads as "this daemon has no image
// service" (see images.proto's skew note).
func loadStatusError(err error) error {
	for _, sentinel := range []error{
		image.ErrLoadReferenceInvalid,
		image.ErrArchiveMalformed,
		image.ErrArchiveUnsupported,
		image.ErrArchiveMultipleImages,
		image.ErrArchiveForeignLayer,
		image.ErrArchiveClaimMismatch,
		image.ErrDigestMismatch,
		image.ErrManifestInconsistent,
		image.ErrBlobTooLarge,
		image.ErrInvalidDigest,
		image.ErrUnsupportedDigestAlgorithm,
	} {
		if errors.Is(err, sentinel) {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	return imageStatusError(err)
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
