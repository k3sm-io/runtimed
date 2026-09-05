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

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// imagesService serves the Images RPCs (apis/runtime/v1/images.proto) over the
// same *Runtime — and, critically, the same grpc.Server and therefore the same
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
// It listed the per-pod REACHABILITY ROOTS until that was fixed, which made
// the answer wrong in the one direction an operator notices: a freshly `k3sm image
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
// Each row carries the manifest_descriptor the index RETAINED — the image id an
// operator reads — and nothing re-derived: the store commits config and layer
// blobs but never the manifest, so a listing that hashed something here would be
// reporting an id no registry ever served. An entry written before the index
// retained manifests has no descriptor, and the row then omits it rather than
// inventing one (see image.IndexEntry.Descriptor).
//
// Filtering is exact-match on the request's reference and, because the index is
// keyed (reference x platform), on its platform when one is given.
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
		out.Images = append(out.Images, &runtimev1.Image{
			ManifestDescriptor: e.Descriptor,
			Manifest:           e.Manifest,
		})
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
// A request shaped as "remove this image" does not say WHICH root the caller
// owns, and the roots on this node are not all alike: most are per-POD records
// the daemon authored, and dropping one would assert that a pod no longer
// references content it is still running on — the exact liveness violation the
// image GC exists to make impossible.
//
// UntagImage is the removal that CAN be granted, and its existence is why this
// refusal stands rather than being softened: it names exactly one operator-owned
// (reference x platform) entry, so it removes a root whose owner asked for it
// and can touch no pod-owned one. A caller wanting bytes back calls PruneImages,
// which re-derives reachability first.
func (s *imagesService) RemoveImage(context.Context, *runtimev1.RemoveImageRequest) (*runtimev1.RemoveImageResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"RemoveImage: this node's image roots are per-pod records, not operator untags; "+
			"removing one would unroot a live pod's content. Use PruneImages, which re-derives reachability.")
}

// PruneImages deletes unreferenced blobs, honoring the request's dry_run.
//
// It runs the same code path as the daemon's disk-pressure reclaim, forced past
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
// the DAEMON IS the sole STORE WRITER here: the client opens the operator's
// archive, which the daemon generally
// cannot read, and streams the bytes; it never writes the content store itself.
// Everything that decides whether those bytes are admitted lives below this
// method, in image.Loader — every blob is re-hashed against the digest the
// archive's own manifest claims for it, and nothing is committed, leased or
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
// It is a plain sequential adapter and holds at most one frame's chunk: the
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
// ErrArchiveUnsupported, which is deliberately not reported as unimplemented —
// the RPC is implemented; it is the archive that is out of scope, and an
// unimplemented status is the one a client reads as "this daemon has no image
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
		// The planner's fail-closed bucket and the executor's re-verification
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

// PullImage warms the local store for a reference, through the daemon's OWN
// puller — the same code path a pod-driven pull takes.
//
// Reusing that path is the contract, not an implementation convenience: it is
// what makes every blob re-hashed against its manifest descriptor before the
// lease commits, keeps the disk-pressure gate in force, and records the
// resulting reference in the one image index pods resolve against. A second
// fetch path here would have forked the daemon's verification story, and the
// forked half is the one nobody re-reads.
//
// It pulls ANONYMOUSLY. PullImageRequest carries no credential field, and that
// is deliberate on the wire: pod pulls take their imagePullSecret through the
// provider's credential seam, which resolves a Secret this operator-CLI request
// has no reference to. A private-registry CLI pull is a credential-source
// design, not a field this method can invent.
//
// PROVENANCE. A successful pull records two things, in this order: the
// reference -> digest index EDGE (inside Pull), and then an OPERATOR ROOT over
// that (reference x platform). The root is
// why a pulled-but-unused image survives PruneImages: it stays reachable until
// the operator removes the name with UntagImage. The root is recorded BEFORE the
// pull's lease is released, never after, for the same reason the pod path
// records its root first — releasing first reopens the window between "the blob
// is on disk" and "something names it", which is exactly the window a concurrent
// reclaim deletes into.
func (s *imagesService) PullImage(ctx context.Context, req *runtimev1.PullImageRequest) (*runtimev1.PullImageResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	ref := req.GetReference()
	if err := image.ValidateReference(ref); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	policy, err := operatorPullPolicy(req.GetPlatform())
	if err != nil {
		return nil, err
	}
	res, err := s.rt.puller.Pull(ctx, ref, nil, policy, req.GetPolicy())
	if err != nil {
		return nil, pullStatusError(err)
	}
	rootErr := s.rt.recordOperatorImage(ref, res.Platform, res.Manifest)
	// Release only after the root is recorded (or has failed, in which case
	// nothing is named and the blobs are correctly reclaimable).
	res.Lease.Release()
	if rootErr != nil {
		return nil, imageStatusError(rootErr)
	}
	s.rt.log.Info("pulled image on operator request",
		"reference", ref, "digest", res.Descriptor.GetDigest(),
		"platform", res.Platform.String(), "already_present", res.CacheHit)
	return &runtimev1.PullImageResponse{
		Image: &runtimev1.Image{
			ManifestDescriptor: res.Descriptor,
			Manifest:           res.Manifest,
		},
		AlreadyPresent: res.CacheHit,
	}, nil
}

// operatorPullPolicy maps the platform an operator named onto the image platform
// policy the puller takes.
//
// UNSET is the daemon's own host platform — the native spine's candidates,
// which is the same default a pod-driven pull takes and is never "every
// platform". A NAMED platform is an OVERRIDE: it pins the pull to exactly that
// manifest with no fallback, which is what an operator warming the store for a
// specific spine is asking for.
//
// A named platform is NOT an execution claim, and the daemon deliberately does
// not refuse one this host cannot run. Warming linux/arm64 on a Mac is the
// ordinary vm case; warming an amd64 image is the ordinary Rosetta case. What a
// node may EXECUTE is decided per pod, at pull time, from the pod's resolved
// sandbox backend (image.PlatformPolicy) — that decision is untouched here, and
// the store is keyed (reference x platform) precisely so warmed bytes for one
// spine can never be served to another.
func operatorPullPolicy(p *runtimev1.Platform) (image.PlatformPolicy, error) {
	want := requestedPlatform(p)
	if want == nil {
		// The native spine's own candidates — the daemon's host platform.
		return image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}, nil
	}
	amd64 := want.Architecture == "amd64"
	switch want.OS {
	case "darwin":
		return image.PlatformPolicy{
			Backend:     runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
			HostRosetta: amd64,
			Override:    want,
		}, nil
	case "linux":
		return image.PlatformPolicy{
			Backend:      runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
			GuestRosetta: amd64,
			Override:     want,
		}, nil
	default:
		return image.PlatformPolicy{}, status.Errorf(codes.InvalidArgument,
			"PullImage: platform os %q is not one this node stores images for (darwin, linux)", want.OS)
	}
}

// TagImage records an ADDITIONAL (reference x platform) entry for content the
// store already holds.
//
// It contacts no registry and writes no blob: everything it does is index work
// plus one operator root. The target is named by DIGEST and never by another
// tag, because roots are digest-pinned — resolving a mutable name here would let
// a concurrent re-pull decide what the new tag ends up meaning.
//
// It never RE-POINTS an existing entry. An existing (reference x platform) key
// that resolves elsewhere is FAILED_PRECONDITION, because re-pointing would drop
// the old edge, which is a root removal wearing a tag's clothes; the operator
// asks for that in two explicit steps, UntagImage then TagImage. An existing key
// that already resolves to this digest is the idempotent OK, and — per the wire
// contract's "nothing was written" — it writes nothing, not even a root.
//
// ORDERING. The edge is written first and the operator root second. The reverse
// order has an unrecoverable failure mode: a root whose name never landed pins
// content that no UntagImage can ever name, so it could never be released. This
// order's failure mode is a name with no root, which is merely the state every
// `k3sm image load`ed image is already in (listed, and reclaim-eligible), and it
// is repaired by untagging and re-tagging.
func (s *imagesService) TagImage(ctx context.Context, req *runtimev1.TagImageRequest) (*runtimev1.TagImageResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	ref := req.GetReference()
	if err := image.ValidateReference(ref); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	digest := req.GetDigest()
	src, err := s.rt.index.ResolveDigest(ctx, digest)
	if err != nil {
		return nil, indexStatusError(err)
	}
	target := src.Platform
	if p := requestedPlatform(req.GetPlatform()); p != nil {
		target = *p
	}
	existing, ok, err := s.rt.index.Get(ctx, ref, target)
	if err != nil {
		return nil, indexStatusError(err)
	}
	if ok {
		if existing.Descriptor.GetDigest() != digest {
			return nil, status.Errorf(codes.FailedPrecondition,
				"TagImage: %s for %s already resolves to %s; untag it first — this verb never re-points an entry",
				ref, target, existing.Descriptor.GetDigest())
		}
		return &runtimev1.TagImageResponse{
			Image:          &runtimev1.Image{ManifestDescriptor: existing.Descriptor, Manifest: existing.Manifest},
			AlreadyPresent: true,
		}, nil
	}

	// The manifest is copied, not shared, and only its reference changes: the
	// bytes and the digest describe content, which a new name cannot alter.
	mfst, ok := proto.Clone(src.Manifest).(*runtimev1.ImageManifest)
	if !ok {
		return nil, status.Error(codes.Internal, "TagImage: cloning the recorded manifest produced the wrong type")
	}
	mfst.Reference = ref
	entry := image.IndexEntry{
		Reference:   ref,
		Platform:    target,
		Manifest:    mfst,
		Descriptor:  src.Descriptor,
		ManifestRaw: src.ManifestRaw,
	}
	if err := s.rt.index.Record(ctx, entry); err != nil {
		return nil, indexStatusError(err)
	}
	if err := s.rt.recordOperatorImage(ref, target, mfst); err != nil {
		return nil, imageStatusError(err)
	}
	s.rt.log.Info("tagged image", "reference", ref, "platform", target.String(), "digest", digest)
	return &runtimev1.TagImageResponse{
		Image: &runtimev1.Image{ManifestDescriptor: entry.Descriptor, Manifest: entry.Manifest},
	}, nil
}

// UntagImage removes ONE (reference x platform) index entry and the operator
// root that entry carried.
//
// This is the provenance model's sanctioned EXPLICIT UNTAG: an authorized,
// local root removal the operator asked for by
// name — which is exactly what RemoveImage cannot be, since a request shaped as
// "remove this image" does not say which root the caller owns, and this node's
// other roots are per-pod records the daemon authored.
//
// It removes a NAME, not bytes. No blob is unlinked; content is reclaimed only
// by PruneImages, which re-derives reachability first. So untagging a name a
// live pod's own root still pins leaves that content reachable and the pod
// unharmed.
//
// It is deliberately NOT idempotent-by-silence: an absent entry is NOT_FOUND,
// because the caller asked to remove a specific name. An unset platform on a
// reference with several entries is FAILED_PRECONDITION and removes nothing — an
// ambiguous untag is never a guess — as is a digest pin the entry does not
// satisfy, which is the guard against a concurrent re-pull moving the entry
// between the caller's read and this write.
//
// ORDERING is the mirror of TagImage's and rests on the same argument: the root
// goes first, the name second. Failing between them leaves a named entry with no
// root — reclaim-eligible but still nameable, so a repeat untag completes the
// job. The reverse would strand a root no verb could ever name again.
func (s *imagesService) UntagImage(ctx context.Context, req *runtimev1.UntagImageRequest) (*runtimev1.UntagImageResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	ref := req.GetReference()
	if ref == "" {
		return nil, status.Error(codes.InvalidArgument, "UntagImage: reference is required")
	}
	entry, err := s.rt.index.Resolve(ctx, ref, requestedPlatform(req.GetPlatform()))
	if err != nil {
		return nil, indexStatusError(err)
	}
	if want := req.GetDigest(); want != "" && entry.Descriptor.GetDigest() != want {
		return nil, status.Errorf(codes.FailedPrecondition,
			"UntagImage: %s for %s resolves to %s, not the pinned %s; nothing was removed",
			ref, entry.Platform, entry.Descriptor.GetDigest(), want)
	}
	if _, err := s.rt.cache.RemoveOperatorImage(ref, entry.Platform); err != nil {
		return nil, imageStatusError(err)
	}
	removed, err := s.rt.index.Remove(ctx, ref, entry.Platform)
	if err != nil {
		return nil, indexStatusError(err)
	}
	if !removed {
		// Raced with another removal between the resolve and the write. The
		// caller's name is gone either way, but it was not this call that removed
		// it, and NOT_FOUND is what the wire contract says about an entry that is
		// not there.
		return nil, status.Errorf(codes.NotFound, "UntagImage: %s for %s is not in the local index", ref, entry.Platform)
	}
	s.rt.log.Info("untagged image",
		"reference", ref, "platform", entry.Platform.String(), "digest", entry.Descriptor.GetDigest())
	return &runtimev1.UntagImageResponse{
		Removed: &runtimev1.Image{ManifestDescriptor: entry.Descriptor, Manifest: entry.Manifest},
	}, nil
}

// InspectImage reports what the store knows about one image — the `docker
// inspect` analog and the read side of the tag verbs.
//
// STRICTLY LOCAL and strictly read-only: it resolves nothing against a registry,
// takes no lease, and records no root, so it can never make content reachable.
// Every fact it returns is read out of the index entry and the config blob.
//
// The target is a (reference x platform) key or a manifest digest. Setting both
// is INVALID_ARGUMENT rather than a precedence rule nobody can remember, and so
// is setting neither.
//
// Absent fields are absent FACTS. A config the store no longer holds — the
// ordinary state after a prune reclaimed an unrooted image's blobs — is reported
// by omitting the config, not by synthesizing an empty one, because the wire
// contract makes every field independently optional for exactly this reason.
func (s *imagesService) InspectImage(ctx context.Context, req *runtimev1.InspectImageRequest) (*runtimev1.InspectImageResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	entry, err := s.resolveTarget(ctx, "InspectImage", req.GetReference(), req.GetDigest(), req.GetPlatform())
	if err != nil {
		return nil, err
	}
	out := &runtimev1.InspectImageResponse{
		Image:          &runtimev1.Image{ManifestDescriptor: entry.Descriptor, Manifest: entry.Manifest},
		TotalSizeBytes: uint64(max(entry.TotalSize(), 0)),
	}
	cfg, ok, err := s.rt.cache.ImageConfig(entry)
	if err != nil {
		return nil, imageStatusError(err)
	}
	if ok {
		out.Config = imageConfigProto(cfg)
	}
	return out, nil
}

// imageConfigProto reports a decoded OCI image config on the wire.
//
// It is a REPORT of what the image declares and never an input: nothing here is
// applied by writing it back, and the runtime's own merge of Entrypoint/Cmd with
// a container's command/args is unchanged by this conversion existing.
//
// config.platform is the platform the CONFIG BLOB declares, which is not the
// same fact as the manifest's resolved platform — they agree on a well-formed
// image, and the wire keeps them separate so a disagreement is visible.
func imageConfigProto(cfg *ggcrv1.ConfigFile) *runtimev1.ImageConfig {
	if cfg == nil {
		return nil
	}
	out := &runtimev1.ImageConfig{
		Entrypoint: cfg.Config.Entrypoint,
		Cmd:        cfg.Config.Cmd,
		Env:        cfg.Config.Env,
		User:       cfg.Config.User,
		WorkingDir: cfg.Config.WorkingDir,
		Labels:     cfg.Config.Labels,
	}
	if cfg.OS != "" || cfg.Architecture != "" || cfg.Variant != "" || cfg.OSVersion != "" {
		out.Platform = &runtimev1.Platform{
			Os:           cfg.OS,
			Architecture: cfg.Architecture,
			Variant:      cfg.Variant,
			OsVersion:    cfg.OSVersion,
		}
	}
	// A zero Created is "the image declares no creation time", which the wire
	// says by omitting the field — never by reporting the epoch as if the image
	// had claimed it.
	if !cfg.Created.Time.IsZero() {
		out.Created = timestamppb.New(cfg.Created.Time)
	}
	return out
}

// saveChunkBytes is the archive slice one SaveImage frame carries.
//
// Chunk boundaries carry no meaning (the proto says so), so the size is chosen
// only against the transport: comfortably under gRPC's 4 MiB default receive
// limit with room for framing, and large enough that a multi-hundred-megabyte
// image is not thousands of round trips.
const saveChunkBytes = 256 << 10

// SaveImage streams one image OUT of the store as a tarred OCI image layout —
// the `docker save` analog and the exact inverse of LoadImage's direction.
//
// The framing mirrors LoadImage in reverse: chunk frames carrying bytes and
// nothing else, then exactly ONE terminal frame that carries no chunk and
// instead reports the exported manifest digest and the byte count the server
// sent. A client that reaches the end of the stream without a terminal frame has
// a truncated archive and must discard it — which is why a mid-transfer failure
// is reported BOTH as a terminal frame carrying the error and as the RPC's own
// status: a client must never have to infer failure from a stream that merely
// stopped.
//
// Everything the daemon can know up front is checked up front, before a single
// chunk goes out: the format, the target's existence, that the entry retains its
// manifest bytes, and that every blob it names is still in the store. A caller
// therefore receives bytes only for an export the daemon believes it can finish.
//
// Export takes no lease, records no root and unlinks nothing, and the client is
// the sole writer of the operator's file — the mirror of LoadImage's rule that
// the daemon is the sole writer of the store.
func (s *imagesService) SaveImage(req *runtimev1.SaveImageRequest, stream runtimev1.Images_SaveImageServer) error {
	ctx := stream.Context()
	switch req.GetFormat() {
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_UNSPECIFIED,
		runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT:
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE:
		// Nameable on the wire, and v1 emits it from nowhere: the OCI layout is
		// the format this store can write verbatim from the manifest it retained,
		// while a docker-save tar would have to synthesize a manifest.json and a
		// repositories map the store never recorded.
		return status.Error(codes.Unimplemented,
			"SaveImage: this daemon exports LOAD_IMAGE_FORMAT_OCI_LAYOUT only")
	default:
		return status.Errorf(codes.InvalidArgument, "SaveImage: unknown archive format %d", int32(req.GetFormat()))
	}
	entry, err := s.resolveTarget(ctx, "SaveImage", req.GetReference(), req.GetDigest(), req.GetPlatform())
	if err != nil {
		return err
	}

	out := &saveStream{stream: stream}
	if err := s.rt.cache.ExportOCILayout(ctx, out, entry); err != nil {
		return s.failSave(stream, err)
	}
	if err := out.flush(); err != nil {
		return s.failSave(stream, err)
	}
	s.rt.log.Info("exported image archive",
		"reference", entry.Reference, "platform", entry.Platform.String(),
		"digest", entry.Descriptor.GetDigest(), "bytes", out.sent)
	return stream.Send(&runtimev1.SaveImageResponse{
		Digest:    entry.Descriptor.GetDigest(),
		SentBytes: out.sent,
	})
}

// failSave reports an export failure the way the wire contract requires: a
// terminal frame carrying the status and no chunk, AND the same status as the
// RPC's own error.
//
// Both, not either. The frame is what lets a client that has already received
// chunks distinguish a truncated archive from a complete one without inspecting
// its own byte count; the RPC status is what makes the call unambiguously a
// failure to every ordinary client. If the frame cannot be sent — the usual
// reason being that the transport is what failed — the status still stands.
func (s *imagesService) failSave(stream runtimev1.Images_SaveImageServer, err error) error {
	st := exportStatus(err)
	if serr := stream.Send(&runtimev1.SaveImageResponse{Error: st.Proto()}); serr != nil {
		s.rt.log.Warn("could not send the SaveImage terminal error frame", "err", serr)
	}
	return st.Err()
}

// saveStream turns the byte stream an export writes into SaveImage chunk frames.
//
// It buffers to saveChunkBytes so the frame count follows the transport's
// preference rather than the exporter's write sizes (a tar writer emits a header
// and a body as separate writes, and one frame per write would be pathological
// for a many-layer image). flush must be called before the terminal frame, or
// the tail of the archive is never sent.
type saveStream struct {
	stream runtimev1.Images_SaveImageServer
	buf    []byte
	sent   int64
}

// Write buffers p, emitting a frame whenever a full chunk is available.
func (s *saveStream) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		room := saveChunkBytes - len(s.buf)
		take := min(room, len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		if len(s.buf) == saveChunkBytes {
			if err := s.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

// flush emits whatever is buffered, if anything.
func (s *saveStream) flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	if err := s.stream.Send(&runtimev1.SaveImageResponse{Chunk: s.buf}); err != nil {
		return err
	}
	s.sent += int64(len(s.buf))
	s.buf = s.buf[:0]
	return nil
}

// resolveTarget resolves the (reference x platform) or digest one read-only verb
// names, applying the wire contract's exactly-one rule.
//
// It is shared by InspectImage and SaveImage because their targeting clauses are
// the same clause; two copies would drift on the first divergent edit, and the
// divergence a caller would notice is precisely the one nobody tests — which of
// reference and digest wins when both are set.
func (s *imagesService) resolveTarget(ctx context.Context, verb, ref, digest string, platform *runtimev1.Platform) (image.IndexEntry, error) {
	switch {
	case ref != "" && digest != "":
		return image.IndexEntry{}, status.Errorf(codes.InvalidArgument,
			"%s: set exactly one of reference and digest, not both", verb)
	case ref == "" && digest == "":
		return image.IndexEntry{}, status.Errorf(codes.InvalidArgument,
			"%s: a reference or a digest is required", verb)
	case digest != "":
		// A digest names one manifest, so the request's platform is ignored — the
		// wire contract says so, and honoring it would let a caller ask for
		// content that a digest has already fully determined.
		e, err := s.rt.index.ResolveDigest(ctx, digest)
		if err != nil {
			return image.IndexEntry{}, indexStatusError(err)
		}
		return e, nil
	default:
		e, err := s.rt.index.Resolve(ctx, ref, requestedPlatform(platform))
		if err != nil {
			return image.IndexEntry{}, indexStatusError(err)
		}
		return e, nil
	}
}

// recordOperatorImage records the operator-owned reachability root for
// (ref x platform), from the manifest the pull or the tag resolved.
//
// It is the operator-side twin of recordPodImage and shares its shape
// deliberately: a root names the CONFIG and LAYER digests only, because those
// are the only things the content-addressed store holds. What differs is who may
// remove it — a pod's root goes when the pod dir goes, an operator's only when
// the operator untags the name (see Cache.RecordOperatorImage).
func (r *Runtime) recordOperatorImage(ref string, platform image.Platform, mfst *runtimev1.ImageManifest) error {
	root := image.ImageRoot{Reference: ref, Config: mfst.GetConfig().GetDigest()}
	for _, l := range mfst.GetLayers() {
		root.Layers = append(root.Layers, l.GetDigest())
	}
	if err := r.cache.RecordOperatorImage(ref, platform, root); err != nil {
		return fmt.Errorf("record operator image root for %q: %w", ref, err)
	}
	return nil
}

// pullStatusError maps a pull failure onto a gRPC status.
//
// It maps the DECIDED verdicts only — the sentinels the pull path returns as
// conclusions rather than as passed-through faults. Classifying a registry's own
// failures (unauthorized, rate-limited, transient) is the kubelet pull-failure
// taxonomy, a separate deliverable that consumes these same sentinels; until it
// lands, an unclassified fault is Internal rather than a guess dressed as a
// code, because a wrong code is acted on and an honest Internal is read.
func pullStatusError(err error) error {
	switch {
	case errors.Is(err, image.ErrImageNotPresent):
		// The reference is absent and the policy forbids fetching it. No registry
		// round trip was made, so NOT_FOUND is a fact about this node.
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, image.ErrPullRefusedDiskPressure):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, image.ErrLoadReferenceInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case image.IsTerminalPlatformError(err):
		// The image has no manifest for the platform asked for. Permanent for
		// this (reference, platform) pair, and the operator can act on it.
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	return imageStatusError(err)
}

// indexStatusError maps an index-resolution failure onto a gRPC status.
//
// The three verdicts are the ones every image verb shares, so they are mapped
// once: a key that is not there is NOT_FOUND; a reference that names several
// platform entries with no platform given is FAILED_PRECONDITION (an ambiguous
// request removed or exported nothing, which is the safe half of the contract);
// and a record this daemon cannot believe is FAILED_PRECONDITION rather than
// Internal, because nothing is broken in the daemon and the operator can act on
// the named entry.
func indexStatusError(err error) error {
	switch {
	case errors.Is(err, image.ErrIndexEntryNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, image.ErrIndexEntryAmbiguous), errors.Is(err, image.ErrIndexDigestMismatch):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, image.ErrInvalidDigest), errors.Is(err, image.ErrUnsupportedDigestAlgorithm),
		errors.Is(err, image.ErrLoadReferenceInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, image.ErrIndexEntryCorrupt), errors.Is(err, image.ErrIndexNotOwned):
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	return imageStatusError(err)
}

// exportStatus maps an export failure onto the status carried by BOTH the
// terminal frame and the RPC.
//
// An entry that retains no manifest, and an entry whose blobs the store no
// longer holds, are both FAILED_PRECONDITION: the request is well-formed and the
// image is named, but the store is not in a state that can satisfy it, and in
// both cases the operator's remedy is the same one sentence — re-pull or re-load
// the reference.
func exportStatus(err error) *status.Status {
	switch {
	case errors.Is(err, image.ErrManifestNotRetained), errors.Is(err, image.ErrExportIncomplete),
		errors.Is(err, image.ErrManifestInconsistent):
		return status.New(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err)
	}
	if st, ok := status.FromError(err); ok {
		return st
	}
	return status.New(codes.Internal, fmt.Sprint(err))
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
// It never returns an error and never stops on one: a pass that refuses (an
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
