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
	"log/slog"
	"path/filepath"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	artifactv1 "k3sm.io/apis/artifact/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
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
// The store holds no user names to remove either: it is an internal pull
// cache, and a user image's name lives in the cluster registry, where `k3sm
// image untag` removes it. A caller wanting bytes back calls PruneImages, which
// re-derives reachability first.
func (s *imagesService) RemoveImage(context.Context, *runtimev1.RemoveImageRequest) (*runtimev1.RemoveImageResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"RemoveImage: this node's image store is an internal pull cache with no user names to remove; "+
			"user images live in the cluster registry, where `k3sm image untag` removes a name. "+
			"PruneImages reclaims cache content no pod uses.")
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
		Force:        true,
		DryRun:       req.GetDryRun(),
		Log:          s.rt.log,
		UntrackedPod: s.rt.podUntracked,
		SweepDerived: s.rt.viewSweeper(),
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

// LoadImage is not served: the node's image store is an internal pull cache,
// and an archive is ingested into the cluster registry instead (`k3sm image
// load` / `import` upload it there as the invoking user, then warm this cache
// through PullImage). The RPC stays on the wire, deprecated, for skew.
func (s *imagesService) LoadImage(runtimev1.Images_LoadImageServer) error {
	return status.Error(codes.Unimplemented,
		"LoadImage: this node's image store is an internal pull cache; "+
			"`k3sm image load` and `k3sm image import` ingest an archive into the cluster registry instead")
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
// PROVENANCE. A pull is a cache warm and records the reference -> digest index
// EDGE (inside Pull) and NO operator root, whatever cache_only says: user names
// live in the cluster registry, so nothing in this store names a pulled image,
// and prune reclaims it once no pod uses it. cache_only is therefore the
// behavior of every pull, kept on the wire for skew. A pull adds no root and
// removes none: a root an older daemon recorded for the same reference is left
// as it is.
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
	// Nothing names the pulled blobs, so they are reclaimable the moment the
	// lease goes; that is the cache contract, not a window.
	res.Lease.Release()
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

// TagImage is not served: the node's image store is an internal pull cache
// that holds no user names, so a tag is recorded in the cluster registry
// (`k3sm image tag`). The RPC stays on the wire, deprecated, for skew.
func (s *imagesService) TagImage(context.Context, *runtimev1.TagImageRequest) (*runtimev1.TagImageResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"TagImage: this node's image store is an internal pull cache; "+
			"`k3sm image tag` tags an image in the cluster registry instead")
}

// UntagImage is not served, for the reason TagImage is not: user names live in
// the cluster registry (`k3sm image untag`). The RPC stays on the wire,
// deprecated, for skew.
func (s *imagesService) UntagImage(context.Context, *runtimev1.UntagImageRequest) (*runtimev1.UntagImageResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"UntagImage: this node's image store is an internal pull cache; "+
			"`k3sm image untag` removes a name from the cluster registry instead")
}

// InspectImage reports what the store knows about one image — the `docker
// inspect` analog over the pull cache.
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
	cfg.UntrackedPod = r.podUntracked
	cfg.SweepDerived = r.viewSweeper()
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
					"bytes_by_class", rep.ReclaimedByClass,
					"free_before", rep.FreeBefore, "free_after", rep.FreeAfter,
					"reached_target", rep.ReachedTarget)
			}
		}
	}
}

// maxConcurrentArtifactPulls bounds PullArtifact RPCs in flight. Each holds a
// manifest (up to 4 MiB) and drives up to two layer transfers, and the caller
// is the local socket, so a small bound keeps memory and connection use flat;
// excess callers wait for a slot under their own deadline.
const maxConcurrentArtifactPulls = 4

// maxArtifactStatusBytes bounds an error rendered into a PullArtifact status:
// the message carries registry text and travels into Pod Events.
const maxArtifactStatusBytes = 1024

// artifactStatus renders err bounded and ASCII-quoted for a status message.
func artifactStatus(c codes.Code, err error) error {
	return status.Error(c, image.QuoteBounded(err.Error(), maxArtifactStatusBytes))
}

// ArtifactView returns the read-only view of the recorded artifact
// manifestDigest restricted to paths (every file when empty), building it when
// absent. It is the entry point the mount path uses; see artifact.Views.
func (r *Runtime) ArtifactView(ctx context.Context, manifestDigest string, paths []string) (string, error) {
	if r.views == nil {
		return "", fmt.Errorf("artifact views unavailable: %w", r.viewsErr)
	}
	return r.views.View(ctx, manifestDigest, paths)
}

// viewSweeper is the image prune's hook into the artifact views: it removes
// the views of manifests no record names (artifact.Views.SweepOrphans). It is
// passed in here, from the wiring, because pkg/image cannot import
// pkg/artifact. Nil when views are disabled.
func (r *Runtime) viewSweeper() func(context.Context) error {
	if r.views == nil {
		return nil
	}
	return r.views.SweepOrphans
}

// newArtifactPuller builds the daemon's own artifact puller over the same cache
// and index the image puller uses, fetching only from the flat registry's
// canonical host through that registry's own transport.
func newArtifactPuller(cache *image.Cache, index *image.FileIndex, flat image.FlatRegistry, log *slog.Logger) (*artifact.Puller, error) {
	tr, plain, err := image.ArtifactTransport(flat)
	if err != nil {
		return nil, err
	}
	return artifact.New(artifact.Config{
		RegistryHost: flat.Host,
		// On the cache volume, so committing a partial is a same-volume copy; denied
		// to pods like every other daemon-private tree.
		PartialDir: filepath.Join(cache.Root(), sandbox.ArtifactPartialSubdir),
		StorePath:  cache.Root(),
		Log:        log,
	}, artifact.Deps{
		Blobs: cache, Leases: cache, Reclaimer: cache, Index: index,
		Fetcher: &artifact.RegistryFetcher{Transport: tr, PlainHTTP: plain},
	})
}

// PullArtifact fetches a platform-less OCI artifact from the cluster registry
// into the node cache (images.proto). It is idempotent and resumable; see
// pkg/artifact for every fail-closed rule. Unlike an image's, the blobs stay
// after the call returns: the artifact record is a GC root until it is removed
// (artifact.Views.Forget).
//
// pull_policy is carried on the wire but not consulted yet: every call resolves
// the manifest, and only the layers not already cached are fetched.
func (s *imagesService) PullArtifact(ctx context.Context, req *runtimev1.PullArtifactRequest) (*runtimev1.PullArtifactResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	ref := req.GetReference()
	if err := image.ValidateReference(ref); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := artifactv1.AllowSetFor(req.GetArtifactPolicy()); err != nil {
		return nil, artifactStatus(codes.InvalidArgument, err)
	}
	if s.rt.artifacts == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"artifact pull refused: this node has no cluster registry configured")
	}
	// The host is checked BEFORE any credential is resolved, so naming a
	// foreign registry can never make the daemon read a Secret.
	if err := s.rt.artifacts.CheckHost(ref); err != nil {
		return nil, artifactStatusError(err)
	}
	select {
	case s.rt.artifactSem <- struct{}{}:
		defer func() { <-s.rt.artifactSem }()
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	cred, err := s.rt.artifactCredential(ctx, req)
	if err != nil {
		return nil, artifactStatus(codes.FailedPrecondition, err)
	}
	res, err := s.rt.artifacts.PullArtifact(ctx, ref, cred, req.GetArtifactPolicy(), req.GetPaths())
	if err != nil {
		return nil, artifactStatusError(err)
	}
	res.Lease.Release()
	s.rt.log.Info("pulled artifact", "reference", ref, "digest", res.ManifestDigest,
		"type", res.ArtifactType, "layers", len(res.LayerDigests), "fetched", res.Fetched)
	return &runtimev1.PullArtifactResponse{
		ManifestDigest: res.ManifestDigest,
		LayerDigests:   res.LayerDigests,
	}, nil
}

// artifactCredential resolves the request's pull credential through the same
// CredentialResolver seam, and under the same disclosure rules, as a pod's
// image pull (pullCredential).
func (r *Runtime) artifactCredential(ctx context.Context, req *runtimev1.PullArtifactRequest) (*image.RegistryCredential, error) {
	return r.pullCredential(ctx, &runtimev1.PodBox{
		Namespace:        req.GetNamespace(),
		ImagePullSecrets: req.GetImagePullSecrets(),
	}, req.GetReference())
}

// artifactStatusError maps an artifact pull failure onto a gRPC status. A
// refusal of what the request asked for is INVALID_ARGUMENT, a host other than
// the cluster registry PERMISSION_DENIED, an artifact this node will not accept
// FAILED_PRECONDITION, a short volume RESOURCE_EXHAUSTED, bytes that fail their
// digest DATA_LOSS and an interrupted transfer UNAVAILABLE (a retry resumes it).
func artifactStatusError(err error) error {
	switch {
	case errors.Is(err, artifact.ErrNotClusterRegistry):
		return artifactStatus(codes.PermissionDenied, err)
	case errors.Is(err, artifact.ErrInsufficientSpace):
		return artifactStatus(codes.ResourceExhausted, err)
	case errors.Is(err, image.ErrDigestMismatch), errors.Is(err, artifact.ErrManifestDigest):
		return artifactStatus(codes.DataLoss, err)
	case errors.Is(err, artifact.ErrBlobTransfer):
		return artifactStatus(codes.Unavailable, err)
	case errors.Is(err, artifact.ErrIndexRefused), errors.Is(err, artifact.ErrImageNotArtifact),
		errors.Is(err, artifact.ErrTypeRefused), errors.Is(err, artifact.ErrTarLayer),
		errors.Is(err, artifact.ErrLayerTypeRefused), errors.Is(err, artifact.ErrTooManyLayers),
		errors.Is(err, artifact.ErrNoLayers), errors.Is(err, artifact.ErrLayerPath),
		errors.Is(err, artifact.ErrManifestTooLarge), errors.Is(err, artifact.ErrManifestInvalid),
		errors.Is(err, artifact.ErrPathNotInArtifact), errors.Is(err, image.ErrBlobTooLarge),
		errors.Is(err, artifact.ErrSizeCap), errors.Is(err, artifact.ErrSizeOverflow),
		errors.Is(err, artifact.ErrVariantNotFound), errors.Is(err, artifact.ErrVariantAmbiguous),
		errors.Is(err, artifact.ErrVariantOnManifest):
		return artifactStatus(codes.FailedPrecondition, err)
	case errors.Is(err, artifact.ErrInvalidReference), errors.Is(err, artifactv1.ErrUnknownPolicy),
		errors.Is(err, artifact.ErrVariantInvalid),
		isPathRuleError(err):
		return artifactStatus(codes.InvalidArgument, err)
	}
	if errors.Is(err, image.ErrFreeSpaceUnknown) {
		return artifactStatus(codes.Unavailable, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return artifactStatus(codes.Internal, err)
}

// isPathRuleError reports a requested-path refusal from artifactv1 (a layer
// path refusal is caught earlier, under artifact.ErrLayerPath).
func isPathRuleError(err error) bool {
	for _, e := range []error{
		artifactv1.ErrEmptyPath, artifactv1.ErrAbsolutePath, artifactv1.ErrPathCharset,
		artifactv1.ErrPathComponent, artifactv1.ErrReservedComponent, artifactv1.ErrPathTooLong,
		artifactv1.ErrPathDepth, artifactv1.ErrComponentTooLong, artifactv1.ErrCodeFile,
		artifactv1.ErrDuplicatePath, artifactv1.ErrCaseCollision, artifactv1.ErrFileDirConflict,
		artifactv1.ErrTooManyPaths,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
