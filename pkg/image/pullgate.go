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

package image

import (
	"context"
	"errors"
	"fmt"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	"k3sm.io/runtimed/pkg/registryfetch"
)

// DefaultPullRefuseFreeBytes is the free-space floor under which the daemon
// refuses to BEGIN a new fetch. It is absolute bytes, for the same reason the
// reclaim floors are (see DefaultReclaimHighFreeBytes): a percentage of an APFS
// container is fiction when every volume reports the same shared free pool.
//
// why a pull gate exists at all, given that reclaim already runs: reclaim frees
// what nothing references, and on a node whose store is entirely referenced
// there is nothing to free — yet the puller would happily keep streaming layers
// into the remaining bytes. /var/lib/k3sm is shared with KINE'S state.db, so a
// volume the image puller exhausts is a control-plane outage, not a node
// inconvenience. Reclamation and admission are different mechanisms: one gives
// bytes back, the other stops spending them.
//
// why 3 GiB — the value is chosen by its ordering against the two thresholds
// that already exist, not on its own:
//
//	10 GiB  DefaultReclaimTargetFreeBytes  reclaim stops here
//	 5 GiB  DefaultReclaimHighFreeBytes    reclaim STARTS here
//	 3 GiB  DefaultPullRefuseFreeBytes     new pulls are refused here
//	 2 GiB  (the proposed node DiskPressure floor)  the node is tainted here
//
// The ordering is the design: the GC gets a 2 GiB window to reclaim before any
// pod is denied its image, and pull refusal gets a further 1 GiB window to stop
// the bleeding before the node condition flips and the scheduler is told. Each
// mechanism therefore fires before the more disruptive one below it, and a
// single filling volume walks the ladder in that order rather than tripping
// everything at once. A floor placed above the reclaim trigger would invert it —
// pods would be refused images while the GC that would have made room had not
// even run — which is why TestPullRefusesUnderDiskPressure asserts the ordering
// against the reclaim constants by symbol rather than trusting the numbers here.
//
// 3 GiB is a reasoned round number in that window, not a measured one; it is
// the figure most likely to want lab tuning, alongside the DiskPressure floor.
const DefaultPullRefuseFreeBytes uint64 = 3 << 30 // 3 GiB

// ErrPullRefusedDiskPressure reports that a pull was refused before any registry
// round trip because the store volume is at or below its free-space floor
// (DefaultPullRefuseFreeBytes).
//
// It is returned only for a pull that would FETCH. A reference already present
// on this node is still served — presence is answered from the index and the
// blob store and writes nothing — so disk pressure stops the node acquiring new
// content without stranding pods whose content it already has.
//
// Like ErrImageNotPresent it is a plain sentinel, not a classified pull failure:
// the kubelet waiting-reason taxonomy is a separate deliverable that consumes
// this with errors.Is.
var ErrPullRefusedDiskPressure = errors.New("image: refusing to start a pull, the store volume is below its free-space floor")

// PullerOption adjusts a Puller at construction. The cache, fetcher and index
// stay required positional arguments, because each of those chooses where bytes
// COME from and a silent default there is the class of bug NewPuller's doc
// comment refuses. An option is admitted only where the ABSENT state is itself a
// complete, correct configuration:
//
//   - the disk-pressure admission seam (WithPullFloor, WithFreeBytes) is a
//     measurement of this machine, with exactly one correct production
//     implementation (StatfsFreeBytes), and its default fails closed — a real
//     statfs that errors refuses the pull. This is the same treatment
//     ReclaimConfig gives FreeBytes and HighFreeBytes;
//   - the cluster-mirror fallback (WithMirrors) is absent on a single-node
//     cluster, which is not a degraded pull path but the only one there is. It
//     is still not a silent default: the option takes BOTH halves and NewPuller
//     refuses a half-wiring, so a node either states its mirrors or has none;
//   - the logger (WithPullLogger) selects a sink, never a behavior;
//   - the local blob source (WithLocalBlobSource) is absent on every node whose
//     registry does not share the cache's volume, and it cannot change which
//     bytes are committed: a local copy is committed only on a digest match;
//   - the space ledger (WithSpaceLedger) defaults to one private to the puller,
//     which still reserves every pull against the others this puller runs; the
//     daemon shares one with its artifact puller.
type PullerOption func(*Puller)

// WithSpaceLedger has the puller reserve its pulls on l, the ledger the
// daemon also hands its artifact puller, so the two paths cannot overcommit the
// store volume against each other. Nil means a ledger private to this puller.
func WithSpaceLedger(l *SpaceLedger) PullerOption {
	return func(p *Puller) { p.ledger = l }
}

// WithLocalBlobSource has the puller offer each blob to src before fetching it:
// a blob src holds on the cache's volume is cloned and re-hashed
// (Cache.CommitFromLocal) instead of copied over the network. Nil leaves every
// blob fetched, exactly as without the option.
func WithLocalBlobSource(src LocalBlobSource) PullerOption {
	return func(p *Puller) { p.localBlobs = src }
}

// WithRegistryBlobSource pairs a direct blob route with the primary fetcher
// (primary, the counterpart of NewPuller's fetch) and with the cluster-mirror
// fetcher (mirror, the counterpart of WithMirrors' fetch). The production pair
// is RemoteBlobSource and RemoteMirrorBlobSource, matching RemoteFetch and
// RemoteMirrorFetch. Either nil yields no route for that path; the flat
// registry's route needs no option, because its transport is the puller's own.
// The routes are data only: which bytes are committed is unchanged.
func WithRegistryBlobSource(primary BlobSourceFunc, mirror MirrorBlobSourceFunc) PullerOption {
	return func(p *Puller) {
		p.remoteBlobs = primary
		p.mirrorBlobs = mirror
	}
}

// WithPartialStore has the puller keep each layer's received bytes in store
// while it fetches them over the reference's direct blob route
// (WithRegistryBlobSource), so a pull cut mid-layer is resumed by the next one
// with a Range request. Every resumed layer is still re-hashed whole by
// CommitBlob before it is committed. A layer with no route, or a nil store,
// is fetched from byte 0 exactly as without the option.
func WithPartialStore(store *registryfetch.PartialStore) PullerOption {
	return func(p *Puller) { p.partials = store }
}

// WithPullFloor overrides the free-space floor under which new fetches are
// refused. Zero means DefaultPullRefuseFreeBytes.
func WithPullFloor(floorBytes uint64) PullerOption {
	return func(p *Puller) { p.floorBytes = floorBytes }
}

// WithFreeBytes overrides how free space on the store volume is sampled. Nil
// means StatfsFreeBytes. It is the seam below the decision, so the admission
// rule is testable with no syscall — the same seam ReclaimConfig.FreeBytes uses,
// deliberately, so the two mechanisms cannot be tested against different notions
// of "free".
func WithFreeBytes(free FreeBytesFunc) PullerOption {
	return func(p *Puller) { p.freeBytes = free }
}

// WithTotalBytes overrides how the store volume's total capacity is sampled
// for the space reservation. Nil means StatfsTotalBytes.
func WithTotalBytes(total TotalBytesFunc) PullerOption {
	return func(p *Puller) { p.totalBytes = total }
}

// admitFetch decides whether this node may BEGIN acquiring new image content.
//
// It is fail-closed on both axes:
//
//   - below the floor, the pull is refused with the measured and required byte
//     counts in the message, so an operator can tell a full volume from any
//     other pull failure without reproducing it;
//   - an UNSAMPLABLE volume is also refused. A statfs that fails is the first
//     symptom of a volume going bad, which is precisely when writing gigabytes
//     into it on the assumption that it is fine is worst. This mirrors reclaim's
//     posture (ErrFreeSpaceUnknown), and the returned error matches both
//     sentinels so a caller can key on the refusal or on its cause.
//
// It is called at the one choke point every fetching path traverses — after the
// presence decision, immediately before the FetchFunc — so a warm IfNotPresent
// or Never serve is never affected, and no code path can acquire new content
// without passing here.
//
// The gate is an early subset of the reservation check (reserveSpace), which
// is why free space is sampled twice per pull: this one refuses before the
// manifest is fetched, that one once its declared sizes are known.
//
// RECORDED residual, not fixed here: the ingest path (LoadImage and the image-load CLI)
// writes the same store without traversing this function, so an operator
// streaming a tarball can still fill the volume. That path is not a pull and its
// admission is its own item's business.
func (p *Puller) admitFetch(ref string) error {
	floor := p.pullFloor()
	root := p.cache.Root()
	avail, err := p.sampleFree()(root)
	if err != nil {
		return fmt.Errorf("pull %q: %w: %w on %s: %v", ref, ErrPullRefusedDiskPressure, ErrFreeSpaceUnknown, root, err)
	}
	if avail < floor {
		return fmt.Errorf("pull %q: %w: %d bytes free on %s, %d required",
			ref, ErrPullRefusedDiskPressure, avail, root, floor)
	}
	return nil
}

// pullFloor is the free-space floor a fetch must leave: WithPullFloor, or
// DefaultPullRefuseFreeBytes.
func (p *Puller) pullFloor() uint64 {
	if p.floorBytes == 0 {
		return DefaultPullRefuseFreeBytes
	}
	return p.floorBytes
}

// sampleFree is the free-space sampler: WithFreeBytes, or StatfsFreeBytes.
func (p *Puller) sampleFree() FreeBytesFunc {
	if p.freeBytes == nil {
		return StatfsFreeBytes
	}
	return p.freeBytes
}

// reserveSpace claims on the puller's SpaceLedger, before any layer is
// requested, the bytes this pull may still add to the content store: the
// declared size of every blob mfst names that the store does not hold (the
// config and the missing layers), plus the commit-time allowance for the
// largest of them, the same allowance the artifact pull reserves (layers commit
// one at a time here). It is measured against free space minus the pull floor,
// with one reclaim pass when short.
//
// A refusal for space is ErrInsufficientSpace and also ErrPullRefusedDiskPressure,
// so a caller that keys on the admission refusal keys on this one too. A
// declared size that is negative or sums past uint64 refuses with
// ErrSizeOverflow, and a claim above the volume's capacity with
// ErrDeclaredSizeRejected; neither is ErrPullRefusedDiskPressure, because both
// refuse the serving registry's manifest rather than this node's free space. A pull missing nothing reserves nothing (a nil Reservation).
//
// The unpacked tree the layers are later extracted into is not covered; see
// SpaceLedger.
func (p *Puller) reserveSpace(ctx context.Context, ref string, mfst *ggcrv1.Manifest, resume bool) (*Reservation, error) {
	seen := make(map[string]bool, len(mfst.Layers)+1)
	var missing []BlobSpace
	for _, d := range append([]ggcrv1.Descriptor{mfst.Config}, mfst.Layers...) {
		digest := d.Digest.String()
		if seen[digest] {
			continue
		}
		seen[digest] = true
		if p.cache.Has(digest) {
			continue
		}
		b := BlobSpace{Size: d.Size}
		if resume && p.partials != nil && digest != mfst.Config.Digest.String() {
			// The partial's bytes are already off free space, as on the
			// artifact path; an overlong partial counts as nothing. When
			// resumeBlob falls back to a whole fetch that leaves the partial
			// in place (another claimant, the partial budget or cap, a
			// refused partial file), this under-charges by the partial's
			// bytes, at most the partial store's budget in total.
			b.Have = p.partials.Bytes(digest, d.Size)
		}
		missing = append(missing, b)
	}
	if len(missing) == 0 {
		return nil, nil
	}
	need, err := SpaceNeeded(missing, 1)
	if err != nil {
		return nil, fmt.Errorf("pull %q: declared blob sizes: %w", ref, err)
	}
	r, err := p.ledger.Reserve(ctx, SpaceClaim{
		Need:       need,
		Path:       p.cache.Root(),
		FloorBytes: p.pullFloor(),
		FreeBytes:  p.sampleFree(),
		TotalBytes: p.totalBytes,
		Reclaimer:  p.cache,
		Log:        p.logger(),
	})
	if err != nil {
		if errors.Is(err, ErrInsufficientSpace) || errors.Is(err, ErrFreeSpaceUnknown) {
			return nil, fmt.Errorf("pull %q: %w: %w", ref, ErrPullRefusedDiskPressure, err)
		}
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}
	return r, nil
}
