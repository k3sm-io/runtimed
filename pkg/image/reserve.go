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
	"log/slog"
	"math/bits"
	"sort"
	"sync"
)

// ErrInsufficientSpace reports a pull refused before its first blob request:
// the bytes its manifest declares, added to what other in-flight pulls have
// reserved, would take the store volume below its free-space floor, and reclaim
// could not make room (by its plan, or by its one real pass). The image pull and the artifact pull return
// this one sentinel (artifact.ErrInsufficientSpace is the same value).
var ErrInsufficientSpace = errors.New("image: refusing the pull, the store volume would fall below its free-space floor")

// ErrSizeOverflow reports space arithmetic that would wrap, or a negative
// declared size. Declared sizes come from a registry, so a wrapped sum is a
// small or zero reservation that would slip past the floor; it refuses instead.
// artifact.ErrSizeOverflow is the same value.
var ErrSizeOverflow = errors.New("image: space arithmetic overflows")

// ErrDeclaredSizeRejected reports that the manifest declares more than this
// volume can ever hold: the declared bytes and the floor alone exceed the
// volume's total capacity, so no reclaim pass could make room. Bytes other pulls
// hold do not count, since they are this node's state, not the manifest's claim.
// The sizes are the serving registry's claim, so it is a refusal of that
// source's manifest, not of this node's free space: another source may serve a
// sane one. artifact.ErrDeclaredSizeRejected is the same value.
var ErrDeclaredSizeRejected = errors.New("image: refusing the pull, the manifest declares more than the store volume can hold")

// MaxManifestLayers is the most layers one image manifest may name. A manifest
// is the serving source's claim, and every path that acts on one (lease,
// reservation, per-layer fetch, presence check) does work linear in its layer
// count, so an unbounded count is a cost the source chooses for this node. Real
// images stay in the tens; 4096 is far above any of them.
const MaxManifestLayers = 4096

// ErrTooManyLayers reports a manifest naming more than MaxManifestLayers
// layers. It refuses that manifest, not the reference: another source may
// serve a sane one.
var ErrTooManyLayers = errors.New("image: refusing the manifest, it names too many layers")

// ErrManifestTooLarge reports manifest bytes over maxIndexManifestBytes, the
// cap the index already applies to the bytes it retains: a manifest over it
// would be fetched and committed only to fail at the record.
var ErrManifestTooLarge = errors.New("image: refusing the manifest, its bytes exceed the manifest size cap")

// refuseLayerCount is the one check every manifest-acting path runs before it
// leases, reserves or fetches: n is the manifest's layer count and rawManifest,
// when not nil, its exact bytes.
func refuseLayerCount(n int, rawManifest []byte) error {
	if n > MaxManifestLayers {
		return fmt.Errorf("%w: %d layers, limit %d", ErrTooManyLayers, n, MaxManifestLayers)
	}
	if rawManifest != nil && len(rawManifest) > maxIndexManifestBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrManifestTooLarge, len(rawManifest), maxIndexManifestBytes)
	}
	return nil
}

// SpaceLedger is the in-process ledger of the bytes in-flight pulls have
// reserved on the store volume. The daemon builds one and hands the same
// instance to the image puller (WithSpaceLedger) and the artifact puller, so
// the two pull paths measure against one another's claims and cannot
// overcommit the volume between them. The zero value is an empty ledger ready
// to use; it is safe for concurrent use.
//
// A reservation covers the blobs a pull writes into the content store. It does
// NOT cover the unpacked tree an image's layers are later extracted into
// (unpacked/ and snapshots/): that tree is written after the pull returns and
// its reservation is released, and its size is not declared by any manifest.
//
// The image path reserves each missing blob at its full declared size even when
// the blob will arrive by a local clone that adds little to the volume: a
// deliberate over-estimate. A Puller the caller injects into the daemon, rather
// than one the daemon builds, does not share the daemon's ledger, so its pulls
// and the artifact pulls do not see one another's claims.
//
// mu guards held and is held across a reservation's whole check, including its
// dry run and its one reclaim pass, so two pulls can never both pass a check
// only one fits.
type SpaceLedger struct {
	mu   sync.Mutex
	held uint64
}

// Reserved returns the bytes currently reserved by in-flight pulls.
func (l *SpaceLedger) Reserved() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}

// SpaceReclaimer runs one disk-pressure reclaim pass; *Cache satisfies it.
// Reserve calls it first with ReclaimConfig.DryRun set and reads the bytes the
// plan would delete from ReclaimReport.ReclaimedBytes, then runs the real pass
// only when those bytes could make the claim fit.
type SpaceReclaimer interface {
	ReclaimUnderPressure(ctx context.Context, cfg ReclaimConfig) (*ReclaimReport, error)
}

// SpaceClaim is one request to SpaceLedger.Reserve.
type SpaceClaim struct {
	// Need is the bytes the pull may still add to the volume (SpaceNeeded).
	Need uint64
	// Path is where free space is sampled: the store root.
	Path string
	// FloorBytes is the free space the pull must leave.
	FloorBytes uint64
	// FreeBytes samples free space. Nil means StatfsFreeBytes.
	FreeBytes FreeBytesFunc
	// TotalBytes samples the volume's total capacity, checked before the
	// reclaim pass. Nil means StatfsTotalBytes.
	TotalBytes TotalBytesFunc
	// Reclaimer plans (dry run) and then runs the one reclaim pass when the
	// claim does not fit. Nil
	// means no pass: a claim that does not fit is refused at once.
	Reclaimer SpaceReclaimer
	// Log receives a failed reclaim pass. Nil discards.
	Log *slog.Logger
}

// Reservation is one pull's claim on a SpaceLedger.
type Reservation struct {
	l    *SpaceLedger
	n    uint64
	once sync.Once
}

// Release returns the claim to its ledger. It is idempotent, and a nil
// Reservation (a pull that had nothing to reserve) releases nothing.
func (r *Reservation) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.l.mu.Lock()
		r.l.held -= r.n
		r.l.mu.Unlock()
	})
}

// Reserve claims c.Need bytes before the pull's first blob request. The claim
// fits when free space is at least c.FloorBytes plus everything already held
// plus c.Need. When it does not and c.Reclaimer is set:
//
//   - c.FloorBytes plus c.Need above the volume's total capacity is
//     ErrDeclaredSizeRejected, with no reclaim pass of either kind.
//   - c.FloorBytes plus the held bytes plus c.Need above capacity is
//     ErrInsufficientSpace with no pass: reclaim cannot free what in-flight
//     pulls hold.
//   - Otherwise a dry-run pass plans the eviction without unlinking. Free
//     space plus the planned bytes still short of the sum is
//     ErrInsufficientSpace with no real pass, so a claim reclaim could not
//     satisfy never empties the unreferenced cache. Only then does one real
//     pass run, asked to bring free space up to the sum, and the check is
//     repeated; still short is ErrInsufficientSpace.
//     The dry plan and the real pass each work from their own snapshot: when the
//     real pass frees less than the plan counted, the claim is refused after
//     that one pass has evicted, and the pass itself stops at its target so it
//     never evicts more than the claim asked for.
//   - A failed plan also runs no real pass. When ctx is done, or the plan's
//     error is context.Canceled or context.DeadlineExceeded, the error wraps
//     the context error and is not ErrInsufficientSpace. When ctx is done and
//     the plan's error is not that context error, the plan's cause is named in
//     the text, bounded by boundErr, as text only: the result does not match
//     the cause (for example ErrFreeSpaceUnknown). Any other plan error
//     is a refusal that matches both ErrInsufficientSpace and the plan's own
//     cause (for example ErrFreeSpaceUnknown), its text bounded by boundErr.
//
// Stated limit: the dry run skips the bound of released artifact records,
// which the real pass runs on every pass, and those bytes are not in its
// plan. (Reserve sets no ReclaimConfig.SweepDerived, so its real pass does not
// sweep artifact views either.) A pull that would fit only after that bound is
// refused; the daemon's own pressure pass runs it.
//
// An unsamplable volume (free space or, before a pass, capacity) refuses with
// ErrFreeSpaceUnknown, and a sum that would wrap refuses with ErrSizeOverflow.
func (l *SpaceLedger) Reserve(ctx context.Context, c SpaceClaim) (*Reservation, error) {
	free := c.FreeBytes
	if free == nil {
		free = StatfsFreeBytes
	}
	total := c.TotalBytes
	if total == nil {
		total = StatfsTotalBytes
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	claimed, err := addChecked(l.held, c.Need)
	if err != nil {
		return nil, err
	}
	want, err := addChecked(c.FloorBytes, claimed)
	if err != nil {
		return nil, err
	}
	fits := func() (uint64, bool, error) {
		avail, err := free(c.Path)
		if err != nil {
			return 0, false, fmt.Errorf("%w: %w", ErrFreeSpaceUnknown, boundErr(err))
		}
		return avail, avail >= want, nil
	}
	avail, ok, err := fits()
	if err != nil {
		return nil, err
	}
	if !ok && c.Reclaimer != nil {
		// A declaration no reclaim could ever satisfy is refused without one:
		// the declared sizes are a registry's, and an impossible declaration
		// must not evict every unreferenced blob on each attempt and still
		// fail. It is judged by this pull alone; bytes other pulls hold are a
		// local shortfall, refused below as ErrInsufficientSpace.
		capacity, err := total(c.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: capacity: %w", ErrFreeSpaceUnknown, boundErr(err))
		}
		own, err := addChecked(c.FloorBytes, c.Need)
		if err != nil {
			return nil, err
		}
		if own > capacity {
			return nil, fmt.Errorf("need %d bytes, floor %d: the claim exceeds the volume's capacity of %d bytes: %w",
				c.Need, c.FloorBytes, capacity, ErrDeclaredSizeRejected)
		}
		// Reclaim cannot free what in-flight pulls hold, so a sum past capacity
		// only because of them is refused without a pass.
		if want > capacity {
			return nil, fmt.Errorf("need %d bytes, %d reserved by other pulls, floor %d: the sum exceeds the volume's capacity of %d bytes: %w",
				c.Need, l.held, c.FloorBytes, capacity, ErrInsufficientSpace)
		}
		cfg := ReclaimConfig{HighFreeBytes: want, TargetFreeBytes: want, FreeBytes: free, Log: c.Log}
		dry := cfg
		dry.DryRun = true
		plan, derr := c.Reclaimer.ReclaimUnderPressure(ctx, dry)
		if derr != nil {
			// A cancelled or expired context is the caller giving up, not a
			// lack of space: report the context's error, not a refusal.
			// When the plan failed for its own reason, that cause is kept as
			// bounded text only (%v), so the result still matches nothing but
			// the context error and status mapping stays a context answer.
			if cerr := ctx.Err(); cerr != nil {
				if errors.Is(derr, cerr) {
					return nil, fmt.Errorf("need %d bytes, %d free, floor %d: reclaim plan interrupted: %w",
						c.Need, avail, c.FloorBytes, cerr)
				}
				return nil, fmt.Errorf("need %d bytes, %d free, floor %d: reclaim plan interrupted (plan failed: %v): %w",
					c.Need, avail, c.FloorBytes, boundErr(derr), cerr)
			}
			if errors.Is(derr, context.Canceled) || errors.Is(derr, context.DeadlineExceeded) {
				return nil, fmt.Errorf("need %d bytes, %d free, floor %d: reclaim plan interrupted: %w",
					c.Need, avail, c.FloorBytes, boundErr(derr))
			}
			return nil, fmt.Errorf("need %d bytes, %d free, floor %d: reclaim plan failed: %w: %w",
				c.Need, avail, c.FloorBytes, boundErr(derr), ErrInsufficientSpace)
		}
		var reclaimable uint64
		if plan != nil && plan.ReclaimedBytes > 0 {
			reclaimable = uint64(plan.ReclaimedBytes)
		}
		if reach, oerr := addChecked(avail, reclaimable); oerr == nil && reach < want {
			return nil, fmt.Errorf("need %d bytes, %d free, %d reclaimable, %d reserved by other pulls, floor %d: %w",
				c.Need, avail, reclaimable, l.held, c.FloorBytes, ErrInsufficientSpace)
		}
		if _, rerr := c.Reclaimer.ReclaimUnderPressure(ctx, cfg); rerr != nil && c.Log != nil {
			c.Log.Warn("pull: reclaim pass before a space reservation failed", "err", rerr)
		}
		avail, ok, err = fits()
		if err != nil {
			return nil, err
		}
	}
	if !ok {
		return nil, fmt.Errorf("need %d bytes, %d free, %d reserved by other pulls, floor %d: %w",
			c.Need, avail, l.held, c.FloorBytes, ErrInsufficientSpace)
	}
	l.held = claimed
	return &Reservation{l: l, n: c.Need}, nil
}

// BlobSpace is one blob a pull may still write: its declared Size and the Have
// bytes of it already on the volume (a resumable partial; zero for none).
type BlobSpace struct {
	Size int64
	Have int64
}

// SpaceNeeded is what a pull of blobs may still add to the volume: the rest of
// every blob (Size-Have), plus a commit-time copy of the committing largest
// blobs, the most that can be committing at once.
//
// The sizes are declared by a registry and are not trusted: a negative size, a
// Have outside 0..Size, or a sum that would wrap uint64 refuses with
// ErrSizeOverflow, because a wrapped sum is a zero reservation that bypasses
// the floor.
func SpaceNeeded(blobs []BlobSpace, committing int) (uint64, error) {
	var need uint64
	add := func(n int64) error {
		if n < 0 {
			return fmt.Errorf("negative size %d: %w", n, ErrSizeOverflow)
		}
		sum, err := addChecked(need, uint64(n))
		if err != nil {
			return err
		}
		need = sum
		return nil
	}
	sizes := make([]int64, 0, len(blobs))
	for _, b := range blobs {
		if b.Size < 0 || b.Have < 0 || b.Have > b.Size {
			return 0, fmt.Errorf("declared size %d with %d on disk: %w", b.Size, b.Have, ErrSizeOverflow)
		}
		if err := add(b.Size - b.Have); err != nil {
			return 0, err
		}
		sizes = append(sizes, b.Size)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] > sizes[j] })
	for i := 0; i < len(sizes) && i < committing; i++ {
		if err := add(sizes[i]); err != nil {
			return 0, err
		}
	}
	return need, nil
}

// addChecked is a+b, refusing a wrap.
func addChecked(a, b uint64) (uint64, error) {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return 0, ErrSizeOverflow
	}
	return sum, nil
}
