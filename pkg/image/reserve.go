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
//   - Otherwise a dry-run pass plans the eviction without unlinking. A plan
//     error, or free space plus the planned bytes still short of the sum, is
//     ErrInsufficientSpace with no real pass, so a claim reclaim could not
//     satisfy never empties the unreferenced cache. Only then does one real
//     pass run, asked to bring free space up to the sum, and the check is
//     repeated; still short is ErrInsufficientSpace.
//
// The dry run's bytes are the whole plan, blobs and trees, and the real pass
// unlinks no blob or tree outside the plan it makes under the same rules, so
// the dry run does not under-count what the real pass can free in the content
// store; the two plans differ only by holds and leases that change between
// them. The two places a real pass differs from a dry run
// add no blob or tree to it. ReclaimConfig.SweepDerived runs only when set, and
// Reserve sets it on neither pass. BoundReleasedArtifacts runs on every real
// pass and removes only released artifact record copies from the index: they
// are eviction-order hints and never roots, so dropping them cannot change the
// plan. What it frees is those small index files, which every release already
// bounds to MaxReleasedArtifactBytes, so in practice only a commit temp a crash
// left or a copy that no longer decodes. No margin is kept for them: a claim
// that fits only once they are gone is refused until the daemon's own pressure
// pass has removed them.
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
			return nil, fmt.Errorf("need %d bytes, %d free, floor %d: reclaim plan failed: %v: %w",
				c.Need, avail, c.FloorBytes, derr, ErrInsufficientSpace)
		}
		var reclaimable uint64
		if plan != nil && plan.ReclaimedBytes > 0 {
			reclaimable = uint64(plan.ReclaimedBytes)
		}
		// A sum that wraps is past every want, so only a sum that does not
		// wrap can be short.
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
