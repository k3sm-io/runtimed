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
	"io"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultReclaimHighFreeBytes is the free-space floor under which the daemon
// starts reclaiming unreferenced image content, and DefaultReclaimTargetFreeBytes
// is the free-space level it reclaims back up to.
//
// They are ABSOLUTE BYTES, deliberately, where kubelet's image GC is a percentage
// of the image filesystem. A percentage of an APFS container is fiction: every
// volume in a container reports the same shared free pool, so "15% of the volume"
// moves as sibling volumes grow. An absolute floor states the invariant that
// actually matters on a single Mac — leave the kine datastore sharing this volume
// this many bytes of headroom.
const (
	DefaultReclaimHighFreeBytes   uint64 = 5 << 30  // 5 GiB
	DefaultReclaimTargetFreeBytes uint64 = 10 << 30 // 10 GiB
)

// DefaultReclaimGrace is how old a node must be before reclaim will consider it.
//
// It is a backstop against the one race a lease cannot cover: content that
// arrived through a path that took no lease at all. It is NOT the primary
// protection — a grace window is vacuous for exactly the case that matters, a
// cache HIT, where the blob is old and no write touches its mtime. The lease is
// what covers that (see Lease).
const DefaultReclaimGrace = 10 * time.Minute

// ErrFreeSpaceUnknown reports that free space on the store volume could not be
// sampled, so no reclaim decision was made.
//
// Fail-closed on ignorance: statfs failing is the first symptom of a volume
// going bad, and that is precisely when deleting content on a guess is worst.
// The cost of refusing is that reclaim does not run; the cost of guessing is
// unlinking the layers of images this node may not be able to fetch again.
var ErrFreeSpaceUnknown = errors.New("image: free space on the store volume is unknown")

// FreeBytesFunc samples the bytes available on the volume holding path. The
// production implementation is StatfsFreeBytes; tests inject a fake. It is the
// seam BELOW the decision, so the reclaim loop is testable with no syscall.
type FreeBytesFunc func(path string) (uint64, error)

// StatfsFreeBytes is the production FreeBytesFunc: f_bavail x f_bsize — the
// bytes available to the daemon's euid, not the root-reserved f_bfree.
func StatfsFreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// FilesystemSample is a raw statfs measurement of the volume holding the image
// store, at one instant.
//
// MEASUREMENT-SHAPED ONLY: it carries facts, never a reclaimable estimate, a
// budget, or a threshold. Under APFS clonefile the number of bytes a prune would
// return to the volume is not a function of anything in here, so any field that
// claimed to be one would be a lie with a type.
type FilesystemSample struct {
	// Mountpoint is the path the sample was taken at (the store root).
	Mountpoint string
	// CapacityBytes is the filesystem's total size.
	CapacityBytes uint64
	// UsedBytes is capacity minus free — the filesystem's own accounting, not
	// the sum of anything this package walked.
	UsedBytes uint64
	// AvailableBytes is what is available to this euid (f_bavail x f_bsize).
	AvailableBytes uint64
	// InodesUsed is total inodes minus free inodes.
	InodesUsed uint64
}

// StatfsSample measures the filesystem holding path.
func StatfsSample(path string) (FilesystemSample, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return FilesystemSample{}, fmt.Errorf("statfs %s: %w", path, err)
	}
	bsize := uint64(st.Bsize)
	return FilesystemSample{
		Mountpoint:     path,
		CapacityBytes:  uint64(st.Blocks) * bsize,
		UsedBytes:      (uint64(st.Blocks) - uint64(st.Bfree)) * bsize,
		AvailableBytes: uint64(st.Bavail) * bsize,
		InodesUsed:     uint64(st.Files) - uint64(st.Ffree),
	}, nil
}

// StoreBytes is the summed logical size of the content-addressed store's blobs.
//
// It is a RAW MEASUREMENT of what the store holds, and it is explicitly NOT an
// estimate of what a prune could reclaim: a blob whose extents are cloned into a
// live pod rootfs contributes its full size here and frees nothing when unlinked.
func (c *Cache) StoreBytes() (int64, error) {
	nodes, err := c.EnumerateBlobs()
	if err != nil {
		return 0, err
	}
	var n int64
	for _, b := range nodes {
		n += b.Size
	}
	return n, nil
}

// ReclaimConfig configures one disk-pressure reclaim pass.
type ReclaimConfig struct {
	// HighFreeBytes is the free-space floor: reclaim runs only when the measured
	// free space is BELOW it. Zero means DefaultReclaimHighFreeBytes.
	HighFreeBytes uint64
	// TargetFreeBytes is the measured free level reclaim stops at. Zero means
	// DefaultReclaimTargetFreeBytes. It must be >= HighFreeBytes.
	TargetFreeBytes uint64
	// Grace is the minimum node age for deletion. Zero means DefaultReclaimGrace.
	Grace time.Duration
	// DryRun plans and reports but unlinks nothing.
	DryRun bool
	// Force runs the prune regardless of measured free space, and drains the whole
	// delete plan instead of stopping at TargetFreeBytes — the operator's explicit
	// `k3sm image prune` ("delete what nothing references"), as opposed to the
	// daemon's pressure trigger ("get back above the target"). Those are different
	// requests and stopping a forced prune at a target it never asked about would
	// silently answer the wrong one.
	//
	// It relaxes no SAFETY rule: roots are still enumerated fail-closed, leases
	// are still honored, the grace window still applies, and every unlink still
	// re-verifies.
	Force bool
	// FreeBytes samples free space. Nil means StatfsFreeBytes.
	FreeBytes FreeBytesFunc
	// Now is the clock. Nil means the cache's own clock.
	Now func() time.Time
	// Log receives the pressure transitions. Nil discards.
	Log *slog.Logger

	// afterInventory runs between the blob inventory and the root read. It is
	// UNEXPORTED and exists only so an in-package test can drive the interleaving
	// the read order is chosen to survive; production can neither set it nor
	// observe it.
	afterInventory func()
}

// ReclaimReport is the typed outcome of a reclaim pass.
type ReclaimReport struct {
	// Triggered reports whether the pass got past the pressure check and planned
	// anything. False means free space was above the floor and nothing was done.
	Triggered bool
	// DryRun echoes the request.
	DryRun bool
	// FreeBefore and FreeAfter are the MEASURED free bytes on the store volume.
	// FreeAfter equals FreeBefore for a dry run.
	FreeBefore, FreeAfter uint64
	// Removed are the digests unlinked, or — under DryRun — the ones that would
	// have been.
	Removed []string
	// ReclaimedBytes is the summed logical size of what was unlinked. Under
	// APFS clonefile this OVERSTATES what the volume got back; FreeAfter minus
	// FreeBefore is the measured truth.
	ReclaimedBytes int64
	// Kept is every blob the pass considered and did not delete, with its
	// verdict — the planner's Keep set plus anything the executor refused.
	Kept []KeptBlob
	// ReachedTarget reports whether measured free space met TargetFreeBytes.
	ReachedTarget bool
}

// KeptBlob is one blob a reclaim pass kept, with the typed verdict.
type KeptBlob struct {
	// Digest is the blob's content digest; empty for a non-content node.
	Digest string
	// Path is the blobs-root-relative path (populated for every kept node, so a
	// node with no digest is still identifiable).
	Path string
	// Reason is the typed verdict.
	Reason PruneReason
	// Detail is a human-readable amplification for an executor refusal; empty
	// for a planner verdict.
	Detail string
}

// ReclaimUnderPressure is the daemon-side image GC: free unreferenced image
// content when the store volume is under disk pressure.
//
// It mirrors kubelet freeing images BEFORE evicting pods, and diverges from it
// in two ways that macOS forces and that are NOT cosmetic:
//
//   - Deleting a blob does not kill a running pod the way it would on overlayfs.
//     A pod's rootfs is materialized with APFS clonefile, so it holds its own
//     references to the extents; what a wrongly-deleted blob breaks is RESTART,
//     re-materialization, and imagePullPolicy:IfNotPresent. That is still data
//     loss on a node that cannot reach the registry, which is why liveness is
//     enforced structurally rather than being treated as best-effort.
//   - Kubelet's byte-budget arithmetic is INVALID here. Unlinking a blob whose
//     extents are still cloned into a live pod frees zero bytes, so a
//     precomputed "delete N bytes" budget would under-delete or over-delete
//     without ever knowing which. This loop re-measures with statfs after EVERY
//     unlink and stops on the measured target.
//
// The safety property, stated exactly: a blob named by any pod's daemon-authored
// reachability record, or pinned by any live ingest lease, is never in the delete
// plan — and if the root set cannot be enumerated in full, NOTHING is deleted
// (ErrRootsIncomplete). Reclaim is not best-effort about liveness; it refuses.
func (c *Cache) ReclaimUnderPressure(ctx context.Context, cfg ReclaimConfig) (*ReclaimReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	high := cfg.HighFreeBytes
	if high == 0 {
		high = DefaultReclaimHighFreeBytes
	}
	target := cfg.TargetFreeBytes
	if target == 0 {
		target = DefaultReclaimTargetFreeBytes
	}
	if target < high {
		return nil, fmt.Errorf("reclaim: target free %d is below the pressure floor %d", target, high)
	}
	grace := cfg.Grace
	if grace == 0 {
		grace = DefaultReclaimGrace
	}
	if grace < 0 {
		return nil, fmt.Errorf("reclaim: negative grace %v", grace)
	}
	free := cfg.FreeBytes
	if free == nil {
		free = StatfsFreeBytes
	}
	now := cfg.Now
	if now == nil {
		now = c.now
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	before, err := free(c.root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFreeSpaceUnknown, err)
	}
	rep := &ReclaimReport{DryRun: cfg.DryRun, FreeBefore: before, FreeAfter: before}
	if !cfg.Force && before >= high {
		rep.ReachedTarget = before >= target
		return rep, nil
	}
	rep.Triggered = true

	// INVENTORY FIRST, ROOTS SECOND, LEASES LAST. The order is the whole race
	// argument, and it is the opposite of the intuitive one.
	//
	// The delete set is `inventory minus roots`. Reading the inventory EARLIER can
	// only shrink it — a blob committed after this read is not a candidate at all.
	// Reading the roots LATER can only grow the protection — a reference recorded
	// while the pass is running is still honored. Both reads therefore err toward
	// keeping. Reversed, the pass has a real hole: a blob whose root is recorded
	// between the root read and the inventory read is absent from the roots and
	// present in the inventory, so it is planned for deletion at exactly the moment
	// a pod started depending on it.
	nodes, err := c.EnumerateBlobs()
	if err != nil {
		return nil, err
	}
	if cfg.afterInventory != nil {
		cfg.afterInventory()
	}
	// Fail-closed: an incomplete root set aborts the whole pass (see Roots).
	roots, err := c.Roots()
	if err != nil {
		return nil, err
	}
	leased := make([]string, 0)
	for d := range c.leasedDigests() {
		leased = append(leased, d)
	}
	plan, err := PlanPrune(nodes, roots, leased, grace, now())
	if err != nil {
		return nil, err
	}
	for _, k := range plan.Keep {
		rep.Kept = append(rep.Kept, KeptBlob{Digest: k.Node.Digest, Path: k.Node.Path, Reason: k.Reason})
	}

	if cfg.DryRun {
		for _, d := range plan.Delete {
			if d.Node.Digest != "" {
				rep.Removed = append(rep.Removed, d.Node.Digest)
			}
		}
		rep.ReclaimedBytes = plan.DeletedBytes()
		rep.ReachedTarget = before >= target
		return rep, nil
	}

	// The stopping rule is a MEASUREMENT, taken between unlinks — never a
	// precomputed byte budget, because under APFS clonefile an unlink whose
	// extents are still shared frees nothing and a budget cannot know that. A
	// sampling error mid-run does not abort the pass: it only means the target
	// cannot be proven met, so the loop continues and the closing measurement
	// below reports the truth.
	//
	// A FORCED prune has no free-space stopping rule at all (see Force) — only
	// cancellation ends it early.
	var sampleErr error
	stop := func() bool {
		if ctx.Err() != nil {
			return true
		}
		if cfg.Force {
			return false
		}
		f, err := free(c.root)
		if err != nil {
			sampleErr = err
			return false
		}
		return f >= target
	}
	exec, err := c.ExecutePrune(plan, grace, now(), stop)
	if err != nil {
		return nil, err
	}
	rep.Removed = exec.Removed
	rep.ReclaimedBytes = exec.DeletedBytes
	for _, s := range exec.Skipped {
		rep.Kept = append(rep.Kept, KeptBlob{Digest: s.Digest, Path: s.Path, Reason: ReasonKeptUnknownProvenance, Detail: s.Reason})
	}

	after, ferr := free(c.root)
	if ferr != nil {
		// The unlinks happened; only the closing measurement is unavailable. Report
		// what is known rather than discarding a successful reclaim.
		log.Warn("image reclaim: closing free-space sample failed",
			"root", c.root, "err", ferr, "deleted", exec.Deleted)
		rep.FreeAfter = before
		return rep, nil
	}
	rep.FreeAfter = after
	rep.ReachedTarget = after >= target
	if !rep.ReachedTarget {
		log.Warn("image reclaim did not reach its free-space target",
			"root", c.root, "free_bytes", after, "target_bytes", target,
			"deleted", exec.Deleted, "sample_err", sampleErr)
	} else {
		log.Info("image reclaim freed space on the store volume",
			"root", c.root, "free_before", before, "free_after", after, "deleted", exec.Deleted)
	}
	return rep, nil
}
