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
	"sort"
)

// evictPass is the state of one reclaim pass run in narrow mode by
// Cache.Evict. Its inputs are the target; the pass fills the rest so Evict can
// build its result from what the pass planned and what the executors did.
type evictPass struct {
	// manifest is the target manifest digest.
	manifest string
	// target is the target's blob digests (config and layers).
	target map[string]struct{}

	// plan is the prune plan narrowed to the target and refined from the
	// classified roots; set by the pass after planning.
	plan *EvictPlan
	// removed are the digests the blob executors unlinked.
	removed []string
	// skipped are the blob executors' refusals, typed where the executor
	// typed them.
	skipped []SkippedBlob
	// leased are the digests dropLeased took out before an executor ran.
	leased map[string]struct{}
	// deletedBytes is the blob executors' summed DeletedBytes.
	deletedBytes int64
	// ran reports that at least one executor call completed, so the fields
	// above describe what the pass did even when a later call failed.
	ran bool
}

// record sets ev's executor fields from the blob executor reports that
// completed and the leased drops dropLeased reported in rep.Kept, and marks
// the pass as having run. It replaces, not accumulates: the caller passes
// every completed report each time.
func (ev *evictPass) record(rep *ReclaimReport, execs ...*ExecuteReport) {
	ev.removed, ev.skipped, ev.deletedBytes = nil, nil, 0
	for _, e := range execs {
		ev.removed = append(ev.removed, e.Removed...)
		ev.skipped = append(ev.skipped, e.Skipped...)
		ev.deletedBytes += e.DeletedBytes
	}
	for _, k := range rep.Kept {
		if k.Reason == ReasonKeptLeased && k.Digest != "" {
			ev.leased[k.Digest] = struct{}{}
		}
	}
	ev.ran = true
}

// MaxEvictBlobs bounds the blob list one Cache.Evict call accepts: one config
// plus 4096 layers. Each target blob costs a full roots walk and a full
// shared-set read under leaseMu, so the function that takes the lock bounds
// its own input.
const MaxEvictBlobs = 4097

// ErrEvictTooManyBlobs reports a Cache.Evict target naming more than
// MaxEvictBlobs blobs; nothing is removed.
var ErrEvictTooManyBlobs = errors.New("image: evict target names too many blobs")

// Evict evicts the cache blobs of one target manifest, and the trees backed
// only by them, through the one reclaim pass: ReclaimUnderPressure run in
// narrow mode. manifest is the target manifest digest and blobs its config and
// layer digests; resolving a reference to them is the caller's job.
//
// Narrow mode changes the pass in three ways and no others:
//
//   - the delete sets are narrowed to the target: PlanEvict over the prune
//     plan for blobs, with the shared set (evictSharedSet) read fail-closed
//     after the roots and before the leases, and narrowTreesByBacking for
//     trees, so nothing the prune plan would keep is ever deleted and nothing
//     outside the target is touched;
//   - every executor call (released artifacts, trees, blobs) runs a guard that
//     re-reads the classified roots and the shared set and drops what they
//     name, and every blob unlink runs through unlinkUnlessLeased;
//   - the pressure check and the free-space stopping rule, the released-copy
//     bound and sweep, and cfg.SweepDerived are skipped: only cancellation
//     ends the executors early, and nothing outside the target is removed.
//
// cfg.DryRun plans and unlinks nothing; the result has the same shape. Of
// cfg's other fields Grace, FreeBytes, Now, Log and UntrackedPod apply as they
// do to a reclaim pass; HighFreeBytes, TargetFreeBytes, Force and
// SweepDerived are ignored. cfg.EvictDerived runs once with manifest, only
// after a pass that returned no error under a live context and in which no
// target blob failed to unlink (none is kept EvictKeptUnlinkFailed; a blob
// kept for any other reason does not stop it); never on a dry run and never
// when the pass errored. Its error is logged at Warn and the eviction still
// succeeds.
//
// Every target blob lands in exactly one of the result's Removed, Kept and
// Absent. A blob an executor refused is kept with the refusal's typed reason,
// or EvictKeptUnlinkFailed when the refusal is untyped; a planned blob that
// vanished before its unlink is absent.
//
// Errors. A malformed target, an empty blob list, a list longer than
// MaxEvictBlobs (ErrEvictTooManyBlobs), or any error before an
// executor call completed (a roots, shared-set or plan failure, the first
// executor's guard failing, a context cancelled before any executor ran)
// returns the error and a nil result: nothing was removed. Once an executor
// call has completed, every error, a later executor's guard failure and a
// cancelled context alike, returns a non-nil result built from what the
// executors did so far beside the error: its Removed are what was unlinked,
// and a target blob never attempted is kept EvictKeptUnlinkFailed. A re-run
// re-plans from scratch.
func (c *Cache) Evict(ctx context.Context, manifest string, blobs []string, cfg ReclaimConfig) (*EvictResult, error) {
	if _, err := parseBlobDigest(manifest); err != nil {
		return nil, fmt.Errorf("evict: target manifest: %w", err)
	}
	if len(blobs) == 0 {
		return nil, errors.New("evict: target names no blobs")
	}
	if len(blobs) > MaxEvictBlobs {
		return nil, fmt.Errorf("%w: %d, limit %d", ErrEvictTooManyBlobs, len(blobs), MaxEvictBlobs)
	}
	target := make(map[string]struct{}, len(blobs))
	for _, d := range blobs {
		if _, err := parseBlobDigest(d); err != nil {
			return nil, fmt.Errorf("evict: target blob: %w", err)
		}
		target[d] = struct{}{}
	}
	ev := &evictPass{manifest: manifest, target: target, leased: make(map[string]struct{})}
	cfg.evict = ev
	_, err := c.ReclaimUnderPressure(ctx, cfg)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if !ev.ran || ev.plan == nil {
			return nil, err
		}
		res, oerr := c.evictOutcome(ev)
		if oerr != nil {
			return nil, errors.Join(err, oerr)
		}
		return res, err
	}
	if ev.plan == nil {
		return nil, errors.New("evict: reclaim pass did not plan")
	}
	if cfg.DryRun {
		return ev.plan.result()
	}
	res, err := c.evictOutcome(ev)
	if err != nil {
		return nil, err
	}
	if cfg.EvictDerived != nil {
		if n := keptUnlinkFailed(res); n > 0 {
			if cfg.Log != nil {
				cfg.Log.Warn("evict: derived content kept, a target blob failed to unlink", "manifest", manifest, "unlinkFailed", n)
			}
		} else if herr := cfg.EvictDerived(ctx, manifest); herr != nil && cfg.Log != nil {
			cfg.Log.Warn("image evict: removal of the target's derived content refused; it is kept", "manifest", manifest, "err", herr)
		}
	}
	return res, nil
}

// keptUnlinkFailed counts the target blobs res keeps EvictKeptUnlinkFailed:
// such a blob is still on disk, so its image's derived content must stay with
// it while the count is non-zero.
func keptUnlinkFailed(res *EvictResult) int {
	n := 0
	for _, k := range res.Kept {
		if k.Reason == EvictKeptUnlinkFailed {
			n++
		}
	}
	return n
}

// evictGuards returns the executor seams of a narrow pass: evictHooks with its
// guard extended to re-read the shared set after the roots, dropping every
// blob another cached manifest now names as evictShared (a root's reason wins),
// and the same guard for the tree executor. Its unlink seam is
// unlinkUnlessHeld with the shared set re-read for each blob under leaseMu,
// after the lease and roots checks. Its tree unlink seam is treeUnlessHeld.
func (c *Cache) evictGuards(ctx context.Context, cfg *ReclaimConfig) (*pruneHooks, *treePruneHooks) {
	// afterPlan runs after the guard's shared-set read, not inside the roots
	// guard, so a test can interleave a writer after both of the guard's reads.
	rootsOnly := *cfg
	rootsOnly.afterPlan = nil
	h := c.evictHooks(&rootsOnly)
	rootsGuard, ev, afterPlan := h.guard, cfg.evict, cfg.afterPlan
	h.guard = func() (map[string]evictReason, error) {
		drop, err := rootsGuard()
		if err != nil {
			return nil, err
		}
		others, err := c.evictSharedSet(ctx, ev.manifest, ev.target)
		if err != nil {
			return nil, err
		}
		for d := range others {
			if _, ok := drop[d]; !ok {
				drop[d] = evictShared
			}
		}
		if afterPlan != nil {
			afterPlan()
		}
		return drop, nil
	}
	sharedNow := func(digest string) (bool, error) {
		others, err := c.evictSharedSet(ctx, ev.manifest, ev.target)
		if err != nil {
			return false, err
		}
		_, ok := others[digest]
		return ok, nil
	}
	untracked := cfg.UntrackedPod
	h.unlink = func(digest string, remove func() error) (bool, evictReason, error) {
		return c.unlinkUnlessHeld(digest, remove, untracked, sharedNow)
	}
	treeUnlink := func(backing []string, remove func() error) (bool, string, evictReason, error) {
		return c.treeUnlessHeld(backing, remove, untracked)
	}
	return h, &treePruneHooks{guard: h.guard, unlink: treeUnlink}
}

// narrowForEvict narrows plan to ev's target in place: its blob delete set to
// PlanEvict's, refined from roots, and its tree delete set to the trees backed
// only by that set. It records the narrowed plan in ev.
func narrowForEvict(plan *PrunePlan, ev *evictPass, others map[string]struct{}, roots *rootSet) error {
	ep, err := PlanEvict(plan, ev.target, others)
	if err != nil {
		return err
	}
	ep = refineEvictRooted(ep, roots)
	set := make(map[string]struct{}, len(ep.Delete))
	for _, d := range ep.Delete {
		set[d.Node.Digest] = struct{}{}
	}
	plan.DeleteTrees = narrowTreesByBacking(plan, set).DeleteTrees
	plan.Delete = ep.Delete
	ev.plan = ep
	return nil
}

// evictOutcome builds the real path's result from the plan and the executors:
// the plan's kept and absent sets as planned, and every digest the plan
// condemned placed by what happened to it, in this order of precedence:
//
//  1. any node of it refused with a typed reason: kept with that reason;
//  2. any node of it refused untyped while the blob is still present: kept
//     EvictKeptUnlinkFailed;
//  3. removed by an executor: removed;
//  4. gone from the store: absent (it vanished before its unlink);
//  5. dropped by dropLeased: kept EvictKeptLeased;
//  6. otherwise (never attempted, still present): kept EvictKeptUnlinkFailed.
func (c *Cache) evictOutcome(ev *evictPass) (*EvictResult, error) {
	planned, err := ev.plan.result()
	if err != nil {
		return nil, err
	}
	out := &EvictResult{Kept: planned.Kept, Absent: planned.Absent, ReclaimedBytes: ev.deletedBytes}
	refused := make(map[string]EvictKeepReason)
	for _, s := range ev.skipped {
		if s.Digest == "" {
			continue
		}
		switch {
		case s.Refusal != nil:
			refused[s.Digest] = s.Refusal.Reason
		case c.Has(s.Digest):
			if _, typed := refused[s.Digest]; !typed {
				refused[s.Digest] = EvictKeptUnlinkFailed
			}
		}
	}
	removed := make(map[string]struct{}, len(ev.removed))
	for _, d := range ev.removed {
		removed[d] = struct{}{}
	}
	for _, d := range planned.Removed {
		if r, ok := refused[d]; ok {
			out.Kept = append(out.Kept, EvictKept{Digest: d, Reason: r})
			continue
		}
		if _, ok := removed[d]; ok {
			out.Removed = append(out.Removed, d)
			continue
		}
		if !c.Has(d) {
			out.Absent = append(out.Absent, d)
			continue
		}
		r := EvictKeptUnlinkFailed
		if _, ok := ev.leased[d]; ok {
			r = EvictKeptLeased
		}
		out.Kept = append(out.Kept, EvictKept{Digest: d, Reason: r})
	}
	sort.Strings(out.Removed)
	sort.Strings(out.Absent)
	sort.Slice(out.Kept, func(i, j int) bool { return out.Kept[i].Digest < out.Kept[j].Digest })
	return out, nil
}
