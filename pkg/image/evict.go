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
	"fmt"
	"slices"
	"sort"
)

// evictReason says why one blob of an eviction target is kept rather than
// deleted. It is local to this package; the wire enum is mapped from it at the
// daemon boundary.
type evictReason string

const (
	// evictRooted marks a blob an operator root or an artifact record keeps.
	// The prune plan alone does not tell a rooted blob from an in-use one
	// (both are ReasonKeptInUse); refineEvictRooted relabels it from the
	// classified roots.
	evictRooted evictReason = "rooted"
	// evictInUse marks a blob a daemon-authored root reaches.
	evictInUse evictReason = "in-use"
	// evictLeased marks a blob an in-flight ingest holds a lease over.
	evictLeased evictReason = "leased"
	// evictShared marks a blob the prune plan would delete but another cached
	// manifest names.
	evictShared evictReason = "shared"
	// evictYoung marks a blob younger than the grace window.
	evictYoung evictReason = "young"
)

// EvictPlan is the prune plan narrowed to one eviction target.
type EvictPlan struct {
	// Delete is plan.Delete intersected with the target's blobs, minus every
	// blob another cached manifest names, in the plan's order. It is always a
	// subset of the prune plan's Delete.
	Delete []PruneDecision
	// kept maps every target blob the plan holds but does not delete to why.
	kept map[string]evictReason
	// absent lists, sorted, the target blobs the prune plan does not name at
	// all (not in the inventory, so there is nothing to delete or keep).
	absent []string
}

// keepReasonForEvict maps a prune keep verdict onto an eviction reason:
//
//	ReasonKeptInUse             -> evictInUse
//	ReasonKeptLeased            -> evictLeased
//	ReasonKeptYoung             -> evictYoung
//	ReasonKeptUnknownProvenance -> evictRooted (fail-closed: the planner cannot
//	                               account for the node, so it is treated as
//	                               held by something outside the target)
//
// Any other reason in Keep is a planner contract breach and is an error.
// evictRooted from a real root and evictShared are not prune verdicts: the
// former needs the classified roots, the latter comes from O in PlanEvict.
func keepReasonForEvict(r PruneReason) (evictReason, error) {
	switch r {
	case ReasonKeptInUse:
		return evictInUse, nil
	case ReasonKeptLeased:
		return evictLeased, nil
	case ReasonKeptYoung:
		return evictYoung, nil
	case ReasonKeptUnknownProvenance:
		return evictRooted, nil
	default:
		return "", fmt.Errorf("plan evict: keep decision with non-keep reason %q", r)
	}
}

// PlanEvict narrows plan to the eviction target whose blob digests are target,
// protecting every blob in others (the blobs other cached manifests name).
//
// It is pure and only narrows: it makes no reachability decision of its own,
// so PlanPrune stays the one rule, and its Delete is always a subset of
// plan.Delete. A target blob the plan keeps carries the plan's verdict mapped
// by keepReasonForEvict; one the plan would delete but others names is kept as
// evictShared (a prune keep verdict wins over shared).
func PlanEvict(plan *PrunePlan, target, others map[string]struct{}) (*EvictPlan, error) {
	if plan == nil {
		return nil, fmt.Errorf("plan evict: nil plan")
	}
	out := &EvictPlan{kept: make(map[string]evictReason)}
	seen := make(map[string]struct{}, len(target))
	for _, d := range plan.Keep {
		dg := d.Node.Digest
		if _, ok := target[dg]; !ok || dg == "" {
			continue
		}
		r, err := keepReasonForEvict(d.Reason)
		if err != nil {
			return nil, err
		}
		seen[dg] = struct{}{}
		if _, dup := out.kept[dg]; !dup {
			out.kept[dg] = r
		}
	}
	for _, d := range plan.Delete {
		dg := d.Node.Digest
		if _, ok := target[dg]; !ok || dg == "" {
			continue
		}
		seen[dg] = struct{}{}
		if _, kept := out.kept[dg]; kept {
			// A digest with a kept node elsewhere is not evicted.
			continue
		}
		if _, ok := others[dg]; ok {
			out.kept[dg] = evictShared
			continue
		}
		out.Delete = append(out.Delete, d)
	}
	for dg := range target {
		if _, ok := seen[dg]; !ok {
			out.absent = append(out.absent, dg)
		}
	}
	sort.Strings(out.absent)
	return out, nil
}

// refineEvictRooted returns a copy of plan in which every blob kept as
// evictInUse that an operator root or an artifact record in roots names is
// kept as evictRooted instead.
//
// PlanEvict has no roots input, so it cannot tell a rooted blob from an in-use
// one: the prune plan keeps both as ReasonKeptInUse. This is the pure
// refinement over the classified roots. It only relabels: Delete and absent
// are copied unchanged, the kept set keeps exactly its digests, and no reason
// other than evictInUse is touched. A blob a pod also names is still labelled
// evictRooted, because the pod going away does not free it. A nil roots, an
// empty digest and a digest only a pod names relabel nothing. A nil plan
// returns nil.
func refineEvictRooted(plan *EvictPlan, roots *rootSet) *EvictPlan {
	if plan == nil {
		return nil
	}
	out := &EvictPlan{
		Delete: slices.Clone(plan.Delete),
		kept:   make(map[string]evictReason, len(plan.kept)),
		absent: slices.Clone(plan.absent),
	}
	rooted := roots.rootedDigests()
	for dg, r := range plan.kept {
		if _, ok := rooted[dg]; ok && r == evictInUse && dg != "" {
			r = evictRooted
		}
		out.kept[dg] = r
	}
	return out
}

// EvictKeepReason says why one blob of an eviction target was not removed. It
// is the exported form of the package's kept reasons plus the executor's own
// failure; the wire enum is mapped from it at the daemon boundary.
type EvictKeepReason string

const (
	// EvictKeptRooted: an operator root or an artifact record names the blob.
	EvictKeptRooted EvictKeepReason = "rooted"
	// EvictKeptInUse: a per-pod record or a pod hold names the blob.
	EvictKeptInUse EvictKeepReason = "in-use"
	// EvictKeptLeased: an in-flight ingest holds a lease over the blob.
	EvictKeptLeased EvictKeepReason = "leased"
	// EvictKeptYoung: the blob is younger than the grace window.
	EvictKeptYoung EvictKeepReason = "young"
	// EvictKeptShared: another cached index entry, artifact record or
	// released copy names the blob.
	EvictKeptShared EvictKeepReason = "shared"
	// EvictKeptUnlinkFailed: the executor's re-verification or unlink refused
	// the blob, or its removal failed. It is a failure, never a plan verdict:
	// no plan reason maps to it.
	EvictKeptUnlinkFailed EvictKeepReason = "unlink-failed"
)

// EvictKept is one target blob an eviction did not remove, and why.
type EvictKept struct {
	// Digest is the blob's content digest.
	Digest string
	// Reason is why the blob was kept.
	Reason EvictKeepReason
}

// EvictResult is the per-blob outcome of evicting one target. Every target
// blob is in exactly one of Removed, Kept and Absent, so the three together
// are the target's whole blob set and a partial eviction is never silent.
type EvictResult struct {
	// Removed are the digests removed, or that would be on a dry run, sorted.
	Removed []string
	// Kept are the target blobs not removed, with their reason, sorted by
	// digest.
	Kept []EvictKept
	// Absent are the target blobs the store does not hold at all, sorted:
	// there was nothing to remove or keep.
	Absent []string
	// ReclaimedBytes is the summed logical size of the removed files. Under
	// APFS clonefile it over-states what the volume gets back, as
	// PrunePlan.DeletedBytes does.
	ReclaimedBytes int64
}

// exportEvictReason maps a kept reason onto the exported vocabulary:
//
//	evictRooted -> EvictKeptRooted
//	evictInUse  -> EvictKeptInUse
//	evictLeased -> EvictKeptLeased
//	evictYoung  -> EvictKeptYoung
//	evictShared -> EvictKeptShared
//
// Any other value, the empty one included, is an error: the set is closed, and
// a reason that cannot be named must not be reported as some other one.
func exportEvictReason(r evictReason) (EvictKeepReason, error) {
	switch r {
	case evictRooted:
		return EvictKeptRooted, nil
	case evictInUse:
		return EvictKeptInUse, nil
	case evictLeased:
		return EvictKeptLeased, nil
	case evictYoung:
		return EvictKeptYoung, nil
	case evictShared:
		return EvictKeptShared, nil
	default:
		return "", fmt.Errorf("evict: unknown kept reason %q", r)
	}
}

// result is the outcome p plans, before any unlink: Delete's digests as
// removed (one entry per digest; every node's bytes counted), the kept set
// with its reasons exported, and the absent list. It is pure; an unknown kept
// reason or a nil plan is an error.
func (p *EvictPlan) result() (*EvictResult, error) {
	if p == nil {
		return nil, fmt.Errorf("evict result: nil plan")
	}
	out := &EvictResult{Absent: slices.Clone(p.absent)}
	seen := make(map[string]struct{}, len(p.Delete))
	for _, d := range p.Delete {
		out.ReclaimedBytes += d.Node.Size
		if _, dup := seen[d.Node.Digest]; dup {
			continue
		}
		seen[d.Node.Digest] = struct{}{}
		out.Removed = append(out.Removed, d.Node.Digest)
	}
	sort.Strings(out.Removed)
	for dg, r := range p.kept {
		er, err := exportEvictReason(r)
		if err != nil {
			return nil, fmt.Errorf("evict result: %s: %w", dg, err)
		}
		out.Kept = append(out.Kept, EvictKept{Digest: dg, Reason: er})
	}
	sort.Slice(out.Kept, func(i, j int) bool { return out.Kept[i].Digest < out.Kept[j].Digest })
	return out, nil
}
