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
