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
	"reflect"
	"testing"
	"time"
)

func digestSet(ns ...BlobNode) map[string]struct{} {
	s := make(map[string]struct{}, len(ns))
	for _, n := range ns {
		s[n.Digest] = struct{}{}
	}
	return s
}

// TestPlanEvict pins the narrowing rule: the evict set is plan.Delete ∩ T minus
// O, always a subset of plan.Delete, and every other target blob is reported
// kept with the reason mapped from the plan, or shared, or absent.
func TestPlanEvict(t *testing.T) {
	cfg, l1, l2 := node('a', 10, time.Hour), node('b', 20, time.Hour), node('c', 30, time.Hour)
	other := node('d', 40, time.Hour)
	young := node('e', 50, time.Minute)
	leased := node('f', 60, time.Hour)
	used := node('1', 70, time.Hour)
	del := func(ns ...BlobNode) []PruneDecision {
		var ds []PruneDecision
		for _, n := range ns {
			ds = append(ds, PruneDecision{Node: n, Reason: ReasonDeleteUnreferenced})
		}
		return ds
	}
	plan := &PrunePlan{
		Delete: del(cfg, l1, l2, other),
		Keep: []PruneDecision{
			{Node: young, Reason: ReasonKeptYoung},
			{Node: leased, Reason: ReasonKeptLeased},
			{Node: used, Reason: ReasonKeptInUse},
		},
	}
	tests := []struct {
		name       string
		target     map[string]struct{}
		others     map[string]struct{}
		wantDelete []PruneDecision
		wantKept   map[string]evictReason
		wantAbsent []string
	}{
		{
			name:       "no sharing deletes every target blob",
			target:     digestSet(cfg, l1, l2),
			wantDelete: del(cfg, l1, l2),
			wantKept:   map[string]evictReason{},
		},
		{
			name:       "layer shared with another manifest is kept as shared",
			target:     digestSet(cfg, l1, l2),
			others:     digestSet(l2, other),
			wantDelete: del(cfg, l1),
			wantKept:   map[string]evictReason{l2.Digest: evictShared},
		},
		{
			name:       "blobs the plan keeps stay kept with the mapped reason",
			target:     digestSet(cfg, young, leased, used),
			others:     digestSet(used),
			wantDelete: del(cfg),
			wantKept: map[string]evictReason{
				young.Digest:  evictYoung,
				leased.Digest: evictLeased,
				used.Digest:   evictInUse,
			},
		},
		{
			name:     "empty target deletes nothing",
			target:   map[string]struct{}{},
			wantKept: map[string]evictReason{},
		},
		{
			name:       "target outside the plan is absent, not deleted",
			target:     digestSet(node('7', 1, time.Hour), node('8', 1, time.Hour)),
			wantKept:   map[string]evictReason{},
			wantAbsent: []string{node('7', 1, 0).Digest, node('8', 1, 0).Digest},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanEvict(plan, tc.target, tc.others)
			if err != nil {
				t.Fatalf("PlanEvict: %v", err)
			}
			if !reflect.DeepEqual(got.Delete, tc.wantDelete) {
				t.Errorf("Delete = %v, want %v", got.Delete, tc.wantDelete)
			}
			if !reflect.DeepEqual(got.kept, tc.wantKept) {
				t.Errorf("kept = %v, want %v", got.kept, tc.wantKept)
			}
			if !reflect.DeepEqual(got.absent, tc.wantAbsent) {
				t.Errorf("absent = %v, want %v", got.absent, tc.wantAbsent)
			}
			inPlan := make(map[string]struct{}, len(plan.Delete))
			for _, d := range plan.Delete {
				inPlan[d.Node.Path] = struct{}{}
			}
			for _, d := range got.Delete {
				if _, ok := inPlan[d.Node.Path]; !ok {
					t.Errorf("evict deletes %s, which plan.Delete does not", d.Node.Path)
				}
			}
			if n := len(got.Delete) + len(got.kept) + len(got.absent); n != len(tc.target) {
				t.Errorf("deleted+kept+absent = %d, want |T| = %d", n, len(tc.target))
			}
		})
	}
}
