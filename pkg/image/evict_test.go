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
	"strings"
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
	dupKept := node('g', 80, time.Hour)
	dupKeptAlias := dupKept
	dupKeptAlias.Path = "sha256/.blob-dup"
	unknown := node('h', 90, time.Hour)
	emptyDigest := BlobNode{Path: "sha256/.blob-0", Kind: BlobKindContent, Size: 1}
	tests := []struct {
		name string
		// plan overrides the shared plan when set; nilPlan passes nil.
		plan       *PrunePlan
		nilPlan    bool
		wantErr    bool
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
		{
			name: "digest with nodes in both keep and delete is kept, not evicted",
			plan: &PrunePlan{
				Delete: del(dupKeptAlias),
				Keep:   []PruneDecision{{Node: dupKept, Reason: ReasonKeptInUse}},
			},
			target:   digestSet(dupKept),
			wantKept: map[string]evictReason{dupKept.Digest: evictInUse},
		},
		{
			name: "keep entry with a non-keep reason is an error",
			plan: &PrunePlan{
				Keep: []PruneDecision{{Node: cfg, Reason: ReasonDeleteUnreferenced}},
			},
			target:  digestSet(cfg),
			wantErr: true,
		},
		{
			name:    "nil plan is an error",
			nilPlan: true,
			target:  digestSet(cfg),
			wantErr: true,
		},
		{
			name: "unknown provenance is kept as rooted",
			plan: &PrunePlan{
				Keep: []PruneDecision{{Node: unknown, Reason: ReasonKeptUnknownProvenance}},
			},
			target:   digestSet(unknown),
			wantKept: map[string]evictReason{unknown.Digest: evictRooted},
		},
		{
			name:     "digest in others and kept by prune reports the prune verdict",
			target:   digestSet(young),
			others:   digestSet(young),
			wantKept: map[string]evictReason{young.Digest: evictYoung},
		},
		{
			name: "delete node with an empty digest never matches the target",
			plan: &PrunePlan{
				Delete: []PruneDecision{{Node: emptyDigest, Reason: ReasonDeleteStaleTemp}},
			},
			target:     map[string]struct{}{"": {}},
			wantAbsent: []string{""},
		},
		{
			// A nil others means "no other manifest names anything". PlanEvict
			// cannot tell that from a caller that forgot to compute it, so the
			// caller must pass the complete set of blobs other cached manifests
			// name; otherwise a shared blob is evicted. Fail closed at the
			// caller: an incomplete others is a caller bug.
			name:       "nil others with a blob prune would delete deletes it",
			target:     digestSet(cfg),
			others:     nil,
			wantDelete: del(cfg),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := plan
			if tc.plan != nil {
				p = tc.plan
			}
			if tc.nilPlan {
				p = nil
			}
			got, err := PlanEvict(p, tc.target, tc.others)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("PlanEvict: got nil error, want one (plan %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("PlanEvict: %v", err)
			}
			if !reflect.DeepEqual(got.Delete, tc.wantDelete) {
				t.Errorf("Delete = %v, want %v", got.Delete, tc.wantDelete)
			}
			if !(len(got.kept) == 0 && len(tc.wantKept) == 0) && !reflect.DeepEqual(got.kept, tc.wantKept) {
				t.Errorf("kept = %v, want %v", got.kept, tc.wantKept)
			}
			if !(len(got.absent) == 0 && len(tc.wantAbsent) == 0) && !reflect.DeepEqual(got.absent, tc.wantAbsent) {
				t.Errorf("absent = %v, want %v", got.absent, tc.wantAbsent)
			}
			inPlan := make(map[string]struct{}, len(p.Delete))
			for _, d := range p.Delete {
				inPlan[d.Node.Digest] = struct{}{}
			}
			for _, d := range got.Delete {
				if _, ok := inPlan[d.Node.Digest]; !ok {
					t.Errorf("evict deletes %s, which plan.Delete does not", d.Node.Digest)
				}
			}
			if n := len(got.Delete) + len(got.kept) + len(got.absent); n != len(tc.target) {
				t.Errorf("deleted+kept+absent = %d, want |T| = %d", n, len(tc.target))
			}
		})
	}
}

// TestRefineEvictRooted pins the refinement over the classified roots: a blob
// kept in use that an operator root or artifact record names becomes rooted,
// nothing else changes, and no blob ever moves between kept and Delete.
func TestRefineEvictRooted(t *testing.T) {
	used, other := node('1', 10, time.Hour), node('2', 20, time.Hour)
	gone := node('3', 30, time.Hour)
	leased, shared := node('4', 40, time.Hour), node('5', 50, time.Hour)
	root := func(ds ...string) []ImageRoot { return []ImageRoot{{Reference: "r", Layers: ds}} }
	base := func() *EvictPlan {
		return &EvictPlan{
			Delete: []PruneDecision{{Node: gone, Reason: ReasonDeleteUnreferenced}},
			kept: map[string]evictReason{
				used.Digest:   evictInUse,
				other.Digest:  evictInUse,
				leased.Digest: evictLeased,
				shared.Digest: evictShared,
			},
			absent: []string{"sha256:" + strings.Repeat("9", 64)},
		}
	}
	keptWith := func(over map[string]evictReason) map[string]evictReason {
		k := base().kept
		for d, r := range over {
			k[d] = r
		}
		return k
	}
	cases := []struct {
		name  string
		plan  func() *EvictPlan
		roots *rootSet
		want  map[string]evictReason
	}{
		{"operator root only", base, &rootSet{operator: root(used.Digest)},
			keptWith(map[string]evictReason{used.Digest: evictRooted})},
		{"artifact record only", base, &rootSet{artifacts: root(used.Digest)},
			keptWith(map[string]evictReason{used.Digest: evictRooted})},
		{"in use only", base, &rootSet{pods: root(used.Digest), holds: root(other.Digest)}, keptWith(nil)},
		{"both rooted and in use", base, &rootSet{pods: root(used.Digest), operator: root(used.Digest)},
			keptWith(map[string]evictReason{used.Digest: evictRooted})},
		{"neither", base, &rootSet{operator: root(node('8', 1, 0).Digest)}, keptWith(nil)},
		{"empty digest", func() *EvictPlan {
			p := base()
			p.kept[""] = evictInUse
			return p
		}, &rootSet{operator: root(""), artifacts: root("")}, keptWith(map[string]evictReason{"": evictInUse})},
		{"nil roots", base, nil, keptWith(nil)},
		{"rooted delete stays deleted", base, &rootSet{operator: root(gone.Digest)}, keptWith(nil)},
		{"other reasons untouched", base, &rootSet{operator: root(leased.Digest, shared.Digest)}, keptWith(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.plan()
			before := tc.plan()
			got := refineEvictRooted(in, tc.roots)
			if !reflect.DeepEqual(got.kept, tc.want) {
				t.Errorf("kept = %v; want %v", got.kept, tc.want)
			}
			// Relabel only: Delete and absent are unchanged, and the input is
			// not mutated.
			if !reflect.DeepEqual(got.Delete, before.Delete) || !reflect.DeepEqual(got.absent, before.absent) {
				t.Errorf("Delete/absent changed: %v %v; want %v %v", got.Delete, got.absent, before.Delete, before.absent)
			}
			if !reflect.DeepEqual(in, before) {
				t.Errorf("input plan mutated: %#v", in)
			}
		})
	}
	if refineEvictRooted(nil, &rootSet{}) != nil {
		t.Error("nil plan refined to non-nil")
	}
}
