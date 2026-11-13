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
	"sort"
	"testing"
	"time"
)

// TestExportEvictReason pins the mapping from the package's kept reasons to
// the exported vocabulary: every plan reason has exactly one exported value,
// no two share one, and a reason outside the closed set is an error rather
// than a guess.
func TestExportEvictReason(t *testing.T) {
	cases := []struct {
		in      evictReason
		want    EvictKeepReason
		wantErr bool
	}{
		{evictRooted, EvictKeptRooted, false},
		{evictInUse, EvictKeptInUse, false},
		{evictLeased, EvictKeptLeased, false},
		{evictYoung, EvictKeptYoung, false},
		{evictShared, EvictKeptShared, false},
		{"", "", true},
		{"unlink-failed", "", true},
		{"bogus", "", true},
	}
	seen := make(map[EvictKeepReason]evictReason)
	for _, tc := range cases {
		got, err := exportEvictReason(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("exportEvictReason(%q) = %q, nil; want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("exportEvictReason(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%q and %q both map to %q", prev, tc.in, got)
		}
		seen[got] = tc.in
	}
	if _, ok := seen[EvictKeptUnlinkFailed]; ok {
		t.Error("a plan reason maps to unlink-failed; only the executor reports it")
	}
}

// TestEvictPlanResult pins the outcome vocabulary over a plan: every target
// blob lands in exactly one of Removed, Kept and Absent, so removed + kept +
// absent is the target set, and the reclaimed bytes are the summed sizes of
// the removed nodes.
func TestEvictPlanResult(t *testing.T) {
	cfg, l1, shared := node('a', 10, time.Hour), node('b', 20, time.Hour), node('c', 30, time.Hour)
	young, leased, used := node('e', 50, time.Minute), node('f', 60, time.Hour), node('1', 70, time.Hour)
	alias := cfg
	alias.Path = "sha256/.blob-alias"
	gone, gone2 := node('9', 1, time.Hour), node('8', 1, time.Hour)
	del := func(ns ...BlobNode) []PruneDecision {
		var ds []PruneDecision
		for _, n := range ns {
			ds = append(ds, PruneDecision{Node: n, Reason: ReasonDeleteUnreferenced})
		}
		return ds
	}
	plan := &PrunePlan{
		// Out of digest order, so Removed's sort is what orders the result.
		Delete: del(shared, l1, alias, cfg),
		Keep: []PruneDecision{
			{Node: young, Reason: ReasonKeptYoung},
			{Node: leased, Reason: ReasonKeptLeased},
			{Node: used, Reason: ReasonKeptInUse},
		},
	}
	tests := []struct {
		name        string
		target      map[string]struct{}
		others      map[string]struct{}
		roots       *rootSet
		wantRemoved []string
		wantKept    []EvictKept
		wantAbsent  []string
		wantBytes   int64
	}{
		{
			name:   "every outcome at once",
			target: digestSet(cfg, l1, shared, young, leased, used, gone, gone2),
			others: digestSet(shared),
			// cfg has two nodes (an alias path): one digest, both files' bytes.
			wantRemoved: sorted(cfg.Digest, l1.Digest),
			wantKept: sortedKept(
				EvictKept{shared.Digest, EvictKeptShared},
				EvictKept{young.Digest, EvictKeptYoung},
				EvictKept{leased.Digest, EvictKeptLeased},
				EvictKept{used.Digest, EvictKeptInUse},
			),
			wantAbsent: []string{gone2.Digest, gone.Digest},
			wantBytes:  cfg.Size + alias.Size + l1.Size,
		},
		{
			// Written out in digest order rather than through sortedKept, so
			// the order itself is the assertion.
			name:   "several kept digests come back in digest order",
			target: digestSet(shared, young, leased, used),
			others: digestSet(shared),
			wantKept: []EvictKept{
				{used.Digest, EvictKeptInUse},
				{shared.Digest, EvictKeptShared},
				{young.Digest, EvictKeptYoung},
				{leased.Digest, EvictKeptLeased},
			},
		},
		{
			name:     "rooted relabel is carried into the result",
			target:   digestSet(used),
			roots:    &rootSet{artifacts: []ImageRoot{{Layers: []string{used.Digest}}}},
			wantKept: []EvictKept{{used.Digest, EvictKeptRooted}},
		},
		{
			name:       "nothing in the plan is all absent",
			target:     digestSet(gone),
			wantAbsent: []string{gone.Digest},
		},
		{
			name:   "empty target is an empty result",
			target: map[string]struct{}{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ep, err := PlanEvict(plan, tc.target, tc.others)
			if err != nil {
				t.Fatalf("PlanEvict: %v", err)
			}
			if tc.roots != nil {
				ep = refineEvictRooted(ep, tc.roots)
			}
			got, err := ep.result()
			if err != nil {
				t.Fatalf("result: %v", err)
			}
			if !reflect.DeepEqual(nilIfEmpty(got.Removed), nilIfEmpty(tc.wantRemoved)) {
				t.Errorf("Removed = %v; want %v", got.Removed, tc.wantRemoved)
			}
			if !(len(got.Kept) == 0 && len(tc.wantKept) == 0) && !reflect.DeepEqual(got.Kept, tc.wantKept) {
				t.Errorf("Kept = %v; want %v", got.Kept, tc.wantKept)
			}
			if !reflect.DeepEqual(nilIfEmpty(got.Absent), nilIfEmpty(tc.wantAbsent)) {
				t.Errorf("Absent = %v; want %v", got.Absent, tc.wantAbsent)
			}
			if got.ReclaimedBytes != tc.wantBytes {
				t.Errorf("ReclaimedBytes = %d; want %d", got.ReclaimedBytes, tc.wantBytes)
			}
			// The invariant: removed + kept + absent is exactly the target
			// set, each digest in one outcome only.
			union := make(map[string]int)
			for _, d := range got.Removed {
				union[d]++
			}
			for _, k := range got.Kept {
				union[k.Digest]++
			}
			for _, d := range got.Absent {
				union[d]++
			}
			if len(union) != len(tc.target) {
				t.Errorf("removed+kept+absent names %d digests; target has %d", len(union), len(tc.target))
			}
			for d, n := range union {
				if _, ok := tc.target[d]; !ok {
					t.Errorf("outcome names %s, which is not a target blob", d)
				}
				if n != 1 {
					t.Errorf("%s appears in %d outcomes; want exactly one", d, n)
				}
			}
		})
	}
}

// TestEvictPlanResultRefusesAnUnknownReason pins that a kept reason outside
// the closed set fails the result rather than reporting an untyped outcome.
func TestEvictPlanResultRefusesAnUnknownReason(t *testing.T) {
	ep := &EvictPlan{kept: map[string]evictReason{node('a', 1, 0).Digest: "bogus"}}
	if got, err := ep.result(); err == nil {
		t.Fatalf("result = %+v, nil; want an error", got)
	}
	if got, err := (*EvictPlan)(nil).result(); err == nil {
		t.Fatalf("nil plan result = %+v, nil; want an error", got)
	}
}

func sorted(ds ...string) []string {
	sort.Strings(ds)
	return ds
}

func sortedKept(ks ...EvictKept) []EvictKept {
	sort.Slice(ks, func(i, j int) bool { return ks[i].Digest < ks[j].Digest })
	return ks
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
