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
)

// TestNarrowTreesByBacking pins the narrowing of a plan's tree deletions to
// the trees backed only by a given blob set: it never adds a tree, never
// touches the blob lists or KeepTrees, and an empty set deletes no tree.
func TestNarrowTreesByBacking(t *testing.T) {
	t.Parallel()

	a, b, c, d := treeDigest("a"), treeDigest("b"), treeDigest("c"), treeDigest("d")
	tree := func(key string, backing ...string) TreeDecision {
		return TreeDecision{Node: TreeNode{Store: TreeStoreUnpacked, Key: key, Kind: TreeKindTree, Backing: backing}, Reason: ReasonDeleteUnreferenced}
	}
	onlyTarget := tree(treeDigest("1"), a, b)
	mixed := tree(treeDigest("2"), a, c)
	other := tree(treeDigest("3"), c, d)
	unusable := TreeDecision{Node: TreeNode{Store: TreeStoreUnpacked, Key: treeDigest("4"), Kind: TreeKindTree, RecordUnusable: true}, Reason: ReasonDeleteUnusableTree}
	kept := tree(treeDigest("5"), a)
	kept.Reason = ReasonKeptInUse
	blobs := []PruneDecision{{Node: BlobNode{Digest: a}, Reason: ReasonDeleteUnreferenced}}
	keepBlobs := []PruneDecision{{Node: BlobNode{Digest: c}, Reason: ReasonKeptInUse}}

	set := func(ds ...string) map[string]struct{} {
		m := make(map[string]struct{}, len(ds))
		for _, dg := range ds {
			m[dg] = struct{}{}
		}
		return m
	}

	tests := []struct {
		name  string
		trees []TreeDecision
		set   map[string]struct{}
		want  []TreeDecision
	}{
		{"a tree backed only by target blobs stays", []TreeDecision{onlyTarget}, set(a, b), []TreeDecision{onlyTarget}},
		{"a tree backed by a non-target blob is removed", []TreeDecision{onlyTarget, mixed}, set(a, b), []TreeDecision{onlyTarget}},
		{"an empty set deletes nothing", []TreeDecision{onlyTarget, mixed, other, unusable}, set(), nil},
		{"a nil set deletes nothing", []TreeDecision{onlyTarget}, nil, nil},
		{"trees of other blobs are untouched by the target", []TreeDecision{other}, set(a, b), nil},
		{"a tree with no backing is never kept", []TreeDecision{unusable, onlyTarget}, set(a, b), []TreeDecision{onlyTarget}},
		{"a superset of a tree's backing keeps it", []TreeDecision{mixed, other}, set(a, b, c, d), []TreeDecision{mixed, other}},
		{"order is the plan's own", []TreeDecision{other, onlyTarget, mixed}, set(a, b, c, d), []TreeDecision{other, onlyTarget, mixed}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan := &PrunePlan{Delete: blobs, Keep: keepBlobs, DeleteTrees: tt.trees, KeepTrees: []TreeDecision{kept}}
			before := append([]TreeDecision(nil), tt.trees...)

			got := narrowTreesByBacking(plan, tt.set)
			if !reflect.DeepEqual(got.DeleteTrees, tt.want) {
				t.Errorf("DeleteTrees = %+v; want %+v", got.DeleteTrees, tt.want)
			}
			if !reflect.DeepEqual(got.Delete, blobs) || !reflect.DeepEqual(got.Keep, keepBlobs) {
				t.Errorf("blob lists changed: Delete %+v Keep %+v", got.Delete, got.Keep)
			}
			if !reflect.DeepEqual(got.KeepTrees, []TreeDecision{kept}) {
				t.Errorf("KeepTrees changed: %+v", got.KeepTrees)
			}
			if !reflect.DeepEqual(plan.DeleteTrees, before) {
				t.Errorf("input plan mutated: %+v", plan.DeleteTrees)
			}
		})
	}

	if narrowTreesByBacking(nil, set(a)) != nil {
		t.Error("nil plan narrowed to non-nil")
	}
}
