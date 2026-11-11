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

// narrowTreesByBacking returns a copy of plan whose DeleteTrees keeps only
// the trees backed entirely by blobs in set: a tree stays condemned iff it
// has at least one Backing digest and every one is in set. It is pure and
// can only shrink: no tree is ever added to DeleteTrees, the kept order is
// the plan's own, and Delete, Keep and KeepTrees are carried over unchanged.
//
// A tree with no Backing (its record is unusable) is dropped, never kept:
// nothing ties it to the blobs being narrowed to, so an empty set condemns
// no tree at all. A nil plan yields nil.
func narrowTreesByBacking(plan *PrunePlan, set map[string]struct{}) *PrunePlan {
	if plan == nil {
		return nil
	}
	out := *plan
	out.DeleteTrees = nil
	for _, d := range plan.DeleteTrees {
		if backedOnlyBy(d.Node, set) {
			out.DeleteTrees = append(out.DeleteTrees, d)
		}
	}
	return &out
}

// backedOnlyBy reports whether n has at least one Backing digest and every
// one is in set.
func backedOnlyBy(n TreeNode, set map[string]struct{}) bool {
	if len(n.Backing) == 0 {
		return false
	}
	for _, dg := range n.Backing {
		if _, ok := set[dg]; !ok {
			return false
		}
	}
	return true
}
