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

package mount

import (
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/internal/testwire"
)

// TestComputeSharePlanIgnoresBoxRootfsPath pins that the share planner derives
// its own pod dir and never reads the retired PodBox field 4 (a caller-supplied
// rootfs path an old producer may still send).
//
// This is a STANDING property asserted in shareplan.go's doc comment. The
// runtime ignores the field too, but the planner sits below the runtime, so a
// caller that reaches ComputeSharePlan directly is covered only here. The
// hostile box is built on the wire, so this pin holds while the schema still
// declares field 4 and after it is removed.
func TestComputeSharePlanIgnoresBoxRootfsPath(t *testing.T) {
	root := t.TempDir()
	podID := "pod-share-rootfs"
	podDir := filepath.Join(root, "pods", podID)

	// Two boxes identical but for field 4: one without it, one naming a tree
	// the planner must never share.
	hostile := filepath.Join(root, "server")
	for _, tc := range []struct {
		name string
		box  *runtimev1.PodBox
	}{
		{"no field 4", &runtimev1.PodBox{PodId: podID}},
		{"field 4 naming the control-plane state dir", testwire.WithWireField4(t, &runtimev1.PodBox{PodId: podID}, hostile)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box := tc.box
			plan, err := ComputeSharePlan(box, podDir, root, planClass(root))
			if err != nil {
				t.Fatalf("ComputeSharePlan: %v", err)
			}
			if len(plan.Shares) == 0 {
				t.Fatal("no shares planned; the table cannot distinguish derivation from an empty plan")
			}
			for _, sh := range plan.Shares {
				if sh.Root == hostile || strings.HasPrefix(sh.Root, hostile+string(filepath.Separator)) {
					t.Errorf("share root %q derives from field 4; the planner must derive its own pod dir", sh.Root)
				}
				if sh.Root != podDir && !IsStrictlyUnder(sh.Root, podDir) {
					t.Errorf("share root %q is outside the pod dir %q", sh.Root, podDir)
				}
			}
		})
	}
}
