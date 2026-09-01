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
)

// TestComputeSharePlanIgnoresBoxRootfsPath pins that the share planner derives
// its own pod dir and never reads box.rootfs_path.
//
// This is a STANDING property asserted in shareplan.go's doc comment, and it was
// previously pinned only indirectly, in pkg/runtime, by a case that fed a
// hostile rootfs_path through CreatePod. The runtime now refuses such a box at
// the seam, so that case can no longer reach the planner — which is a tightening
// upstream, but it left this layer's independence unasserted. The planner sits
// below that guard, so if it ever started honoring the field, the runtime check
// would not catch it for a caller that reaches ComputeSharePlan directly.
func TestComputeSharePlanIgnoresBoxRootfsPath(t *testing.T) {
	root := t.TempDir()
	podID := "pod-share-rootfs"
	podDir := filepath.Join(root, "pods", podID)

	// Two boxes identical but for rootfs_path: one empty, one naming a tree the
	// planner must never share.
	hostile := filepath.Join(root, "server")
	for _, tc := range []struct {
		name       string
		rootfsPath string
	}{
		{"empty rootfs_path", ""},
		{"hostile rootfs_path naming the control-plane state dir", hostile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box := &runtimev1.PodBox{PodId: podID, RootfsPath: tc.rootfsPath}
			plan, err := ComputeSharePlan(box, podDir, root, planClass(root))
			if err != nil {
				t.Fatalf("ComputeSharePlan: %v", err)
			}
			if len(plan.Shares) == 0 {
				t.Fatal("no shares planned; the table cannot distinguish derivation from an empty plan")
			}
			for _, sh := range plan.Shares {
				if sh.Root == hostile || strings.HasPrefix(sh.Root, hostile+string(filepath.Separator)) {
					t.Errorf("share root %q derives from box.rootfs_path; the planner must derive its own pod dir", sh.Root)
				}
				if sh.Root != podDir && !IsStrictlyUnder(sh.Root, podDir) {
					t.Errorf("share root %q is outside the pod dir %q", sh.Root, podDir)
				}
			}
		})
	}
}
