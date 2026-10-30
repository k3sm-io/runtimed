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

package runtime

import (
	"testing"

	"k3sm.io/apis/k3smtest/runtimecontract"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRuntimeContract runs the shared runtime/v1 contract suite against this
// daemon's real gRPC surface, over fake subsystem seams (no root, no real
// sandbox), so the fields the node acts on are checked here once rather than
// re-proved by every end-to-end test that crosses the seam.
func TestRuntimeContract(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	runtimecontract.RunRuntimeContract(t, runtimecontract.RuntimeContract{
		Client: runtimecontract.ServeRuntime(t, rt),
		Pod:    func(id string) *runtimev1.PodBox { return hostBinBox(rt, id) },
	})
}
