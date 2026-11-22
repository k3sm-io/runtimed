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

package execshim

import (
	"errors"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestDropShimProductionLookup runs dropShim with a nil group lookup, so it
// judges the drop with supervisor.LookupGroupID asking this Mac: a drop to
// everyone (12), a host-assigned system group only the lookup refuses, is
// refused before the shim chowns or changes identity. euid 0 passes the
// privilege check without the test holding the privilege, since the refusal
// comes before any call on the seam.
func TestDropShimProductionLookup(t *testing.T) {
	r := &recDrop{}
	to := supervisor.Credential{UID: 300, GID: 12, Groups: []int{12}, Drop: true}
	svc := supervisor.ServiceIdentity{UID: 250, GID: 250, Known: true}
	if err := dropShim(r, r.chown, to, 0, svc, nil, "/d"); !errors.Is(err, supervisor.ErrPodGroupRefused) || len(r.calls) != 0 {
		t.Fatalf("drop to everyone (12): err=%v calls=%v, want ErrPodGroupRefused and no calls", err, r.calls)
	}
}
