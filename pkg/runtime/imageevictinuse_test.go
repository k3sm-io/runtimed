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
	"context"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestEvictImageInUseByPodUnlinksNothing pins the handler end of the in-use
// refusal: a pod record written by the runtime's own writer (recordPodImage)
// for image A names all of A's blobs, so a forced EvictImage of A is
// FAILED_PRECONDITION IMAGE_IN_USE and unlinks no blob and removes no view.
func TestEvictImageInUseByPodUnlinksNothing(t *testing.T) {
	s := newEvictRPCScene(t)
	ent, err := s.rt.index.Resolve(context.Background(), s.refA, nil)
	if err != nil {
		t.Fatalf("resolve A: %v", err)
	}
	if err := s.rt.recordPodImage("evictinusepod", ent.Manifest); err != nil {
		t.Fatalf("recordPodImage: %v", err)
	}
	before := s.state()
	_, err = s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Reference: s.refA, Force: true})
	if !hasReason(err, runtimev1.EvictReasonImageInUse) {
		t.Fatalf("EvictImage = %v, want FAILED_PRECONDITION IMAGE_IN_USE", err)
	}
	diffState(t, "after the refused eviction", s.state(), before)
}
