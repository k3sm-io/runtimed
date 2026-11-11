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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestEvictEmptyTargetIsNotInUse pins that a target naming no blobs is never
// refused IMAGE_IN_USE (a retryable refusal with no pod to wait for): it
// reaches Cache.Evict, whose empty-target error stays INTERNAL with no
// ErrorInfo detail, for a forced call and a dry run alike.
func TestEvictEmptyTargetIsNotInUse(t *testing.T) {
	s := newEvictRPCScene(t)
	ref := "registry.test/evict/empty:v1"
	s.entry(ref, "empty", "")
	for _, force := range []bool{false, true} {
		_, err := s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Reference: ref, Force: force})
		st := status.Convert(err)
		if st.Code() != codes.Internal {
			t.Fatalf("EvictImage(empty, force=%v) = %v, want INTERNAL", force, err)
		}
		if len(st.Details()) != 0 {
			t.Errorf("EvictImage(empty, force=%v) details = %v, want none", force, st.Details())
		}
	}
}
