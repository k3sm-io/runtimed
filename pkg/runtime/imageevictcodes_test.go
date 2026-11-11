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
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
)

// TestEvictImageRejectsMalformedRequests pins, through the RPC, that every
// malformed request is INVALID_ARGUMENT with no ErrorInfo detail and leaves
// the scene's on-disk state unchanged, forced or not.
func TestEvictImageRejectsMalformedRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func(s *evictRPCScene) *runtimev1.EvictImageRequest
	}{
		{name: "reference and digest", req: func(s *evictRPCScene) *runtimev1.EvictImageRequest {
			return &runtimev1.EvictImageRequest{Reference: s.refA, Digest: s.manA}
		}},
		{name: "neither", req: func(*evictRPCScene) *runtimev1.EvictImageRequest {
			return &runtimev1.EvictImageRequest{}
		}},
		{name: "platform beside a digest", req: func(s *evictRPCScene) *runtimev1.EvictImageRequest {
			return &runtimev1.EvictImageRequest{Digest: s.manA, Platform: &runtimev1.Platform{Os: "linux", Architecture: "arm64"}}
		}},
		{name: "malformed digest", req: func(*evictRPCScene) *runtimev1.EvictImageRequest {
			return &runtimev1.EvictImageRequest{Digest: "sha256:not-hex"}
		}},
		{name: "more than MaxEvictBlobs blobs", req: func(s *evictRPCScene) *runtimev1.EvictImageRequest {
			// The bound is checked before any blob is read, so the layers
			// need no blob files.
			layers := make([]string, image.MaxEvictBlobs)
			for i := range layers {
				sum := sha256.Sum256([]byte("evict-codes-layer-" + strconv.Itoa(i)))
				layers[i] = "sha256:" + hex.EncodeToString(sum[:])
			}
			ref := "registry.test/evict/huge:v1"
			s.entry(ref, "huge", s.cfgA, layers...)
			return &runtimev1.EvictImageRequest{Reference: ref}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEvictRPCScene(t)
			req := tc.req(s)
			before := s.state()
			for _, force := range []bool{false, true} {
				req.Force = force
				_, err := s.client.EvictImage(context.Background(), req)
				st := status.Convert(err)
				if st.Code() != codes.InvalidArgument {
					t.Errorf("EvictImage(force=%v) = %v, want INVALID_ARGUMENT", force, err)
				}
				if len(st.Details()) != 0 {
					t.Errorf("EvictImage(force=%v) details = %v, want none", force, st.Details())
				}
				diffState(t, "after the refusal", s.state(), before)
			}
		})
	}
}

// TestEvictImageFailsClosed pins, through the RPC, the refusals that fail
// closed: each returns its code (and reason, where one is named) with nothing
// unlinked and no view removed, forced or not.
func TestEvictImageFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		call       func(s *evictRPCScene) (context.Context, *runtimev1.EvictImageRequest)
		wantCode   codes.Code
		wantReason string
	}{
		{name: "entry with no retained manifest digest", wantCode: codes.FailedPrecondition,
			call: func(s *evictRPCScene) (context.Context, *runtimev1.EvictImageRequest) {
				ref := "registry.test/evict/old:v1"
				if err := s.rt.index.Record(context.Background(), image.IndexEntry{
					Reference: ref, Platform: image.Platform{OS: "linux", Architecture: "arm64"},
					Manifest: &runtimev1.ImageManifest{Reference: ref, Config: &runtimev1.Descriptor{Digest: s.cfgA, Size: 1},
						Layers: []*runtimev1.Descriptor{{Digest: s.ownA, Size: 1}}},
				}); err != nil {
					s.t.Fatalf("record %s: %v", ref, err)
				}
				return context.Background(), &runtimev1.EvictImageRequest{Reference: ref}
			}},
		{name: "incomplete root set", wantCode: codes.FailedPrecondition, wantReason: runtimev1.EvictReasonRootsIncomplete,
			call: func(s *evictRPCScene) (context.Context, *runtimev1.EvictImageRequest) {
				if err := s.rt.index.PutArtifactRecord(context.Background(),
					artifact.Key("registry.test/evict/corrupt:v1", "application/vnd.test.artifact"), []byte("{not json")); err != nil {
					s.t.Fatal(err)
				}
				return context.Background(), &runtimev1.EvictImageRequest{Reference: s.refA}
			}},
		{name: "records naming different manifests", wantCode: codes.FailedPrecondition,
			wantReason: runtimev1.EvictReasonReferenceAmbiguous,
			call: func(s *evictRPCScene) (context.Context, *runtimev1.EvictImageRequest) {
				ref := "registry.test/evict/amb:v1"
				s.putRecord(ref, "application/vnd.test.one", s.manA, s.cfgA, s.ownA)
				s.putRecord(ref, "application/vnd.test.two", s.manB, s.cfgB, s.ownB)
				return context.Background(), &runtimev1.EvictImageRequest{Reference: ref}
			}},
		{name: "context cancelled before the call", wantCode: codes.Canceled,
			call: func(s *evictRPCScene) (context.Context, *runtimev1.EvictImageRequest) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, &runtimev1.EvictImageRequest{Reference: s.refA}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEvictRPCScene(t)
			ctx, req := tc.call(s)
			before := s.state()
			for _, force := range []bool{false, true} {
				req.Force = force
				_, err := s.client.EvictImage(ctx, req)
				st := status.Convert(err)
				if st.Code() != tc.wantCode {
					t.Errorf("EvictImage(force=%v) = %v, want %v", force, err, tc.wantCode)
				}
				if tc.wantReason != "" {
					if !hasReason(err, tc.wantReason) {
						t.Errorf("EvictImage(force=%v) = %v, want reason %s", force, err, tc.wantReason)
					}
				} else if len(st.Details()) != 0 {
					t.Errorf("EvictImage(force=%v) details = %v, want none", force, st.Details())
				}
				diffState(t, "after the refusal", s.state(), before)
			}
		})
	}
}
