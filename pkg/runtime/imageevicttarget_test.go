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
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
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

// evictArtifact is an artifact D recorded only in the artifact namespace (no
// image index entry names it), with its view planted, beside the RPC scene's
// two images.
type evictArtifact struct {
	ref, typ, key string
	manifest      string
	config, layer string
	view          string
}

func (s *evictRPCScene) artifactD() *evictArtifact {
	s.t.Helper()
	sum := sha256.Sum256([]byte(`{"schemaVersion":2,"fixture":"evict-rpc-D"}`))
	d := &evictArtifact{
		ref: "registry.test/evict/d:v1", typ: "application/vnd.test.artifact",
		manifest: "sha256:" + hex.EncodeToString(sum[:]),
		config:   putBlob(s.t, s.rt, "evict-rpc-cfg-d"), layer: putBlob(s.t, s.rt, "evict-rpc-layer-d"),
	}
	d.key = artifact.Key(d.ref, d.typ)
	s.putRecord(d.ref, d.typ, d.manifest, d.config, d.layer)
	d.view = s.view(d.manifest)
	return d
}

// putRecord writes a live artifact record of the shape pkg/artifact writes.
func (s *evictRPCScene) putRecord(ref, typ, manifest, config string, layers ...string) {
	s.t.Helper()
	buf, err := json.Marshal(artifact.Record{
		Schema: 1, Key: artifact.Key(ref, typ), Reference: ref, ArtifactType: typ,
		ManifestDigest: manifest, ConfigDigest: config, LayerDigests: layers,
	})
	if err != nil {
		s.t.Fatal(err)
	}
	if err := s.rt.index.PutArtifactRecord(context.Background(), artifact.Key(ref, typ), buf); err != nil {
		s.t.Fatalf("put record %s: %v", ref, err)
	}
}

func (s *evictRPCScene) evictDigest(d string) *runtimev1.EvictImageResponse {
	s.t.Helper()
	resp, err := s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Digest: d, Force: true})
	if err != nil {
		s.t.Fatalf("EvictImage(%s): %v", d, err)
	}
	if resp.GetManifestDigest() != d {
		s.t.Errorf("manifest_digest = %q, want %q", resp.GetManifestDigest(), d)
	}
	return resp
}

func present(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// TestEvictArtifactByDigestWhileRecorded pins that a digest only a live
// artifact record names resolves (not NOT_FOUND) and that the record, a root,
// keeps every blob and the view.
func TestEvictArtifactByDigestWhileRecorded(t *testing.T) {
	s := newEvictRPCScene(t)
	d := s.artifactD()
	resp := s.evictDigest(d.manifest)
	if len(resp.GetRemovedDigests()) != 0 {
		t.Errorf("removed = %v, want none while the record is live", resp.GetRemovedDigests())
	}
	if len(resp.GetKept()) != 2 {
		t.Errorf("kept = %v, want both of D's blobs", resp.GetKept())
	}
	if !s.rt.cache.Has(d.config) || !s.rt.cache.Has(d.layer) || !present(d.view) {
		t.Error("a live record's blobs or view were removed")
	}
}

// TestEvictReleasedArtifactByDigest pins that a digest named only by a
// released copy resolves through FileIndex.ReleasedArtifact: its blobs are
// unlinked and its view removed. A pod hold on the manifest keeps the view:
// a hold naming D's blobs refuses the call IMAGE_IN_USE with nothing touched,
// and a hold naming D's manifest but none of D's blobs lets the blobs go and
// still keeps the view (the view removal's own hold guard).
func TestEvictReleasedArtifactByDigest(t *testing.T) {
	for _, tc := range []struct {
		name string
		hold func(d *evictArtifact, s *evictRPCScene) *image.HeldManifest
	}{
		{name: "no hold", hold: func(*evictArtifact, *evictRPCScene) *image.HeldManifest { return nil }},
		{name: "hold on its blobs", hold: func(d *evictArtifact, _ *evictRPCScene) *image.HeldManifest {
			return &image.HeldManifest{Digest: d.manifest, Config: d.config, Layers: []string{d.layer}}
		}},
		{name: "hold on its manifest only", hold: func(d *evictArtifact, s *evictRPCScene) *image.HeldManifest {
			return &image.HeldManifest{Digest: d.manifest, Config: s.cfgB, Layers: []string{s.ownB}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEvictRPCScene(t)
			d := s.artifactD()
			if ok, err := s.rt.index.RemoveArtifactRecordIf(context.Background(), d.key, nil); err != nil || !ok {
				t.Fatalf("release record: %v, %v", ok, err)
			}
			if _, _, found, err := s.rt.index.ReleasedArtifact(d.manifest); err != nil || !found {
				t.Fatalf("no released copy: %v, %v", found, err)
			}
			h := tc.hold(d, s)
			if h != nil {
				pid, err := image.ParsePodID("evictpod")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.rt.index.AddArtifactHoldManifest(context.Background(), pid, *h); err != nil {
					t.Fatalf("hold: %v", err)
				}
			}
			req := &runtimev1.EvictImageRequest{Digest: d.manifest, Force: true}
			resp, err := s.client.EvictImage(context.Background(), req)
			wantGone := tc.name != "hold on its blobs"
			if wantGone {
				if err != nil || resp.GetManifestDigest() != d.manifest {
					t.Fatalf("EvictImage = %v, %v; want OK for %s", resp, err, d.manifest)
				}
			} else if !hasReason(err, runtimev1.EvictReasonImageInUse) {
				t.Fatalf("EvictImage = %v, want IMAGE_IN_USE", err)
			}
			if gone := !s.rt.cache.Has(d.config) && !s.rt.cache.Has(d.layer); gone != wantGone {
				t.Errorf("D's blobs gone = %v, want %v", gone, wantGone)
			}
			if wantView := h != nil; present(d.view) != wantView {
				t.Errorf("D's view present = %v, want %v", present(d.view), wantView)
			}
			if !present(s.viewA) || !s.rt.cache.Has(s.cfgA) || !s.rt.cache.Has(s.cfgB) {
				t.Error("evicting D touched image A or B")
			}
		})
	}
}

// hasReason reports whether err is FAILED_PRECONDITION with an ErrorInfo of
// reason.
func hasReason(err error, reason string) bool {
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition {
		return false
	}
	for _, x := range st.Details() {
		if info, ok := x.(*errdetails.ErrorInfo); ok && info.GetReason() == reason {
			return true
		}
	}
	return false
}

// TestEvictTargetNamedByNoSource pins NOT_FOUND only when no index entry,
// live record or released copy names the target, by digest and by reference.
func TestEvictTargetNamedByNoSource(t *testing.T) {
	s := newEvictRPCScene(t)
	s.artifactD()
	sum := sha256.Sum256([]byte("evict-rpc-nobody"))
	for _, req := range []*runtimev1.EvictImageRequest{
		{Digest: "sha256:" + hex.EncodeToString(sum[:]), Force: true},
		{Reference: "registry.test/evict/nobody:v1", Force: true},
	} {
		if _, err := s.client.EvictImage(context.Background(), req); status.Code(err) != codes.NotFound {
			t.Errorf("EvictImage(%v) = %v, want NOT_FOUND", req, err)
		}
	}
}

// TestEvictArtifactByReference pins the by-reference fall-through to the live
// records, and REFERENCE_AMBIGUOUS when the index entry and a record name the
// same reference with different manifests.
func TestEvictArtifactByReference(t *testing.T) {
	s := newEvictRPCScene(t)
	d := s.artifactD()
	resp, err := s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Reference: d.ref})
	if err != nil || resp.GetManifestDigest() != d.manifest {
		t.Fatalf("EvictImage(%s) = %v, %v; want manifest %s", d.ref, resp, err, d.manifest)
	}

	s.putRecord(s.refA, "application/vnd.test.other", d.manifest, d.config, d.layer)
	_, err = s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Reference: s.refA})
	if !hasReason(err, runtimev1.EvictReasonReferenceAmbiguous) {
		t.Errorf("EvictImage(%s) = %v, want REFERENCE_AMBIGUOUS", s.refA, err)
	}
}
