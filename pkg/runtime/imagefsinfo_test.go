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
	"encoding/json"
	"fmt"
	"maps"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

const (
	fsInfoModelType = "application/vnd.cncf.model.manifest.v1+json"
	fsInfoWasmType  = "application/vnd.wasm.config.v0+json"
)

// putArtifactRecord writes an artifact record of artifactType naming config
// and layers under key, in the shape pkg/artifact writes.
func putArtifactRecord(t *testing.T, rt *Runtime, key, artifactType, config string, layers ...string) {
	t.Helper()
	buf, err := json.Marshal(map[string]any{
		"schema": 1, "key": key, "reference": key, "artifactType": artifactType,
		"configDigest": config, "layerDigests": layers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.index.PutArtifactRecord(context.Background(), key, buf); err != nil {
		t.Fatalf("PutArtifactRecord: %v", err)
	}
}

// TestImageFsInfoSplitsByClass pins the wire half of the per-class store
// accounting: ImageFsInfo reports store_bytes_by_class from the same inventory
// as store_bytes, so the classes always sum to the total, and a class with no
// content is absent rather than reported as zero.
//
// Each row runs against a real store behind the real gRPC server; sizes are
// the byte lengths of the blob contents.
func TestImageFsInfoSplitsByClass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, rt *Runtime)
		want  map[string]uint64
	}{
		{
			name: "image only",
			setup: func(t *testing.T, rt *Runtime) {
				recordIndex(t, rt, "example.test/app:v1", putBlob(t, rt, "image config"), putBlob(t, rt, "image layer 1"))
			},
			want: map[string]uint64{image.ClassImage: 12 + 13},
		},
		{
			name: "model artifact",
			setup: func(t *testing.T, rt *Runtime) {
				putArtifactRecord(t, rt, "example.test/models/a:v1@"+fsInfoModelType, fsInfoModelType,
					putBlob(t, rt, "model config"), putBlob(t, rt, "model shard"))
			},
			want: map[string]uint64{fsInfoModelType: 12 + 11},
		},
		{
			name: "wasm artifact",
			setup: func(t *testing.T, rt *Runtime) {
				putArtifactRecord(t, rt, "example.test/fn/b:v1@"+fsInfoWasmType, fsInfoWasmType,
					putBlob(t, rt, "wasm config"), putBlob(t, rt, "wasm module"))
			},
			want: map[string]uint64{fsInfoWasmType: 11 + 11},
		},
		{
			name: "held by a pod with no record",
			setup: func(t *testing.T, rt *Runtime) {
				held := putBlob(t, rt, "held, never recorded")
				pod, err := image.ParsePodID("pod-held")
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256([]byte("held manifest"))
				if err := rt.index.AddArtifactHoldManifest(context.Background(), pod, image.HeldManifest{
					Digest: fmt.Sprintf("sha256:%x", sum), Config: held, Layers: []string{held},
				}); err != nil {
					t.Fatalf("AddArtifactHoldManifest: %v", err)
				}
			},
			want: map[string]uint64{image.ClassArtifact: 20},
		},
		{
			name: "unattributed stray",
			setup: func(t *testing.T, rt *Runtime) {
				putBlob(t, rt, "stray")
			},
			want: map[string]uint64{image.ClassUnattributed: 5},
		},
		{
			// A blob is one file per digest, so a layer an image and a live
			// model record share counts once, under the record.
			name: "shared between an image and a model",
			setup: func(t *testing.T, rt *Runtime) {
				shared := putBlob(t, rt, "shared weights")
				recordIndex(t, rt, "example.test/app:v1", putBlob(t, rt, "image config"), shared)
				putArtifactRecord(t, rt, "example.test/models/a:v1@"+fsInfoModelType, fsInfoModelType,
					putBlob(t, rt, "model config"), shared)
			},
			want: map[string]uint64{image.ClassImage: 12, fsInfoModelType: 12 + 14},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, rt := imagesTestClient(t)
			tc.setup(t, rt)

			resp, err := client.ImageFsInfo(context.Background(), &runtimev1.ImageFsInfoRequest{})
			if err != nil {
				t.Fatalf("ImageFsInfo: %v", err)
			}
			got := resp.GetStoreBytesByClass()
			if !maps.Equal(got, tc.want) {
				t.Fatalf("store_bytes_by_class = %v; want %v", got, tc.want)
			}
			var sum uint64
			for class, n := range got {
				if n == 0 {
					t.Errorf("class %q reported with zero bytes; an empty class must be absent", class)
				}
				sum += n
			}
			if sum != resp.GetStoreBytes() {
				t.Fatalf("classes sum to %d; store_bytes is %d", sum, resp.GetStoreBytes())
			}
			for _, class := range []string{image.ClassImage, image.ClassArtifact, image.ClassUnattributed, fsInfoModelType, fsInfoWasmType} {
				if _, ok := tc.want[class]; ok {
					continue
				}
				if _, ok := got[class]; ok {
					t.Errorf("empty class %q is present; want it absent", class)
				}
			}
		})
	}
}

// TestImageFsInfoEmptyStore pins a store with no blobs: the call succeeds, the
// split is empty and the total is zero, and the filesystem sample is still
// reported because it comes from statfs of the store root, not from the walk.
func TestImageFsInfoEmptyStore(t *testing.T) {
	client, rt := imagesTestClient(t)
	resp, err := client.ImageFsInfo(context.Background(), &runtimev1.ImageFsInfoRequest{})
	if err != nil {
		t.Fatalf("ImageFsInfo on an empty store: %v", err)
	}
	if got := resp.GetStoreBytesByClass(); len(got) != 0 {
		t.Errorf("store_bytes_by_class = %v; want empty", got)
	}
	if resp.GetStoreBytes() != 0 {
		t.Errorf("store_bytes = %d; want 0", resp.GetStoreBytes())
	}
	if len(resp.GetFilesystems()) != 1 || resp.GetFilesystems()[0].GetMountpoint() != rt.cache.Root() {
		t.Errorf("filesystems = %v; want one sample at the store root", resp.GetFilesystems())
	}
}

// TestImageFsInfoClassFailureFailsCall pins that a store that cannot be classed
// fails the RPC rather than answering with a total beside an empty split. An
// artifact record that does not decode makes the class read fail.
func TestImageFsInfoClassFailureFailsCall(t *testing.T) {
	client, rt := imagesTestClient(t)
	putBlob(t, rt, "some content")
	if err := rt.index.PutArtifactRecord(context.Background(), "example.test/bad:v1", []byte("not json")); err != nil {
		t.Fatalf("PutArtifactRecord: %v", err)
	}
	resp, err := client.ImageFsInfo(context.Background(), &runtimev1.ImageFsInfoRequest{})
	if err == nil {
		t.Fatalf("ImageFsInfo succeeded with an undecodable artifact record: %v", resp)
	}
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("ImageFsInfo code = %v (%v); want Internal", got, err)
	}
	if resp != nil {
		t.Errorf("ImageFsInfo returned a response alongside the error: %v", resp)
	}
}

// TestImageStoreBytesByClassMatchesImageFsInfo pins that the in-process accessor
// and the RPC are one computation: equal map and sum on a seeded store, and both
// fail on a store that cannot be classed.
func TestImageStoreBytesByClassMatchesImageFsInfo(t *testing.T) {
	ctx := context.Background()
	client, rt := imagesTestClient(t)
	recordIndex(t, rt, "example.test/app:v1", putBlob(t, rt, "image config"), putBlob(t, rt, "layer"))
	putBlob(t, rt, "stray")

	resp, err := client.ImageFsInfo(ctx, &runtimev1.ImageFsInfoRequest{})
	if err != nil {
		t.Fatalf("ImageFsInfo: %v", err)
	}
	byClass, sum, err := rt.ImageStoreBytesByClass(ctx)
	if err != nil {
		t.Fatalf("ImageStoreBytesByClass: %v", err)
	}
	if len(byClass) == 0 {
		t.Fatal("ImageStoreBytesByClass returned no classes on a seeded store")
	}
	if !maps.Equal(byClass, resp.GetStoreBytesByClass()) || sum != resp.GetStoreBytes() {
		t.Fatalf("accessor = %v (%d); RPC = %v (%d)", byClass, sum, resp.GetStoreBytesByClass(), resp.GetStoreBytes())
	}

	if err := rt.index.PutArtifactRecord(ctx, "example.test/bad:v1", []byte("not json")); err != nil {
		t.Fatalf("PutArtifactRecord: %v", err)
	}
	if _, err := client.ImageFsInfo(ctx, &runtimev1.ImageFsInfoRequest{}); err == nil {
		t.Error("ImageFsInfo succeeded with an undecodable artifact record")
	}
	if m, n, err := rt.ImageStoreBytesByClass(ctx); err == nil || m != nil || n != 0 {
		t.Errorf("ImageStoreBytesByClass = %v, %d, %v; want nil, 0, error", m, n, err)
	}
}
