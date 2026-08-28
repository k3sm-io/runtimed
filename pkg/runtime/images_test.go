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
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestImagesServedOnTheRuntimeListener is the daemon-side half of the Images
// service's socket posture, and it is the ONLY place that half can be asserted.
//
// images.proto records that the service inherits the daemon's single unix socket
// (0700 dir / 0600 socket, dialable only by the daemon's own uid), but a proto
// file cannot observe what listener anything is registered on — an apis-scope
// test would go green while the daemon quietly served Images on a second,
// world-dialable socket, handing every local uid PruneImages. So this gate
// asserts the co-registration mechanically: ONE grpc.Server carries both
// services, and both answer over ONE connection.
func TestImagesServedOnTheRuntimeListener(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	srv := NewServer(rt)

	// (a) Both services are registered on the SAME *grpc.Server instance.
	info := srv.grpc.GetServiceInfo()
	for _, want := range []string{"k3sm.runtime.v1.Runtime", "k3sm.runtime.v1.Images"} {
		if _, ok := info[want]; !ok {
			t.Fatalf("service %s is not registered on the runtime gRPC server (registered: %v)", want, keysOf(info))
		}
	}

	// (b) And both answer over ONE connection to ONE listener — the property that
	// would still be false if a second grpc.Server had been stood up elsewhere.
	lis := bufconn.Listen(1 << 20)
	ctx, cancel, errc := serveTestServer(t, srv, lis)
	defer func() {
		cancel()
		<-errc
	}()
	cc, err := grpc.NewClient("passthrough:///runtimed",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer cc.Close()

	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	if _, err := runtimev1.NewRuntimeClient(cc).GetRuntimeInfo(rctx, &runtimev1.GetRuntimeInfoRequest{}); err != nil {
		t.Fatalf("Runtime.GetRuntimeInfo over the shared listener: %v", err)
	}
	if _, err := runtimev1.NewImagesClient(cc).ImageFsInfo(rctx, &runtimev1.ImageFsInfoRequest{}); err != nil {
		t.Fatalf("Images.ImageFsInfo over the SAME listener: %v", err)
	}
}

func keysOf(m map[string]grpc.ServiceInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// imagesTestClient stands up the daemon over a bufconn and returns an Images
// client plus the Runtime whose store it serves.
func imagesTestClient(t *testing.T) (runtimev1.ImagesClient, *Runtime) {
	t.Helper()
	rt := newTestRuntime(t, Deps{})
	srv := NewServer(rt)
	lis := bufconn.Listen(1 << 20)
	_, cancel, errc := serveTestServer(t, srv, lis)
	t.Cleanup(func() {
		cancel()
		<-errc
	})
	cc, err := grpc.NewClient("passthrough:///runtimed",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return runtimev1.NewImagesClient(cc), rt
}

// putBlob commits content into rt's store and back-dates it past any grace
// window. It returns the digest.
func putBlob(t *testing.T, rt *Runtime, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := rt.cache.CommitBlob(digest, int64(len(content)), func(w io.Writer) error {
		_, err := io.WriteString(w, content)
		return err
	}); err != nil {
		t.Fatalf("CommitBlob: %v", err)
	}
	p, err := rt.cache.BlobPath(digest)
	if err != nil {
		t.Fatalf("BlobPath: %v", err)
	}
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	return digest
}

// putPod creates a pod dir with a reachability record, as the daemon does.
func putPod(t *testing.T, rt *Runtime, id string, roots ...image.ImageRoot) image.PodID {
	t.Helper()
	pid, err := image.ParsePodID(id)
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	if err := os.MkdirAll(rt.cache.PodRootfs(pid), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := rt.cache.EnsurePodReferences(pid); err != nil {
		t.Fatalf("EnsurePodReferences: %v", err)
	}
	for _, r := range roots {
		if err := rt.cache.RecordPodImage(pid, r); err != nil {
			t.Fatalf("RecordPodImage: %v", err)
		}
	}
	return pid
}

// TestPruneImagesRefusesAndReportsTypedReasons is the wire half of the
// reachability contract: the refusal must FIRE over the RPC, and the response
// must carry the typed per-digest reason the caller needs to see why a blob
// survived — without the daemon exporting its policy.
func TestPruneImagesRefusesAndReportsTypedReasons(t *testing.T) {
	t.Run("a live pod's blob is refused and reported IN_USE", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		live := putBlob(t, rt, "live layer")
		orphan := putBlob(t, rt, "orphan layer")
		putPod(t, rt, "pod-live", image.ImageRoot{Reference: "app:v1", Config: live})

		resp, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{})
		if err != nil {
			t.Fatalf("PruneImages: %v", err)
		}
		if !contains(resp.GetRemovedDigests(), orphan) {
			t.Errorf("the unreferenced blob was not pruned (removed: %v)", resp.GetRemovedDigests())
		}
		if contains(resp.GetRemovedDigests(), live) {
			t.Fatalf("a LIVE pod's blob was pruned over the wire")
		}
		if !rt.cache.Has(live) {
			t.Fatalf("a live pod's blob was unlinked")
		}
		if got := skipReasonFor(resp, live); got != runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE {
			t.Errorf("skip reason for the live blob = %v; want IN_USE", got)
		}
	})

	t.Run("an in-flight lease is reported LEASED", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		inflight := putBlob(t, rt, "in-flight layer")
		putPod(t, rt, "pod-a")
		lease := rt.cache.AcquireLease([]string{inflight}, time.Hour)
		defer lease.Release()

		resp, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{})
		if err != nil {
			t.Fatalf("PruneImages: %v", err)
		}
		if !rt.cache.Has(inflight) {
			t.Fatalf("a leased blob was unlinked over the wire")
		}
		if got := skipReasonFor(resp, inflight); got != runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_LEASED {
			t.Errorf("skip reason for the leased blob = %v; want LEASED", got)
		}
	})

	t.Run("an incomplete root set is FAILED_PRECONDITION and deletes nothing", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		orphan := putBlob(t, rt, "orphan")
		pid := putPod(t, rt, "pod-live", image.ImageRoot{Reference: "app:v1", Config: putBlob(t, rt, "cfg")})
		if err := os.Remove(filepath.Join(rt.cache.PodDir(pid), image.PodReferencesName)); err != nil {
			t.Fatalf("remove record: %v", err)
		}

		_, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("PruneImages err = %v (code %v); want FailedPrecondition", err, status.Code(err))
		}
		if !rt.cache.Has(orphan) {
			t.Errorf("a blob was deleted despite an incomplete root set")
		}
	})

	t.Run("dry run is reported but not executed", func(t *testing.T) {
		client, rt := imagesTestClient(t)
		orphan := putBlob(t, rt, "orphan")
		putPod(t, rt, "pod-a")

		resp, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{DryRun: true})
		if err != nil {
			t.Fatalf("PruneImages: %v", err)
		}
		if !contains(resp.GetRemovedDigests(), orphan) {
			t.Errorf("dry run did not report the reclaimable blob (%v)", resp.GetRemovedDigests())
		}
		if !rt.cache.Has(orphan) {
			t.Fatalf("dry run DELETED a blob")
		}
	})

	t.Run("RemoveImage refuses rather than unrooting a live pod", func(t *testing.T) {
		client, _ := imagesTestClient(t)
		_, err := client.RemoveImage(context.Background(), &runtimev1.RemoveImageRequest{Reference: "app:v1"})
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("RemoveImage err = %v (code %v); want Unimplemented", err, status.Code(err))
		}
	})
}

// TestImagesListAndFsInfo covers the two read RPCs: the listing is assembled
// from the daemon-authored records, and the filesystem info is a raw statfs
// measurement of the store volume.
func TestImagesListAndFsInfo(t *testing.T) {
	client, rt := imagesTestClient(t)
	cfg := putBlob(t, rt, "cfg")
	layer := putBlob(t, rt, "layer")
	putPod(t, rt, "pod-a", image.ImageRoot{Reference: "example.test/app:v1", Config: cfg, Layers: []string{layer}})

	list, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(list.GetImages()) != 1 {
		t.Fatalf("ListImages returned %d images; want 1", len(list.GetImages()))
	}
	got := list.GetImages()[0].GetManifest()
	if got.GetReference() != "example.test/app:v1" || got.GetConfig().GetDigest() != cfg {
		t.Errorf("listed image = %v; want the recorded reference and config digest", got)
	}
	if len(got.GetLayers()) != 1 || got.GetLayers()[0].GetDigest() != layer {
		t.Errorf("listed layers = %v; want the recorded layer digest", got.GetLayers())
	}

	filtered, err := client.ListImages(context.Background(), &runtimev1.ListImagesRequest{Reference: "other:v1"})
	if err != nil {
		t.Fatalf("ListImages(filtered): %v", err)
	}
	if len(filtered.GetImages()) != 0 {
		t.Errorf("reference filter returned %d images; want 0", len(filtered.GetImages()))
	}

	fs, err := client.ImageFsInfo(context.Background(), &runtimev1.ImageFsInfoRequest{})
	if err != nil {
		t.Fatalf("ImageFsInfo: %v", err)
	}
	if len(fs.GetFilesystems()) != 1 {
		t.Fatalf("ImageFsInfo returned %d filesystems; want 1", len(fs.GetFilesystems()))
	}
	u := fs.GetFilesystems()[0]
	if u.GetCapacityBytes() == 0 || u.GetMountpoint() != rt.cache.Root() {
		t.Errorf("filesystem usage = %v; want a real statfs sample at the store root", u)
	}
	if fs.GetStoreBytes() == 0 {
		t.Errorf("store_bytes = 0 with two blobs committed")
	}
}

// TestPodCreateRecordsImageReferences pins the daemon wiring the GC depends on:
// a pod dir must carry a reachability record from the moment it exists, even for
// a pod that pulls nothing. Without it, Roots reports the whole node incomplete
// and the GC stops working entirely.
func TestPodCreateRecordsImageReferences(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-record")})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod rejected: %v", resp.GetError())
	}
	pid, err := image.ParsePodID("pod-record")
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rt.cache.PodDir(pid), image.PodReferencesName)); err != nil {
		t.Fatalf("pod dir carries no reachability record: %v", err)
	}
	// And the node is therefore enumerable — the property the record exists for.
	if _, err := rt.cache.Roots(); err != nil {
		t.Fatalf("Roots after CreatePod: %v", err)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func skipReasonFor(resp *runtimev1.PruneImagesResponse, digest string) runtimev1.PruneSkipReason {
	for _, s := range resp.GetSkipped() {
		if s.GetDigest() == digest {
			return s.GetReason()
		}
	}
	return runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_UNSPECIFIED
}

// TestImageGCTriggersOnDiskPressure pins the TRIGGER, not just the mechanism: a
// running daemon reclaims unreferenced content on its own when the store volume
// drops below the free-space floor, and does not touch a live pod's content
// while doing it. Without this, every other gate here would pass against a GC
// that nothing ever calls.
func TestImageGCTriggersOnDiskPressure(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	live := putBlob(t, rt, "live layer")
	orphan := putBlob(t, rt, "orphan layer")
	putPod(t, rt, "pod-live", image.ImageRoot{Reference: "app:v1", Config: live})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rt.RunImageGC(ctx, time.Millisecond, image.ReclaimConfig{
			HighFreeBytes:   1 << 40, // always under pressure
			TargetFreeBytes: 1 << 40,
			Grace:           time.Nanosecond,
			FreeBytes:       func(string) (uint64, error) { return 0, nil },
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for rt.cache.Has(orphan) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if rt.cache.Has(orphan) {
		t.Fatalf("the GC timer never reclaimed the unreferenced blob")
	}
	if !rt.cache.Has(live) {
		t.Fatalf("the GC timer deleted a live pod's blob")
	}

	// And it stops when its context does — a daemon loop that outlives Serve is a
	// goroutine leak with filesystem side effects.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("RunImageGC did not return after its context was cancelled")
	}
}
