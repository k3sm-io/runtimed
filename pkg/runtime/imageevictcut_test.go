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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestEvictImageCutLiveConverges cuts a real forced eviction of image A while
// it runs, pins what the cut pass itself returns and leaves on disk, then
// re-runs it and pins that the re-run ends in the state
// TestEvictImageRemovesOnlyTheNamedImage expects (wantEvicted).
//
// The two view-hook rows are driven below the gRPC handler: the handler wires
// ReclaimConfig.EvictDerived from Runtime.viewEvictor with no seam to wrap it,
// and swapping the views of a serving Runtime races its startup, so those rows
// call Cache.Evict with the handler's config (Log, UntrackedPod, the target's
// blobs) and a wrapped hook, as TestEvictViewEvictorNilWithoutHoldSource does.
// The unlink row needs no hook and runs through the EvictImage RPC: the blob
// directory is made read-only so every unlink of A's own blobs fails, then
// restored before the re-run (skipped as root, which ignores the mode).
func TestEvictImageCutLiveConverges(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, s *evictRPCScene)
	}{
		{name: "view hook fails after the unlinks", run: cutViewHookFails},
		{name: "context cancelled inside the view hook", run: cutViewHookCancels},
		{name: "blob unlink refused", run: cutUnlinkRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEvictRPCScene(t)
			tc.run(t, s)
		})
	}
}

// evictDirect runs Cache.Evict over A as the forced handler configures it,
// with hook as EvictDerived.
func (s *evictRPCScene) evictDirect(ctx context.Context, hook func(context.Context, string) error) (*image.EvictResult, error) {
	return s.rt.cache.Evict(ctx, s.manA, []string{s.cfgA, s.ownA, s.shared}, image.ReclaimConfig{
		Log: s.rt.log, UntrackedPod: s.rt.podUntracked, EvictDerived: hook,
	})
}

// sortedA is A's own blobs, sorted, as EvictResult lists them.
func (s *evictRPCScene) sortedA() []string {
	out := []string{s.cfgA, s.ownA}
	slices.Sort(out)
	return out
}

// rerunConverges re-runs the eviction with the real view hook and pins the
// final state, then a further RPC run removes nothing and keeps it.
func rerunConverges(t *testing.T, s *evictRPCScene) {
	t.Helper()
	viewHook := s.rt.viewEvictor()
	if viewHook == nil {
		t.Fatal("the test runtime has a nil view evictor")
	}
	if _, err := s.evictDirect(context.Background(), viewHook); err != nil {
		t.Fatalf("re-run Evict: %v", err)
	}
	diffState(t, "after the re-run", s.state(), wantEvicted())
	if resp := s.evict(true); len(resp.GetRemovedDigests()) != 0 {
		t.Errorf("a converged RPC re-run removed %v", resp.GetRemovedDigests())
	}
	diffState(t, "after a further RPC run", s.state(), wantEvicted())
}

// cutViewHookFails: the hook refuses after the blobs are unlinked. The pass
// only logs that refusal: it returns no error and a result naming both of
// A's own blobs removed, and A's view is still on disk.
func cutViewHookFails(t *testing.T, s *evictRPCScene) {
	called := false
	res, err := s.evictDirect(context.Background(), func(context.Context, string) error {
		called = true
		return errors.New("cut: view removal refused")
	})
	if err != nil {
		t.Fatalf("cut pass: err = %v, want nil (a view refusal is only logged)", err)
	}
	if !called {
		t.Fatal("cut pass never ran the view hook")
	}
	if !slices.Equal(res.Removed, s.sortedA()) {
		t.Errorf("cut pass: removed = %v, want %v", res.Removed, s.sortedA())
	}
	want := wantEvicted()
	want["view A"] = true
	diffState(t, "after the cut pass", s.state(), want)
	rerunConverges(t, s)
}

// cutViewHookCancels: the hook cancels the call's context, then runs the real
// view removal under it. The pass does not re-check the context after the
// hook: it returns no error and a result naming both of A's own blobs removed,
// and the cancelled view removal leaves A's view on disk.
func cutViewHookCancels(t *testing.T, s *evictRPCScene) {
	viewHook := s.rt.viewEvictor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var herr error
	res, err := s.evictDirect(ctx, func(ctx context.Context, m string) error {
		cancel()
		herr = viewHook(ctx, m)
		return herr
	})
	if err != nil {
		t.Fatalf("cut pass: err = %v, want nil", err)
	}
	if !errors.Is(herr, context.Canceled) {
		t.Errorf("view removal under a cancelled context: err = %v, want context.Canceled", herr)
	}
	if !slices.Equal(res.Removed, s.sortedA()) {
		t.Errorf("cut pass: removed = %v, want %v", res.Removed, s.sortedA())
	}
	want := wantEvicted()
	want["view A"] = true
	diffState(t, "after the cut pass", s.state(), want)
	rerunConverges(t, s)
}

// cutUnlinkRefused: A's own blobs cannot be unlinked (their directory is
// read-only). The RPC answers INTERNAL for the kept unlink-failed blobs and
// every blob is still present, but A's view was removed; restoring the mode,
// the re-run converges.
func cutUnlinkRefused(t *testing.T, s *evictRPCScene) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	p, err := s.rt.cache.BlobPath(s.cfgA)
	if err != nil {
		t.Fatalf("BlobPath: %v", err)
	}
	dir := filepath.Dir(p)
	if q, _ := s.rt.cache.BlobPath(s.ownA); filepath.Dir(q) != dir {
		t.Fatalf("A's own blobs live in different directories: %s, %s", dir, filepath.Dir(q))
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat blob dir: %v", err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod blob dir: %v", err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := os.Chmod(dir, fi.Mode().Perm()); err != nil {
				t.Fatalf("restore blob dir: %v", err)
			}
		}
	}
	t.Cleanup(restore)
	_, err = s.client.EvictImage(context.Background(), &runtimev1.EvictImageRequest{Reference: s.refA, Force: true})
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("cut pass: code = %v (err %v), want Internal", got, err)
	}
	want := wantEvicted()
	// Cache.Evict reports the kept unlink-failed blobs without an error, so
	// the view hook still ran: A's view is gone though its blobs are not.
	want["blob cfgA"], want["blob ownA"] = true, true
	diffState(t, "after the cut pass", s.state(), want)
	restore()
	rerunConverges(t, s)
}
