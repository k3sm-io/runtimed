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
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestCreatePodStartsFromAnEmptyRootfs pins that a create never inherits what
// an earlier life of the pod id left in its rootfs: the stale entries are
// cleared without following a symlink out of the pod dir, and only the rootfs
// entry is cleared, so the pod dir's other records survive.
func TestCreatePodStartsFromAnEmptyRootfs(t *testing.T) {
	const podID = "pod-stale"
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})

	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(podDir, "rootfs")
	staleFile := filepath.Join(rootfs, "stale")
	staleDir := filepath.Join(rootfs, "nested", "deeper")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "f"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(t.TempDir(), "canary")
	if err := os.Mkdir(canary, 0o755); err != nil {
		t.Fatal(err)
	}
	canaryFile := filepath.Join(canary, "keep")
	if err := os.WriteFile(canaryFile, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(rootfs, "escape")); err != nil {
		t.Fatal(err)
	}
	podMarker := filepath.Join(podDir, "pod-marker")
	if err := os.WriteFile(podMarker, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod = (%v, %v)", resp, err)
	}

	for _, p := range []string{staleFile, filepath.Join(rootfs, "nested"), filepath.Join(rootfs, "escape")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale %s survived the create: %v", p, err)
		}
	}
	if b, err := os.ReadFile(canaryFile); err != nil || string(b) != "outside" {
		t.Errorf("canary outside the pod dir = (%q, %v), want it intact", b, err)
	}
	if b, err := os.ReadFile(podMarker); err != nil || string(b) != "keep" {
		t.Errorf("pod dir marker = (%q, %v), want it intact", b, err)
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		t.Errorf("rootfs after create = (%v, %v), want a directory", fi, err)
	}
}

// gatedSpawner holds the first Spawn until release is closed, after writing a
// file into the pod's rootfs and signalling entered: it stands for a create
// that has built its rootfs and has not registered the pod yet.
type gatedSpawner struct {
	fakeSpawner
	once    sync.Once
	place   string
	entered chan struct{}
	release chan struct{}
}

func (g *gatedSpawner) Spawn(ctx context.Context, spec supervisor.SpawnSpec) (int, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		if err := os.WriteFile(g.place, []byte("first"), 0o644); err != nil {
			return 0, err
		}
		close(g.entered)
		<-g.release
	}
	return g.fakeSpawner.Spawn(ctx, spec)
}

// TestConcurrentCreateDoesNotClearALivePodRootfs pins that a second CreatePod
// for a pod id whose first create is still in flight is refused, and that the
// refusal leaves the first create's rootfs and its outcome untouched.
func TestConcurrentCreateDoesNotClearALivePodRootfs(t *testing.T) {
	const podID = "pod-twice"
	sp := &gatedSpawner{entered: make(chan struct{}), release: make(chan struct{})}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	sp.place = filepath.Join(podDir, "rootfs", "placed-by-first")

	type result struct {
		resp *runtimev1.CreatePodResponse
		err  error
	}
	first := make(chan result, 1)
	go func() {
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
		first <- result{resp, err}
	}()
	select {
	case <-sp.entered:
	case <-time.After(30 * time.Second):
		close(sp.release)
		t.Fatal("first create never reached its spawn")
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	close(sp.release)
	if !errors.Is(err, ErrPodCreateInFlight) {
		t.Errorf("second CreatePod = (%v, %v), want ErrPodCreateInFlight", resp, err)
	} else if got := status.Code(err); got != codes.Aborted {
		t.Errorf("second CreatePod code = %v, want Aborted", got)
	}

	var r result
	select {
	case r = <-first:
	case <-time.After(30 * time.Second):
		t.Fatal("first create never returned")
	}
	if r.err != nil || r.resp.GetError() != nil {
		t.Fatalf("first CreatePod = (%v, %v), want success", r.resp, r.err)
	}
	if b, err := os.ReadFile(sp.place); err != nil || string(b) != "first" {
		t.Errorf("file the first create placed = (%q, %v), want it intact", b, err)
	}
}

// TestCreatePodRefusesASymlinkedPodDir pins that a pod dir planted as a
// symlink fails the create and the link's target is never cleared.
func TestCreatePodRefusesASymlinkedPodDir(t *testing.T) {
	const podID = "pod-linked"
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	keep := filepath.Join(target, "rootfs", "keep")
	if err := os.MkdirAll(filepath.Dir(keep), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(podDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, podDir); err != nil {
		t.Fatal(err)
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil || resp.GetError() == nil {
		t.Fatalf("CreatePod = (%v, %v), want a create failure", resp, err)
	}
	if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP {
		t.Errorf("reason = %v, want ROOTFS_SETUP", got)
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "outside" {
		t.Errorf("symlink target's file = (%q, %v), want it intact", b, err)
	}
}

// TestCreatePodClearsAnUnreadableStaleRootfs pins that a stale rootfs the
// probe cannot read is still cleared, and the create succeeds.
func TestCreatePodClearsAnUnreadableStaleRootfs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 directory")
	}
	const podID = "pod-unreadable"
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(podDir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootfs, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rootfs, 0o755) })

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod = (%v, %v), want success", resp, err)
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() || fi.Mode().Perm()&0o700 != 0o700 {
		t.Errorf("rootfs after create = (%v, %v), want a fresh usable directory", fi, err)
	}
}
