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
// that has built its rootfs and has not registered the pod yet. With fail set,
// the held first Spawn then fails, so that first create fails.
type gatedSpawner struct {
	fakeSpawner
	once    sync.Once
	place   string
	fail    bool
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
		if g.fail {
			return 0, errors.New("gated spawn failure")
		}
	}
	return g.fakeSpawner.Spawn(ctx, spec)
}

type createResult struct {
	resp *runtimev1.CreatePodResponse
	err  error
}

// startHeldCreate starts a first CreatePod of podID on rt and returns once it
// is held inside sp's first Spawn, with the channel its result arrives on.
func startHeldCreate(t *testing.T, rt *Runtime, sp *gatedSpawner, podID string) <-chan createResult {
	t.Helper()
	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	sp.place = filepath.Join(podDir, "rootfs", "placed-by-first")
	first := make(chan createResult, 1)
	go func() {
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
		first <- createResult{resp, err}
	}()
	select {
	case <-sp.entered:
	case <-time.After(30 * time.Second):
		close(sp.release)
		t.Fatal("first create never reached its spawn")
	}
	return first
}

// waitResult reads one create result, failing the test after 30s.
func waitResult(t *testing.T, ch <-chan createResult, what string) createResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never returned", what)
		return createResult{}
	}
}

// TestConcurrentCreateDoesNotClearALivePodRootfs pins that a second CreatePod
// for a pod id whose first create is still in flight waits for the first, then
// answers with the registered pod's status, and leaves the first create's
// rootfs untouched.
func TestConcurrentCreateDoesNotClearALivePodRootfs(t *testing.T) {
	const podID = "pod-twice"
	sp := &gatedSpawner{entered: make(chan struct{}), release: make(chan struct{})}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	first := startHeldCreate(t, rt, sp, podID)

	second := make(chan createResult, 1)
	go func() {
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
		second <- createResult{resp, err}
	}()
	select {
	case r := <-second:
		close(sp.release)
		t.Fatalf("second CreatePod returned (%v, %v) while the first was held", r.resp, r.err)
	case <-time.After(200 * time.Millisecond):
	}
	close(sp.release)

	r := waitResult(t, first, "first create")
	if r.err != nil || r.resp.GetError() != nil {
		t.Fatalf("first CreatePod = (%v, %v), want success", r.resp, r.err)
	}
	r2 := waitResult(t, second, "second create")
	if r2.err != nil || r2.resp.GetError() != nil {
		t.Fatalf("second CreatePod = (%v, %v), want the registered pod's status", r2.resp, r2.err)
	}
	if got, want := r2.resp.GetStatus().GetPodId(), podID; got != want {
		t.Errorf("second CreatePod status pod id = %q, want %q", got, want)
	}
	if b, err := os.ReadFile(sp.place); err != nil || string(b) != "first" {
		t.Errorf("file the first create placed = (%q, %v), want it intact", b, err)
	}
}

// TestConcurrentCreateAfterAFailedFirstCreatesAfresh pins that a second
// CreatePod waiting on a first create that then fails runs its own create,
// after the first's pod dir removal, and succeeds on a fresh rootfs.
func TestConcurrentCreateAfterAFailedFirstCreatesAfresh(t *testing.T) {
	const podID = "pod-retry"
	sp := &gatedSpawner{fail: true, entered: make(chan struct{}), release: make(chan struct{})}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	first := startHeldCreate(t, rt, sp, podID)

	second := make(chan createResult, 1)
	go func() {
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
		second <- createResult{resp, err}
	}()
	select {
	case r := <-second:
		close(sp.release)
		t.Fatalf("second CreatePod returned (%v, %v) while the first was held", r.resp, r.err)
	case <-time.After(200 * time.Millisecond):
	}
	close(sp.release)

	r := waitResult(t, first, "first create")
	if r.err != nil || r.resp.GetError() == nil {
		t.Fatalf("first CreatePod = (%v, %v), want a create failure", r.resp, r.err)
	}
	r2 := waitResult(t, second, "second create")
	if r2.err != nil || r2.resp.GetError() != nil {
		t.Fatalf("second CreatePod = (%v, %v), want success", r2.resp, r2.err)
	}
	if _, err := os.Stat(sp.place); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file the failed first create placed: stat err = %v, want it gone (fresh rootfs)", err)
	}
	rt.mu.Lock()
	_, live := rt.pods[podID]
	rt.mu.Unlock()
	if !live {
		t.Error("pod not registered after the second create")
	}
}

// TestConcurrentCreateWaiterCtxCancel pins that a second CreatePod waiting on
// an in-flight first create returns promptly when its ctx is cancelled, with
// context.Canceled and ErrPodCreateInFlight in the chain, and that the first
// create is unaffected.
func TestConcurrentCreateWaiterCtxCancel(t *testing.T) {
	const podID = "pod-cancel"
	sp := &gatedSpawner{entered: make(chan struct{}), release: make(chan struct{})}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	first := startHeldCreate(t, rt, sp, podID)

	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan createResult, 1)
	go func() {
		resp, err := rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
		second <- createResult{resp, err}
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	var r2 createResult
	select {
	case r2 = <-second:
	case <-time.After(5 * time.Second):
		close(sp.release)
		t.Fatal("cancelled second CreatePod did not return promptly")
	}
	if !errors.Is(r2.err, context.Canceled) || !errors.Is(r2.err, ErrPodCreateInFlight) {
		t.Errorf("second CreatePod = (%v, %v), want context.Canceled and ErrPodCreateInFlight", r2.resp, r2.err)
	}
	if got := status.Code(r2.err); got != codes.Canceled {
		t.Errorf("second CreatePod code = %v, want Canceled", got)
	}
	close(sp.release)

	r := waitResult(t, first, "first create")
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
