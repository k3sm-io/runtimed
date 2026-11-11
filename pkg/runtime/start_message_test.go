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
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// failingUnpacker fails MaterializeTree the way the image unpacker does: the
// tree key, the destination rootfs and a cause, which here carries a sentinel
// so the test can find the one log line holding it.
type failingUnpacker struct{ treeUnpacker }

const unpackDetail = "UNPACK-DETAIL: no space left on device"

func (u *failingUnpacker) MaterializeTree(_ context.Context, _ *runtimev1.ImageManifest, _ image.UnpackPolicy, dst string) (*image.MaterializeResult, error) {
	return nil, fmt.Errorf("materialize tree %q into %s: %w", "sha256:"+hexRun('e'), dst, errors.New(unpackDetail))
}

// toggleWrapBackend fails WrapCommand, once failing is set, the way the sbpl
// backend does when it cannot stage a profile: the staging path and a cause.
type toggleWrapBackend struct {
	fakeBackend
	failing *atomic.Bool
}

const wrapDetail = "WRAP-DETAIL"

func (b toggleWrapBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	if b.failing.Load() {
		return "", nil, nil, fmt.Errorf("stage profile %s: %w", "/var/k3sm/sbpl/"+wrapDetail+"/profile.sb", errors.New("read-only file system"))
	}
	return b.fakeBackend.WrapCommand(ctx, profile, argv, spec)
}

// spawnDetail marks the host exec-shim path a failed spawn's error names.
const spawnDetail = "SPAWN-DETAIL"

// TestStartFailureMessageHidesHostPaths pins what a pod is told when its
// container's start fails because the image program escapes the rootfs or the
// image could not be materialized: a fixed sentence naming only what the pod
// wrote (the program, the image reference). The cache root and the rootfs path
// stay in the daemon's one Warn line, which carries the full error.
func TestStartFailureMessageHidesHostPaths(t *testing.T) {
	const imageRef = "example.test/app:v1"

	cases := []struct {
		name     string
		unpacker Unpacker
		// pullErr, when set, fails the pull with it.
		pullErr error
		// own is the pod's own string the sentence must name.
		own      string
		sentence string
		reason   runtimev1.FailureReason
		// marker finds the one log line with the full error; wants are what that
		// line must carry beyond it.
		marker func(rootfs string) string
		wants  func(rootfs string) []string
	}{
		{
			name: "argv-escape",
			unpacker: &treeUnpacker{
				files:  map[string]string{"bin/app": "payload"},
				runCfg: image.ImageRunConfig{Entrypoint: []string{"../escape"}},
			},
			own:      "../escape",
			sentence: "resolves outside the image's root filesystem",
			reason:   runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG,
			marker:   func(rootfs string) string { return filepath.Join(rootfs, "../escape") },
			wants:    func(rootfs string) []string { return []string{rootfs, ErrImageArgvEscapes.Error()} },
		},
		{
			name:     "materialize",
			unpacker: &failingUnpacker{},
			own:      imageRef,
			sentence: "could not be prepared; the daemon log has the cause",
			reason:   runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			marker:   func(string) string { return "UNPACK-DETAIL" },
			wants:    func(rootfs string) []string { return []string{rootfs, unpackDetail} },
		},
		{
			name:     "pull",
			unpacker: &treeUnpacker{},
			pullErr:  &fs.PathError{Op: "open", Path: "/var/k3sm/blobs/PULL-DETAIL/sha256", Err: fs.ErrPermission},
			own:      imageRef,
			sentence: "could not be pulled; the daemon log has the cause",
			reason:   runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			marker:   func(string) string { return "PULL-DETAIL" },
			wants:    func(string) []string { return []string{"pull image", fs.ErrPermission.Error()} },
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			podID := fmt.Sprintf("pod-start-msg-%d", i)
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			rt := newTestRuntimeCfg(t, cfg, Deps{
				Signer:  &scriptedSigner{check: func(string) error { return nil }},
				Spawner: &fakeSpawner{},
				Puller: &fakePuller{
					manifest:   &runtimev1.ImageManifest{Reference: imageRef, Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}},
					descriptor: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('d')},
					err:        tc.pullErr,
				},
				Unpacker: tc.unpacker,
			})
			box := hostBinBox(rt, podID)
			box.Containers = []*runtimev1.Container{{Name: "main", Image: imageRef}}
			rootfs := derivedRootfs(t, rt, podID)

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed %v; the start failure is container-class", resp.GetError())
			}
			w := statusNamed(t, rt, podID, "main").GetState().GetWaiting()
			if w == nil {
				t.Fatal("container is not Waiting after a failed start")
			}
			if got := w.GetFailureReason(); got != tc.reason {
				t.Errorf("failure_reason = %v, want %v", got, tc.reason)
			}
			assertNoHostPaths(t, "waiting message", w.GetMessage(), tc.own, tc.own, tc.sentence,
				rt.cache.Root(), rootfs, "UNPACK-DETAIL", "PULL-DETAIL")

			assertLoggedOnce(t, logs.String(), tc.marker(rootfs), tc.wants(rootfs))

			sresp, err := rt.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: podID, Container: "main"})
			if err != nil {
				t.Fatal(err)
			}
			if sresp.GetError() == nil {
				t.Fatal("StartContainer succeeded through a failing start")
			}
			assertNoHostPaths(t, "StartContainer error", sresp.GetError().GetMessage(),
				podID+"/main", tc.own, tc.sentence, rt.cache.Root(), rootfs, "UNPACK-DETAIL", "PULL-DETAIL")
		})
	}

	// The spawn and the wrap are pod-class at CreatePod, so they reach a client
	// through the restart reply (startErrorReply), driven here end to end.
	restarts := []struct {
		name     string
		sentence string
		reason   runtimev1.FailureReason
		marker   string
		wants    []string
		fail     func(t *testing.T, sp *fakeSpawner, wrap *atomic.Bool, cacheRoot, logDir string)
	}{
		{
			name:     "spawn-missing-program",
			sentence: "could not be started (no such file or directory); the daemon log has the cause",
			reason:   runtimev1.FailureReason_FAILURE_REASON_SPAWN,
			marker:   spawnDetail,
			wants:    []string{"spawn container main", "no such file or directory"},
			fail: func(_ *testing.T, sp *fakeSpawner, _ *atomic.Bool, cacheRoot, _ string) {
				sp.mu.Lock()
				sp.err = &fs.PathError{Op: "fork/exec", Path: filepath.Join(cacheRoot, spawnDetail, "exec-shim"), Err: syscall.ENOENT}
				sp.mu.Unlock()
			},
		},
		{
			name:     "wrap-command",
			sentence: "could not be sandboxed; the daemon log has the cause",
			reason:   runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			marker:   wrapDetail,
			wants:    []string{"wrap command for main", "read-only file system"},
			fail:     func(_ *testing.T, _ *fakeSpawner, wrap *atomic.Bool, _, _ string) { wrap.Store(true) },
		},
		{
			// The container's log dir turned read-only under the daemon: the next
			// instance's log file cannot be created.
			name:     "open-container-log",
			sentence: "could not be started: its log could not be opened; the daemon log has the cause",
			reason:   runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			marker:   "open container log for main",
			wants:    []string{"permission denied"},
			fail: func(t *testing.T, _ *fakeSpawner, _ *atomic.Bool, _, logDir string) {
				dir := containerLogDir(logDir, "main")
				if err := os.Chmod(dir, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
	}
	for i, tc := range restarts {
		t.Run("restart/"+tc.name, func(t *testing.T) {
			podID := fmt.Sprintf("pod-restart-msg-%d", i)
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			sp := &fakeSpawner{}
			wrap := &atomic.Bool{}
			w := newBlockingWaiter()
			rt := newTestRuntimeCfg(t, cfg, Deps{
				Backend: toggleWrapBackend{fakeBackend: fakeBackend{available: true}, failing: wrap},
				Signer:  &scriptedSigner{check: func(string) error { return nil }},
				Spawner: sp,
				Waiter:  w,
				Puller: &fakePuller{
					manifest:   &runtimev1.ImageManifest{Reference: imageRef, Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}},
					descriptor: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('d')},
				},
				Unpacker: &treeUnpacker{
					files:  map[string]string{"bin/app": "payload"},
					runCfg: image.ImageRunConfig{Entrypoint: []string{"/bin/app"}},
				},
			})
			box := hostBinBox(rt, podID)
			box.Containers = []*runtimev1.Container{{Name: "main", Image: imageRef}}
			rootfs := derivedRootfs(t, rt, podID)

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed: %v", resp.GetError())
			}

			tc.fail(t, sp, wrap, rt.cache.Root(), box.GetLogDirectory())
			go w.release(1001) // the old instance exits when RestartContainer stops it
			rresp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
			if err != nil {
				t.Fatal(err)
			}
			if rresp.GetError() == nil {
				t.Fatal("RestartContainer succeeded through a failing start")
			}
			if got := rresp.GetFailureReason(); got != tc.reason {
				t.Errorf("failure_reason = %v, want %v", got, tc.reason)
			}
			assertNoHostPaths(t, "RestartContainer error", rresp.GetError().GetMessage(),
				podID+"/main", `container \"main\"`, tc.sentence, rt.cache.Root(), rootfs, box.GetLogDirectory(), spawnDetail, wrapDetail)
			assertLoggedOnceAt(t, logs.String(), "level=ERROR", tc.marker, tc.wants)
		})
	}

	// At first create the same spawn and wrap failures are pod-class, so they
	// reach a client through the CreatePod reply (createFailure).
	for i, tc := range restarts[:2] {
		t.Run("create/"+tc.name, func(t *testing.T) {
			podID := fmt.Sprintf("pod-create-msg-%d", i)
			logs := &lockedBuffer{}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
			sp := &fakeSpawner{}
			wrap := &atomic.Bool{}
			rt := newTestRuntimeCfg(t, cfg, Deps{
				Backend: toggleWrapBackend{fakeBackend: fakeBackend{available: true}, failing: wrap},
				Signer:  &scriptedSigner{check: func(string) error { return nil }},
				Spawner: sp,
				Puller: &fakePuller{
					manifest:   &runtimev1.ImageManifest{Reference: imageRef, Config: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')}},
					descriptor: &runtimev1.Descriptor{Digest: "sha256:" + hexRun('d')},
				},
				Unpacker: &treeUnpacker{
					files:  map[string]string{"bin/app": "payload"},
					runCfg: image.ImageRunConfig{Entrypoint: []string{"/bin/app"}},
				},
			})
			box := hostBinBox(rt, podID)
			box.Containers = []*runtimev1.Container{{Name: "main", Image: imageRef}}
			rootfs := derivedRootfs(t, rt, podID)

			tc.fail(t, sp, wrap, rt.cache.Root(), box.GetLogDirectory())
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() == nil {
				t.Fatal("CreatePod succeeded through a failing first start")
			}
			if got := resp.GetFailureReason(); got != tc.reason {
				t.Errorf("failure_reason = %v, want %v", got, tc.reason)
			}
			assertNoHostPaths(t, "CreatePod error", resp.GetError().GetMessage(),
				`container \"main\"`, `container \"main\"`, tc.sentence, rt.cache.Root(), rootfs, spawnDetail, wrapDetail)
			assertLoggedOnceAt(t, logs.String(), "level=ERROR", tc.marker, tc.wants)
		})
	}

	// The fixed sentence rides beside the error, not instead of it: the
	// sentinel, the reason and the full text stay what callers match on.
	t.Run("error-identity", func(t *testing.T) {
		full := fmt.Errorf("container main: %w: %q resolves to %q, outside %q", ErrImageArgvEscapes, "../x", "/c/x", "/c/r")
		err := resolveFailed(runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG, withClientMessage("fixed", full))
		if !errors.Is(err, ErrImageArgvEscapes) {
			t.Error("errors.Is lost ErrImageArgvEscapes")
		}
		if got := resolveFailureReason(err); got != runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG {
			t.Errorf("reason = %v", got)
		}
		if err.Error() != full.Error() {
			t.Errorf("Error() = %q, want %q", err.Error(), full.Error())
		}
		if got := boundedFailureMessage(err); got != `"fixed"` {
			t.Errorf("boundedFailureMessage = %q, want the fixed sentence", got)
		}
		if got := startErrorReply(err); got != `"fixed"` {
			t.Errorf("startErrorReply = %q, want the fixed sentence", got)
		}
	})
}

// TestSpawnStartErrorClass pins the closed errno classes a failed spawn's
// client sentence may name, and that any other cause names none, while the
// full error and its sentinels stay what errors.Is sees.
func TestSpawnStartErrorClass(t *testing.T) {
	const tail = "; the daemon log has the cause"
	for _, tc := range []struct {
		errno syscall.Errno
		want  string
	}{
		{syscall.ENOENT, `container "main" could not be started (no such file or directory)` + tail},
		{syscall.EACCES, `container "main" could not be started (permission denied)` + tail},
		{syscall.ENOEXEC, `container "main" could not be started (exec format error)` + tail},
		{syscall.E2BIG, `container "main" could not be started` + tail},
	} {
		cause := &fs.PathError{Op: "fork/exec", Path: "/cache/" + spawnDetail + "/exec-shim", Err: tc.errno}
		err := spawnStartError("main", cause)
		if !errors.Is(err, tc.errno) {
			t.Errorf("%v: errors.Is lost the errno", tc.errno)
		}
		if want := "spawn container main: " + cause.Error(); err.Error() != want {
			t.Errorf("%v: Error() = %q, want %q", tc.errno, err.Error(), want)
		}
		if got, want := boundedFailureMessage(err), fmt.Sprintf("%q", tc.want); got != want {
			t.Errorf("%v: boundedFailureMessage = %s, want %s", tc.errno, got, want)
		}
		if got := startErrorReply(err); strings.Contains(got, spawnDetail) {
			t.Errorf("%v: startErrorReply %q carries the host path", tc.errno, got)
		}
	}
}

// TestShimStartErrorHidesHostPaths covers the resident-shim preparation site,
// which CreatePod reaches only with the concrete exec-shim backend
// (hostsResidentShim): the error is built as the site builds it and both
// client renderers are asserted directly.
func TestShimStartErrorHidesHostPaths(t *testing.T) {
	cause := fmt.Errorf("stage shim argv %s: %w", "/cache/run/shim/SHIM-DETAIL/argv", fs.ErrPermission)
	err := shimStartError("main", cause)
	if !errors.Is(err, fs.ErrPermission) {
		t.Error("errors.Is lost the cause")
	}
	if want := "prepare the resident shim for main: " + cause.Error(); err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	const want = `"container \"main\" could not be started: its shim could not be prepared; the daemon log has the cause"`
	if got := boundedFailureMessage(err); got != want {
		t.Errorf("boundedFailureMessage = %s, want %s", got, want)
	}
	if got := startErrorReply(err); got != want {
		t.Errorf("startErrorReply = %s, want %s", got, want)
	}
}

// assertLoggedOnce fails t unless exactly one line of out carries marker,
// holding every one of wants.
func assertLoggedOnce(t *testing.T, out, marker string, wants []string) {
	t.Helper()
	assertLoggedOnceAt(t, out, "level=WARN", marker, wants)
}

// assertLoggedOnceAt is assertLoggedOnce at the given slog level token.
func assertLoggedOnceAt(t *testing.T, out, level, marker string, wants []string) {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, marker) {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("the full start error (%q) was logged %d times, want once:\n%s", marker, len(lines), out)
	}
	if !strings.Contains(lines[0], level) {
		t.Errorf("start error logged as %q, want %s", lines[0], level)
	}
	for _, want := range wants {
		if !strings.Contains(lines[0], want) {
			t.Errorf("daemon log line %q lacks %q", lines[0], want)
		}
	}
}

// TestThreeMoreStartErrorsHidePaths covers the shim dir allocation, the
// process record and the pod's image record: each builds its error as its
// site does and both client renderers are asserted directly.
func TestThreeMoreStartErrorsHidePaths(t *testing.T) {
	const detail = "HOST-DETAIL"
	cause := &fs.PathError{Op: "open", Path: "/cache/" + detail + "/rec", Err: fs.ErrPermission}
	for _, tc := range []struct {
		name      string
		err       error
		wantError string
		want      string
	}{
		{"shim dir", shimDirStartError("main", cause), cause.Error(),
			`container "main" could not be started: its shim could not be prepared; the daemon log has the cause`},
		{"process record", procRecordStartError("main", cause), "record container main process group: " + cause.Error(),
			`container "main" could not be started: its process record could not be written; the daemon log has the cause`},
		{"image record", imageRecordError("example.com/app:1", cause), cause.Error(),
			`image "example.com/app:1" could not be recorded for the pod; the daemon log has the cause`},
	} {
		if !errors.Is(tc.err, fs.ErrPermission) {
			t.Errorf("%s: errors.Is lost the cause", tc.name)
		}
		if tc.err.Error() != tc.wantError {
			t.Errorf("%s: Error() = %q, want %q", tc.name, tc.err.Error(), tc.wantError)
		}
		want := fmt.Sprintf("%q", tc.want)
		if got := boundedFailureMessage(tc.err); got != want {
			t.Errorf("%s: boundedFailureMessage = %s, want %s", tc.name, got, want)
		}
		if got := startErrorReply(tc.err); got != want || strings.Contains(got, detail) {
			t.Errorf("%s: startErrorReply = %s, want %s", tc.name, got, want)
		}
	}
}
