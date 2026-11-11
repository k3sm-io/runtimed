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
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// configFailWorld is an imageWorld whose pulls succeed but whose image config
// cannot be read.
type configFailWorld struct{ *imageWorld }

func (configFailWorld) ImageRunConfig(*runtimev1.ImageManifest) (image.ImageRunConfig, error) {
	return image.ImageRunConfig{}, configReadErr
}

// TestVMStartFailureMessageHidesHostPaths pins what a vm pod's CreatePod
// reply says when its image cannot be pulled or its config cannot be read: a
// fixed sentence naming only the pod's image reference, while the daemon's one
// Error line carries the full error with the host blob path.
func TestVMStartFailureMessageHidesHostPaths(t *testing.T) {
	const ref = "example.test/vmapp:v1"
	for i, tc := range []struct {
		name     string
		world    func(w *imageWorld) Unpacker
		sentence string
		marker   string
		wants    []string
	}{
		{
			name: "pull",
			world: func(w *imageWorld) Unpacker {
				w.failsWith(ref, &fs.PathError{Op: "open", Path: "/var/k3sm/blobs/PULL-DETAIL/sha256", Err: fs.ErrPermission})
				return w
			},
			sentence: "could not be pulled; the daemon log has the cause",
			marker:   "PULL-DETAIL",
			wants:    []string{"pull image", fs.ErrPermission.Error()},
		},
		{
			name:     "config-read",
			world:    func(w *imageWorld) Unpacker { return configFailWorld{w} },
			sentence: "could not be read; the daemon log has the cause",
			marker:   configDetail,
			wants:    []string{"read image config for", fs.ErrPermission.Error()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newImageWorld(map[string]image.ImageRunConfig{ref: {Entrypoint: []string{"/app"}}})
			logs := &lockedBuffer{}
			vmb := &fakeVMBackend{available: true, bootOK: true}
			cfg, d := vmPodConfig(t, Deps{VMBackend: vmb, Puller: w, Unpacker: tc.world(w)})
			cfg.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			rt := newTestRuntimeCfg(t, cfg, d)
			box := vmBoxWith(rt, fmt.Sprintf("pod-vm-start-msg-%d", i), nil,
				[]*runtimev1.Container{{Name: "app", Image: ref}})

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() == nil {
				t.Fatal("CreatePod succeeded through a failing image resolution")
			}
			if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
				t.Errorf("failure_reason = %v, want IMAGE_PULL", got)
			}
			if n, _ := vmb.created(); n != 0 {
				t.Errorf("CreateVM called %d times after a failed image resolution; must be 0", n)
			}
			assertNoHostPaths(t, "CreatePod error", resp.GetError().GetMessage(), ref, ref, tc.sentence,
				rt.cache.Root(), "/var/k3sm/blobs", "PULL-DETAIL", configDetail)
			assertLoggedOnceAt(t, logs.String(), "level=ERROR", tc.marker, tc.wants)
		})
	}
}

// TestWrappedStartErrorsReachClientRenderers takes the image-record,
// shim-directory and process-record start errors through resolveFailed and
// the client renderers, and drives the image-record and process-record sites
// end to end, so a caller between the wrapper and the reply cannot put the
// host path back.
func TestWrappedStartErrorsReachClientRenderers(t *testing.T) {
	const imageRef = "example.test/app:v1"

	// Classified the way resolveBinary classifies, rendered the way the
	// Waiting message and the RPC replies render.
	t.Run("classified", func(t *testing.T) {
		const detail = "HOST-DETAIL"
		cause := &fs.PathError{Op: "open", Path: "/cache/" + detail + "/rec", Err: fs.ErrPermission}
		for _, tc := range []struct {
			name   string
			reason runtimev1.FailureReason
			err    error
			want   string
		}{
			{"image record", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, imageRecordError(imageRef, cause),
				`image "` + imageRef + `" could not be recorded for the pod; the daemon log has the cause`},
			{"shim dir", runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP, shimDirStartError("main", cause),
				`container "main" could not be started: its shim could not be prepared; the daemon log has the cause`},
			{"process record", runtimev1.FailureReason_FAILURE_REASON_SPAWN, procRecordStartError("main", cause),
				`container "main" could not be started: its process record could not be written; the daemon log has the cause`},
		} {
			err := resolveFailed(tc.reason, tc.err)
			if got := resolveFailureReason(err); got != tc.reason {
				t.Errorf("%s: reason = %v, want %v", tc.name, got, tc.reason)
			}
			if !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), detail) {
				t.Errorf("%s: the classified error lost its cause: %v", tc.name, err)
			}
			want := fmt.Sprintf("%q", tc.want)
			if got := boundedFailureMessage(err); got != want {
				t.Errorf("%s: Waiting message = %s, want %s", tc.name, got, want)
			}
			if got := startErrorReply(err); got != want {
				t.Errorf("%s: reply = %s, want %s", tc.name, got, want)
			}
			if got := createFailure(tc.reason, err).GetError().GetMessage(); strings.Contains(got, detail) {
				t.Errorf("%s: CreatePod reply %q carries the host path", tc.name, got)
			}
		}
	})

	// A directory where the pod's image record belongs fails the record with
	// an error naming the pod dir under the cache root.
	t.Run("image-record", func(t *testing.T) {
		const podID = "pod-image-record-msg"
		logs := &lockedBuffer{}
		cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
		rt := newTestRuntimeCfg(t, cfg, Deps{
			Signer:  &scriptedSigner{check: func(string) error { return nil }},
			Spawner: &fakeSpawner{},
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
		id, err := image.ParsePodID(podID)
		if err != nil {
			t.Fatal(err)
		}
		podDir := rt.cache.PodDir(id)
		if err := os.MkdirAll(filepath.Join(podDir, image.PodReferencesName), 0o755); err != nil {
			t.Fatal(err)
		}

		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() != nil {
			t.Fatalf("CreatePod failed %v; the image record failure is container-class", resp.GetError())
		}
		const sentence = "could not be recorded for the pod; the daemon log has the cause"
		w := statusNamed(t, rt, podID, "main").GetState().GetWaiting()
		if w == nil {
			t.Fatal("container is not Waiting after a failed image record")
		}
		if got := w.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
			t.Errorf("failure_reason = %v, want IMAGE_PULL", got)
		}
		assertNoHostPaths(t, "waiting message", w.GetMessage(), imageRef, imageRef, sentence, rt.cache.Root(), podDir, rootfs)
		assertLoggedOnce(t, logs.String(), "record image references for pod", []string{podDir, image.PodReferencesName})

		sresp, err := rt.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatal(err)
		}
		if sresp.GetError() == nil {
			t.Fatal("StartContainer succeeded through a failing image record")
		}
		assertNoHostPaths(t, "StartContainer error", sresp.GetError().GetMessage(),
			podID+"/main", imageRef, sentence, rt.cache.Root(), podDir, rootfs)
	})

	// The pod's reap record dir turned read-only under the daemon: the
	// restarted instance's process group cannot be recorded.
	t.Run("process-record", func(t *testing.T) {
		const podID = "pod-proc-record-msg"
		logs := &lockedBuffer{}
		cfg := Config{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
		wt := newBlockingWaiter()
		rt := newTestRuntimeCfg(t, cfg, Deps{
			Signer:  &scriptedSigner{check: func(string) error { return nil }},
			Spawner: &fakeSpawner{},
			Waiter:  wt,
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
		reapDir, err := rt.podReapDir(podID)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(reapDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(reapDir, 0o700) })

		go wt.release(1001) // the old instance exits when RestartContainer stops it
		rresp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatal(err)
		}
		if rresp.GetError() == nil {
			t.Fatal("RestartContainer succeeded through a failing process record")
		}
		if got := rresp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_SPAWN {
			t.Errorf("failure_reason = %v, want SPAWN", got)
		}
		assertNoHostPaths(t, "RestartContainer error", rresp.GetError().GetMessage(),
			podID+"/main", `container \"main\"`, "its process record could not be written; the daemon log has the cause",
			rt.cache.Root(), reapDir, rootfs)
		assertLoggedOnceAt(t, logs.String(), "level=ERROR", "record container main process group",
			[]string{reapDir, "permission denied"})
	})
}
