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
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"

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
				rt.cache.Root(), rootfs, "UNPACK-DETAIL")

			assertLoggedOnce(t, logs.String(), tc.marker(rootfs), tc.wants(rootfs))

			sresp, err := rt.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: podID, Container: "main"})
			if err != nil {
				t.Fatal(err)
			}
			if sresp.GetError() == nil {
				t.Fatal("StartContainer succeeded through a failing start")
			}
			assertNoHostPaths(t, "StartContainer error", sresp.GetError().GetMessage(),
				podID+"/main", tc.own, tc.sentence, rt.cache.Root(), rootfs, "UNPACK-DETAIL")
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

// assertLoggedOnce fails t unless exactly one line of out carries marker,
// holding every one of wants.
func assertLoggedOnce(t *testing.T, out, marker string, wants []string) {
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
	if !strings.Contains(lines[0], "level=WARN") {
		t.Errorf("start error logged as %q, want level=WARN", lines[0])
	}
	for _, want := range wants {
		if !strings.Contains(lines[0], want) {
			t.Errorf("daemon log line %q lacks %q", lines[0], want)
		}
	}
}
