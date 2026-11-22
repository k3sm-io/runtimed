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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestStartContainerRefusesAPodIdentity drives startContainer through
// CreatePod with fakes and pins that a container whose drop target the pod
// identity rule refuses (a login-range uid, a staff group) fails the pod as an
// invalid box before the command is wrapped or spawned. Nothing else on that
// path judges the credential, so removing the check in startContainer fails
// this test.
func TestStartContainerRefusesAPodIdentity(t *testing.T) {
	for name, sc := range map[string]*runtimev1.SecurityContext{
		"login-range uid": {RunAsUser: 501, RunAsGroup: 300},
		"staff group":     {RunAsUser: 300, RunAsGroup: 20},
	} {
		t.Run(name, func(t *testing.T) {
			be := &recordingExecBackend{}
			sp := &fakeSpawner{}
			rt := newTestRuntime(t, Deps{Backend: be, Spawner: sp})
			box := hostBinBox(rt, "pod-refused")
			box.Containers[0].SecurityContext = sc
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if resp.GetError() == nil || resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Fatalf("CreatePod = %v (reason %v), want an INVALID_POD_BOX refusal", resp.GetError(), resp.GetFailureReason())
			}
			if msg := resp.GetError().GetMessage(); !strings.Contains(msg, "pod uid refused") && !strings.Contains(msg, "pod group refused") {
				t.Errorf("refusal %q does not name the pod identity rule", msg)
			}
			if len(be.argvs) != 0 || len(sp.specs) != 0 {
				t.Errorf("wrapped %d and spawned %d commands, want none", len(be.argvs), len(sp.specs))
			}
		})
	}
}

// TestExecRefusesAPodIdentity drives Exec through its stream entry point with
// fakes and pins that an exec whose resolved credential the pod identity rule
// refuses is PermissionDenied before the command is wrapped. The pod is
// created with an allowed identity and its box then carries a login-range
// pod runAsUser, so only Exec's own check stands between the request and
// WrapCommand; removing it fails this test.
func TestExecRefusesAPodIdentity(t *testing.T) {
	be := &recordingExecBackend{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Backend: be, Waiter: w})
	mustCreatePod(t, rt, hostBinBox(rt, "pod-exec-refused"))
	defer w.release(1001)

	rt.mu.Lock()
	p := rt.pods["pod-exec-refused"]
	p.box.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsUser: 501, RunAsGroup: 300}
	rt.mu.Unlock()
	be.mu.Lock()
	wrapped := len(be.argvs)
	be.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newFakeExecStream(ctx)
	st.feed(&runtimev1.ExecRequest{PodId: "pod-exec-refused", Command: []string{"/bin/echo", "hi"}})
	st.closeSend()
	err := rt.Exec(st)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "pod uid refused") {
		t.Fatalf("Exec = %v, want PermissionDenied naming the pod uid rule", err)
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.argvs) != wrapped {
		t.Errorf("Exec wrapped a command after the refusal: %v", be.argvs[wrapped:])
	}
}

// TestStartContainerResolvesTheServiceOwnerEachStart pins that the service
// identity is resolved at each start, not once in New: with the service user
// lookup answering "not found" and the installed work dir not there yet, a
// start that drops to uid 270 runs; once the work dir is created, owned by
// 270, a later start's drop to 270 is refused before anything is wrapped.
func TestStartContainerResolvesTheServiceOwnerEachStart(t *testing.T) {
	const owner = 270
	stateDir := filepath.Join(t.TempDir(), "node-work")
	be := &recordingExecBackend{}
	rt := newTestRuntimeCfg(t, Config{StateDir: stateDir}, Deps{
		Backend:       be,
		lookupService: func() (supervisor.ServiceIdentity, error) { return supervisor.ServiceIdentity{}, nil },
		installedOwner: func(dir string) (int, bool, error) {
			if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
				return 0, false, nil
			} else if err != nil {
				return 0, false, err
			}
			return owner, true, nil
		},
	})
	start := func(name string) *runtimev1.CreatePodResponse {
		t.Helper()
		box := hostBinBox(rt, name)
		box.Containers[0].SecurityContext = &runtimev1.SecurityContext{RunAsUser: owner, RunAsGroup: 300}
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatalf("CreatePod %s: %v", name, err)
		}
		return resp
	}
	if resp := start("pod-before-install"); resp.GetError() != nil {
		t.Fatalf("start before the work dir exists = %v, want it to run", resp.GetError())
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	wrapped := len(be.argvs)
	be.mu.Unlock()
	resp := start("pod-after-install")
	if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX || !strings.Contains(resp.GetError().GetMessage(), "pod uid refused") {
		t.Fatalf("start after the work dir is installed = %v (reason %v), want a pod uid refusal", resp.GetError(), resp.GetFailureReason())
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.argvs) != wrapped {
		t.Errorf("wrapped %d commands after the install, want none", len(be.argvs)-wrapped)
	}
}
