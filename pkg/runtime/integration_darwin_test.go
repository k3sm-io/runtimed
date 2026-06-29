//go:build integration && darwin

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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestIntegrationFullStackCreatePod drives the entire M1 runtime end-to-end with
// the PRODUCTION subsystems: the real exec-shim sandbox.Backend (libsandbox
// confinement), the real posix_spawn/kqueue supervisor, and the signature gate —
// running a host-binary pod (a generated arm64 binary) to completion under
// Seatbelt. This is the integration proof that the RuntimeServer wiring spawns a
// confined native pod process and reaps it.
func TestIntegrationFullStackCreatePod(t *testing.T) {
	root := t.TempDir()

	// Build + ad-hoc sign the exec-shim helper.
	shim := filepath.Join(root, sandbox.ExecShimName)
	build := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shim: %v\n%s", err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("sign shim: %v\n%s", err, out)
	}

	backend, err := sandbox.NewExecShimBackend(shim, root)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.Available() {
		t.Skip("exec-shim backend unavailable on this host")
	}

	// A pod binary that writes a marker and exits 0.
	podDir := filepath.Join(root, "podbin")
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		t.Fatal(err)
	}
	podBin := filepath.Join(podDir, "app")
	src := filepath.Join(root, "app.c")
	if err := os.WriteFile(src, []byte("#include <stdio.h>\nint main(void){printf(\"pod-ran\\n\");return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-o", podBin, src).CombinedOutput(); err != nil {
		t.Skipf("clang unavailable: %v\n%s", err, out)
	}

	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{Root: root, RuntimeVersion: "test"}, Deps{
		Cache:   cache,
		Backend: backend,
		Spawner: supervisor.PosixSpawner{},
		Waiter:  supervisor.KqueueReaper{},
		Network: supervisor.NodeNetwork{IP: "127.0.0.1"},
		// Real signer (ad-hoc sign + policy gate) exercises codesign on pull.
	})
	if err != nil {
		t.Fatal(err)
	}

	box := &runtimev1.PodBox{
		PodId:      "pod-int",
		Namespace:  "default",
		Name:       "int",
		RootfsPath: filepath.Join(root, "pods", "pod-int", "rootfs"),
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: filepath.Join(root, "pods", "pod-int", "rootfs"),
			// Allow reading the pod binary's dir and the OS.
			ExtraReadPaths: []string{podDir, "/private/tmp", "/private/var/folders", root},
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			// Host-binary convention: image is the absolute path, no command.
			{Name: "main", Image: podBin},
		},
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}

	// The container is short-lived; poll its status until terminated.
	deadline := time.Now().Add(20 * time.Second)
	var phase runtimev1.PodPhase
	for time.Now().Before(deadline) {
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-int"})
		cs := gs.GetStatus().GetContainerStatuses()
		if len(cs) == 1 && cs[0].GetState().GetTerminated() != nil {
			term := cs[0].GetState().GetTerminated()
			if term.GetExitCode() != 0 {
				t.Fatalf("pod container exited %d: %s", term.GetExitCode(), term.GetMessage())
			}
			phase = gs.GetStatus().GetPhase()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if phase != runtimev1.PodPhase_POD_PHASE_SUCCEEDED {
		t.Fatalf("pod did not reach SUCCEEDED; phase=%v", phase)
	}

	// Logs must have captured the marker the confined pod printed.
	stream := newFakeLogStream(context.Background())
	if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-int", Container: "main"}, stream); err != nil {
		t.Fatalf("GetLogs: %v", err)
	}
	found := false
	for _, e := range stream.entries {
		if string(e.GetLine()) == "pod-ran" {
			found = true
		}
	}
	if !found {
		t.Errorf("pod log marker not captured; entries=%v", stream.entries)
	}

	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-int"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
}
