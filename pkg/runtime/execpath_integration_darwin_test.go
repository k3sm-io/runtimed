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
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestExecResolvesTarOnTheHostPath drives the production exec path (the daemon's
// Exec RPC into a resident shim's confined exec session) with a bare command
// name, the shape `kubectl cp` sends (`tar ...`). A bare name must be resolved on
// the session's PATH, not execve'd relative to the working directory; an unknown
// name must fail with the not-found convention (exit 127, a stable message) and
// leave the daemon serving; an absolute path must run untouched.
func TestExecResolvesTarOnTheHostPath(t *testing.T) {
	root := shortRoot(t)

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

	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{Root: root, RuntimeVersion: "test", PodLogsDir: filepath.Join(root, "podlogs")}, Deps{
		Cache:   cache,
		Backend: backend,
		Spawner: supervisor.PosixSpawner{},
		Waiter:  supervisor.KqueueReaper{},
		Network: supervisor.NodeNetwork{IP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	const podID = "pod-execpath"
	box := &runtimev1.PodBox{
		PodId:        podID,
		Namespace:    "default",
		Name:         "execpath",
		LogDirectory: testPodLogDir(rt, podID),
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: derivedRootfs(t, rt, podID),
			ExtraReadPaths: []string{"/private/tmp", "/private/var/folders", root},
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			// The native sentinel: command[0] is an absolute host binary.
			{Name: "main", Image: NativeImage, Command: []string{"/bin/sleep", "60"}},
		},
	}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	defer func() {
		_, _ = rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID})
	}()

	waitRunning(t, rt, podID)

	run := func(t *testing.T, cmdv ...string) (stdout, stderr string, code int32) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: podID, Command: cmdv, Stdout: true, Stderr: true})
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec(%v): %v", cmdv, err)
		}
		var out, errb []byte
		for {
			select {
			case r := <-st.out:
				out = append(out, r.GetStdout()...)
				errb = append(errb, r.GetStderr()...)
				if r.GetExit() != nil {
					return string(out), string(errb), r.GetExit().GetExitCode()
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("Exec(%v): timed out collecting output", cmdv)
			}
		}
	}

	t.Run("bare-tar-resolves-on-PATH", func(t *testing.T) {
		out, errOut, code := run(t, "tar", "--version")
		if code != 0 {
			t.Fatalf("tar --version exit = %d, want 0 (stderr %q)", code, errOut)
		}
		if !strings.Contains(out, "bsdtar") {
			t.Errorf("tar --version stdout = %q, want it to contain bsdtar", out)
		}
	})

	t.Run("unknown-bare-name-is-not-found", func(t *testing.T) {
		const want = `exec: "definitely-not-a-binary": executable not found on the pod's PATH`
		_, errOut, code := run(t, "definitely-not-a-binary")
		if code != 127 {
			t.Errorf("exit = %d, want 127 (stderr %q)", code, errOut)
		}
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr = %q, want it to contain %q", errOut, want)
		}
		// The daemon keeps serving the pod.
		if _, errOut, code := run(t, "/usr/bin/true"); code != 0 {
			t.Errorf("exec after a not-found exit = %d, want 0 (stderr %q)", code, errOut)
		}
	})

	t.Run("absolute-path-untouched", func(t *testing.T) {
		if _, errOut, code := run(t, "/usr/bin/true"); code != 0 {
			t.Errorf("/usr/bin/true exit = %d, want 0 (stderr %q)", code, errOut)
		}
	})
}

// waitRunning polls until the pod's single container reports running.
func waitRunning(t *testing.T, rt *Runtime, podID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
		cs := gs.GetStatus().GetContainerStatuses()
		if len(cs) == 1 {
			if cs[0].GetState().GetRunning() != nil {
				return
			}
			if term := cs[0].GetState().GetTerminated(); term != nil {
				t.Fatalf("container terminated before exec: exit %d: %s", term.GetExitCode(), term.GetMessage())
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	t.Fatalf("container did not reach running: %v", gs.GetStatus())
}
