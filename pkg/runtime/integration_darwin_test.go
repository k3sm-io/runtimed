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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

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

	// Ask the runtime for the derived pod data volume rather than re-spelling the
	// layout: B140 accepts rootfs_path only when it is byte-equal to it, and the
	// SBPL data volume moves with it.
	intRootfs := derivedRootfs(t, rt, "pod-int")

	box := &runtimev1.PodBox{
		PodId:      "pod-int",
		Namespace:  "default",
		Name:       "int",
		RootfsPath: intRootfs,
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: intRootfs,
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

// TestIntegrationMaterializeTreeThenExec is acceptance M11.2-a6: the M11.2-d7
// unpacker produces an unpacked tree that createPod materializes via
// MaterializeTree, and the pod EXECS argv[0] out of a MULTI-LAYER image.
//
// It is the whole substrate end to end with the PRODUCTION subsystems — the real
// registry pull path, the real cache, the real unpacker, the real APFS clone,
// the real ad-hoc signer and signature gate, the real exec-shim Seatbelt backend
// and the real posix_spawn/kqueue supervisor. Nothing about the image is faked;
// the only concession to hermeticity is that the registry is in-process on
// loopback.
//
// Two layers, each carrying a REAL and DIFFERENT Mach-O at bin/app, is the
// load-bearing part of the fixture. A single-layer image cannot distinguish an
// unpacker that applies layers in order from one that applies only the first (or
// only the last): both would exec something. Here the first layer's binary
// prints the WRONG marker and would exit non-zero, so a mis-ordered apply fails
// loudly instead of passing.
func TestIntegrationMaterializeTreeThenExec(t *testing.T) {
	root := t.TempDir()

	// Build + ad-hoc sign the exec-shim helper (the confinement backend).
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

	// The image resolves under the NATIVE platform policy, which admits
	// darwin/arm64 only (pullPolicy leaves HostRosetta false), so the payload
	// must be arm64 Mach-O — and this host must be able to run one.
	if runtime.GOARCH != "arm64" && !hostIsAppleSilicon(t) {
		t.Skip("darwin/arm64 payload cannot execute on this host")
	}
	layer1Bin := buildMarkerBinary(t, root, "layer1", "pod-ran-from-layer-1", 3)
	layer2Bin := buildMarkerBinary(t, root, "layer2", "pod-ran-from-layer-2", 0)

	ref := pushExecutableImage(t, testRegistryHost(t), "a6", layer1Bin, layer2Bin)

	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	// Deps carries NO Puller and NO Unpacker: New builds the daemon's own pair
	// over one cache, which is the wiring this acceptance is about.
	rt, err := New(Config{Root: root, RuntimeVersion: "test"}, Deps{
		Cache:   cache,
		Backend: backend,
		Spawner: supervisor.PosixSpawner{},
		Waiter:  supervisor.KqueueReaper{},
		Network: supervisor.NodeNetwork{IP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	podRootfs := derivedRootfs(t, rt, "pod-a6")
	box := &runtimev1.PodBox{
		PodId:      "pod-a6",
		Namespace:  "default",
		Name:       "a6",
		RootfsPath: podRootfs,
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: podRootfs,
			ExtraReadPaths: []string{"/private/tmp", "/private/var/folders", root},
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			// A RELATIVE command: it is resolvable only because the unpacked tree
			// was materialized into the pod rootfs. Before M11.2-d7 this named a
			// file that never existed.
			{Name: "main", Image: ref, Command: []string{"bin/app"}},
		},
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}

	// The materialized rootfs must hold BOTH the later layer's binary and the
	// earlier layer's untouched file — the multi-layer apply, on disk.
	if _, serr := os.Stat(filepath.Join(podRootfs, "bin/app")); serr != nil {
		t.Fatalf("bin/app was not materialized: %v", serr)
	}
	if got := readFile(t, filepath.Join(podRootfs, "etc/from-layer-1")); got != "ONE" {
		t.Errorf("etc/from-layer-1 = %q, want ONE", got)
	}

	deadline := time.Now().Add(30 * time.Second)
	var phase runtimev1.PodPhase
	for time.Now().Before(deadline) {
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-a6"})
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

	// argv[0] came out of the SECOND layer.
	stream := newFakeLogStream(context.Background())
	if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-a6", Container: "main"}, stream); err != nil {
		t.Fatalf("GetLogs: %v", err)
	}
	var lines []string
	for _, e := range stream.entries {
		lines = append(lines, string(e.GetLine()))
	}
	found := false
	for _, l := range lines {
		if l == "pod-ran-from-layer-2" {
			found = true
		}
		if l == "pod-ran-from-layer-1" {
			t.Fatalf("the FIRST layer's binary ran; layers were applied out of order (log %v)", lines)
		}
	}
	if !found {
		t.Errorf("marker not captured; entries=%v", lines)
	}

	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-a6"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
}

// buildMarkerBinary compiles an arm64 Mach-O that prints marker and exits with
// code. It skips the test when no usable toolchain is present, rather than
// failing: the acceptance is about the unpacker, not about clang.
func buildMarkerBinary(t *testing.T, root, name, marker string, code int) string {
	t.Helper()
	src := filepath.Join(root, name+".c")
	body := "#include <stdio.h>\nint main(void){printf(\"" + marker + "\\n\");fflush(stdout);return " + strconv.Itoa(code) + ";}\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, name+".bin")
	// -arch arm64 explicitly: the native pull policy admits darwin/arm64 only, so
	// a translated toolchain defaulting to x86_64 would build a payload this node
	// is not allowed to pull an image for.
	if out, err := exec.Command("clang", "-arch", "arm64", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("clang cannot build an arm64 binary here: %v\n%s", err, out)
	}
	return bin
}

// hostIsAppleSilicon reports whether the hardware is arm64 even when the test
// binary itself is translated (a Rosetta-hosted toolchain reports GOARCH=amd64
// on an Apple Silicon Mac).
func hostIsAppleSilicon(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("sysctl", "-n", "hw.optional.arm64").Output()
	return err == nil && strings.TrimSpace(string(out)) == "1"
}

// pushExecutableImage publishes a two-layer darwin/arm64 image whose second
// layer's bin/app replaces the first's, and returns its reference.
func pushExecutableImage(t *testing.T, host, repo, layer1Bin, layer2Bin string) string {
	t.Helper()
	l1 := layerFromTar(t, []testTarEntry{
		{name: "bin", dir: true, mode: 0o755},
		{name: "bin/app", mode: 0o755, data: readFile(t, layer1Bin)},
		{name: "etc", dir: true, mode: 0o755},
		{name: "etc/from-layer-1", mode: 0o644, data: "ONE"},
	})
	l2 := layerFromTar(t, []testTarEntry{
		{name: "bin/app", mode: 0o755, data: readFile(t, layer2Bin)},
	})
	img, err := mutate.AppendLayers(empty.Image, l1, l2)
	if err != nil {
		t.Fatalf("append layers: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = "darwin", "arm64", ""
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("write image %s: %v", ref, err)
	}
	return ref.String()
}
