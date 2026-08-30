//go:build darwin

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

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/apis/k3smtest"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Environment knobs the LAB HARNESS sets to run this gate. They are declared
// inputs, not discovery: this package must not go hunting for a Python
// interpreter on PATH (see the k3sm-execshim probe's rationale — a planted binary
// on an admin-writable PATH executes as the daemon identity), and it must not
// bake in one lab's directory layout.
const (
	// envMLXPython is an absolute path to a Python interpreter with mlx installed.
	envMLXPython = "K3SM_MLX_PYTHON"
	// envMLXReadPaths is a colon-separated list of host trees the confined process
	// must read (the interpreter prefix, the site-packages tree). Empty defaults to
	// the interpreter's prefix (the parent of its bin/ directory).
	envMLXReadPaths = "K3SM_MLX_READ_PATHS"
	// envMLXModel is an optional local model directory. When set, the gate also
	// runs a full text-generation round trip through mlx_lm on top of the matmul.
	envMLXModel = "K3SM_MLX_MODEL"
)

// gpuProbeScript is the matmul the confined process runs. It PINS the GPU device
// explicitly, so a run that silently fell back to the CPU fails instead of
// reporting a green GPU gate, and it checks the computed value rather than merely
// that the call returned: ones(256,256) @ ones(256,256) sums to 256**3.
const gpuProbeScript = `
import mlx.core as mx

mx.set_default_device(mx.gpu)
dev = str(mx.default_device())
if "gpu" not in dev.lower():
    raise SystemExit("device is %s, not the GPU" % dev)

n = 256
a = mx.ones((n, n))
b = mx.ones((n, n))
c = a @ b
mx.eval(c)
total = int(c.sum().item())
want = n * n * n
if total != want:
    raise SystemExit("matmul sum %d, want %d" % (total, want))
print("MATMUL_OK", total, dev)
`

// gpuGenerateScript is the optional full inference round trip: load a local model
// and generate tokens, all under the same profile.
const gpuGenerateScript = `
import os
import mlx.core as mx
from mlx_lm import load, generate

mx.set_default_device(mx.gpu)
model, tokenizer = load(os.environ["K3SM_MLX_MODEL"])
out = generate(model, tokenizer, prompt="Name one primary color.", max_tokens=16)
if not out.strip():
    raise SystemExit("generation produced no tokens")
print("GENERATE_OK", len(out))
`

// TestIntegrationMetalMatmulUnderProfile is acceptance M8.2-a4: a real MLX matmul
// runs on the GPU inside the profile Generate produces for allow_gpu.
//
// It is the ONLY check that can falsify the Metal allow-set. The unit goldens pin
// what the generator emits; they cannot know whether those two IOKit user-client
// classes are the ones Metal actually opens on a given chip family — SBPL class
// names are data, with no linker-symbol canary behind them. So this test is where
// a family whose class names differ, or a macOS release that renames one, is
// caught.
//
// It SKIPS off a GPU lab rig (k3smtest gates it on the apple-gpu capability), which
// is the expected outcome of an ordinary `go test ./...`. It is deliberately NOT
// behind the `integration` build tag so it still COMPILES in that run: a lab-only
// gate that stops compiling is a gate nobody notices is broken until the lab needs
// it. Naming apple-gpu in K3SM_CI_REQUIRE turns the skip into a failure, which is
// how the lab harness asserts it really ran.
func TestIntegrationMetalMatmulUnderProfile(t *testing.T) {
	k3smtest.SkipUnless(t, k3smtest.AppleGPU)

	python := os.Getenv(envMLXPython)
	if python == "" {
		t.Skipf("%s is unset: point it at an absolute path to a Python interpreter with mlx installed", envMLXPython)
	}
	if !filepath.IsAbs(python) {
		t.Fatalf("%s = %q must be an absolute path (a PATH lookup would run whatever an admin-writable directory holds)", envMLXPython, python)
	}
	if _, err := os.Stat(python); err != nil {
		t.Fatalf("%s = %q: %v", envMLXPython, python, err)
	}

	readPaths := mlxReadPaths(t, python)
	posture, dataVol := gpuPodVolume(t, "pod-gpu-matmul")
	profile, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
		AllowGpu:       true,
		ExtraReadPaths: readPaths,
	}, GenerateOptions{Posture: posture})
	if err != nil {
		t.Fatalf("Generate(allow_gpu) with read paths %v: %v\n"+
			"if this is ErrProtectedPath, stage the MLX interpreter outside the protected prefixes "+
			"(user homes, /private/var/db, the cryptexes) and set %s", readPaths, err, envMLXReadPaths)
	}

	shim := buildGPUExecShim(t)
	env := gpuPodEnv(dataVol)

	t.Run("matmul", func(t *testing.T) {
		out := runGPUScript(t, shim, profile, env, dataVol, python, "matmul.py", gpuProbeScript)
		if !strings.Contains(out, "MATMUL_OK") {
			t.Fatalf("MLX matmul did not run on the GPU under the allow_gpu profile:\n%s", out)
		}
		t.Logf("matmul under profile: %s", strings.TrimSpace(out))
	})

	// The one negative that proves the allow-set is load-bearing rather than
	// decorative: WITHOUT allow_gpu the same script must fail to reach a device.
	t.Run("denied without allow_gpu", func(t *testing.T) {
		denied, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath: dataVol,
			ExtraReadPaths: readPaths,
		}, GenerateOptions{Posture: posture})
		if err != nil {
			t.Fatalf("Generate(no gpu): %v", err)
		}
		out := runGPUScriptAllowFail(t, shim, denied, env, dataVol, python, "matmul-denied.py", gpuProbeScript)
		if strings.Contains(out, "MATMUL_OK") {
			t.Fatalf("the GPU was reachable WITHOUT allow_gpu; the profile grants it by default:\n%s", out)
		}
	})

	if model := os.Getenv(envMLXModel); model != "" {
		t.Run("generate", func(t *testing.T) {
			out := runGPUScript(t, shim, profile, append(env, envMLXModel+"="+model), dataVol, python, "generate.py", gpuGenerateScript)
			if !strings.Contains(out, "GENERATE_OK") {
				t.Fatalf("MLX generation did not complete under the allow_gpu profile:\n%s", out)
			}
			t.Logf("generation under profile: %s", strings.TrimSpace(out))
		})
	}
}

// mlxReadPaths returns the host trees the confined process must read: the declared
// list, or the interpreter's prefix (the parent of its bin/ dir) by default.
func mlxReadPaths(t *testing.T, python string) []string {
	t.Helper()
	if declared := os.Getenv(envMLXReadPaths); declared != "" {
		return strings.Split(declared, ":")
	}
	return []string{filepath.Dir(filepath.Dir(python))}
}

// gpuPodVolume builds a node posture rooted at a fresh temp work-dir plus the pod
// data volume under it, exactly as the production layout derives it (Generate
// bounds the data volume to <WorkDir>/pods, so a bare temp dir is refused).
func gpuPodVolume(t *testing.T, podID string) (Posture, string) {
	t.Helper()
	workDir := t.TempDir()
	dataVol := filepath.Join(workDir, "pods", podID, "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	return Posture{WorkDir: workDir}, dataVol
}

// gpuPodEnv points every cache/home variable at the pod's own writable data volume.
//
// The HOME redirect is not hygiene, it is the difference between running and not:
// a confined process whose cwd or HOME is a denied path dies inside its own import
// machinery (os.getcwd() → PermissionError) long before any GPU rule is consulted.
func gpuPodEnv(dataVol string) []string {
	return append(os.Environ(),
		"HOME="+dataVol,
		"TMPDIR="+dataVol,
		"XDG_CACHE_HOME="+filepath.Join(dataVol, ".cache"),
		"HF_HOME="+filepath.Join(dataVol, ".cache", "huggingface"),
		"PYTHONDONTWRITEBYTECODE=1",
	)
}

// buildGPUExecShim builds and ad-hoc signs the k3sm-execshim helper so the script
// runs through the REAL libsandbox path a pod does, not through sandbox-exec.
func buildGPUExecShim(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, ExecShimName)
	build := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build k3sm-execshim: %v\n%s", err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("codesign shim: %v\n%s", err, out)
	}
	return shim
}

// runGPUScript runs script under profile and fails the test if it exits non-zero.
func runGPUScript(t *testing.T, shim, profile string, env []string, dataVol, python, name, script string) string {
	t.Helper()
	out, err := execGPUScript(t, shim, profile, env, dataVol, python, name, script)
	if err != nil {
		t.Fatalf("%s under the profile: %v\n%s", name, err, out)
	}
	return out
}

// runGPUScriptAllowFail runs script under profile and returns its output whatever
// the exit status — the negative case expects failure.
func runGPUScriptAllowFail(t *testing.T, shim, profile string, env []string, dataVol, python, name, script string) string {
	t.Helper()
	out, _ := execGPUScript(t, shim, profile, env, dataVol, python, name, script)
	return out
}

// execGPUScript writes script into the pod's data volume and runs it through the
// exec-shim under profile, with the process's CWD inside that volume.
func execGPUScript(t *testing.T, shim, profile string, env []string, dataVol, python, name, script string) (string, error) {
	t.Helper()
	path := filepath.Join(dataVol, name)
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(pf, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	// Shim contract: <uid> <gid> <groups-csv> <rlimits> <qos> <profile.sb> <binary>...
	argv := []string{"-1", "-1", "-", "-", "-", pf, python, path}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, shim, argv...)
	cmd.Env = env
	// CWD inside the pod's own writable volume — a denied cwd kills the interpreter
	// during import, with an error that points nowhere near the sandbox.
	cmd.Dir = dataVol
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}
