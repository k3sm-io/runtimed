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
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// mcProbeSpawner records, AT the MOMENT OF the spawn, whether the directory a
// spec's CLANG_MODULE_CACHE_PATH names already exists — the same ordering
// property podtmpdir_test asserts for TMPDIR, and for the same reason: a cache
// directory provisioned after the compiler looked for it is not provisioned.
type mcProbeSpawner struct {
	mu    sync.Mutex
	next  int
	specs []supervisor.SpawnSpec
	found []bool
	modes []os.FileMode
}

func (f *mcProbeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, spec)
	ok, mode := false, os.FileMode(0)
	if dir, has := envValue(spec.Env, clangModuleCacheEnv); has {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			ok, mode = true, fi.Mode().Perm()
		}
	}
	f.found = append(f.found, ok)
	f.modes = append(f.modes, mode)
	f.next++
	return 3000 + f.next, nil
}

func (f *mcProbeSpawner) last() (supervisor.SpawnSpec, bool, os.FileMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.specs)
	if n == 0 {
		return supervisor.SpawnSpec{}, false, 0
	}
	return f.specs[n-1], f.found[n-1], f.modes[n-1]
}

// TestPodLaunchEnvCarriesModuleCacheInDataVolume is TMPDIR's story a second
// time, in the one place TMPDIR could not reach.
//
// Apple's clang and swift front ends do not take their module cache from
// $TMPDIR. They call confstr(_CS_DARWIN_USER_CACHE_DIR), which ignores the
// environment and names the invoking uid's shared /var/folders tree — a path
// the pod profile denies, and should keep denying: every pod on a node shares
// this daemon's uid, and a module cache holds .pcm files the NEXT compile
// loads, so a writable shared cache would be a build-poisoning channel between
// pods rather than merely a disclosure one.
//
// The consequence, measured on macOS 26.6 before this change: plain C and plain
// Objective-C compile and run in a pod, because they touch no module cache, but
// anything using clang modules — `-fmodules`, and Swift always — dies with
// "unable to open output file … /clang/ModuleCache/…: Operation not permitted".
// That reproduces on the Command Line Tools with no Xcode grant of any kind,
// which is why the fix lives here and not in the toolchain grant.
func TestPodLaunchEnvCarriesModuleCacheInDataVolume(t *testing.T) {
	t.Run("injected into the launch env, and the dir exists pre-spawn", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-mc"

		mustCreatePod(t, rt, hostBinBox(rt, podID))

		spec, found, mode := sp.last()
		want := podModuleCacheDir(derivedRootfs(t, rt, podID))
		got := mustEnvValue(t, spec.Env, clangModuleCacheEnv)
		if got != want {
			t.Errorf("%s = %q, want %q inside the pod data volume", clangModuleCacheEnv, got, want)
		}
		if !found {
			t.Errorf("%s=%q did not exist at the moment of the spawn", clangModuleCacheEnv, got)
		}
		if mode != 0o700 {
			t.Errorf("pod module cache mode = %#o, want 0700", mode)
		}
	})

	t.Run("a pulled image gets it too", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-mc-img"

		mustCreatePod(t, rt, pulledImageBox(t, rt, podID))

		spec, found, _ := sp.last()
		if got, want := mustEnvValue(t, spec.Env, clangModuleCacheEnv), podModuleCacheDir(derivedRootfs(t, rt, podID)); got != want {
			t.Errorf("%s = %q, want %q", clangModuleCacheEnv, got, want)
		}
		if !found {
			t.Error("pod module cache did not exist at the moment of the spawn")
		}
	})

	t.Run("a spec-set module cache wins, exactly once", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-mc-own"

		box := hostBinBox(rt, podID)
		box.GetContainers()[0].Env = []*runtimev1.EnvVar{{Name: clangModuleCacheEnv, Value: "/spec/mc"}}
		mustCreatePod(t, rt, box)

		spec, _, _ := sp.last()
		if got := mustEnvValue(t, spec.Env, clangModuleCacheEnv); got != "/spec/mc" {
			t.Errorf("%s = %q, want the spec's own /spec/mc", clangModuleCacheEnv, got)
		}
		if n := countName(spec.Env, clangModuleCacheEnv); n != 1 {
			t.Errorf("%s appears %d times in the launch env, want exactly 1: %v", clangModuleCacheEnv, n, spec.Env)
		}
	})

	// The two injections are independent, because the toolchain treats them as
	// independent. A container that names its own TMPDIR must still get a module
	// cache — an implementation that derived one from the other would silently
	// point the cache at a path the spec never provisioned.
	t.Run("a spec-set TMPDIR does not suppress the module cache", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-mc-tmponly"

		box := hostBinBox(rt, podID)
		box.GetContainers()[0].Env = []*runtimev1.EnvVar{{Name: tmpDirEnv, Value: "/spec/tmp"}}
		mustCreatePod(t, rt, box)

		spec, found, _ := sp.last()
		if got := mustEnvValue(t, spec.Env, tmpDirEnv); got != "/spec/tmp" {
			t.Errorf("%s = %q, want the spec's own /spec/tmp", tmpDirEnv, got)
		}
		want := podModuleCacheDir(derivedRootfs(t, rt, podID))
		if got := mustEnvValue(t, spec.Env, clangModuleCacheEnv); got != want {
			t.Errorf("%s = %q, want %q — the module cache is not derived from TMPDIR", clangModuleCacheEnv, got, want)
		}
		if !found {
			t.Error("pod module cache did not exist at the moment of the spawn")
		}
	})

	// Containment: the injected path must stay inside the data volume the
	// profile already write-allows. This is what stops a future "just point it
	// at the user cache dir" from reintroducing the shared-cache channel.
	t.Run("the dir is inside the pod data volume", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
		const podID = "pod-mc-scope"
		rootfs := derivedRootfs(t, rt, podID)
		want := rootfs + "/" + podTmpDirName + "/" + podModuleCacheName
		if got := podModuleCacheDir(rootfs); got != want {
			t.Errorf("podModuleCacheDir = %q, want %q", got, want)
		}
		// Containment against the DATA VOLUME, not against the literal
		// /var/folders string: a test tempdir legitimately lives under
		// /var/folders itself, so the string check would fail on a correct path.
		// What matters is that the cache is inside the tree the profile
		// write-allows.
		if !strings.HasPrefix(podModuleCacheDir(rootfs), rootfs+"/") {
			t.Errorf("podModuleCacheDir %q is not inside the pod data volume %q", podModuleCacheDir(rootfs), rootfs)
		}
	})
}

// TestConfinedSwiftCompileNeedsTheInjectedModuleCache is the execution test the
// golden could not be: it compiles Swift under a REAL generated pod profile and
// asserts that the injected module cache is what makes it work.
//
// A golden-diff test cannot see a missing grant — the profile was correct, and
// the compile still failed, because the toolchain asked confstr for a directory
// nobody had told the profile about. Only running the compiler finds that. Both
// directions are asserted, so this stays honest if the default ever changes:
// with the module cache pointed inside the data volume the compile SUCCEEDS,
// and with it left at the platform default the compile FAILS.
func TestConfinedSwiftCompileNeedsTheInjectedModuleCache(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	swiftc, err := exec.LookPath("swiftc")
	if err != nil {
		t.Skip("no swiftc on PATH")
	}
	if err := exec.Command(swiftc, "--version").Run(); err != nil {
		t.Skipf("swiftc does not run on this host: %v", err)
	}

	work := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(work); err == nil {
		work = resolved
	}
	if strings.HasPrefix(work, "/Users/") {
		t.Skipf("TMPDIR resolves under /Users (%s), which the pod profile denies", work)
	}
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	if err := os.MkdirAll(podModuleCacheDir(dataVol), 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dataVol, "main.swift")
	if err := os.WriteFile(src, []byte("print(\"hello from a pod\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	profile, err := generateTestPodProfile(dataVol, work)
	if err != nil {
		t.Fatalf("generate profile: %v", err)
	}
	profPath := filepath.Join(work, "pod.sb")
	if err := os.WriteFile(profPath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}

	compile := func(t *testing.T, moduleCache string, out string) (string, error) {
		t.Helper()
		cmd := exec.Command("/usr/bin/sandbox-exec", "-f", profPath, swiftc, "-o", out, "main.swift")
		cmd.Dir = dataVol
		env := []string{"PATH=/usr/bin:/bin", "HOME=" + dataVol, tmpDirEnv + "=" + podTmpDir(dataVol)}
		if moduleCache != "" {
			env = append(env, clangModuleCacheEnv+"="+moduleCache)
		}
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		return string(b), err
	}

	// RED: the platform default, which is what a pod got before this change.
	out, err := compile(t, "", "without")
	if err == nil {
		t.Errorf("a confined swiftc compiled with NO module cache injected — the platform default is reachable from a pod, so this test no longer proves anything:\n%s", out)
	} else if !strings.Contains(out, "ModuleCache") && !strings.Contains(out, "Operation not permitted") {
		t.Errorf("the confined compile failed for an unexpected reason (want a module-cache denial):\n%s", out)
	}

	// GREEN: the injected per-pod cache.
	if out, err := compile(t, podModuleCacheDir(dataVol), "with"); err != nil {
		t.Fatalf("a confined swiftc failed WITH the injected module cache, which is the whole point:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dataVol, "with")); err != nil {
		t.Fatalf("the compile reported success but produced no binary: %v", err)
	}
}

// generateTestPodProfile renders a pod profile with the SHIPPED generator, so
// the execution test above runs against the bytes a real pod gets rather than a
// hand-written replica — the distinction that let the module-cache gap survive
// a full ablation the first time.
func generateTestPodProfile(dataVol, workDir string) (string, error) {
	return sandbox.Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
	}, sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: workDir}})
}
