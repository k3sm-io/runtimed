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
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
	shimv1 "k3sm.io/apis/shim/v1"

	"k3sm.io/runtimed/pkg/supervisor"
)

// podDylib is the DYLD_INSERT_LIBRARIES value the pod sets in these tests: a
// library inside the pod's own rootfs, which must reach the pod binary and
// never the exec-shim that launches it.
const podDylib = "/var/lib/k3sm/pods/p/rootfs/libpod.dylib"

// envKeys returns the variable names in env.
func envKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		keys = append(keys, k)
	}
	return keys
}

// assertNoPodEnv fails when environ shares any key with podEnv (or is not
// empty at all: the shim's environ carries nothing).
func assertNoPodEnv(t *testing.T, environ, podEnv []string) {
	t.Helper()
	if len(environ) != 0 {
		t.Errorf("the exec-shim's own environ = %q, want it empty", environ)
	}
	for _, k := range envKeys(environ) {
		if slices.Contains(envKeys(podEnv), k) {
			t.Errorf("the exec-shim's own environ carries the pod's %s", k)
		}
	}
}

// assertPodEnvp decodes payload off the wire the shim reads, builds the pod's
// exec from it exactly as the shim does (LaunchPayload.PodExec), and checks
// the pod still receives its DYLD_INSERT_LIBRARIES and the rest of its env.
func assertPodEnvp(t *testing.T, wire []byte, podArgv, podEnv []string, wantArgv0 string) {
	t.Helper()
	p, err := supervisor.DecodeLaunchPayload(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("decode the launch payload: %v", err)
	}
	path, argv, envp := p.PodExec(podArgv)
	if path != podArgv[0] {
		t.Errorf("exec path = %q, want %q", path, podArgv[0])
	}
	if wantArgv0 != "" && (len(argv) == 0 || argv[0] != wantArgv0) {
		t.Errorf("pod argv = %q, want argv[0] %q", argv, wantArgv0)
	}
	if !slices.Contains(envp, "DYLD_INSERT_LIBRARIES="+podDylib) {
		t.Errorf("pod envp = %q, want it to carry DYLD_INSERT_LIBRARIES=%s", envp, podDylib)
	}
	if !slices.Equal(envp, podEnv) {
		t.Errorf("pod envp = %q, want exactly the pod env %q", envp, podEnv)
	}
}

// encodePayload renders the payload a spawn carries as the bytes the shim
// reads from supervisor.LaunchSpecChildFD.
func encodePayload(t *testing.T, spec supervisor.SpawnSpec) []byte {
	t.Helper()
	if spec.Launch == nil {
		t.Fatalf("spawn %q carries no launch payload", spec.Argv)
	}
	b, err := supervisor.EncodeLaunchPayload(*spec.Launch)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestLaunchModeCarriesPodEnvInSpec is the gate for the empty-environ launch:
// on every path that runs the exec-shim in launch mode — a container's launch,
// the daemon's own exec session, and the resident shim's spawn of its
// container — the shim itself starts with an EMPTY environment (so a pod-set
// DYLD_INSERT_LIBRARIES cannot load into it before the drop and
// sandbox_apply), and the pod's envp, built from the launch payload the way
// the shim builds it, still carries that DYLD_INSERT_LIBRARIES.
func TestLaunchModeCarriesPodEnvInSpec(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("WrapCommand exercises Available(), which requires darwin")
	}
	b := newTestBackend(t, 26, nil)
	profile, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"}, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	podEnv := []string{
		"PATH=/usr/bin:/bin",
		"DYLD_INSERT_LIBRARIES=" + podDylib,
		"API_TOKEN=from-a-secret",
	}
	podArgv := []string{"/var/lib/k3sm/pods/p/rootfs/app", "--serve"}
	ctx := context.Background()

	wrap := func(t *testing.T, argv []string) (string, []string) {
		t.Helper()
		path, shimArgv, cleanup, err := b.WrapCommand(ctx, profile, argv, supervisor.LaunchSpec{})
		if err != nil {
			t.Fatalf("WrapCommand: %v", err)
		}
		t.Cleanup(func() { _ = cleanup() })
		if len(shimArgv) < 3 || shimArgv[1] != supervisor.ShimModeLaunch || shimArgv[2] != supervisor.LaunchSpecToken {
			t.Fatalf("shim argv = %q, want [shim launch %s ...]", shimArgv, supervisor.LaunchSpecToken)
		}
		return path, shimArgv
	}

	t.Run("container launch", func(t *testing.T) {
		path, shimArgv := wrap(t, podArgv)
		sp := &fakeSpawner{}
		w := newFakeWaiter()
		proc := supervisor.NewProcess(sp, w, supervisor.SpawnSpec{
			Path:   path,
			Argv:   shimArgv,
			Env:    []string{},
			Launch: &supervisor.LaunchPayload{Env: podEnv},
		}, nil)
		proc.ObserveExec(func(int, bool) {}, time.Second)
		if err := proc.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { w.release(proc.PID()) })
		spec := sp.specs[len(sp.specs)-1]
		assertNoPodEnv(t, spec.Env, podEnv)
		if spec.Launch == nil || !spec.Launch.ExecSync || spec.ExecSyncFD == 0 {
			t.Errorf("the exec-sync hand-off is not in the payload: launch=%+v fd=%d", spec.Launch, spec.ExecSyncFD)
		}
		assertPodEnvp(t, encodePayload(t, spec), podArgv, podEnv, "")
	})

	t.Run("exec session", func(t *testing.T) {
		path, shimArgv := wrap(t, []string{"/bin/sh", "-c", "id"})
		cmd := exec.Command(path, shimArgv[1:]...)
		release, err := supervisor.AttachLaunchPayload(cmd, supervisor.LaunchPayload{Env: podEnv})
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if cmd.Env == nil {
			t.Fatal("cmd.Env is nil, which os/exec reads as this process's whole environment")
		}
		assertNoPodEnv(t, cmd.Env, podEnv)
		if n := len(cmd.ExtraFiles); n != supervisor.LaunchSpecChildFD-2 || cmd.ExtraFiles[n-1] == nil {
			t.Fatalf("ExtraFiles = %v, want the payload pipe as fd %d", cmd.ExtraFiles, supervisor.LaunchSpecChildFD)
		}
		wire, err := io.ReadAll(cmd.ExtraFiles[len(cmd.ExtraFiles)-1])
		if err != nil {
			t.Fatal(err)
		}
		assertPodEnvp(t, wire, []string{"/bin/sh", "-c", "id"}, podEnv, "")
	})

	t.Run("serve-to-launch hop", func(t *testing.T) {
		_, shimArgv := wrap(t, podArgv)
		// What the daemon hands the serve-mode shim (residentshim.go), through
		// the same stdin wire the shim decodes.
		stdin, err := supervisor.EncodeShimSpec(supervisor.ShimSpec{
			APIVersion:  shimv1.APIVersion,
			Container:   "c",
			Dir:         "/var/lib/k3sm/run/shim/0a1b2c3d",
			LogPath:     "/var/log/pods/p/c/0.log",
			ShimProfile: shimArgv[8] + ".shim.sb",
			Launch:      shimArgv[3:],
			Env:         podEnv,
			Argv0:       "sh",
			ExecDir:     "/var/lib/k3sm/pods/p/rootfs",
			ExecSync:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		spec, err := supervisor.DecodeShimSpec(bytes.NewReader(stdin))
		if err != nil {
			t.Fatal(err)
		}
		const self = "/usr/local/libexec/k3sm/k3sm-execshim"
		sp := &fakeSpawner{}
		if _, err := sp.Spawn(ctx, spec.ContainerSpawn(self)); err != nil {
			t.Fatal(err)
		}
		got := sp.specs[0]
		assertNoPodEnv(t, got.Env, podEnv)
		if want := append([]string{self, supervisor.ShimModeLaunch, supervisor.LaunchSpecToken}, shimArgv[3:]...); !slices.Equal(got.Argv, want) {
			t.Errorf("launch argv = %q, want %q", got.Argv, want)
		}
		if !got.KeepGroup || got.ExecSyncFD != supervisor.ExecSyncChildFD || got.Launch == nil || !got.Launch.ExecSync {
			t.Errorf("spawn = %+v, want KeepGroup, the exec-sync fd relayed and flagged in the payload", got)
		}
		assertPodEnvp(t, encodePayload(t, got), shimArgv[9:], podEnv, "sh")
	})
}

// TestLaunchPayloadReachesARealChildOnly runs the production spawner and the
// os/exec helper against /bin/sh: the child's environ is empty, and fd
// LaunchSpecChildFD carries the payload. It is the descriptor-level half of
// the gate above (no exec-shim, no privilege).
func TestLaunchPayloadReachesARealChildOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("PosixSpawner is darwin-only")
	}
	t.Setenv("K3SM_PARENT_ONLY", "must-not-leak")
	podEnv := []string{"DYLD_INSERT_LIBRARIES=" + podDylib, "A=b"}
	const script = `env; echo ---; cat <&4`

	check := func(t *testing.T, out string) {
		t.Helper()
		environ, wire, ok := strings.Cut(out, "---\n")
		if !ok {
			t.Fatalf("no separator in child output:\n%s", out)
		}
		for _, line := range strings.Split(strings.TrimSpace(environ), "\n") {
			// sh may export PWD/SHLVL/_ of its own; nothing else may appear.
			if k, _, _ := strings.Cut(line, "="); line != "" && k != "PWD" && k != "SHLVL" && k != "_" && k != "OLDPWD" {
				t.Errorf("the child's environ carries %q", line)
			}
		}
		p, err := supervisor.DecodeLaunchPayload(strings.NewReader(wire))
		if err != nil {
			t.Fatalf("decode the child's fd %d: %v\n%s", supervisor.LaunchSpecChildFD, err, wire)
		}
		if !slices.Equal(p.Env, podEnv) {
			t.Errorf("payload env = %q, want %q", p.Env, podEnv)
		}
	}

	t.Run("posix_spawn", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		// Env nil would mean "inherit" without a payload; with one it is empty.
		pid, err := supervisor.PosixSpawner{}.Spawn(context.Background(), supervisor.SpawnSpec{
			Path:     "/bin/sh",
			Argv:     []string{"/bin/sh", "-c", script},
			Launch:   &supervisor.LaunchPayload{Env: podEnv},
			StdoutFD: w.Fd(),
		})
		_ = w.Close()
		if err != nil {
			t.Fatalf("Spawn: %v", err)
		}
		out, _ := io.ReadAll(r)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _ = supervisor.KqueueReaper{}.WaitExit(ctx, pid)
		check(t, string(out))
	})

	t.Run("os/exec", func(t *testing.T) {
		cmd := exec.Command("/bin/sh", "-c", script)
		release, err := supervisor.AttachLaunchPayload(cmd, supervisor.LaunchPayload{Env: podEnv})
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		var buf bytes.Buffer
		cmd.Stdout = &buf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		release()
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child: %v", err)
		}
		check(t, buf.String())
	})

	t.Run("a launch spawn with an environ is refused", func(t *testing.T) {
		_, err := supervisor.PosixSpawner{}.Spawn(context.Background(), supervisor.SpawnSpec{
			Path:   "/bin/sh",
			Argv:   []string{"/bin/sh", "-c", "true"},
			Env:    podEnv,
			Launch: &supervisor.LaunchPayload{Env: podEnv},
		})
		if !errors.Is(err, supervisor.ErrLaunchEnviron) {
			t.Fatalf("Spawn = %v, want ErrLaunchEnviron for a launch-spec spawn carrying an environ", err)
		}
	})
}
