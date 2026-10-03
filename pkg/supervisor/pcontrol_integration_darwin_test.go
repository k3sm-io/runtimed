//go:build integration && darwin && cgo

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

package supervisor_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// buildShim builds and ad-hoc signs the real k3sm-execshim into a temp dir.
func buildShim(t *testing.T) string {
	t.Helper()
	shim := filepath.Join(t.TempDir(), sandbox.ExecShimName)
	cmd := exec.Command("go", "build", "-o", shim, "k3sm.io/runtimed/cmd/k3sm-execshim")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build k3sm-execshim: %v\n%s", err, out)
	}
	if out, err := exec.Command("codesign", "-s", "-", "-f", shim).CombinedOutput(); err != nil {
		t.Fatalf("codesign shim: %v\n%s", err, out)
	}
	return shim
}

// podProfile renders the production pod SBPL for a fresh pod data volume and
// writes it to a file, returning the profile path and the data volume.
func podProfile(t *testing.T, podID string) (string, string) {
	t.Helper()
	workDir := t.TempDir()
	dataVol := filepath.Join(workDir, "pods", podID, "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	prof, err := sandbox.Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol,
		ExtraReadPaths: []string{"/private/tmp", "/private/var/folders", dataVol},
	}, sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: workDir}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pf := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(pf, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	return pf, dataVol
}

// shimArgv is the launch-mode exec-shim argv for a no-drop, no-limit,
// default-QoS pod.
func shimArgv(shim, profile string, pod ...string) []string {
	return append([]string{shim, supervisor.ShimModeLaunch, "-1", "-1", "-", "-", "-", profile}, pod...)
}

// comm returns pid's kernel command name, or "" when it cannot be read.
func comm(pid int) string {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return ""
	}
	b := make([]byte, 0, len(kp.Proc.P_comm))
	for _, c := range kp.Proc.P_comm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// awaitComm polls until pid's command name is want (the exec has happened).
func awaitComm(t *testing.T, pid int, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if comm(pid) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d never became %q (comm %q)", pid, want, comm(pid))
}

// spawnMarked starts argv through the production marked spawner and registers
// a group SIGKILL plus a reap.
func spawnMarked(t *testing.T, argv []string) int {
	t.Helper()
	pid, err := supervisor.PosixSpawner{PressureKill: true}.Spawn(context.Background(),
		supervisor.SpawnSpec{Path: argv[0], Argv: argv, Env: os.Environ()})
	if err != nil {
		t.Fatalf("Spawn %v: %v", argv, err)
	}
	t.Cleanup(func() {
		_ = supervisor.SignalGroup(pid, unix.SIGKILL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _ = supervisor.KqueueReaper{}.WaitExit(ctx, pid)
	})
	return pid
}

// startUnderOSExec starts argv with os/exec (fork+exec, the exec-session path)
// and registers a kill plus a wait.
func startUnderOSExec(t *testing.T, argv []string) int {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %v: %v", argv, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

func mustFlags(t *testing.T, pid int) uint32 {
	t.Helper()
	f, err := supervisor.PcontrolFlags(pid)
	if err != nil {
		t.Fatalf("PcontrolFlags(%d): %v", pid, err)
	}
	return f
}

// TestIntegrationPodSpawnPcontrolReadback proves the pressure-kill mark reaches
// the process a pod actually runs as, on both paths a pod process is started,
// and pins the kernel behaviour that shapes the design:
//
//   - container: the marked spawner starts the real exec-shim under the real
//     pod profile, which execs /bin/sleep; the sleep carries the mark;
//   - plain execve: a marked /bin/sh execs /bin/sleep after a file handshake,
//     with no shim involved. The sh is marked before the exec and the sleep is
//     NOT after it: execve clears the mark, which is why the shim execs through
//     posix_spawn(POSIX_SPAWN_SETEXEC) with the attribute. If an OS update
//     starts keeping the mark this fails, and the SETEXEC path can be revisited.
//     The sh's own forked child is logged (an observation, not an assertion);
//   - exec session: os/exec (fork, so no inherited mark) starts the shim, whose
//     marked exec is the only source of the bit; a direct os/exec of
//     /bin/sleep is the unmarked control.
func TestIntegrationPodSpawnPcontrolReadback(t *testing.T) {
	shim := buildShim(t)
	profile, _ := podProfile(t, "pod-pcontrol")

	t.Run("container-shim-chain", func(t *testing.T) {
		pid := spawnMarked(t, shimArgv(shim, profile, "/bin/sleep", "60"))
		awaitComm(t, pid, "sleep")
		if f := mustFlags(t, pid); !supervisor.PcontrolIsKill(f) {
			t.Fatalf("container process pbi_flags = 0x%x, want pcontrol-KILL", f)
		}
	})

	t.Run("plain-execve-clears-spawn-mark", func(t *testing.T) {
		dir := t.TempDir()
		childFile, goFile := filepath.Join(dir, "child"), filepath.Join(dir, "go")
		script := "/bin/sleep 61 & echo $! > " + childFile +
			"; while [ ! -e " + goFile + " ]; do /bin/sleep 0.05; done; exec /bin/sleep 60"
		pid := spawnMarked(t, []string{"/bin/sh", "-c", script})

		if f := mustFlags(t, pid); !supervisor.PcontrolIsKill(f) {
			t.Fatalf("marked sh before execve: pbi_flags = 0x%x, want pcontrol-KILL", f)
		}
		var childPid int
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(childFile); err == nil {
				if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
					childPid = n
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if childPid > 0 {
			if f, err := supervisor.PcontrolFlags(childPid); err == nil {
				t.Logf("observation: forked child of a marked process: pbi_flags 0x%x, pcontrol-KILL=%v", f, supervisor.PcontrolIsKill(f))
			} else {
				t.Logf("observation: forked child flags unreadable: %v", err)
			}
		} else {
			t.Logf("observation: forked child pid never written")
		}

		if err := os.WriteFile(goFile, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		awaitComm(t, pid, "sleep")
		if f := mustFlags(t, pid); supervisor.PcontrolIsKill(f) {
			t.Fatalf("after a plain execve: pbi_flags = 0x%x still pcontrol-KILL; execve no longer clears the mark", f)
		}
	})

	t.Run("exec-session-self-marks", func(t *testing.T) {
		control := startUnderOSExec(t, []string{"/bin/sleep", "60"})
		awaitComm(t, control, "sleep")
		if f := mustFlags(t, control); supervisor.PcontrolIsKill(f) {
			t.Fatalf("control: os/exec /bin/sleep carries pcontrol-KILL (0x%x); the test host marks everything", f)
		}

		pid := startUnderOSExec(t, shimArgv(shim, profile, "/bin/sleep", "60"))
		awaitComm(t, pid, "sleep")
		if f := mustFlags(t, pid); !supervisor.PcontrolIsKill(f) {
			t.Fatalf("exec-session process pbi_flags = 0x%x, want pcontrol-KILL from the shim's marked exec", f)
		}
	})
}

// TestIntegrationConfinedPodCanClearPcontrolToday PINS what a confined pod can do
// to its own mark today. A helper running under the real pod profile reads its
// mark, calls proc_setpcontrol(PROC_SETPC_NONE) on itself and reads it again.
// The observed behaviour (see the assertion) is recorded, not endorsed: today
// the pod starts marked and CAN clear its own mark. The test fails when the
// observation changes, so a profile or OS change is noticed.
func TestIntegrationConfinedPodCanClearPcontrolToday(t *testing.T) {
	shim := buildShim(t)
	profile, dataVol := podProfile(t, "pod-pcontrol-clear")

	src := filepath.Join(dataVol, "clear.c")
	helper := filepath.Join(dataVol, "clear")
	const prog = `#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <unistd.h>
static int flags(unsigned *out) {
	struct proc_bsdinfo bi; memset(&bi, 0, sizeof bi);
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi) return errno ? errno : EIO;
	*out = bi.pbi_flags & PROC_FLAG_PC_MASK; return 0;
}
int main(void) {
	unsigned before = 0, after = 0;
	int e1 = flags(&before);
	errno = 0;
	int rc = proc_setpcontrol(PROC_SETPC_NONE);
	int se = rc ? errno : 0;
	int e2 = flags(&after);
	printf("before=0x%x readerr=%d set_rc=%d set_errno=%d after=0x%x readerr2=%d\n", before, e1, rc, se, after, e2);
	return 0;
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-o", helper, src).CombinedOutput(); err != nil {
		t.Skipf("clang unavailable to build the helper (%v): %s", err, out)
	}

	argv := shimArgv(shim, profile, helper)
	cmd := exec.Command(argv[0], argv[1:]...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper under the pod profile: %v\n%s", err, buf.String())
	}
	got := strings.TrimSpace(buf.String())
	t.Logf("observation: %s", got)
	const want = "before=0x600 readerr=0 set_rc=0 set_errno=0 after=0x0 readerr2=0"
	if got != want {
		t.Fatalf("confined self-clear observation changed:\n got  %s\n want %s", got, want)
	}
}
