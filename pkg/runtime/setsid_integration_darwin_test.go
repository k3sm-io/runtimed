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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// B1868: a native pod's process that left its process group with setsid, and
// whose parent then exited, must not outlive the pod: not its DeletePod, and not
// the startup reap after a daemon binary change. Every process here is one the
// test started; nothing else on the host is signalled or inspected beyond the
// sweep under test.

// setsidRig is a real runtime (exec-shim Seatbelt backend, posix_spawn
// supervisor) plus the B1868 fixture binary, all under one short root.
type setsidRig struct {
	root, shim, fixture string
	backend             *sandbox.ExecShimBackend
}

func newSetsidRig(t *testing.T) *setsidRig {
	t.Helper()
	root := shortRoot(t)
	shim := filepath.Join(root, sandbox.ExecShimName)
	for _, b := range []struct{ out, pkg string }{
		{shim, "k3sm.io/runtimed/cmd/k3sm-execshim"},
		{filepath.Join(root, "setsidchild"), "./testdata/setsidchild"},
	} {
		build := exec.Command("go", "build", "-o", b.out, b.pkg)
		build.Env = append(os.Environ(), "CGO_ENABLED=1")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.pkg, err, out)
		}
		if out, err := exec.Command("codesign", "-s", "-", "-f", b.out).CombinedOutput(); err != nil {
			t.Fatalf("sign %s: %v\n%s", b.out, err, out)
		}
	}
	backend, err := sandbox.NewExecShimBackend(shim, root)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.Available() {
		t.Skip("exec-shim backend unavailable on this host")
	}
	return &setsidRig{root: root, shim: shim, fixture: filepath.Join(root, "setsidchild"), backend: backend}
}

// runtime opens a Runtime on the rig's root. fingerprint stands for the daemon
// build: a different one is a binary change, after which nothing re-attaches.
func (g *setsidRig) runtime(t *testing.T, fingerprint string) *Runtime {
	t.Helper()
	cache, err := image.NewCache(g.root)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{Root: g.root, RuntimeVersion: "test", PodLogsDir: filepath.Join(g.root, "podlogs")}, Deps{
		Cache:              cache,
		Backend:            g.backend,
		Spawner:            supervisor.PosixSpawner{},
		Waiter:             supervisor.KqueueReaper{},
		Network:            supervisor.NodeNetwork{IP: "127.0.0.1"},
		ProcTable:          supervisor.ReadProcTable,
		PolicyProbe:        sandbox.ProbePolicy,
		RuntimeFingerprint: fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// startSetsidPod creates a pod whose container orphans a setsid sleeper, and
// returns the sleeper's pid. mode is "stay" or "exit" (the container's own fate).
func (g *setsidRig) startSetsidPod(t *testing.T, rt *Runtime, podID, mode string) int {
	t.Helper()
	rootfs := derivedRootfs(t, rt, podID)
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(rootfs, "setsidchild")
	raw, err := os.ReadFile(g.fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(rootfs, "sleeper.pid")
	box := &runtimev1.PodBox{
		PodId:                         podID,
		Namespace:                     "default",
		Name:                          podID,
		LogDirectory:                  testPodLogDir(rt, podID),
		TerminationGracePeriodSeconds: 2,
		SandboxProfile:                &runtimev1.SandboxProfile{DataVolumePath: rootfs},
		SignaturePolicy:               runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			{Name: "main", Image: NativeImage, Command: []string{bin, pidFile, mode}},
		},
	}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod transport: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if b, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				g.mustBeEscaped(t, pid)
				if start, ok := supervisor.ProcStartTimeNano(pid); ok {
					t.Cleanup(func() { killSameInstance(pid, start) })
				}
				// The go-ahead a swap-mode fixture waits for before it
				// removes its rootfs, pid file included.
				if err := os.WriteFile(filepath.Join(rootfs, "go"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return pid
			}
		}
		if time.Now().After(deadline) {
			st, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
			ents, _ := os.ReadDir(rootfs)
			t.Fatalf("pod %s: the fixture never recorded its sleeper's pid (status %v, rootfs %v, log %q)",
				podID, st, ents, containerLogLines(t, rt, podID))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// mustBeEscaped asserts the fixture did what B1868 is about: the sleeper is
// launchd's child in its own session, outside every container group.
func (g *setsidRig) mustBeEscaped(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			t.Fatalf("sleeper %d: %v", pid, err)
		}
		if int(kp.Eproc.Ppid) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sleeper %d still has parent %d; the fixture did not orphan it", pid, kp.Eproc.Ppid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sid, err := unix.Getsid(pid); err != nil || sid == unix.Getpid() {
		t.Fatalf("sleeper %d session %d (err %v)", pid, sid, err)
	}
}

// killSameInstance is cleanup for a test's own sleeper: it signals pid only
// while it is still the instance the test recorded (same kernel start time), so
// a reused pid is never hit.
func killSameInstance(pid int, start int64) {
	if st, ok := supervisor.ProcStartTimeNano(pid); ok && st == start {
		_ = unix.Kill(pid, unix.SIGKILL)
	}
}

// awaitGone waits up to bound for pid to exit.
func awaitGone(t *testing.T, pid int, bound time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		if errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: pid %d is still alive %s later", what, pid, bound)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func mustAlive(t *testing.T, pid int, what string) {
	t.Helper()
	if err := unix.Kill(pid, 0); err != nil {
		t.Fatalf("%s: pid %d was killed (kill(pid, 0) = %v); it is not the deleted pod's", what, pid, err)
	}
}

// startBystander starts a process the test owns outside any pod, running as the
// same user as every pod process, and returns its pid.
func startBystander(t *testing.T, name string, args ...string) int {
	t.Helper()
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd.Process.Pid
}

// TestSetsidDescendantReapedOnDelete: after DeletePod, the pod's setsid
// sleeper is gone, while a second pod's sleeper, an unsandboxed same-user
// process and a same-user process under a permissive Seatbelt profile all live.
func TestSetsidDescendantReapedOnDelete(t *testing.T) {
	g := newSetsidRig(t)
	rt := g.runtime(t, "build-a")
	t.Cleanup(func() { _ = rt.Close() })

	victim := g.startSetsidPod(t, rt, "pod-setsid-del", "stay")
	other := g.startSetsidPod(t, rt, "pod-setsid-other", "stay")
	plain := startBystander(t, "/bin/sleep", "300")
	permissive := startBystander(t, "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/sleep", "300")

	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-setsid-del"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	awaitGone(t, victim, 5*time.Second, "the deleted pod's setsid sleeper")
	mustAlive(t, other, "another pod's setsid sleeper")
	mustAlive(t, plain, "an unsandboxed same-user process")
	mustAlive(t, permissive, "a same-user process under a permissive sandbox")

	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-setsid-other"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	awaitGone(t, other, 5*time.Second, "the second pod's setsid sleeper")
	mustAlive(t, plain, "an unsandboxed same-user process")
	mustAlive(t, permissive, "a same-user process under a permissive sandbox")
}

// TestSetsidDescendantReapedOnRecreate: a daemon binary change recreates every
// pod. The previous run's pod, still running and with a setsid sleeper it
// orphaned (the agentd-leader and codex-broker shape), is reaped by the next
// run's startup reap, sleeper included, and unrelated same-user processes
// survive it.
func TestSetsidDescendantReapedOnRecreate(t *testing.T) {
	g := newSetsidRig(t)
	rt1 := g.runtime(t, "build-a")
	victim := g.startSetsidPod(t, rt1, "pod-setsid-rec", "stay")
	plain := startBystander(t, "/bin/sleep", "300")
	permissive := startBystander(t, "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/sleep", "300")
	if err := rt1.Close(); err != nil {
		t.Fatalf("close the first run: %v", err)
	}
	mustAlive(t, victim, "the setsid sleeper across the daemon stop")

	rt2 := g.runtime(t, "build-b")
	t.Cleanup(func() { _ = rt2.Close() })
	if err := rt2.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	awaitGone(t, victim, 5*time.Second, "the previous run's setsid sleeper after the startup reap")
	mustAlive(t, plain, "an unsandboxed same-user process")
	mustAlive(t, permissive, "a same-user process under a permissive sandbox")
}

// TestSetsidDescendantReapedDespiteRootfsSwap is the hostile pod: before it is
// deleted it replaces its own rootfs with a symlink to another pod's rootfs.
// The policy probe resolves symlinks, so an identity that named the rootfs
// would then vouch for the OTHER pod's processes. The identity names only
// nodes a pod cannot replace: the hostile pod's own sleeper is still reaped
// and the other pod's is untouched.
func TestSetsidDescendantReapedDespiteRootfsSwap(t *testing.T) {
	g := newSetsidRig(t)
	rt := g.runtime(t, "build-a")
	t.Cleanup(func() { _ = rt.Close() })

	bystander := g.startSetsidPod(t, rt, "pod-setsid-victim", "stay")
	const hostile = "pod-setsid-hostile"
	hostileRootfs := derivedRootfs(t, rt, hostile)
	target := derivedRootfs(t, rt, "pod-setsid-victim")
	sleeper := g.startSetsidPod(t, rt, hostile, "swap:"+hostileRootfs+":"+target)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if fi, err := os.Lstat(hostileRootfs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hostile pod never replaced its rootfs with a symlink; the attack this test defends against did not happen (log %q)",
				containerLogLines(t, rt, hostile))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: hostile}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	awaitGone(t, sleeper, 5*time.Second, "the hostile pod's own setsid sleeper")
	mustAlive(t, bystander, "the pod whose rootfs the hostile pod linked to")
	if _, err := os.Stat(filepath.Join(target, "setsidchild")); err != nil {
		t.Errorf("the other pod's rootfs was damaged by the hostile pod's delete: %v", err)
	}
}
