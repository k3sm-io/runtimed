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

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"

	guestv1 "k3sm.io/apis/guest/v1"
	"k3sm.io/apis/k3smtest"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// THE M11.2-d9 LIVE VM-BOOT SMOKE: a real k3sm-vmhost, a real Virtualization
// machine, a real Linux guest, driven by a real in-process runtime.Runtime.
//
// WHAT IT IS FOR, given the unit tier already exists. The unit gate (a8) drives
// the whole boot state machine against fake spawn/reap/health seams, which proves
// the LOGIC — the readiness race, the deadline kill, the grace arithmetic, the
// orphan decision. It cannot prove the two things only hardware can answer:
// whether the bytes this daemon writes are bytes a real helper will boot from,
// and whether the handshake it waits for actually completes across a hypervisor.
// Both were false at first contact: the first live run died on a virtiofs share
// root nothing created, which every fake-seam test had waved through because its
// share plan was empty.
//
// It is NOT behind the `integration` build tag, deliberately, and for the reason
// TestIntegrationMetalMatmulUnderProfile gives: a lab-only gate that stops
// COMPILING is a gate nobody notices is broken until the lab needs it. It stays
// in the ordinary build and SKIPS, so `go test ./...` on any machine keeps it
// honest without running it.
//
// IT DECLARES ITS INPUTS, it does not discover them. There is no hunting for a
// kernel on the filesystem and no PATH lookup for the helper: the kernel and
// modules are named by environment, and the helper is BUILT AND SIGNED FROM THIS
// TREE, so the smoke can never accidentally certify a helper someone else left
// lying around.

// The declared lab inputs.
const (
	// envSmokeKernel is an absolute path to an arm64 Linux kernel image (an
	// uncompressed `Image`, which is what VZLinuxBootLoader takes).
	envSmokeKernel = "K3SM_VM_SMOKE_KERNEL"
	// envSmokeModules is an optional colon-separated list of absolute .ko paths
	// to load, IN THE ORDER GIVEN, before the guest agent binds. Stock distro
	// kernels ship AF_VSOCK as a module, so a lab using one names
	// vsock.ko:vmw_vsock_virtio_transport_common.ko:vmw_vsock_virtio_transport.ko
	// here. A kernel with vsock built in leaves it unset.
	envSmokeModules = "K3SM_VM_SMOKE_MODULES"
)

// smokeBootBudget bounds one whole leg (spawn -> boot -> Health). It is far above
// the ~0.7 s the chain measures on a warm rig and exists only so a wedged lab
// fails the test rather than the go-test binary's own 10-minute panic.
const smokeBootBudget = 90 * time.Second

// requireEntitledHelper fails unless the vm backend reports itself usable with
// the helper this test just built.
//
// IT IS A PROBE, NOT AN ASSUMPTION, and it is the SECOND of two gates. The first
// (k3smtest.SkipUnless(VZ), called before anything is built) is an operator's
// CLAIM about the machine; this is the daemon's own five-term conjunction —
// darwin, macOS >= 26, +[VZVirtualMachine isSupported], the helper resolves, and
// that helper's signature is VALID and carries
// com.apple.security.virtualization. A rig where the claim holds and the probe
// does not is the interesting case (an unsigned or mis-signed helper, or a
// malformed entitlements plist, which AMFI accepts into a validly signed binary
// carrying no entitlements at all), and it must fail LEGIBLY here rather than as
// an opaque boot-deadline expiry two minutes later. Hence Fatal, not Skip: the
// lab promised a VZ host, so an unusable one is a broken lab, not an absent one.
func requireEntitledHelper(t *testing.T, helper string) {
	t.Helper()
	probe := sandbox.NewVMBackend(sandbox.WithVMHostLocator(func() (string, error) { return helper, nil }))
	if !probe.Available() {
		t.Fatalf("%s declares a VZ lab but the vm backend is unavailable with the helper this test built (%s): "+
			"the host must be macOS >= 26 with +[VZVirtualMachine isSupported], and the helper's signature must be VALID "+
			"and carry com.apple.security.virtualization", "K3SM_CAP_VZ", helper)
	}
}

// buildSignedVMHost builds cmd/k3sm-vmhost from THIS TREE and ad-hoc signs it
// with cmd/k3sm-vmhost/vmhost.entitlements.
//
// Building it here rather than taking a path is what makes the smoke a test of
// the current source: a lab-supplied binary would let the gate stay green while
// the helper in the tree stopped working. The entitlements file is the shipped
// one, so the smoke also exercises the exact plist a release signs with — and
// AMFI's XML reader is strict enough that a malformed one produces a validly
// signed binary carrying NO entitlements, which Available() would then reject
// above with a legible message instead of a mysterious SIGABRT.
func buildSignedVMHost(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, sandbox.VMHostName)
	build := exec.Command("go", "build", "-o", helper, "k3sm.io/runtimed/cmd/k3sm-vmhost")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", sandbox.VMHostName, err, out)
	}
	ents, err := filepath.Abs(filepath.Join("..", "..", "cmd", "k3sm-vmhost", "vmhost.entitlements"))
	if err != nil {
		t.Fatalf("resolve the entitlements path: %v", err)
	}
	sign := exec.Command("codesign", "--force", "--sign", "-", "--entitlements", ents, helper)
	if out, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("codesign %s with %s: %v\n%s", sandbox.VMHostName, ents, err, out)
	}
	t.Logf("built + signed helper %s sha256=%s", helper, sha256File(t, helper))
	return helper
}

// buildSmokeInitramfs composes the lab initramfs from testdata/vmsmokeguest plus
// whatever modules the lab declared, and returns its path.
//
// THE ARCHIVE IS BUILT, NEVER COMMITTED. A checked-in initramfs would be a
// multi-megabyte opaque blob nobody could review, and it would drift silently
// from guest/v1 the first time that contract changed.
//
// It shells out to cpio rather than writing newc bytes here, for a scope reason
// rather than a laziness one: a pure-Go BYTE-DETERMINISTIC newc writer is a named
// M11.2-d3 deliverable with its own golden gate, and a second implementation in a
// test file is exactly the drifting duplicate that gate exists to prevent. This
// archive only has to be readable by one kernel, once.
func buildSmokeInitramfs(t *testing.T, modules []string) string {
	t.Helper()
	if _, err := exec.LookPath("cpio"); err != nil {
		t.Fatalf("cpio is required to compose the lab initramfs: %v", err)
	}
	work := t.TempDir()
	stage := filepath.Join(work, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "mods"), 0o755); err != nil {
		t.Fatalf("stage dir: %v", err)
	}

	guestSrc := filepath.Join("testdata", "vmsmokeguest", "init.go")
	init := filepath.Join(stage, "init")
	build := exec.Command("go", "build", "-o", init, guestSrc)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cross-build the lab guest %s: %v\n%s", guestSrc, err, out)
	}
	if err := os.Chmod(init, 0o755); err != nil {
		t.Fatalf("chmod the lab guest: %v", err)
	}
	t.Logf("lab guest /init sha256=%s", sha256File(t, init))

	// Modules are staged with a NUMERIC PREFIX preserving the declared order:
	// the guest loads them lexically, and finit_module does no dependency
	// resolution, so vsock's virtio transport must not sort before the common
	// layer it needs.
	for i, mod := range modules {
		dst := filepath.Join(stage, "mods", fmt.Sprintf("%02d-%s", i, filepath.Base(mod)))
		copyFile(t, mod, dst)
		t.Logf("lab module %s sha256=%s", filepath.Base(dst), sha256File(t, dst))
	}

	archive := filepath.Join(work, "initramfs.cpio")
	out, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create the initramfs: %v", err)
	}
	defer func() { _ = out.Close() }()
	// `find .` then cpio -H newc is the ordinary initramfs recipe; the archive is
	// consumed by one kernel and never compared, so its ordering is unimportant.
	var stderr strings.Builder
	pipeline := exec.Command("sh", "-c", "find . | cpio -o -H newc --quiet")
	pipeline.Dir = stage
	pipeline.Stdout = out
	pipeline.Stderr = &stderr
	if err := pipeline.Run(); err != nil {
		t.Fatalf("compose the initramfs: %v\n%s", err, stderr.String())
	}
	t.Logf("lab initramfs %s sha256=%s", archive, sha256File(t, archive))
	return archive
}

// smokeArtifacts resolves the declared kernel + modules, skipping when the lab
// has not named a kernel. It returns the locator the vm backend boots from.
func smokeArtifacts(t *testing.T) (sandbox.GuestArtifactLocator, string) {
	t.Helper()
	kernel := os.Getenv(envSmokeKernel)
	if kernel == "" {
		t.Skipf("%s is unset: point it at an absolute path to an arm64 Linux kernel image", envSmokeKernel)
	}
	if !filepath.IsAbs(kernel) {
		t.Fatalf("%s = %q must be an absolute path", envSmokeKernel, kernel)
	}
	if _, err := os.Stat(kernel); err != nil {
		t.Fatalf("%s = %q: %v", envSmokeKernel, kernel, err)
	}
	var modules []string
	if raw := os.Getenv(envSmokeModules); raw != "" {
		for _, m := range strings.Split(raw, ":") {
			if m == "" {
				continue
			}
			if !filepath.IsAbs(m) {
				t.Fatalf("%s entry %q must be an absolute path", envSmokeModules, m)
			}
			if _, err := os.Stat(m); err != nil {
				t.Fatalf("%s entry %q: %v", envSmokeModules, m, err)
			}
			modules = append(modules, m)
		}
	}
	t.Logf("lab kernel %s sha256=%s", kernel, sha256File(t, kernel))
	initramfs := buildSmokeInitramfs(t, modules)
	return func() (sandbox.GuestArtifacts, error) {
		return sandbox.GuestArtifacts{
			KernelPath:    kernel,
			InitramfsPath: initramfs,
			// reboot=k + panic=1 make a guest that dies do so promptly and
			// visibly on the console rather than sitting in a kernel prompt the
			// host would only observe as a boot-deadline expiry.
			Cmdline: "console=hvc0 reboot=k panic=1",
		}, nil
	}, kernel
}

// newSmokeRuntime builds a Runtime whose vm backend is the REAL one, wired to the
// built helper and the composed artifacts, over the given state root.
//
// Only the two seams the smoke cannot supply are faked (image pull/unpack), and
// the vm route touches neither — a vm pod resolves no host binary. Everything on
// the path under test is production code.
func newSmokeRuntime(t *testing.T, root, helper string, artifacts sandbox.GuestArtifactLocator) *Runtime {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	vmb := sandbox.NewVMBackend(
		sandbox.WithStateRoot(root),
		sandbox.WithLogger(log),
		sandbox.WithGuestArtifacts(artifacts),
		sandbox.WithVMHostLocator(func() (string, error) { return helper, nil }),
	)
	rt, err := New(Config{Root: root, Logger: log}, testDeps(t, Deps{
		VMBackend: vmb,
		Puller:    &fakePuller{},
		Unpacker:  &fakeUnpacker{},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rt
}

// TestIntegrationVMBootSmokeLifecycle is legs 1 and 2: a vm pod boots to Running
// through a real guest handshake, and DeletePod leaves neither helper nor socket.
func TestIntegrationVMBootSmokeLifecycle(t *testing.T) {
	// The capability gate runs BEFORE anything is built: an ordinary
	// `go test ./...` on a non-lab machine must cost a skip, not a helper build.
	k3smtest.SkipUnless(t, k3smtest.VZ)
	helper := buildSignedVMHost(t)
	requireEntitledHelper(t, helper)
	artifacts, _ := smokeArtifacts(t)

	root := smokeRoot(t)
	rt := newSmokeRuntime(t, root, helper, artifacts)
	const podID = "smoke-lifecycle"
	// The safety net for EVERY exit path, registered before anything can boot:
	// a failed assertion mid-test must not leave a virtual machine running.
	t.Cleanup(func() { killSmokeHelpers(t, root, podID) })

	ctx, cancel := context.WithTimeout(context.Background(), smokeBootBudget)
	defer cancel()

	t.Run("leg 1: CreatePod boots a guest that answers Health", func(t *testing.T) {
		start := time.Now()
		resp, err := rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: vmPodBox(rt, podID, 5)})
		if err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("CreatePod failed: %v (reason %v) — the guest console is under the pod dir",
				resp.GetError(), resp.GetFailureReason())
		}
		elapsed := time.Since(start)
		if resp.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Fatalf("phase = %v, want RUNNING", resp.GetStatus().GetPhase())
		}
		t.Logf("SMOKE leg 1 OK: create -> guest Health -> Running in %s", elapsed)

		// A SECOND, INDEPENDENT round trip, through the daemon's own GuestDialer
		// rather than the backend's readiness probe. It proves the socket the
		// helper bound is the socket the Exec/GetLogs route reaches — the two
		// derivations agree — which the boot alone does not show.
		conn, err := rt.dialGuest(podID)
		if err != nil {
			t.Fatalf("dialGuest: %v", err)
		}
		defer func() { _ = conn.Close() }()
		hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
		defer hcancel()
		health, err := guestv1.NewGuestAgentClient(conn).Health(hctx, &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health over the daemon's own guest dialer: %v", err)
		}
		if !health.GetReady() {
			t.Errorf("guest reports ready=false")
		}
		t.Logf("SMOKE leg 1 OK: Health via the daemon's GuestDialer ready=%v api=%q",
			health.GetReady(), health.GetApiVersion())
	})

	t.Run("leg 2: DeletePod stops the helper and clears its socket", func(t *testing.T) {
		pids := smokeHelperPIDs(t, root, podID)
		if len(pids) != 1 {
			t.Fatalf("found %d live helpers for %s before delete, want exactly 1", len(pids), podID)
		}
		start := time.Now()
		if _, err := rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: podID}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		t.Logf("SMOKE leg 2: DeletePod returned in %s", time.Since(start))

		// The lab guest ignores SIGTERM by design, so this exercises the
		// ESCALATION arm: the helper's guest-stop goes unanswered, its grace
		// expires, it halts the machine hard and exits.
		if alive := waitPIDGone(pids[0], 30*time.Second); alive {
			t.Errorf("helper pid %d is still alive after DeletePod; a deleted pod must not leave a machine running", pids[0])
		}
		sock, err := guestAgentSocket(root, podID)
		if err != nil {
			t.Fatalf("guestAgentSocket: %v", err)
		}
		if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("agent socket %s survived DeletePod (stat err %v)", sock, err)
		}
		t.Logf("SMOKE leg 2 OK: helper pid %d exited, %s gone", pids[0], sock)
	})
}

// smokeDaemonEnv marks the re-executed child that plays the DAEMON in leg 3.
const smokeDaemonEnv = "K3SM_VM_SMOKE_DAEMON"

// TestIntegrationVMBootSmokeOrphanSweep is leg 3: a daemon killed WITHOUT
// teardown leaves its helper alive, and the next daemon's startup sweep kills it.
//
// THE DAEMON IS A REAL SUBPROCESS, and it has to be. The property under test is
// what survives a `kill -9` of the process that spawned the helper, and a test
// binary cannot SIGKILL itself and go on asserting. So the test re-executes
// ITSELF (the standard os/exec helper-process pattern) into
// TestVMBootSmokeDaemonHelperProcess, which builds the same Runtime over the same
// state root, creates the pod, and parks. The parent then SIGKILLs it — no
// teardown, no Close, no chance to clean up — which is exactly the state the
// sweep exists for.
func TestIntegrationVMBootSmokeOrphanSweep(t *testing.T) {
	k3smtest.SkipUnless(t, k3smtest.VZ)
	helper := buildSignedVMHost(t)
	requireEntitledHelper(t, helper)
	artifacts, kernel := smokeArtifacts(t)
	_ = artifacts // the child re-derives them from the same declared inputs

	root := smokeRoot(t)
	const podID = "smoke-orphan"
	t.Cleanup(func() { killSmokeHelpers(t, root, podID) })

	// The child inherits the declared lab inputs plus the root, pod id and the
	// helper path the parent built, so both processes agree on every artifact.
	child := exec.Command(os.Args[0], "-test.run", "^TestVMBootSmokeDaemonHelperProcess$", "-test.v")
	child.Env = append(os.Environ(),
		smokeDaemonEnv+"=1",
		"K3SM_VM_SMOKE_ROOT="+root,
		"K3SM_VM_SMOKE_POD="+podID,
		"K3SM_VM_SMOKE_HELPER="+helper,
		envSmokeKernel+"="+kernel,
	)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("child stdout: %v", err)
	}
	child.Stderr = child.Stdout
	if err := child.Start(); err != nil {
		t.Fatalf("start the daemon subprocess: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})

	if err := awaitLine(stdout, "SMOKE_DAEMON_READY", smokeBootBudget); err != nil {
		t.Fatalf("the daemon subprocess never booted its pod: %v", err)
	}
	pids := smokeHelperPIDs(t, root, podID)
	if len(pids) != 1 {
		t.Fatalf("found %d live helpers for %s, want exactly 1", len(pids), podID)
	}
	orphan := pids[0]
	t.Logf("SMOKE leg 3: daemon subprocess pid %d booted helper pid %d", child.Process.Pid, orphan)

	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL the daemon subprocess: %v", err)
	}
	_, _ = child.Process.Wait()

	// The helper is a SETSID session leader, so killing its parent reparents it
	// to launchd and leaves it running. That is the leak the sweep closes; if it
	// died with its parent there would be nothing to sweep and this leg would be
	// vacuous, so the survival is asserted rather than assumed.
	if !pidAlive(orphan) {
		t.Fatalf("helper pid %d died with its daemon; the orphan leg is vacuous unless the helper survives (POSIX_SPAWN_SETSID)", orphan)
	}
	t.Logf("SMOKE leg 3: helper pid %d survived the daemon's kill -9, as SETSID requires", orphan)

	// A FRESH Runtime over the same state root — a daemon restart.
	fresh := newSmokeRuntime(t, root, helper, artifacts)
	if err := fresh.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	if alive := waitPIDGone(orphan, 30*time.Second); alive {
		t.Errorf("the startup sweep did not kill orphaned helper pid %d", orphan)
	}
	runDir := filepath.Join(root, "run", "vm", podID)
	if _, err := os.Stat(runDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the orphan's run dir %s survived the sweep (stat err %v); the next pod with this id would bind inside it", runDir, err)
	}
	t.Logf("SMOKE leg 3 OK: the startup sweep killed orphan pid %d and cleared %s", orphan, runDir)
}

// TestVMBootSmokeDaemonHelperProcess is NOT a test. It is the daemon half of
// leg 3, run only in the re-executed child, and it exits without ever returning
// so the parent's SIGKILL is what ends it.
func TestVMBootSmokeDaemonHelperProcess(t *testing.T) {
	if os.Getenv(smokeDaemonEnv) != "1" {
		t.Skip("not the daemon subprocess")
	}
	root, podID, helper := os.Getenv("K3SM_VM_SMOKE_ROOT"), os.Getenv("K3SM_VM_SMOKE_POD"), os.Getenv("K3SM_VM_SMOKE_HELPER")
	artifacts, _ := smokeArtifacts(t)
	rt := newSmokeRuntime(t, root, helper, artifacts)

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: vmPodBox(rt, podID, 5)})
	if err != nil || resp.GetError() != nil {
		fmt.Printf("SMOKE_DAEMON_FAILED err=%v resp=%v\n", err, resp.GetError())
		os.Exit(1)
	}
	fmt.Println("SMOKE_DAEMON_READY")
	os.Stdout.Sync()
	// Park until the parent SIGKILLs us. The generous ceiling is a backstop
	// against a parent that died first — this process must never outlive the run
	// and keep a machine alive.
	time.Sleep(10 * time.Minute)
	os.Exit(2)
}

// --- lab helpers ------------------------------------------------------------

// smokeRoot returns a SHORT state root, not t.TempDir().
//
// The length is load-bearing rather than fussy: the agent socket is
// <root>/run/vm/<pod>/agent.sock and a unix socket path is capped near 104 bytes
// by sockaddr_un, while a `go test` temp dir is long enough on its own to blow
// that. A run under one fails at bind(2) with "invalid argument", which reads as
// a code bug rather than a path-length one.
func smokeRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "k3vm")
	if err != nil {
		t.Fatalf("smoke root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// smokeHelperPIDs returns the live k3sm-vmhost pids serving podID under root,
// found by matching the -spec argument — which names the pod dir, so it cannot
// match another test's helper or another pod's.
func smokeHelperPIDs(t *testing.T, root, podID string) []int {
	t.Helper()
	needle := filepath.Join(root, "pods", podID, sandbox.VMSpecFileName)
	out, err := exec.Command("ps", "-Ao", "pid=,command=").Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// killSmokeHelpers is the unconditional cleanup: SIGKILL any helper still serving
// podID, whatever path the test exited by.
//
// It signals the process GROUP, which is the helper's own session (SETSID), so a
// helper that forked is torn down whole. A test that leaves a virtual machine
// running has cost the rig memory and a hypervisor slot until someone notices,
// which is exactly the failure mode the orphan sweep exists for — a smoke that
// created it would be embarrassing.
func killSmokeHelpers(t *testing.T, root, podID string) {
	t.Helper()
	for _, pid := range smokeHelperPIDs(t, root, podID) {
		t.Logf("cleanup: killing leftover vm host helper pid %d", pid)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// pidAlive reports whether pid exists (signal 0 is the standard existence probe).
func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// waitPIDGone waits up to d for pid to disappear, reporting whether it is STILL
// ALIVE at the end (so the caller reads `if alive {`).
func waitPIDGone(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return pidAlive(pid)
}

// awaitLine reads r until a line containing want appears, or d elapses. It
// ECHOES what it read on failure: the child's output is the only account of why
// a subprocess daemon did not come up.
func awaitLine(r io.Reader, want string, d time.Duration) error {
	type result struct {
		seen bool
		log  string
	}
	done := make(chan result, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
				if strings.Contains(sb.String(), want) {
					done <- result{seen: true, log: sb.String()}
					return
				}
			}
			if err != nil {
				done <- result{seen: false, log: sb.String()}
				return
			}
		}
	}()
	select {
	case res := <-done:
		if res.seen {
			return nil
		}
		return fmt.Errorf("the subprocess ended without printing %q; its output was:\n%s", want, res.log)
	case <-time.After(d):
		return fmt.Errorf("timed out after %s waiting for %q", d, want)
	}
}

// sha256File returns the hex digest of path, so every artifact a run booted from
// is identified in the log. A smoke that says "it passed" without saying WHICH
// kernel and initramfs it passed against is not a reproducible result.
func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// copyFile copies src to dst with 0644.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %s -> %s: %v", src, dst, err)
	}
}
