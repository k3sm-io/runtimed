//go:build darwin && cgo

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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The FAKE HELPER. The vm-attach gate needs a real, long-lived process in the
// helper's place — its own session, its own code-directory hash, a control
// socket the kernel can name the peer of — and this test binary is one. When
// the backend spawns it with envFakeVMHost set it runs runFakeVMHost instead of
// the tests: it serves the control socket beside the agent socket, says one
// line on stderr (which is the helper's output file), and exits on SIGTERM.
const (
	envFakeVMHost = "K3SM_TEST_FAKE_VMHOST"
	// envFakeVMHostProtocol overrides the protocol the fake answers: empty is
	// sandbox.VMHostProtocolVersion, "none" serves no control socket at all.
	envFakeVMHostProtocol = "K3SM_TEST_FAKE_VMHOST_PROTOCOL"
	fakeVMHostUpLine      = "fake vm host up"
)

func init() {
	if os.Getenv(envFakeVMHost) == "" {
		return
	}
	os.Exit(runFakeVMHost(os.Args[1:]))
}

func runFakeVMHost(args []string) int {
	signal.Ignore(syscall.SIGPIPE)
	fs := flag.NewFlagSet("fake-vmhost", flag.ContinueOnError)
	agentSocket := fs.String("agent-socket", "", "")
	_ = fs.String("spec", "", "")
	_ = fs.String("console-log", "", "")
	_ = fs.Duration("stop-grace", 0, "")
	_ = fs.String("log-file", "", "")
	if err := fs.Parse(args); err != nil || *agentSocket == "" {
		return 2
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)

	protocol := sandbox.VMHostProtocolVersion
	switch v := os.Getenv(envFakeVMHostProtocol); v {
	case "":
	case "none":
		protocol = -1
	default:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 2
		}
		protocol = n
	}
	if protocol >= 0 {
		ctl := filepath.Join(filepath.Dir(*agentSocket), sandbox.VMHostControlSocketName)
		_ = os.Remove(ctl)
		lis, err := net.Listen("unix", ctl)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fake vm host: control socket:", err)
			return 1
		}
		go func() {
			_ = sandbox.ServeVMHostControl(lis, sandbox.VMHostVersion{Protocol: protocol, Pid: os.Getpid()})
		}()
	}
	fmt.Fprintln(os.Stderr, fakeVMHostUpLine)
	<-term
	return 0
}

// TestAttachPodAdoptsARunningVMHelper is the runtimed gate: a vm pod's
// helper survives a daemon restart and the next daemon adopts it, fail closed.
//
// One real helper process per row, spawned by the real backend through the
// real CreateVM (output file, record, owner marker, record lock). The runtime
// is then closed — which must leave the helper running — and a NEW runtime over
// the same state root attaches the pod. The adopted row asserts the same pid,
// unchanged start time, survival of the startup reap, and that the new runtime
// stops exactly that process on DeletePod. Every other row breaks one identity
// element and asserts the attach is refused and the startup reap kills the
// helper — except a changed leader start, which is a group the sweep can no
// longer prove is ours and so must never signal.
//
// Non-vacuous on the pre-change path: Close used to stop every helper, and
// AttachPod refused every vm pod ("not a host-process pod"), so the adopted
// row fails at the first liveness check after Close.
func TestAttachPodAdoptsARunningVMHelper(t *testing.T) {
	cases := []struct {
		name       string
		protocol   string
		tamper     func(t *testing.T, rec map[string]any, runDir string)
		wantAdopt  bool
		wantKilled bool
	}{
		{name: "a running helper is adopted with the same pid", wantAdopt: true},
		{name: "a record an earlier build wrote is killed", wantKilled: true,
			tamper: func(_ *testing.T, rec map[string]any, _ string) {
				for k := range rec {
					switch k {
					case "podId", "pgid", "startUnixNano", "agentSocket", "runDir":
					default:
						delete(rec, k)
					}
				}
			}},
		{name: "another daemon build is killed", wantKilled: true,
			tamper: func(_ *testing.T, rec map[string]any, _ string) { rec["runtimeVersion"] = "cdhash:00" }},
		{name: "another boot session is killed", wantKilled: true,
			tamper: func(_ *testing.T, rec map[string]any, _ string) {
				rec["bootSession"] = "00000000-0000-0000-0000-000000000000"
			}},
		{name: "a helper code-directory hash mismatch is killed", wantKilled: true,
			tamper: func(_ *testing.T, rec map[string]any, _ string) { rec["helperCdhash"] = "00" }},
		{name: "a recorded protocol mismatch is killed", wantKilled: true,
			tamper: func(_ *testing.T, rec map[string]any, _ string) {
				rec["helperProtocol"] = sandbox.VMHostProtocolVersion + 1
			}},
		{name: "a helper answering another protocol is killed", wantKilled: true,
			protocol: strconv.Itoa(sandbox.VMHostProtocolVersion + 1)},
		{name: "a helper that does not answer is killed", wantKilled: true, protocol: "none"},
		{name: "a run dir stamped for another pod is killed", wantKilled: true,
			tamper: func(t *testing.T, _ map[string]any, runDir string) {
				if err := os.WriteFile(filepath.Join(runDir, ".k3sm-vm-owner"), []byte("another-pod"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a leader start mismatch is refused and never signalled",
			tamper: func(_ *testing.T, rec map[string]any, _ string) {
				rec["startUnixNano"] = json.Number(strconv.FormatInt(mustInt64(rec["startUnixNano"])+1, 10))
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startVMHelperUnderRuntime(t, tc.protocol)

			// The daemon exits: nothing may stop the helper.
			if err := h.rt.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			if !processIsInstance(h.pid, h.start) {
				t.Fatalf("the vm helper (pid %d) did not survive the daemon's Close", h.pid)
			}

			if tc.tamper != nil {
				h.rewriteRecord(t, func(rec map[string]any) { tc.tamper(t, rec, h.runDir) })
			}

			rt2 := h.restart(t)
			st, err := rt2.AttachPod(context.Background(), h.box)
			if tc.wantAdopt {
				if err != nil {
					t.Fatalf("AttachPod: %v", err)
				}
				if st.GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
					t.Fatalf("phase = %v, want RUNNING", st.GetPhase())
				}
				if _, ok := rt2.lookupPod(h.podID); !ok {
					t.Fatal("the adopted pod is not registered")
				}
			} else if !errors.Is(err, ErrNothingToAttach) {
				t.Fatalf("AttachPod = (%v, %v), want ErrNothingToAttach", st.GetPhase(), err)
			}

			// The startup reap follows every attach (the ordering invariant).
			if err := rt2.ReapOrphanedPods(); err != nil {
				t.Fatalf("ReapOrphanedPods: %v", err)
			}

			switch {
			case tc.wantAdopt:
				time.Sleep(100 * time.Millisecond)
				if !processIsInstance(h.pid, h.start) {
					t.Fatalf("the adopted helper (pid %d) did not survive the startup reap", h.pid)
				}
				if _, err := os.Stat(h.recordPath); err != nil {
					t.Fatalf("the adopted helper's record is gone: %v", err)
				}
				if _, err := os.Stat(h.runDir); err != nil {
					t.Fatalf("the adopted helper's run dir is gone: %v", err)
				}
				// The new daemon owns exactly that process: its DeletePod stops it.
				if _, err := rt2.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: h.podID, GracePeriodSeconds: 2}); err != nil {
					t.Fatalf("DeletePod: %v", err)
				}
				if !waitGone(h.pid, h.start, 5*time.Second) {
					t.Fatalf("DeletePod on the new runtime did not stop the adopted helper (pid %d)", h.pid)
				}
			case tc.wantKilled:
				if !waitGone(h.pid, h.start, 5*time.Second) {
					t.Fatalf("the refused helper (pid %d) survived the startup reap", h.pid)
				}
			default:
				time.Sleep(100 * time.Millisecond)
				if !processIsInstance(h.pid, h.start) {
					t.Fatalf("a helper the sweep cannot prove is ours (pid %d) was signalled", h.pid)
				}
			}
		})
	}
}

// vmHelperHarness is one vm pod booted by a real backend whose helper is this
// test binary, and the inputs to rebuild a runtime over the same state.
type vmHelperHarness struct {
	root       string
	podID      string
	box        *runtimev1.PodBox
	rt         *Runtime
	deps       func(opts ...sandbox.VMBackendOption) Deps
	pid        int
	start      int64
	recordPath string
	runDir     string
}

// startVMHelperUnderRuntime boots a vm pod through createVMPod with the real
// spawn path and returns once the helper has written to its output file.
func startVMHelperUnderRuntime(t *testing.T, protocol string) *vmHelperHarness {
	t.Helper()
	t.Setenv(envFakeVMHost, "1")
	t.Setenv(envFakeVMHostProtocol, protocol)

	// A unix socket path is capped near 104 bytes and t.TempDir() is long on
	// macOS, so the state root is a short directory of its own.
	root, err := os.MkdirTemp("/private/tmp", "k3vm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(root, "guest", "Image")
	initramfs := filepath.Join(root, "guest", "initramfs.cpio")
	for _, p := range []string{kernel, initramfs} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const ref = "docker.io/library/app:1"
	world := newImageWorld(map[string]image.ImageRunConfig{ref: {Entrypoint: []string{"/bin/app"}, WorkingDir: "/"}})
	deps := func(opts ...sandbox.VMBackendOption) Deps {
		return Deps{
			Puller:   world,
			Unpacker: world,
			Resolver: fakeResolver{},
			Network:  &guestNetworkerNetwork{cfg: testGuestNetwork(), ok: true},
			VMBackend: sandbox.NewVMBackend(append([]sandbox.VMBackendOption{
				sandbox.WithStateRoot(root),
				sandbox.WithGuestArtifacts(func() (sandbox.GuestArtifacts, error) {
					return sandbox.GuestArtifacts{KernelPath: kernel, InitramfsPath: initramfs, Cmdline: "console=hvc0"}, nil
				}),
				sandbox.WithVMHostLocator(func() (string, error) { return self, nil }),
				// Only the guest readiness probe is faked: there is no guest. The
				// spawn, the reaper, signals and the process-table probes are real.
				sandbox.WithVMProcessSeams(nil, nil, func(context.Context, string) error { return nil }, nil, nil, nil),
			}, opts...)...),
		}
	}
	rt := newTestRuntimeCfg(t, Config{Root: root}, deps())
	const podID = "pod-adopt"
	box := vmBoxWith(rt, podID, nil, []*runtimev1.Container{{Name: "app", Image: ref}})
	p, reason, err := rt.createVMPod(context.Background(), box, box.GetSandboxProfile())
	if err != nil {
		t.Fatalf("createVMPod: %v (reason %v)", err, reason)
	}
	rt.mu.Lock()
	rt.pods[podID] = p
	rt.mu.Unlock()

	h := &vmHelperHarness{root: root, podID: podID, box: box, rt: rt, deps: deps}
	entries, err := os.ReadDir(filepath.Join(root, sandbox.VMReapSubdir))
	if err != nil || len(entries) != 1 {
		t.Fatalf("vm record store = %v (%v), want exactly one record", entries, err)
	}
	h.recordPath = filepath.Join(root, sandbox.VMReapSubdir, entries[0].Name())
	h.pid, err = strconv.Atoi(strings.TrimSuffix(entries[0].Name(), ".json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-h.pid, syscall.SIGKILL) })
	start, ok := supervisor.ProcStartTimeNano(h.pid)
	if !ok {
		t.Fatalf("the helper pid %d is not running", h.pid)
	}
	h.start = start
	rec := h.readRecord(t)
	h.runDir, _ = rec["runDir"].(string)

	// The helper's stderr is the file in its run dir, not a daemon pipe.
	logPath := filepath.Join(h.runDir, sandbox.VMHostLogName)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, _ := os.ReadFile(logPath); strings.Contains(string(b), fakeVMHostUpLine) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper never wrote to its output file %s", logPath)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return h
}

// restart builds a fresh runtime, and a fresh vm backend, over the same state
// root: what a daemon restart leaves the next daemon.
func (h *vmHelperHarness) restart(t *testing.T, opts ...sandbox.VMBackendOption) *Runtime {
	t.Helper()
	return newTestRuntimeCfg(t, Config{Root: h.root}, h.deps(opts...))
}

func (h *vmHelperHarness) readRecord(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(h.recordPath)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	rec := map[string]any{}
	if err := dec.Decode(&rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func (h *vmHelperHarness) rewriteRecord(t *testing.T, edit func(map[string]any)) {
	t.Helper()
	rec := h.readRecord(t)
	edit(rec)
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.recordPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustInt64(v any) int64 {
	n, _ := v.(json.Number).Int64()
	return n
}

// processIsInstance reports whether pid is alive as exactly the instance that
// started at start.
func processIsInstance(pid int, start int64) bool {
	got, ok := supervisor.ProcStartTimeNano(pid)
	return ok && got == start
}

// waitGone waits for the instance to leave the process table.
func waitGone(pid int, start int64, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !processIsInstance(pid, start) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestHeldVMHelperIsNeverBootedTwice pins the fail-closed outcome of the window
// in which neither runtime acts on a live helper: its record is held by another
// holder, so the new runtime's attach refuses it (ErrVMHelperUnadoptable, with
// ErrNothingToAttach), its startup sweep stands down with a Warn and keeps the
// record, and its CreatePod refuses the pod rather than boot a second guest
// beside the live one or remove the pod dir the guest shares. The helper keeps
// running throughout.
func TestHeldVMHelperIsNeverBootedTwice(t *testing.T) {
	h := startVMHelperUnderRuntime(t, "")
	if err := h.rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Another holder: an exclusive lock on the record, as a second runtime's
	// adoption takes.
	f, err := os.Open(h.recordPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("hold the record lock: %v", err)
	}

	var logs lockedBuffer
	rt2 := h.restart(t, sandbox.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	_, err = rt2.AttachPod(context.Background(), h.box)
	if !errors.Is(err, ErrNothingToAttach) || !errors.Is(err, ErrVMHelperUnadoptable) {
		t.Fatalf("AttachPod = %v, want ErrNothingToAttach and ErrVMHelperUnadoptable", err)
	}
	if err := rt2.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	if !processIsInstance(h.pid, h.start) {
		t.Fatalf("the held helper (pid %d) was stopped by a runtime that does not own it", h.pid)
	}
	if _, err := os.Stat(h.recordPath); err != nil {
		t.Fatalf("the held helper's record was retired: %v", err)
	}
	if !strings.Contains(logs.String(), "level=WARN msg=\"vm orphan sweep: a live vm host helper's record is held by another runtime") {
		t.Errorf("the sweep stood down silently:\n%s", logs.String())
	}

	resp, err := rt2.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: h.box})
	if !errors.Is(err, ErrVMHelperUnadoptable) {
		t.Fatalf("CreatePod = (%v, %v), want ErrVMHelperUnadoptable", resp, err)
	}
	if _, ok := rt2.lookupPod(h.podID); ok {
		t.Error("the refused pod was registered")
	}
	entries, err := os.ReadDir(filepath.Join(h.root, sandbox.VMReapSubdir))
	if err != nil || len(entries) != 1 {
		t.Errorf("vm record store = %v (%v), want only the held helper's record: no second helper", entries, err)
	}
	podDir, err := rt2.podDir(h.podID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(podDir); err != nil {
		t.Errorf("the live guest's pod dir was removed by the refused create: %v", err)
	}
	if !processIsInstance(h.pid, h.start) {
		t.Fatalf("the held helper (pid %d) did not survive the refused create", h.pid)
	}
}

// TestDeferredVMSweepKeepsHelpersRunning pins what a start that could not read
// its pods does with the vm helpers a previous run left: none is killed (a
// helper nothing attached may be a running pod's), each stays detached with its
// record for the next start, and the pod is not booted a second time meanwhile.
func TestDeferredVMSweepKeepsHelpersRunning(t *testing.T) {
	h := startVMHelperUnderRuntime(t, "")
	if err := h.rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rt2 := h.restart(t)
	rt2.DeferVMSweep("the startup pod list failed")
	if err := rt2.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if !processIsInstance(h.pid, h.start) {
		t.Fatalf("a deferred sweep killed the helper (pid %d)", h.pid)
	}
	if _, err := os.Stat(h.recordPath); err != nil {
		t.Fatalf("a deferred sweep retired the helper's record: %v", err)
	}
	if _, err := rt2.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: h.box}); !errors.Is(err, ErrVMHelperUnadoptable) {
		t.Fatalf("CreatePod beside the kept helper = %v, want ErrVMHelperUnadoptable", err)
	}

	// The next start, with its pod list, adopts it as usual.
	rt3 := h.restart(t)
	if _, err := rt3.AttachPod(context.Background(), h.box); err != nil {
		t.Fatalf("AttachPod on the next start: %v", err)
	}
	if err := rt3.ReapOrphanedPods(); err != nil {
		t.Fatal(err)
	}
	if !processIsInstance(h.pid, h.start) {
		t.Fatalf("the next start did not keep the adopted helper (pid %d)", h.pid)
	}
}
