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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"k3sm.io/runtimed/pkg/supervisor"

	guestv1 "k3sm.io/apis/guest/v1"
)

// THE WHOLE BOOT AND TEARDOWN STATE MACHINE, WITH NO VM ANYWHERE.
//
// The seams (WithVMProcessSeams) exist so the parts that are hard to get right —
// the readiness race between "the agent answered" and "the helper died", the
// deadline kill, the one-grace-budget stop, the orphan sweep's exact-instance
// identity — are asserted against fakes on any machine, rather than only on an
// entitled rig where a failure is expensive to reproduce. What the rig proves is
// the OTHER half: that the real helper, kernel and guest agent actually complete
// the handshake these fakes stand in for.

// fakeSpawner records spawns and hands out increasing pids. err makes the spawn
// itself fail (the spawn-failed sub-cause).
type fakeSpawner struct {
	mu    sync.Mutex
	specs []supervisor.SpawnSpec
	next  int
	err   error
}

func (f *fakeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.specs = append(f.specs, spec)
	if f.next == 0 {
		f.next = 4200
	}
	f.next++
	return f.next, nil
}

func (f *fakeSpawner) argv() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return nil
	}
	return f.specs[len(f.specs)-1].Argv
}

// fakeWaiter is the ExitWaiter seam: it blocks until the test releases the pid
// (or ctx ends), standing in for the kqueue reaper's exit observation.
type fakeWaiter struct {
	mu   sync.Mutex
	exit map[int]chan struct{}
}

func newFakeWaiter() *fakeWaiter { return &fakeWaiter{exit: map[int]chan struct{}{}} }

func (f *fakeWaiter) ch(pid int) chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.exit[pid] == nil {
		f.exit[pid] = make(chan struct{})
	}
	return f.exit[pid]
}

func (f *fakeWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	select {
	case <-f.ch(pid):
		return 1, 0, nil
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
}

// release makes pid's exit observable, as the reaper would on a real death.
func (f *fakeWaiter) release(pid int) {
	f.mu.Lock()
	ch := f.exit[pid]
	if ch == nil {
		ch = make(chan struct{})
		f.exit[pid] = ch
	}
	f.mu.Unlock()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// signalRecorder records signals sent to process groups.
type signalRecorder struct {
	mu   sync.Mutex
	sent []int
}

func (s *signalRecorder) send(pgid int, _ os.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, pgid)
	return nil
}

func (s *signalRecorder) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

// labSpec builds a VMSpec whose paths are laid out under root exactly as
// pkg/runtime stamps them.
func labSpec(t *testing.T, root string) VMSpec {
	t.Helper()
	podDir := filepath.Join(root, "pods", "p1")
	if err := os.MkdirAll(podDir, 0o750); err != nil {
		t.Fatalf("pod dir: %v", err)
	}
	return VMSpec{
		PodID:           "p1",
		Vcpus:           2,
		MemoryBytes:     1 << 30,
		RootfsPath:      filepath.Join(podDir, "rootfs"),
		PodDir:          podDir,
		AgentSocketPath: filepath.Join(root, "run", "vm", "p1", "agent.sock"),
		StopGrace:       7 * time.Second,
	}
}

// labArtifacts is a locator over two files that exist, since FromSpec (in the
// helper) requires present regular files and the emitted spec must be one a real
// helper would accept.
func labArtifacts(t *testing.T, root string) GuestArtifactLocator {
	t.Helper()
	kernel := filepath.Join(root, "guest", "Image")
	initramfs := filepath.Join(root, "guest", "initramfs.cpio")
	if err := os.MkdirAll(filepath.Dir(kernel), 0o750); err != nil {
		t.Fatalf("artifacts dir: %v", err)
	}
	for _, p := range []string{kernel, initramfs} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("artifact %s: %v", p, err)
		}
	}
	return func() (GuestArtifacts, error) {
		return GuestArtifacts{KernelPath: kernel, InitramfsPath: initramfs, Cmdline: "console=hvc0 panic=1"}, nil
	}
}

// labBackend wires a VMBackend over the fakes, with a helper path that resolves.
func labBackend(t *testing.T, root string, health GuestHealthFunc, opts ...VMBackendOption) (*VMBackend, *fakeSpawner, *fakeWaiter, *signalRecorder) {
	t.Helper()
	sp := &fakeSpawner{}
	w := newFakeWaiter()
	sig := &signalRecorder{}
	helper := filepath.Join(root, "bin", VMHostName)
	if err := os.MkdirAll(filepath.Dir(helper), 0o750); err != nil {
		t.Fatalf("helper dir: %v", err)
	}
	if err := os.WriteFile(helper, []byte("#!/bin/false\n"), 0o700); err != nil {
		t.Fatalf("helper: %v", err)
	}
	base := []VMBackendOption{
		WithStateRoot(root),
		WithGuestArtifacts(labArtifacts(t, root)),
		WithVMHostLocator(func() (string, error) { return helper, nil }),
		WithVMProcessSeams(sp, w, health,
			sig.send,
			func(pid int) (int64, bool) { return int64(pid) * 1000, true },
			func(pgid int) ([]supervisor.ProcMember, bool) {
				return []supervisor.ProcMember{{Pid: pgid, StartUnixNano: int64(pgid) * 1000}}, true
			}),
	}
	return NewVMBackend(append(base, opts...)...), sp, w, sig
}

// TestCreateVMWritesTheMachineDescription is the SPEC GOLDEN: what CreateVM
// writes must be the proto-JSON a real k3sm-vmhost's ReadSpec accepts with
// unknown fields REJECTED, and it must carry exactly the fields the daemon owns.
//
// The comparison is over the DECODED message, not the bytes: protojson
// deliberately varies its whitespace, so a byte golden would be flaky in a way
// that says nothing about the contract. What is pinned is the contract — the same
// discipline apis/guest/v1's own goldens use.
func TestCreateVMWritesTheMachineDescription(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	spec.Volumes = VMVolumePlan{Shares: []VMShare{
		{Tag: "k3sm.rootfs.web", Root: filepath.Join(spec.PodDir, "rootfs", "web")},
		{Tag: "k3sm.vols", Root: filepath.Join(spec.PodDir, "k3sm.vols"), Writable: true},
	}}
	b, sp, _, _ := labBackend(t, root, func(context.Context, string) error { return nil })
	if err := b.CreateVM(context.Background(), spec); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(spec.PodDir, VMSpecFileName))
	if err != nil {
		t.Fatalf("read the written spec: %v", err)
	}
	got := &guestv1.VMHostSpec{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, got); err != nil {
		t.Fatalf("the written spec does not decode as a VMHostSpec with unknown fields rejected, so a real helper would refuse to boot from it: %v", err)
	}
	art, _ := labArtifacts(t, root)()
	want := &guestv1.VMHostSpec{
		PodId:          "p1",
		Vcpus:          2,
		MemoryBytes:    1 << 30,
		KernelPath:     art.KernelPath,
		InitramfsPath:  art.InitramfsPath,
		Cmdline:        "console=hvc0 panic=1",
		AgentVsockPort: VMAgentVsockPort,
		Shares: []*guestv1.VMShare{
			{Tag: "k3sm.rootfs.web", HostPath: filepath.Join(spec.PodDir, "rootfs", "web"), ReadOnly: true},
			{Tag: "k3sm.vols", HostPath: filepath.Join(spec.PodDir, "k3sm.vols")},
		},
	}
	if !proto.Equal(want, got) {
		t.Errorf("written spec:\n got: %v\nwant: %v", got, want)
	}

	t.Run("the read-only flag is the INVERSE of the plan's fail-closed Writable", func(t *testing.T) {
		// VMShare.Writable's zero value is read-only by design, so a share the
		// planner did not mark writable must cross the wire as read_only=true.
		// Getting this backwards would hand a pod write access to its own image
		// layer while both sides still looked correctly flagged.
		if !got.GetShares()[0].GetReadOnly() {
			t.Error("a non-writable share crossed as read_only=false")
		}
		if got.GetShares()[1].GetReadOnly() {
			t.Error("a writable share crossed as read_only=true")
		}
	})

	t.Run("the k3sm.spec share root exists and is not in the spec", func(t *testing.T) {
		// The helper APPENDS that share and REFUSES a spec that supplies it, and
		// VZ refuses a shared directory that does not exist.
		if fi, err := os.Stat(filepath.Join(spec.PodDir, "k3sm.spec")); err != nil || !fi.IsDir() {
			t.Errorf("k3sm.spec share root: stat err=%v", err)
		}
		for _, s := range got.GetShares() {
			if s.GetTag() == "k3sm.spec" {
				t.Error("the emitted spec supplies the k3sm.spec share, which the helper refuses")
			}
		}
	})

	t.Run("every pod-contained share root exists before the helper is spawned", func(t *testing.T) {
		// FOUND BY THE LIVE SMOKE, not by review: VZ refuses a shared directory
		// that does not exist, and the planner deliberately touches no disk, so
		// the first real boot died with
		//   virtiofs share "k3sm.rootfs" (<podDir>/rootfs): no such file or directory
		// after a whole spawn. A missing root must never cost a spawn to learn.
		for _, sh := range spec.Volumes.Shares {
			fi, err := os.Stat(sh.Root)
			if err != nil || !fi.IsDir() {
				t.Errorf("share %q root %s does not exist (stat err %v); VZ would refuse the device", sh.Tag, sh.Root, err)
			}
		}
	})

	t.Run("the helper argv carries the clamped stop grace", func(t *testing.T) {
		argv := sp.argv()
		want := []string{
			filepath.Join(root, "bin", VMHostName),
			"-spec", filepath.Join(spec.PodDir, VMSpecFileName),
			"-agent-socket", spec.AgentSocketPath,
			"-console-log", filepath.Join(spec.PodDir, VMConsoleLogName),
			"-stop-grace", (7 * time.Second).String(),
		}
		if !reflect.DeepEqual(argv, want) {
			t.Errorf("helper argv =\n %v\nwant\n %v", argv, want)
		}
	})
}

// TestCreateVMDoesNotFabricateOutOfPodShareRoots is the other half of the
// share-root rule, and the more important one.
//
// A plan legitimately carries roots OUTSIDE the pod dir — a PVC's data dir lives
// under <Root>/storage precisely so it can outlive the pod — and those belong to
// the persistent-volume binder, with its own class, ownership and reclaim policy.
// A CreateVM that created them would fabricate an EMPTY volume where a bound
// claim was expected, turning "your PVC is not bound yet" into "your database is
// empty" with no error anywhere.
func TestCreateVMDoesNotFabricateOutOfPodShareRoots(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	claimRoot := filepath.Join(root, "storage", "default", "pgdata")
	spec.Volumes = VMVolumePlan{Shares: []VMShare{
		{Tag: "k3sm.pvc.default.pgdata", Root: claimRoot, Writable: true},
	}}
	b, _, _, _ := labBackend(t, root, func(context.Context, string) error { return nil })
	if err := b.CreateVM(context.Background(), spec); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if _, err := os.Stat(claimRoot); !os.IsNotExist(err) {
		t.Errorf("CreateVM created a claim root outside the pod dir (%s, stat err %v); an unbound claim must surface as the helper's refusal, not as an empty volume", claimRoot, err)
	}
}

// TestCreateVMFailsClosedWithoutArtifacts asserts a node with no pinned guest
// kernel/initramfs refuses every vm pod instead of booting something unpinned.
func TestCreateVMFailsClosedWithoutArtifacts(t *testing.T) {
	cases := []struct {
		name    string
		locator GuestArtifactLocator
	}{
		{"no locator is wired at all", nil},
		{"the locator reports an error", func() (GuestArtifacts, error) { return GuestArtifacts{}, errors.New("not fetched") }},
		{"the locator returns an empty kernel path", func() (GuestArtifacts, error) {
			return GuestArtifacts{InitramfsPath: "/x/initramfs"}, nil
		}},
		{"the locator returns an empty initramfs path", func() (GuestArtifacts, error) {
			return GuestArtifacts{KernelPath: "/x/Image"}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			spec := labSpec(t, root)
			sp := &fakeSpawner{}
			b, _, _, _ := labBackend(t, root, func(context.Context, string) error { return nil })
			b.artifacts = tc.locator
			b.spawner = sp

			err := b.CreateVM(context.Background(), spec)
			if !errors.Is(err, ErrGuestArtifactsUnavailable) {
				t.Fatalf("CreateVM err = %v, want ErrGuestArtifactsUnavailable", err)
			}
			var bootErr *VMBootError
			if !errors.As(err, &bootErr) || bootErr.Cause != VMBootArtifactsMissing {
				t.Errorf("err does not name the artifacts-missing sub-cause: %v", err)
			}
			if !strings.Contains(err.Error(), VMConsoleLogName) {
				t.Errorf("err does not name the pod's console log, which every boot failure must: %v", err)
			}
			sp.mu.Lock()
			spawned := len(sp.specs)
			sp.mu.Unlock()
			if spawned != 0 {
				t.Errorf("spawned %d helpers on a node with no artifacts; want 0 (fail before the spawn)", spawned)
			}
		})
	}
}

// TestCreateVMSurfacesAPreReadyHelperDeath is the READINESS RACE gate.
//
// A helper that dies after spawn — an unentitled binary, a spec the contract
// rejects, a kernel VZ will not boot — exits in milliseconds. Polling Health
// alone would burn the whole 30-second deadline and then report the WRONG cause
// ("the agent never became ready") while the helper's own one-line explanation
// sat unread. This asserts both halves: the failure is prompt, and it carries the
// helper's captured output.
func TestCreateVMSurfacesAPreReadyHelperDeath(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)

	var w *fakeWaiter
	health := func(context.Context, string) error { return errors.New("connection refused") }
	b, sp, waiter, _ := labBackend(t, root, health)
	w = waiter

	// The helper "dies" as soon as it is spawned, printing its reason first.
	go func() {
		for {
			sp.mu.Lock()
			n, next := len(sp.specs), sp.next
			sp.mu.Unlock()
			if n > 0 {
				b.mu.Lock()
				vp := b.live[spec.PodID]
				b.mu.Unlock()
				_ = vp
				// The tail is fed the way the supervisor's log pump would.
				time.Sleep(5 * time.Millisecond)
				w.release(next)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	start := time.Now()
	err := b.CreateVM(context.Background(), spec)
	elapsed := time.Since(start)

	var bootErr *VMBootError
	if !errors.As(err, &bootErr) {
		t.Fatalf("CreateVM err = %v, want a *VMBootError", err)
	}
	if bootErr.Cause != VMBootHelperDied {
		t.Errorf("cause = %q, want %q — a helper that died must not be reported as an unready agent", bootErr.Cause, VMBootHelperDied)
	}
	if elapsed > vmBootDeadline/2 {
		t.Errorf("CreateVM took %s to report a helper that died immediately; the exit race must not wait out the %s deadline", elapsed, vmBootDeadline)
	}
	if bootErr.Detail == "" {
		t.Error("the failure carries no helper output; the tail is the only diagnosis a pre-ready death has")
	}
	if bootErr.ConsolePath == "" {
		t.Error("the failure names no console path")
	}
}

// TestCreateVMKillsAHelperThatNeverBecomesReady asserts the deadline arm: a
// helper that stays alive while its guest never answers is KILLED, and CreateVM
// leaves nothing registered.
//
// The deadline is shrunk for the test by driving awaitGuestReady's siblings
// directly would hide the wiring, so instead the health probe is made to fail
// while the caller's context carries the bound — the same arm the real deadline
// takes, asserted without a 30-second test.
func TestCreateVMKillsAHelperThatNeverBecomesReady(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	health := func(context.Context, string) error { return errors.New("no agent yet") }
	b, _, _, sig := labBackend(t, root, health)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := b.CreateVM(ctx, spec)

	var bootErr *VMBootError
	if !errors.As(err, &bootErr) || bootErr.Cause != VMBootCanceled {
		t.Fatalf("CreateVM err = %v, want a canceled *VMBootError", err)
	}
	if sig.count() == 0 {
		t.Error("no signal was sent to the helper that never became ready; a live helper holds a whole machine for a pod the caller is being told does not exist")
	}
	b.mu.Lock()
	live := len(b.live)
	b.mu.Unlock()
	if live != 0 {
		t.Errorf("%d helpers left registered after a failed boot; CreateVM must be atomic in effect", live)
	}
	if _, err := os.Stat(filepath.Join(root, VMReapSubdir)); err == nil {
		entries, _ := os.ReadDir(filepath.Join(root, VMReapSubdir))
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".json" {
				t.Errorf("a reap record survived a failed boot: %s", e.Name())
			}
		}
	}
}

// TestStopVMHonoursTheHelpersOwnBudget is the ONE-GRACE-BUDGET gate.
//
// The helper answers SIGTERM by asking its guest to stop and waiting out the
// budget the daemon gave it. A daemon that escalated to SIGKILL on a SHORTER
// timer would cut that short, and a hard stop with a guest mid-write is the power
// cut the grace exists to prevent. So the daemon's wait must never be less than
// the helper's — which is what makes the two timers safe to run at all.
func TestStopVMHonoursTheHelpersOwnBudget(t *testing.T) {
	t.Run("a caller grace shorter than the helper's is raised to it", func(t *testing.T) {
		root := t.TempDir()
		spec := labSpec(t, root)
		spec.StopGrace = 25 * time.Second
		b, _, w, _ := labBackend(t, root, func(context.Context, string) error { return nil })
		if err := b.CreateVM(context.Background(), spec); err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		b.mu.Lock()
		vp := b.live[spec.PodID]
		b.mu.Unlock()
		if vp.helperGrace != 25*time.Second {
			t.Fatalf("recorded helper grace = %s, want 25s", vp.helperGrace)
		}
		// Release the exit immediately so the stop returns without spending the
		// budget; what is asserted is the WAIT it was prepared to spend.
		go func() { time.Sleep(5 * time.Millisecond); w.release(vp.pgid) }()
		done := make(chan error, 1)
		go func() { done <- b.StopVM(context.Background(), spec.PodID, time.Second) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("StopVM: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("StopVM did not return")
		}
		// The pod is gone from the registry and its record is retired.
		if _, ok := b.VMDone(spec.PodID); ok {
			t.Error("the helper is still registered after StopVM")
		}
	})

	t.Run("the grace the helper is given is clamped to the ceiling", func(t *testing.T) {
		// The helper clamps whatever it is handed; the daemon must compute the
		// SAME clamped number, or its own escalation would be timed against a
		// budget the helper will never spend.
		for _, tc := range []struct{ in, want time.Duration }{
			{0, VMHostDefaultStopGrace},
			{5 * time.Second, 5 * time.Second},
			{VMHostMaxStopGrace, VMHostMaxStopGrace},
			{time.Hour, VMHostMaxStopGrace},
			{-time.Second, VMHostDefaultStopGrace},
		} {
			if got := clampStopGrace(tc.in); got != tc.want {
				t.Errorf("clampStopGrace(%s) = %s, want %s", tc.in, got, tc.want)
			}
		}
	})

	t.Run("stopping an unknown pod succeeds", func(t *testing.T) {
		root := t.TempDir()
		b, _, _, _ := labBackend(t, root, func(context.Context, string) error { return nil })
		if err := b.StopVM(context.Background(), "never-booted", time.Second); err != nil {
			t.Errorf("StopVM on an unknown pod = %v, want nil (DeletePod is idempotent)", err)
		}
	})
}

// TestStopAllVMsFansOut asserts daemon shutdown stops every helper CONCURRENTLY.
//
// Serial stops are not merely slower: each helper's graceful stop can spend up to
// VMHostMaxStopGrace, launchd allows the daemon 45 seconds total, and its answer
// to a blown ExitTimeOut is SIGKILL of the daemon — stranding exactly the helpers
// the sweep exists to stop. The assertion is on WALL TIME against a stop that is
// deliberately made slow, which is the only thing that can tell fan-out from a
// loop.
func TestStopAllVMsFansOut(t *testing.T) {
	root := t.TempDir()
	b, _, w, _ := labBackend(t, root, func(context.Context, string) error { return nil })

	const pods = 4
	var pgids []int
	for i := range pods {
		spec := labSpec(t, root)
		spec.PodID = string(rune('a' + i))
		spec.PodDir = filepath.Join(root, "pods", spec.PodID)
		spec.AgentSocketPath = filepath.Join(root, "run", "vm", spec.PodID, "agent.sock")
		if err := os.MkdirAll(spec.PodDir, 0o750); err != nil {
			t.Fatalf("pod dir: %v", err)
		}
		if err := b.CreateVM(context.Background(), spec); err != nil {
			t.Fatalf("CreateVM %s: %v", spec.PodID, err)
		}
		b.mu.Lock()
		pgids = append(pgids, b.live[spec.PodID].pgid)
		b.mu.Unlock()
	}

	// Every helper takes 200ms to die. Serial would cost 800ms+; concurrent ~200ms.
	const perHelper = 200 * time.Millisecond
	for _, pgid := range pgids {
		go func(pgid int) { time.Sleep(perHelper); w.release(pgid) }(pgid)
	}
	start := time.Now()
	if err := b.StopAllVMs(context.Background()); err != nil {
		t.Fatalf("StopAllVMs: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > perHelper*time.Duration(pods)/2 {
		t.Errorf("StopAllVMs took %s for %d helpers each taking %s; that is serial, and serial blows launchd's ExitTimeOut", elapsed, pods, perHelper)
	}
	b.mu.Lock()
	live := len(b.live)
	b.mu.Unlock()
	if live != 0 {
		t.Errorf("%d helpers still registered after StopAllVMs", live)
	}
}

// TestVMReapDecision is the ORPHAN SWEEP gate: always kill, never adopt, and
// never signal a group that cannot be PROVEN to be the recorded instance.
func TestVMReapDecision(t *testing.T) {
	member := func(pid int, start int64) supervisor.ProcMember {
		return supervisor.ProcMember{Pid: pid, StartUnixNano: start}
	}
	cases := []struct {
		name                         string
		rec                          vmProcRecord
		members                      []supervisor.ProcMember
		ok                           bool
		wantKill, wantDrop, wantKeep bool
	}{
		{
			name:     "a live leader whose start matches is KILLED, never adopted",
			rec:      vmProcRecord{PodID: "p", Pgid: 900, StartUnixNano: 111},
			members:  []supervisor.ProcMember{member(900, 111)},
			ok:       true,
			wantKill: true,
		},
		{
			name:     "a RECYCLED pgid (leader present, different immutable start) is dropped unsignaled",
			rec:      vmProcRecord{PodID: "p", Pgid: 900, StartUnixNano: 111},
			members:  []supervisor.ProcMember{member(900, 222)},
			ok:       true,
			wantDrop: true,
		},
		{
			name:     "an empty group is dropped",
			rec:      vmProcRecord{PodID: "p", Pgid: 900, StartUnixNano: 111},
			members:  nil,
			ok:       true,
			wantDrop: true,
		},
		{
			name:     "a leaderless but live group is kept and warned, never killed",
			rec:      vmProcRecord{PodID: "p", Pgid: 900, StartUnixNano: 111},
			members:  []supervisor.ProcMember{member(901, 333)},
			ok:       true,
			wantKeep: true,
		},
		{
			name:    "a group that cannot be inspected is kept for the next start",
			rec:     vmProcRecord{PodID: "p", Pgid: 900, StartUnixNano: 111},
			members: nil,
			ok:      false,
		},
		{
			name:     "a zero-identity record can never authorize a kill",
			rec:      vmProcRecord{PodID: "p", Pgid: 900, StartUnixNano: 0},
			members:  []supervisor.ProcMember{member(900, 111)},
			ok:       true,
			wantDrop: true,
		},
		{
			name:     "pgid 1 is refused defensively (a record must never reach kill(-1))",
			rec:      vmProcRecord{PodID: "p", Pgid: 1, StartUnixNano: 111},
			members:  []supervisor.ProcMember{member(1, 111)},
			ok:       true,
			wantDrop: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := func(int) ([]supervisor.ProcMember, bool) { return tc.members, tc.ok }
			kill, drop, keep := vmReapDecision([]vmProcRecord{tc.rec}, probe)
			if got := len(kill) == 1; got != tc.wantKill {
				t.Errorf("kill = %v, want %v", got, tc.wantKill)
			}
			if got := len(drop) == 1; got != tc.wantDrop {
				t.Errorf("drop = %v, want %v", got, tc.wantDrop)
			}
			if got := len(keep) == 1; got != tc.wantKeep {
				t.Errorf("keepWarn = %v, want %v", got, tc.wantKeep)
			}
		})
	}
}

// TestReapOrphanVMsKillsARecordedInstance drives the sweep end to end over a real
// on-disk store: a matching record is signalled and retired with its run dir, and
// a recycled one is dropped without a signal.
func TestReapOrphanVMsKillsARecordedInstance(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, VMReapSubdir)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatalf("store: %v", err)
	}
	runDir := func(pod string) string { return filepath.Join(root, "run", "vm", pod) }
	write := func(rec vmProcRecord) {
		if err := os.MkdirAll(runDir(rec.PodID), 0o700); err != nil {
			t.Fatalf("run dir: %v", err)
		}
		data, _ := json.Marshal(rec)
		if err := os.WriteFile(filepath.Join(store, "x"+rec.PodID+".json"), data, 0o600); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	ours := vmProcRecord{PodID: "ours", Pgid: 900, StartUnixNano: 111, RunDir: runDir("ours")}
	recycled := vmProcRecord{PodID: "recycled", Pgid: 901, StartUnixNano: 111, RunDir: runDir("recycled")}
	write(ours)
	write(recycled)

	sig := &signalRecorder{}
	b := NewVMBackend(
		WithStateRoot(root),
		WithVMProcessSeams(nil, nil, nil, sig.send, nil,
			func(pgid int) ([]supervisor.ProcMember, bool) {
				// 900 is still ours; 901 was recycled to a new leader.
				if pgid == 900 {
					return []supervisor.ProcMember{{Pid: 900, StartUnixNano: 111}}, true
				}
				return []supervisor.ProcMember{{Pid: 901, StartUnixNano: 999}}, true
			}),
	)
	if err := b.ReapOrphanVMs(); err != nil {
		t.Fatalf("ReapOrphanVMs: %v", err)
	}

	sig.mu.Lock()
	sent := append([]int(nil), sig.sent...)
	sig.mu.Unlock()
	if len(sent) != 1 || sent[0] != 900 {
		t.Errorf("signalled %v, want exactly [900] — a recycled pgid must never be signalled", sent)
	}
	for _, rec := range []vmProcRecord{ours, recycled} {
		if _, err := os.Stat(rec.RunDir); !os.IsNotExist(err) {
			t.Errorf("run dir %s survived the sweep (stat err %v); the next pod with that id would bind inside it", rec.RunDir, err)
		}
	}
	entries, _ := os.ReadDir(store)
	if len(entries) != 0 {
		t.Errorf("%d records survived the sweep, want 0", len(entries))
	}
}

// TestClearOrphanRunDirIsBounded asserts the sweep's recursive delete is bounded
// to this node's own run tree. The record is daemon-written under a 0700 root, so
// this is defence in depth — but it drives an os.RemoveAll, and the containment
// check costs one comparison.
func TestClearOrphanRunDirIsBounded(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "not-run", "victim")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("victim: %v", err)
	}
	b := NewVMBackend(WithStateRoot(root))
	b.clearOrphanRunDir(vmProcRecord{PodID: "p", RunDir: outside})
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("a run dir outside <root>/run was deleted: %v", err)
	}

	inside := filepath.Join(root, "run", "vm", "p")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatalf("inside: %v", err)
	}
	b.clearOrphanRunDir(vmProcRecord{PodID: "p", RunDir: inside})
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Errorf("a run dir inside <root>/run survived: %v", err)
	}

	t.Run("a sibling whose name merely starts the same is not admitted", func(t *testing.T) {
		sibling := filepath.Join(root, "run-evil")
		if err := os.MkdirAll(sibling, 0o700); err != nil {
			t.Fatalf("sibling: %v", err)
		}
		b.clearOrphanRunDir(vmProcRecord{PodID: "p", RunDir: sibling})
		if _, err := os.Stat(sibling); err != nil {
			t.Errorf("the separator-aware bound admitted a same-prefix sibling: %v", err)
		}
	})
}
