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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestVMAdoptDecision pins the fail-closed adoption predicate: a record is
// adopted only when every element matches, each mismatch is refused with its
// own reason, and the costly probes (the code-directory read, the version call)
// never run once a cheaper check has refused.
func TestVMAdoptDecision(t *testing.T) {
	const pgid = 900
	good := vmProcRecord{
		Schema:         vmRecordSchema,
		PodID:          "p1",
		Pgid:           pgid,
		StartUnixNano:  111,
		AgentSocket:    "/r/run/vm/p1/agent.sock",
		RunDir:         "/r/run/vm/p1",
		HelperCDHash:   "abc",
		HelperProtocol: VMHostProtocolVersion,
		RuntimeVersion: "cdhash:self",
		BootSession:    "boot-1",
	}
	want := vmAdoptExpect{runtimeVersion: "cdhash:self", bootSession: "boot-1"}
	answer := vmHostAnswer{VMHostVersion: VMHostVersion{Protocol: VMHostProtocolVersion, Pid: pgid}, PeerPid: pgid}

	type world struct {
		identity bool
		owned    bool
		cdHash   string
		cdErr    error
		answer   vmHostAnswer
		verErr   error
	}
	healthy := world{identity: true, owned: true, cdHash: "abc", answer: answer}

	cases := []struct {
		name       string
		rec        func(*vmProcRecord)
		want       func(*vmAdoptExpect)
		world      func(*world)
		refusal    string // "" = adopted
		noVersion  bool   // the version call must not have been made
		noCodeRead bool   // the code-directory read must not have been made
	}{
		{name: "every element matches: adopted"},
		{name: "a record an earlier build wrote (no schema)", rec: func(r *vmProcRecord) { r.Schema = 0 }, refusal: "schema", noVersion: true, noCodeRead: true},
		{name: "a record of a later schema", rec: func(r *vmProcRecord) { r.Schema = vmRecordSchema + 1 }, refusal: "schema", noVersion: true, noCodeRead: true},
		{name: "another daemon build spawned it", rec: func(r *vmProcRecord) { r.RuntimeVersion = "cdhash:other" }, refusal: "another daemon build", noVersion: true, noCodeRead: true},
		{name: "this daemon cannot name its build", want: func(w *vmAdoptExpect) { w.runtimeVersion = "" }, refusal: "cannot name its own build", noVersion: true, noCodeRead: true},
		{name: "recorded in another boot session", rec: func(r *vmProcRecord) { r.BootSession = "boot-0" }, refusal: "another boot session", noVersion: true, noCodeRead: true},
		{name: "the boot session cannot be read", want: func(w *vmAdoptExpect) { w.bootSession = "" }, refusal: "boot session cannot be read", noVersion: true, noCodeRead: true},
		{name: "the leader is not the recorded instance", world: func(w *world) { w.identity = false }, refusal: "not the recorded instance", noVersion: true, noCodeRead: true},
		{name: "a zero-identity record", rec: func(r *vmProcRecord) { r.StartUnixNano = 0 }, refusal: "not the recorded instance", noVersion: true, noCodeRead: true},
		{name: "the agent socket is outside the run dir", rec: func(r *vmProcRecord) { r.AgentSocket = "/elsewhere/agent.sock" }, refusal: "inconsistent run dir", noVersion: true, noCodeRead: true},
		{name: "the run dir carries no owner marker for the pod", world: func(w *world) { w.owned = false }, refusal: "not proven", noVersion: true, noCodeRead: true},
		{name: "no helper hash was recorded", rec: func(r *vmProcRecord) { r.HelperCDHash = "" }, refusal: "no helper code-directory hash", noVersion: true, noCodeRead: true},
		{name: "the running hash cannot be read", world: func(w *world) { w.cdErr = errors.New("ESRCH") }, refusal: "cannot be read", noVersion: true},
		{name: "the running helper is another binary", world: func(w *world) { w.cdHash = "def" }, refusal: "differs", noVersion: true},
		{name: "the record speaks another protocol", rec: func(r *vmProcRecord) { r.HelperProtocol = VMHostProtocolVersion + 1 }, refusal: "recorded speaking protocol", noVersion: true},
		{name: "the helper does not answer", world: func(w *world) { w.verErr = errors.New("connection refused") }, refusal: "did not answer"},
		{name: "the helper answers another protocol", world: func(w *world) { w.answer.Protocol = VMHostProtocolVersion + 1 }, refusal: "answers protocol"},
		{name: "the helper names another pid", world: func(w *world) { w.answer.Pid = pgid + 1 }, refusal: "served by pid"},
		{name: "the kernel says another process answered", world: func(w *world) { w.answer.PeerPid = pgid + 1 }, refusal: "served by pid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, w, wv := good, healthy, want
			if tc.rec != nil {
				tc.rec(&rec)
			}
			if tc.world != nil {
				tc.world(&w)
			}
			if tc.want != nil {
				tc.want(&wv)
			}
			var codeReads, versionCalls int
			var socket string
			probes := vmAdoptProbes{
				identity: func(vmProcRecord) bool { return w.identity },
				owned:    func(vmProcRecord) bool { return w.owned },
				cdHash: func(pid int) (string, error) {
					codeReads++
					if pid != rec.Pgid {
						t.Errorf("code-directory read of pid %d, want the recorded %d", pid, rec.Pgid)
					}
					return w.cdHash, w.cdErr
				},
				version: func(ctx context.Context, s string) (vmHostAnswer, error) {
					versionCalls++
					socket = s
					if _, ok := ctx.Deadline(); !ok {
						t.Error("the version call carries no deadline")
					}
					return w.answer, w.verErr
				},
			}
			got := vmAdoptDecision(context.Background(), rec, wv, probes)
			if tc.refusal == "" {
				if got != "" {
					t.Fatalf("refused %q, want adopted", got)
				}
				if socket != filepath.Join(good.RunDir, VMHostControlSocketName) {
					t.Errorf("version call on %q, want the run dir's control socket", socket)
				}
				return
			}
			if !strings.Contains(got, tc.refusal) {
				t.Fatalf("refusal = %q, want one containing %q", got, tc.refusal)
			}
			if tc.noVersion && versionCalls != 0 {
				t.Errorf("the version call was made %d times after a cheaper check refused", versionCalls)
			}
			if tc.noCodeRead && codeReads != 0 {
				t.Errorf("the code-directory hash was read %d times after a cheaper check refused", codeReads)
			}
		})
	}
}

// adoptWorld is an on-disk record store over a fake process table, for the
// adopt-or-sweep ownership tests. Signals to an adopted pgid close its exit edge,
// as a real kill would.
type adoptWorld struct {
	root string
	mu   sync.Mutex
	sent []int
	exit map[int]chan struct{}
}

func newAdoptWorld(t *testing.T) *adoptWorld {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, VMReapSubdir), 0o700); err != nil {
		t.Fatal(err)
	}
	return &adoptWorld{root: root, exit: map[int]chan struct{}{}}
}

func (w *adoptWorld) runDir(pod string) string { return filepath.Join(w.root, "run", "vm", pod) }

// record writes a stamped run dir and a record as spawnVMHost would.
func (w *adoptWorld) record(t *testing.T, rec vmProcRecord) vmProcRecord {
	t.Helper()
	rec.RunDir = w.runDir(rec.PodID)
	rec.AgentSocket = filepath.Join(rec.RunDir, "agent.sock")
	if err := writeVMOwnerMarker(w.root, rec.RunDir, rec.PodID); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.root, VMReapSubdir, strconv.Itoa(rec.Pgid)+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return rec
}

func (w *adoptWorld) send(pgid int, _ os.Signal) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sent = append(w.sent, pgid)
	if ch := w.exit[pgid]; ch != nil {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
	return nil
}

func (w *adoptWorld) signalled() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]int(nil), w.sent...)
}

// backend builds a VMBackend over the world: every pgid's leader lives with
// start pgid*1000, every helper's code-directory hash is "h<pgid>", and every
// control socket answers protocol 1 from the recorded pid.
func (w *adoptWorld) backend() *VMBackend {
	b := NewVMBackend(
		WithStateRoot(w.root),
		WithVMProcessSeams(nil, nil, nil, w.send,
			func(pid int) (int64, bool) { return int64(pid) * 1000, true },
			func(pgid int) ([]supervisor.ProcMember, bool) {
				return []supervisor.ProcMember{{Pid: pgid, StartUnixNano: int64(pgid) * 1000}}, true
			}),
		WithVMAdoptionProbes(
			func() (string, error) { return "cdhash:self", nil },
			func() (string, error) { return "boot-1", nil },
			func(pid int) (string, error) { return fmt.Sprintf("h%d", pid), nil },
			func(_ context.Context, socket string) (VMHostVersion, int, error) {
				var pid int
				_, _ = fmt.Sscanf(filepath.Base(filepath.Dir(socket)), "pod%d", &pid)
				return VMHostVersion{Protocol: VMHostProtocolVersion, Pid: pid}, pid, nil
			}),
	)
	b.adopt.watchExit = func(_ context.Context, pid int, verify func() bool) (<-chan struct{}, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		ch := w.exit[pid]
		if ch == nil {
			ch = make(chan struct{})
			w.exit[pid] = ch
		}
		if !verify() {
			close(ch)
		}
		return ch, nil
	}
	return b
}

// adoptableRecord is a schema-current record the world's backend admits.
func adoptableRecord(pgid int) vmProcRecord {
	return vmProcRecord{
		Schema:         vmRecordSchema,
		PodID:          fmt.Sprintf("pod%d", pgid),
		Pgid:           pgid,
		StartUnixNano:  int64(pgid) * 1000,
		StopGraceNanos: int64(5 * time.Second),
		HelperCDHash:   fmt.Sprintf("h%d", pgid),
		HelperProtocol: VMHostProtocolVersion,
		RuntimeVersion: "cdhash:self",
		BootSession:    "boot-1",
	}
}

// TestAdoptVMOwnsAHelperBeforeTheSweep pins the ownership split: an attach
// adopts a helper only before the sweep, only one runtime can hold it (the
// record lock), the sweep kills every recorded helper nothing adopted and
// spares the adopted one and its run dir, and an adopted helper is stopped and
// cleaned up exactly as a spawned one.
func TestAdoptVMOwnsAHelperBeforeTheSweep(t *testing.T) {
	w := newAdoptWorld(t)
	adopted := w.record(t, adoptableRecord(900))
	old := adoptableRecord(901)
	old.Schema = 0 // an earlier build's record
	old = w.record(t, old)

	b1, b2 := w.backend(), w.backend()
	ctx := context.Background()

	if err := b1.AdoptVM(ctx, adopted.PodID); err != nil {
		t.Fatalf("AdoptVM: %v", err)
	}
	if _, ok := b1.VMDone(adopted.PodID); !ok {
		t.Fatal("an adopted helper has no exit edge")
	}
	if err := b1.AdoptVM(ctx, old.PodID); !errors.Is(err, ErrVMNotAdopted) || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("AdoptVM(old record) = %v, want a schema refusal", err)
	}

	// A second runtime over the same store cannot take a helper the first holds.
	if err := b2.AdoptVM(ctx, adopted.PodID); !errors.Is(err, ErrVMNotAdopted) || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("second runtime AdoptVM = %v, want a lock refusal", err)
	}
	// Once the first lets go (a daemon exit), the second can.
	b1.DetachVMs()
	if err := b2.AdoptVM(ctx, adopted.PodID); err != nil {
		t.Fatalf("AdoptVM after the holder detached: %v", err)
	}

	if err := b2.ReapOrphanVMs(); err != nil {
		t.Fatalf("ReapOrphanVMs: %v", err)
	}
	if got := w.signalled(); len(got) != 1 || got[0] != old.Pgid {
		t.Fatalf("the sweep signalled %v, want exactly the unadopted [%d]", got, old.Pgid)
	}
	if _, err := os.Stat(adopted.RunDir); err != nil {
		t.Errorf("the adopted helper's run dir is gone after the sweep: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.root, VMReapSubdir, "900.json")); err != nil {
		t.Errorf("the adopted helper's record is gone after the sweep: %v", err)
	}
	if err := b2.AdoptVM(ctx, "pod902"); !errors.Is(err, ErrVMNotAdopted) || !strings.Contains(err.Error(), "sweep has begun") {
		t.Fatalf("AdoptVM after the sweep = %v, want the sweep refusal", err)
	}

	if err := b2.StopVM(ctx, adopted.PodID, 0); err != nil {
		t.Fatalf("StopVM(adopted): %v", err)
	}
	if got := w.signalled(); len(got) != 2 || got[1] != adopted.Pgid {
		t.Fatalf("signals = %v, want the adopted helper's group stopped", got)
	}
	if _, err := os.Stat(adopted.RunDir); !os.IsNotExist(err) {
		t.Errorf("the stopped helper's run dir survived (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(w.root, VMReapSubdir, "900.json")); !os.IsNotExist(err) {
		t.Errorf("the stopped helper's record survived (stat err %v)", err)
	}
}

// TestSweepSparesALiveHelpersRunDir pins that an older record for the same pod
// as an adopted helper never takes the live helper's run dir with it.
func TestSweepSparesALiveHelpersRunDir(t *testing.T) {
	w := newAdoptWorld(t)
	live := w.record(t, adoptableRecord(900))
	older := adoptableRecord(800)
	older.PodID = live.PodID
	older.StartUnixNano = 800 * 1000
	older.Schema = 0
	_ = w.record(t, older)

	b := w.backend()
	if err := b.AdoptVM(context.Background(), live.PodID); err != nil {
		t.Fatalf("AdoptVM: %v", err)
	}
	if err := b.ReapOrphanVMs(); err != nil {
		t.Fatal(err)
	}
	if got := w.signalled(); len(got) != 1 || got[0] != 800 {
		t.Fatalf("the sweep signalled %v, want the older instance [800]", got)
	}
	if _, err := os.Stat(live.RunDir); err != nil {
		t.Errorf("the live helper's run dir was removed with an older record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.root, VMReapSubdir, "800.json")); !os.IsNotExist(err) {
		t.Errorf("the older record was not retired (stat err %v)", err)
	}
}

// TestReadVMHostLogTail pins the diagnosis read: the last lines of the current
// file, topped up from the rotation when the current file is short, and a
// stated absence when there is nothing.
func TestReadVMHostLogTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, VMHostLogName)
	if got := readVMHostLogTail(path, 3); got != "(the helper produced no output)" {
		t.Errorf("no file: %q", got)
	}
	if err := os.WriteFile(path+".1", []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readVMHostLogTail(path, 3); got != "a | b | c" {
		t.Errorf("short current file: %q, want the rotation's tail first", got)
	}
	if err := os.WriteFile(path, []byte("c\nd\ne\nf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readVMHostLogTail(path, 3); got != "d | e | f" {
		t.Errorf("long current file: %q, want its last three lines", got)
	}
}
