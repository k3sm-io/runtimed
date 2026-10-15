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

package supervisor

import (
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeTable is a mutable process table; killing a pid removes it unless the
// pid is marked unkillable.
type fakeTable struct {
	mu         sync.Mutex
	rows       map[int]ProcEntry
	unkillable map[int]bool
	killed     []int
	groups     []int
}

func (f *fakeTable) read() ([]ProcEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ProcEntry, 0, len(f.rows))
	for _, e := range f.rows {
		out = append(out, e)
	}
	return out, true
}

func (f *fakeTable) kill(pid int, _ unix.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, pid)
	if !f.unkillable[pid] {
		delete(f.rows, pid)
	}
	return nil
}

func (f *fakeTable) killGroup(pgid int, _ os.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = append(f.groups, pgid)
	for pid, e := range f.rows {
		if e.Pgid == pgid && !f.unkillable[pid] {
			delete(f.rows, pid)
		}
	}
	return nil
}

func (f *fakeTable) set(e ProcEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[e.Pid] = e
}

func (f *fakeTable) start(pid int) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.rows[pid]
	return e.StartUnixNano, ok
}

func (f *fakeTable) getpgid(pid int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.rows[pid]
	if !ok {
		return 0, unix.ESRCH
	}
	return e.Pgid, nil
}

func (f *fakeTable) config() TreeConfig {
	return TreeConfig{
		Table: f.read, Kill: f.kill, KillGroup: f.killGroup,
		ProcStart: f.start, Getpgid: f.getpgid,
		Budget: 200 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func row(pid, ppid, pgid, sid int, start int64) ProcEntry {
	return ProcEntry{Pid: pid, Ppid: ppid, Pgid: pgid, Sid: sid, StartUnixNano: start}
}

func TestProcTreeSweep(t *testing.T) {
	t.Run("ancestry, group and session members are killed; strangers are not", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),  // init (root)
			101: row(101, 100, 100, 100, 2), // child in the group
			102: row(102, 100, 102, 102, 3), // setsid escapee: ancestry only
			103: row(103, 1, 103, 100, 4),   // reparented, own group, pod session
			104: row(104, 1, 100, 100, 5),   // reparented, pod group
			105: row(105, 102, 102, 102, 6), // the escapee's own child
			200: row(200, 1, 200, 200, 7),   // a stranger
		}}
		tr := newProcTree(f.config(), 100)
		// The init exits and is reaped.
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		res := tr.sweep()
		if res.Killed != 5 || len(res.Survivors) != 0 {
			t.Fatalf("sweep = %+v, want 5 killed, no survivors", res)
		}
		for _, pid := range f.killed {
			if pid == 200 {
				t.Fatal("a stranger was signalled")
			}
		}
	})

	t.Run("a recycled pid is never signalled and does not vouch for the group", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 1, 100, 100, 2),
		}}
		tr := newProcTree(f.config(), 100)
		// Both die; 101 is recycled into an unrelated process that, by
		// coincidence, now sits in a group numbered 100 again.
		f.mu.Lock()
		delete(f.rows, 100)
		f.rows[101] = row(101, 1, 100, 300, 99)
		f.mu.Unlock()
		res := tr.sweep()
		if len(f.killed) != 0 || len(f.groups) != 0 {
			t.Fatalf("signalled pids %v groups %v, want none", f.killed, f.groups)
		}
		if res.Killed != 0 || len(res.Survivors) != 0 {
			t.Fatalf("sweep = %+v, want nothing", res)
		}
	})

	t.Run("a member that vanishes after the table read nominates no group", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 100, 101, 101, 2),
		}}
		cfg := f.config()
		// The re-read just before the signal no longer finds 101.
		cfg.ProcStart = func(pid int) (int64, bool) { return 0, pid != 101 }
		tr := newProcTree(cfg, 100)
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		tr.sweep()
		if len(f.killed) != 0 {
			t.Fatalf("signalled pids %v, want none", f.killed)
		}
		for _, g := range f.groups {
			if g == 101 {
				t.Fatalf("group 101 signalled for a member that no longer verifies: %v", f.groups)
			}
		}
	})

	t.Run("a member in the daemon's own process group never gets that group signalled", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 100, 777, 100, 2),
		}}
		tr := newProcTree(f.config(), 100)
		tr.selfPgid = 777
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		tr.sweep()
		for _, g := range f.groups {
			if g == 777 || g <= 1 {
				t.Fatalf("signalled group %d (the daemon's own, or <= 1): %v", g, f.groups)
			}
		}
	})

	t.Run("a member that moved group after the table read nominates its new group, not the old", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 100, 555, 100, 2),
		}, unkillable: map[int]bool{101: true}}
		cfg := f.config()
		// The snapshot says 555; the live process has since moved to 101.
		cfg.Getpgid = func(pid int) (int, error) {
			if pid == 101 {
				return 101, nil
			}
			return f.getpgid(pid)
		}
		cfg.Budget = time.Millisecond
		tr := newProcTree(cfg, 100)
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		tr.sweep()
		for _, g := range f.groups {
			if g == 555 {
				t.Fatalf("the snapshot's stale group 555 was signalled: %v", f.groups)
			}
		}
	})

	t.Run("without a start-time reader nothing is signalled", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 100, 100, 100, 2),
		}}
		cfg := f.config()
		cfg.ProcStart = nil
		tr := newProcTree(cfg, 100)
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		tr.sweep()
		if len(f.killed) != 0 || len(f.groups) != 0 {
			t.Fatalf("signalled pids %v groups %v without an identity check", f.killed, f.groups)
		}
	})

	t.Run("a member that will not die is a survivor, and a later sweep retries it", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 100, 101, 101, 2),
		}, unkillable: map[int]bool{101: true}}
		tr := newProcTree(f.config(), 100)
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		res := tr.sweep()
		if len(res.Survivors) != 1 || res.Survivors[0].Pid != 101 || res.Survivors[0].Sid != 101 {
			t.Fatalf("survivors = %+v, want pid 101", res.Survivors)
		}
		f.mu.Lock()
		f.unkillable = nil
		f.mu.Unlock()
		if res := tr.sweep(); len(res.Survivors) != 0 {
			t.Fatalf("second sweep survivors = %+v", res.Survivors)
		}
	})

	t.Run("a child forked during the sweep is killed too", func(t *testing.T) {
		f := &fakeTable{rows: map[int]ProcEntry{
			100: row(100, 50, 100, 100, 1),
			101: row(101, 100, 101, 101, 2),
		}}
		cfg := f.config()
		kill := cfg.Kill
		forked := false
		cfg.Kill = func(pid int, sig unix.Signal) error {
			if pid == 101 && !forked {
				forked = true
				f.mu.Lock()
				f.rows[102] = row(102, 101, 101, 101, 3) // inherits its parent's group
				f.mu.Unlock()
			}
			return kill(pid, sig)
		}
		tr := newProcTree(cfg, 100)
		f.mu.Lock()
		delete(f.rows, 100)
		f.mu.Unlock()
		tr.sweep()
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, alive := f.rows[102]; alive {
			t.Fatalf("the child forked mid-sweep survived; killed %v", f.killed)
		}
	})
}

// TestTrackTreeIgnoresAnIncompleteConfig pins that an unwired config tracks
// nothing, so a sweep is a no-op.
func TestTrackTreeIgnoresAnIncompleteConfig(t *testing.T) {
	p := &Process{pid: 4242, done: make(chan struct{})}
	p.TrackTree(t.Context(), TreeConfig{})
	if res := p.KillTree(); res.Killed != 0 || res.Survivors != nil {
		t.Fatalf("KillTree on an untracked process = %+v", res)
	}
}

// TestProcTableCacheSharesOneRead pins the shared snapshot: reads within maxAge
// reuse one table read, maxAge 0 always reads, and a failed read is not cached.
func TestProcTableCacheSharesOneRead(t *testing.T) {
	reads, fail := 0, false
	c := NewProcTableCache(func() ([]ProcEntry, bool) {
		reads++
		return []ProcEntry{{Pid: reads}}, !fail
	})
	for i := 0; i < 5; i++ {
		if _, ok := c.Read(time.Hour); !ok {
			t.Fatal("read failed")
		}
	}
	if reads != 1 {
		t.Fatalf("five tick reads made %d table reads, want 1", reads)
	}
	if _, _ = c.Read(0); reads != 2 {
		t.Fatalf("a fresh read made %d table reads, want 2", reads)
	}
	fail = true
	if _, ok := c.Read(0); ok {
		t.Fatal("a failed read reported ok")
	}
	fail = false
	if e, ok := c.Read(time.Hour); !ok || e[0].Pid != 2 {
		t.Fatalf("after a failed read the cache serves %v %v, want the last good snapshot", e, ok)
	}
}
