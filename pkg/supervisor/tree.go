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
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultTreeTick is how often a running container's process tree is
// re-enumerated (TreeConfig.Tick). One enumeration is a single sysctl plus a
// getsid per process, well under a millisecond, so a two-second tick per
// container costs nothing measurable; the tick only has to be short enough to
// see a child before its parent exits and reparents it to launchd, and the
// refresh at every termination request covers the moment that matters most.
const DefaultTreeTick = 2 * time.Second

// treeKillPoll is how often a sweep re-reads the process table while it waits
// for the members it killed to be gone.
const treeKillPoll = 50 * time.Millisecond

// ProcEntry is one row of the host process table.
type ProcEntry struct {
	// Pid, Ppid, Pgid and Sid are the process's id, parent, process group and
	// session. Sid is 0 when it could not be read.
	Pid, Ppid, Pgid, Sid int
	// StartUnixNano is the kernel start time, derived exactly as
	// ProcStartTimeNano derives it, so the two compare bit-exactly.
	StartUnixNano int64
	// Zombie is set for a process that has exited and awaits its reap.
	Zombie bool
	// Comm is the process's short command name.
	Comm string
}

// ProcTable reads the whole host process table. ok is false when it cannot be
// read; the tracker then learns nothing, and never treats that as empty.
type ProcTable func() (entries []ProcEntry, ok bool)

// TreeMember is one process known to belong to a container's process tree,
// named by its exact instance: a pid alone is never a target, because the
// kernel reuses pids.
type TreeMember struct {
	Pid           int
	StartUnixNano int64
	Pgid, Sid     int
	Comm          string
}

// TreeConfig wires a Process's tree tracking (TrackTree). Table and Kill are
// required; the rest default.
type TreeConfig struct {
	// Table reads the process table (ReadProcTable in production).
	Table ProcTable
	// Kill signals one process (KillPID in production).
	Kill func(pid int, sig unix.Signal) error
	// KillGroup signals a process group (SignalGroup in production). nil skips
	// the group kill; the per-member kills still run.
	KillGroup func(pgid int, sig os.Signal) error
	// ProcStart re-reads one process's start time immediately before it is
	// signalled (ProcStartTimeNano in production), narrowing the window between
	// the table read and the kill to a single syscall. Required: TrackTree
	// refuses a config without it, and a tree without it signals nothing, so
	// the identity check can never fail open.
	ProcStart func(pid int) (int64, bool)
	// Getpgid reads a process's current process group, the one a verified
	// member nominates for the group kill (nil selects unix.Getpgid). The
	// snapshot's pgid is never used for that: a member may have called
	// setpgid(2) since the table read.
	Getpgid func(pid int) (int, error)
	// Tick is the enumeration period while the container runs (0 selects
	// DefaultTreeTick).
	Tick time.Duration
	// Budget bounds a sweep's wait for the killed members to be gone (0 selects
	// DefaultExitObservationGrace).
	Budget time.Duration
	// Logger receives the sweep's account (nil selects slog.Default()).
	Logger *slog.Logger
	// Cache, when set, is the daemon-wide snapshot of Table every tracker
	// shares: a tick reuses a read no older than the tick and a sweep poll one
	// no older than its poll period, so the steady-state cost is one table read
	// per tick for the whole daemon, not one per container. The read at
	// tracking start and the refresh before a stop signal are always fresh.
	Cache *ProcTableCache
}

// ProcTableCache is one process-table snapshot shared by every tracker in the
// daemon (TreeConfig.Cache).
//
// Concurrency: mu guards the snapshot. The entries slice is handed to every
// reader and never mutated after it is stored.
type ProcTableCache struct {
	read ProcTable

	mu      sync.Mutex
	at      time.Time
	entries []ProcEntry
}

// NewProcTableCache returns a cache over read.
func NewProcTableCache(read ProcTable) *ProcTableCache {
	return &ProcTableCache{read: read}
}

// Read returns a snapshot taken less than maxAge ago, reading the table anew
// when there is none (maxAge <= 0 always reads). A failed read is not cached.
func (c *ProcTableCache) Read(maxAge time.Duration) ([]ProcEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if maxAge > 0 && !c.at.IsZero() && time.Since(c.at) < maxAge {
		return c.entries, true
	}
	entries, ok := c.read()
	if !ok {
		return nil, false
	}
	c.at, c.entries = time.Now(), entries
	return entries, true
}

// readTable reads the process table no older than maxAge (0 = fresh), through
// the shared cache when one is wired.
func (cfg TreeConfig) readTable(maxAge time.Duration) ([]ProcEntry, bool) {
	if cfg.Cache != nil {
		return cfg.Cache.Read(maxAge)
	}
	return cfg.Table()
}

// TreeSweep is what a sweep of a container's process tree did.
type TreeSweep struct {
	// Killed counts the members other than the container's own leader that
	// the sweep signalled: the stragglers.
	Killed int
	// Survivors are the members still alive when the budget ran out.
	Survivors []TreeMember
}

// procTree is one container's process tree: the members it is known to have,
// re-enumerated on a tick and at every termination request, and swept when the
// container's leader exits.
//
// Concurrency: mu guards every field below cfg and self, and is held for the
// whole of a sweep so a second sweep (DeletePod's) waits for the first instead
// of racing it.
type procTree struct {
	cfg  TreeConfig
	self int
	// selfPgid is the daemon's own process group, never signalled.
	selfPgid int

	mu      sync.Mutex
	roots   []TreeMember
	pgid    int
	sid     int
	members map[int]TreeMember
	last    TreeSweep
}

// newProcTree builds a tree rooted at the live processes among rootPids (the
// group leader and, when it differs, the container child), taking the pod's
// process group and session from the first root found.
func newProcTree(cfg TreeConfig, rootPids ...int) *procTree {
	t := &procTree{cfg: cfg, self: os.Getpid(), selfPgid: unix.Getpgrp(), members: map[int]TreeMember{}}
	entries, ok := cfg.readTable(0)
	if !ok {
		return t
	}
	byPid := make(map[int]ProcEntry, len(entries))
	for _, e := range entries {
		byPid[e.Pid] = e
	}
	for _, pid := range rootPids {
		e, found := byPid[pid]
		if pid <= 1 || pid == t.self || !found {
			continue
		}
		t.roots = append(t.roots, memberOf(e))
		if t.pgid == 0 {
			t.pgid, t.sid = e.Pgid, e.Sid
		}
	}
	t.refreshLocked(entries)
	return t
}

func memberOf(e ProcEntry) TreeMember {
	return TreeMember{Pid: e.Pid, StartUnixNano: e.StartUnixNano, Pgid: e.Pgid, Sid: e.Sid, Comm: e.Comm}
}

// run re-enumerates the tree every tick until ctx is done or the container
// has exited (done closes).
func (t *procTree) run(ctx context.Context, done <-chan struct{}) {
	tick := t.cfg.Tick
	if tick <= 0 {
		tick = DefaultTreeTick
	}
	tk := time.NewTicker(tick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-tk.C:
			t.refresh(tick)
		}
	}
}

// refresh re-enumerates the tree from a table read no older than maxAge
// (0 = fresh).
func (t *procTree) refresh(maxAge time.Duration) {
	entries, ok := t.cfg.readTable(maxAge)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refreshLocked(entries)
}

// refreshLocked recomputes the member set from entries. Caller holds t.mu.
//
// The seeds are only processes proven to be ours by exact instance: a root
// still present with its recorded start, and every earlier member still alive
// with its recorded start. That second set is what keeps a child known after
// its parent exits: reparenting to launchd erases its ancestry, but not its
// identity. The pod's process group and session add their members only while
// a seed is in them, so a group or session id the kernel recycled after the
// pod's last member left is never trusted (BSD does not reuse an id while a
// group or session by that number exists). The set is then closed over
// children by parent pid. The daemon itself and pids 0 and 1 are never
// members, and neither is a zombie: it is already dead.
func (t *procTree) refreshLocked(entries []ProcEntry) {
	byPid := make(map[int]ProcEntry, len(entries))
	children := make(map[int][]int, len(entries))
	for _, e := range entries {
		byPid[e.Pid] = e
		children[e.Ppid] = append(children[e.Ppid], e.Pid)
	}
	same := func(m TreeMember) (ProcEntry, bool) {
		e, ok := byPid[m.Pid]
		return e, ok && e.StartUnixNano == m.StartUnixNano
	}
	next := make(map[int]TreeMember, len(t.members))
	var queue []int
	add := func(e ProcEntry) {
		if e.Pid <= 1 || e.Pid == t.self || e.Zombie {
			return
		}
		if _, dup := next[e.Pid]; dup {
			return
		}
		next[e.Pid] = memberOf(e)
		queue = append(queue, e.Pid)
	}
	var inGroup, inSession bool
	vouch := func(e ProcEntry) {
		inGroup = inGroup || (t.pgid > 1 && e.Pgid == t.pgid)
		inSession = inSession || (t.sid > 1 && e.Sid == t.sid)
	}
	for _, r := range t.roots {
		if e, ok := same(r); ok {
			vouch(e)
			add(e)
		}
	}
	for _, m := range t.members {
		if e, ok := same(m); ok && !e.Zombie {
			vouch(e)
			add(e)
		}
	}
	if inGroup || inSession {
		for _, e := range entries {
			if (inGroup && e.Pgid == t.pgid) || (inSession && e.Sid == t.sid) {
				add(e)
			}
		}
	}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range children[pid] {
			add(byPid[c])
		}
	}
	t.members = next
}

// isRoot reports whether m is one of the tree's roots (the leader or the
// container child), which a straggler count leaves out.
func (t *procTree) isRoot(m TreeMember) bool {
	for _, r := range t.roots {
		if r.Pid == m.Pid && r.StartUnixNano == m.StartUnixNano {
			return true
		}
	}
	return false
}

// sweep SIGKILLs every member of the tree and waits, bounded by the budget,
// for them to be gone, killing any child a member forks meanwhile. There is no
// SIGTERM: this runs after the container's leader has exited, where the
// runc rule is KILL to everything left. Each member is signalled by pid only
// while it is the exact instance recorded; a process group is signalled only
// when a member proven ours was in it at the same table read (a group with
// none left may carry a recycled id, and is skipped). It is idempotent: a later sweep starts
// from the survivors of the last one.
func (t *procTree) sweep() TreeSweep {
	t.mu.Lock()
	defer t.mu.Unlock()
	budget := t.cfg.Budget
	if budget <= 0 {
		budget = DefaultExitObservationGrace
	}
	log := t.cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	deadline := time.Now().Add(budget)
	signalled := map[TreeMember]bool{}
	killed := 0
	for {
		if entries, ok := t.cfg.readTable(treeKillPoll); ok {
			t.refreshLocked(entries)
		}
		if len(t.members) == 0 {
			break
		}
		// The groups to signal after the members: each one a member is in
		// right after its identity was re-verified, read fresh (getpgid), not
		// from the snapshot. A member that no longer verifies, or whose group
		// cannot be read, nominates nothing, so a group with no such member
		// left (which may carry a recycled id) is skipped, as are pgid <= 1
		// and the daemon's own group.
		groups := map[int]bool{}
		for _, m := range t.members {
			key := TreeMember{Pid: m.Pid, StartUnixNano: m.StartUnixNano}
			if !t.stillSame(m) {
				continue
			}
			if pg, err := t.getpgid(m.Pid); err == nil && pg > 1 && pg != t.selfPgid {
				groups[pg] = true
			}
			if signalled[key] {
				continue
			}
			if err := t.cfg.Kill(m.Pid, unix.SIGKILL); err != nil {
				log.Debug("kill a member of the container's process tree", "pid", m.Pid, "err", err)
				continue
			}
			signalled[key] = true
			if !t.isRoot(m) {
				killed++
			}
		}
		// The group kill also reaches a child a member forked between the
		// table read and its kill, which inherited the member's group.
		if t.cfg.KillGroup != nil {
			for pgid := range groups {
				_ = t.cfg.KillGroup(pgid, unix.SIGKILL)
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(treeKillPoll)
	}
	res := TreeSweep{Killed: killed}
	for _, m := range t.members {
		res.Survivors = append(res.Survivors, m)
	}
	sort.Slice(res.Survivors, func(i, j int) bool { return res.Survivors[i].Pid < res.Survivors[j].Pid })
	if killed > 0 {
		log.Info("killed the stragglers of a container's process tree after its leader exited",
			"pgid", t.pgid, "killed", killed)
	}
	for _, m := range res.Survivors {
		log.Warn("a process of a stopped container's tree survived SIGKILL; its reap record is kept for the next sweep",
			"pid", m.Pid, "startUnixNano", m.StartUnixNano, "sid", m.Sid, "command", m.Comm, "budget", budget.String())
	}
	t.last = res
	return res
}

// getpgid reads pid's current process group through the seam.
func (t *procTree) getpgid(pid int) (int, error) {
	if t.cfg.Getpgid != nil {
		return t.cfg.Getpgid(pid)
	}
	return unix.Getpgid(pid)
}

// stillSame re-reads m's start time immediately before it is signalled. It
// fails closed: without a ProcStart seam nothing is the same instance.
func (t *procTree) stillSame(m TreeMember) bool {
	if t.cfg.ProcStart == nil {
		return false
	}
	start, ok := t.cfg.ProcStart(m.Pid)
	return ok && start == m.StartUnixNano
}

// survivors returns the last sweep's survivors.
func (t *procTree) survivors() []TreeMember {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]TreeMember(nil), t.last.Survivors...)
}

// snapshot returns the current members, sorted by pid.
func (t *procTree) snapshot() []TreeMember {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TreeMember, 0, len(t.members))
	for _, m := range t.members {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pid < out[j].Pid })
	return out
}

// TrackTree starts tracking the running process's tree: the group leader, the
// container child, everything descended from them, and the members of the
// pod's process group and session (see procTree.refreshLocked). It is
// enumerated now, every cfg.Tick until ctx is done or the process exits, and
// again before every signal StopSignal delivers. When the process exits (its
// exit observed, not a cancelled wait) the tree is swept before the exit is
// reported: see procTree.sweep. Call it once, after Start or an Adopt
// constructor; a cfg without Table, Kill or ProcStart (logged), or a process
// with no pid, is not tracked.
func (p *Process) TrackTree(ctx context.Context, cfg TreeConfig) {
	if cfg.Table == nil || cfg.Kill == nil || cfg.ProcStart == nil {
		log := cfg.Logger
		if log == nil {
			log = slog.Default()
		}
		log.Warn("process-tree tracking disabled: the config lacks a process table, a kill or a start-time reader",
			"pid", p.PID(), "table", cfg.Table != nil, "kill", cfg.Kill != nil, "procStart", cfg.ProcStart != nil)
		return
	}
	p.mu.Lock()
	pid, child, already := p.pid, p.childPID, p.tree != nil
	p.mu.Unlock()
	if pid <= 1 || already {
		return
	}
	t := newProcTree(cfg, pid, child)
	p.mu.Lock()
	p.tree = t
	p.mu.Unlock()
	go t.run(ctx, p.done)
}

// procTreeOf returns the process's tree, or nil when it is not tracked.
func (p *Process) procTreeOf() *procTree {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tree
}

// RefreshTree re-enumerates the process's tree now (a no-op when untracked).
// StopSignal calls it before every signal, because a child's ancestry is
// readable only while its parent lives.
func (p *Process) RefreshTree() {
	if t := p.procTreeOf(); t != nil {
		t.refresh(0)
	}
}

// KillTree sweeps the process's tree (procTree.sweep) and reports what it did.
// It is what DeletePod runs unconditionally once the pod's containers are
// stopped; the exit path runs the same sweep on its own. Untracked, it does
// nothing.
func (p *Process) KillTree() TreeSweep {
	t := p.procTreeOf()
	if t == nil {
		return TreeSweep{}
	}
	return t.sweep()
}

// TreeSurvivors returns the members the last sweep could not kill (nil when
// none, or untracked). It only reads.
func (p *Process) TreeSurvivors() []TreeMember {
	t := p.procTreeOf()
	if t == nil {
		return nil
	}
	return t.survivors()
}

// TreeMembers returns the tree's current members (nil when untracked).
func (p *Process) TreeMembers() []TreeMember {
	t := p.procTreeOf()
	if t == nil {
		return nil
	}
	return t.snapshot()
}

// sweepOnExit sweeps the tree once the leader's exit has been observed. err
// is the exit wait's error: a cancelled or failed wait says nothing about
// whether the leader lives (a daemon shutdown cancels it while every pod runs
// on by design), so only an observed exit sweeps.
func (p *Process) sweepOnExit(err error) {
	if err != nil && !isErrExitUnknown(err) {
		return
	}
	if t := p.procTreeOf(); t != nil {
		t.sweep()
	}
}

// isErrExitUnknown reports an observed exit whose status could not be read
// (an adopted process): the exit itself is real.
func isErrExitUnknown(err error) bool { return errors.Is(err, ErrExitUnknown) }
