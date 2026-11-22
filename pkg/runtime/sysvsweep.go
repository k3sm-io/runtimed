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
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"
	"k3sm.io/runtimed/pkg/sysvipc"
)

// The System V IPC sweeper (B1788).
//
// WHY. Seatbelt does not mediate shmget, semget or msgget: under a pod's
// (deny default) profile they create objects, while every later use (attach,
// operate, stat, remove) is EPERM. The path-rebase shim refuses the create
// calls with ENOSYS (shim/pathrebase_shim.c), but a process that does not load
// the shim (a platform binary, a container that sets its own
// DYLD_INSERT_LIBRARIES) still creates objects it can never use or remove.
// Each holds a slot of a host-wide table (kern.sysv.shmmni is 32 on macOS) until
// something with the right to remove it does. This sweeper is that something.
//
// WHAT IT MAY REMOVE. Only an object for which every one of these holds:
//
//  1. It is owned AND was created by this daemon's own uid, and that uid is the
//     dedicated service account (sysvSweepUser), never root. Native pods run as
//     the daemon's uid, so this is the pod uid. A daemon that is root (the dev
//     --datapath tier, the legacy root posture) or runs as a person (k3sm dev)
//     never sweeps, because its objects are not distinguishable from the
//     operator's. Running unprivileged also lets the kernel enforce the rule:
//     IPC_STAT and IPC_RMID on another user's 0600 object fail.
//  2. It was never used: no attach or detach, no semaphore operation, no
//     message sent or received, nothing queued, nothing attached now, and no
//     process blocked on it (a semaphore set's semncnt and semzcnt, which a
//     blocked semop raises before it completes and so before the set reads
//     used). A pod cannot do any of these (the profile refuses them), so an
//     object a pod made is always in this state, while a live user leaves it.
//  3. It has been unchanged for at least sysvSweepGrace (its ctime is older),
//     which covers the window between another process's create and first use.
//  4. For shared memory, whose creator pid is recorded: the creator is not a
//     live process outside every pod's session. A live creator inside a pod, or
//     one the kernel reports gone (ESRCH), does not block. Any other answer
//     about the creator keeps the object, and so does a reused pid, which reads
//     as a live non-pod process (the safe direction).
//  5. It is not a message queue. A queue records no creator and exposes no
//     count of blocked receivers, so an idle queue a host process waits on is
//     indistinguishable from one a pod left. Queues are reported once and kept.
//
// Immediately before IPC_RMID the object is read again, and it is removed only
// if its key, creator uid, creator pid and ctime still match and it still
// qualifies. That re-read is a state check, not an identity proof: a leaked
// object's key is IPC_PRIVATE (0) and ctime has one-second granularity. What
// keeps a reused slot from being mistaken for the old object is xnu's id
// itself, which carries a per-slot sequence number, so a recreated object in
// the same slot has a different id. The gap between the re-read and IPC_RMID
// cannot be closed from user space; the grace period makes it irrelevant for
// an object that was just created.
//
// WHAT IT CANNOT PROVE. A semaphore set records no creator, so rule 4 is
// unavailable for it, and a host process running as the service account that
// creates a set, leaves it unoperated and unwaited-on for the grace period,
// and only then uses it would lose it. A wait-for-zero semop on an all-zero
// set completes at once and so sets the operation time, so the only use this
// misses is a set left wholly untouched for the grace period. The k3sm daemons
// use no System V IPC.
//
// WHAT IT CANNOT SEE. IPC_STAT needs the owner's read bit, so an object
// created with no owner read permission (mode 0000 or 0200) fails the stat
// with EACCES even for its owner, although its owner could remove it. Such an
// object is skipped like another user's: a process bypassing the shim can
// leak one deliberately, and only the operator's ipcrm removes it.
type sysvSweeper struct {
	uid      uint32
	grace    time.Duration
	now      func() time.Time
	list     func(context.Context) ([]sysvipc.Ref, error)
	stat     func(sysvipc.Ref) (sysvipc.Object, error)
	remove   func(sysvipc.Ref) error
	sessions func() map[int]bool        // the session ids of every pod's running containers
	sidOf    func(pid int) (int, error) // the session of a pid; ESRCH means it is gone
	log      *slog.Logger
	// reported holds the queues already logged as kept (rule 5), keyed by
	// id and ctime, so each is reported once rather than every scan. Only
	// sweepOnce touches it, from the one sweep goroutine.
	reported map[sysvipc.Ref]time.Time
}

// sysvSweepUser is the only account whose objects the sweeper touches: the
// installed daemon's service user (k3sm's defaults.ServiceUser).
const sysvSweepUser = supervisor.ServiceUser

// sysvSweepGrace is how long an object must stand unchanged and unused before
// it is removed.
const sysvSweepGrace = 2 * time.Minute

// DefaultSysVSweepInterval is how often RunSysVSweep scans.
const DefaultSysVSweepInterval = time.Minute

// sysvSweepEligibleUser decides whether a daemon running as uid with the
// account name name may sweep at all.
func sysvSweepEligibleUser(uid uint32, name string) bool {
	return uid != 0 && name == sysvSweepUser
}

// verdict reports whether o may be removed, and why not when it may not.
func (s *sysvSweeper) verdict(o sysvipc.Object, sessions map[int]bool) (bool, string) {
	switch {
	case o.UID != s.uid || o.CUID != s.uid:
		return false, "not owned and created by the pod uid"
	case o.Nattch > 0:
		return false, "attached"
	case o.Used:
		return false, "has been used"
	case o.Waiters > 0:
		return false, "a process is blocked on it"
	case s.now().Sub(o.Ctime) < s.grace:
		return false, "changed within the grace period"
	case o.Kind == sysvipc.Msg:
		return false, "a message queue: no creator or waiter count to attribute it by"
	}
	if o.Kind == sysvipc.Shm && o.CPID > 0 {
		sid, err := s.sidOf(o.CPID)
		switch {
		case err != nil && !errors.Is(err, unix.ESRCH):
			return false, "its creator's liveness is unknown"
		case err == nil && !sessions[sid]:
			return false, "its creator is a live process outside every pod"
		}
	}
	return true, ""
}

// sweepOnce scans the host once and removes what qualifies. It returns the
// objects it removed.
func (s *sysvSweeper) sweepOnce(ctx context.Context) []sysvipc.Object {
	refs, err := s.list(ctx)
	if err != nil {
		s.log.Warn("sysv sweep: cannot list System V IPC objects", "err", err)
		return nil
	}
	sessions := s.sessions()
	var removed []sysvipc.Object
	for _, r := range refs {
		o, err := s.stat(r)
		if err != nil {
			// Someone else's object, one we may not read (EACCES, see WHAT IT
			// CANNOT SEE), or one already gone: never removed.
			continue
		}
		ok, why := s.verdict(o, sessions)
		if !ok {
			s.reportKeptQueue(o, why)
			continue
		}
		again, err := s.stat(r)
		if err != nil || again.Key != o.Key || again.CUID != o.CUID || again.CPID != o.CPID || !again.Ctime.Equal(o.Ctime) {
			continue
		}
		if ok, _ := s.verdict(again, sessions); !ok {
			continue
		}
		if err := s.remove(r); err != nil {
			if !errors.Is(err, sysvipc.ErrGone) {
				s.log.Warn("sysv sweep: remove failed", "kind", r.Kind.String(), "id", r.ID, "err", err)
			}
			continue
		}
		s.log.Info("sysv sweep: removed an unusable System V IPC object a pod left",
			"kind", r.Kind.String(), "id", r.ID, "key", o.Key, "creator_pid", o.CPID,
			"age", s.now().Sub(o.Ctime).Round(time.Second).String())
		removed = append(removed, o)
	}
	return removed
}

// reportKeptQueue logs, once per queue, a message queue that rule 5 alone
// keeps: one the service account owns and created and never used, past the
// grace period. Such a queue is most likely one a pod left, and the operator
// removes it with ipcrm -q once nothing waits on it.
func (s *sysvSweeper) reportKeptQueue(o sysvipc.Object, why string) {
	if o.Kind != sysvipc.Msg || o.UID != s.uid || o.CUID != s.uid || o.Used || s.now().Sub(o.Ctime) < s.grace {
		return
	}
	if t, seen := s.reported[o.Ref]; seen && t.Equal(o.Ctime) {
		return
	}
	if s.reported == nil {
		s.reported = map[sysvipc.Ref]time.Time{}
	}
	s.reported[o.Ref] = o.Ctime
	s.log.Warn("sysv sweep: kept an unused System V message queue the service account owns; remove it with ipcrm -q once nothing waits on it",
		"id", o.ID, "key", o.Key, "reason", why, "age", s.now().Sub(o.Ctime).Round(time.Second).String())
}

// podSessions returns the session ids of every pod's running containers. Each
// container is started as a session leader, so its process group id is its
// session id.
func (r *Runtime) podSessions() map[int]bool {
	r.mu.Lock()
	pods := make([]*pod, 0, len(r.pods))
	for _, p := range r.pods {
		pods = append(pods, p)
	}
	r.mu.Unlock()
	out := map[int]bool{}
	for _, p := range pods {
		for _, g := range p.containerPgids() {
			out[g] = true
		}
	}
	return out
}

// newSysVSweeper returns the sweeper for this daemon, or nil when the daemon's
// identity rules sweeping out (rule 1 above).
func (r *Runtime) newSysVSweeper() *sysvSweeper {
	uid := os.Geteuid()
	u, err := user.LookupId(strconv.Itoa(uid))
	if uid < 0 || err != nil || !sysvSweepEligibleUser(uint32(uid), u.Username) {
		return nil
	}
	return &sysvSweeper{
		uid:      uint32(uid),
		grace:    sysvSweepGrace,
		now:      time.Now,
		list:     sysvipc.List,
		stat:     sysvipc.Stat,
		remove:   sysvipc.Remove,
		sessions: r.podSessions,
		sidOf:    unix.Getsid,
		log:      r.log,
	}
}

// RunSysVSweep removes, every interval, the System V IPC objects pods created
// and can never use (see sysvSweeper). It returns when ctx ends, and at once
// when this daemon may not sweep. interval <= 0 selects
// DefaultSysVSweepInterval.
func (r *Runtime) RunSysVSweep(ctx context.Context, interval time.Duration) {
	s := r.newSysVSweeper()
	if s == nil {
		r.log.Info("sysv sweep: off (the daemon is not the " + sysvSweepUser + " service account)")
		return
	}
	if interval <= 0 {
		interval = DefaultSysVSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.sweepOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
