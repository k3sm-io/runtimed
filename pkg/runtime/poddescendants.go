/*
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
*/

package runtime

import (
	"context"
	"os"
	"syscall"
	"time"

	"k3sm.io/runtimed/pkg/image"
)

// A native pod's processes are reaped by process group (DeletePod, the startup
// reap) and by process tree (supervisor.TrackTree, which follows parent links).
// Neither reaches a process that called setsid (POSIX_SPAWN_SETSID) and whose
// parent then exited: it has its own session and group, and launchd is its
// parent. Yureisha's agentd leader spawns its worker exactly that way, and such
// workers outlived every pod recreate (B1868).
//
// What such a process cannot leave is its Seatbelt policy. Every process a pod
// starts inherits the pod's policy, and neither setsid nor reparenting changes
// it. The pod profile denies the whole pods root and re-allows only this pod's
// own rootfs (sandbox.Generate), so a policy that allows a write to
// <pods>/<id>/rootfs is this pod's and no other pod's. libsandbox answers that
// question for a pid (sandbox.ProbeWritePolicy). Two measured facts shape the
// check:
//
//   - an unsandboxed process (and a profile that allows everything) answers
//     "allowed" for every path. So a member must ALSO be sandboxed and must be
//     DENIED a write to the pods root itself, which every pod profile denies
//     and no permissive profile does;
//   - a path that does not exist answers "denied". So the grant probe is the
//     rootfs directory, which exists for as long as the pod dir does; when it
//     is gone the identity is unavailable and nothing is signalled.
//
// The uid is never part of the identity: every pod runs as the same account.

// podPolicyProbe asks a process's Seatbelt policy whether it allows a write to
// path (sandbox.ProbeWritePolicy).
type podPolicyProbe func(pid int, path string) (sandboxed, allowed, ok bool)

// podIdentity is what a process's policy must say to be one of a pod's
// processes: allow a write to grant (the pod's rootfs) and deny one to canary
// (the pods root).
type podIdentity struct {
	grant, canary string
}

// holds reports whether pid's policy is this pod's. Every doubt (a failed
// query, an unsandboxed process, a policy that allows the canary) answers false.
func (id podIdentity) holds(probe podPolicyProbe, pid int) bool {
	if probe == nil || id.grant == "" || id.canary == "" || id.grant == id.canary || pid <= 1 {
		return false
	}
	sb, own, ok := probe(pid, id.grant)
	if !ok || !sb || !own {
		return false
	}
	sb, other, ok := probe(pid, id.canary)
	return ok && sb && !other
}

// podIdentityFor derives podID's identity, or ok=false when it cannot be probed:
// an id that is not a legal pod id, or a rootfs that is not a real directory.
func (r *Runtime) podIdentityFor(podID string) (podIdentity, bool) {
	id, err := image.ParsePodID(podID)
	if err != nil {
		return podIdentity{}, false
	}
	grant, canary := r.cache.PodRootfs(id), r.cache.PodsRoot()
	for _, dir := range []string{grant, canary} {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			return podIdentity{}, false
		}
	}
	return podIdentity{grant: grant, canary: canary}, true
}

// podMember is one live process whose policy is the pod's, named by its exact
// instance (pid plus kernel start time) so a reused pid is never a target.
type podMember struct {
	pid   int
	start int64
}

// podMembers lists the live processes whose policy is id's. bornBefore, when
// non-zero, keeps only processes that started before it (unix nanoseconds).
func (r *Runtime) podMembers(id podIdentity, bornBefore int64) ([]podMember, bool) {
	entries, ok := r.procTable()
	if !ok {
		return nil, false
	}
	self := os.Getpid()
	var out []podMember
	for _, e := range entries {
		if e.Pid <= 1 || e.Pid == self || e.Zombie {
			continue
		}
		if bornBefore != 0 && e.StartUnixNano >= bornBefore {
			continue
		}
		if id.holds(r.policyProbe, e.Pid) {
			out = append(out, podMember{pid: e.Pid, start: e.StartUnixNano})
		}
	}
	return out, true
}

// signalMember signals m only if it is still the same instance and its policy
// is still the pod's, both re-read immediately before the signal.
func (r *Runtime) signalMember(id podIdentity, m podMember, sig syscall.Signal) bool {
	if st, ok := r.procStart(m.pid); !ok || st != m.start {
		return false
	}
	if !id.holds(r.policyProbe, m.pid) {
		return false
	}
	return r.killProcess(m.pid, sig) == nil
}

// podSweep configures one descendant sweep.
type podSweep struct {
	// grace is the SIGTERM-to-SIGKILL window; zero sends SIGKILL at once.
	grace time.Duration
	// bornBefore, when non-zero, spares every process that started at or after
	// it (the startup sweep's daemon start, so a same-id pod this run created
	// is never touched).
	bornBefore int64
	// mayProceed is re-checked before every signal round; false aborts the
	// sweep (a new instance of the same pod id was registered meanwhile).
	mayProceed func() bool
}

// podSweepRounds bounds the SIGKILL passes: a member forked between one table
// read and the next signal is caught by the next pass.
const podSweepRounds = 8

// sweepPodDescendants terminates every live process whose Seatbelt policy is
// podID's: SIGTERM, up to s.grace for them to exit, then SIGKILL, re-reading the
// table each pass. It returns how many distinct processes it signalled. It is a
// no-op when the process table or the policy probe is not wired (tests with an
// injected spawner) or the pod's identity cannot be derived.
func (r *Runtime) sweepPodDescendants(ctx context.Context, podID string, s podSweep) int {
	if r.procTable == nil || r.policyProbe == nil {
		return 0
	}
	id, ok := r.podIdentityFor(podID)
	if !ok {
		r.log.Warn("pod descendant sweep skipped: the pod's rootfs is gone, so its processes cannot be identified",
			"pod", podID)
		return 0
	}
	proceed := func() bool { return s.mayProceed == nil || s.mayProceed() }
	signalled := make(map[podMember]struct{})

	if s.grace > 0 {
		members, ok := r.podMembers(id, s.bornBefore)
		if !ok || len(members) == 0 {
			return 0
		}
		if !proceed() {
			r.log.Warn("pod descendant sweep aborted: the pod id was registered again", "pod", podID)
			return 0
		}
		for _, m := range members {
			if r.signalMember(id, m, syscall.SIGTERM) {
				signalled[m] = struct{}{}
			}
		}
		r.awaitMembersGone(ctx, members, s.grace)
	}
	for range podSweepRounds {
		members, ok := r.podMembers(id, s.bornBefore)
		if !ok || len(members) == 0 {
			break
		}
		if !proceed() {
			r.log.Warn("pod descendant sweep aborted: the pod id was registered again", "pod", podID)
			break
		}
		for _, m := range members {
			if r.signalMember(id, m, syscall.SIGKILL) {
				signalled[m] = struct{}{}
				r.log.Info("killed a pod process outside its process group (setsid descendant)",
					"pod", podID, "pid", m.pid)
			}
		}
		r.awaitMembersGone(ctx, members, survivorPoll)
	}
	if left, ok := r.podMembers(id, s.bornBefore); ok && len(left) > 0 {
		r.log.Warn("pod processes outside its process group survived the sweep", "pod", podID, "count", len(left))
	}
	return len(signalled)
}

// awaitMembersGone waits until every member has exited (its pid is gone or
// names another instance), the wait elapses, or ctx ends.
func (r *Runtime) awaitMembersGone(ctx context.Context, members []podMember, wait time.Duration) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(survivorPoll)
	defer tick.Stop()
	for {
		alive := false
		for _, m := range members {
			if st, ok := r.procStart(m.pid); ok && st == m.start {
				alive = true
				break
			}
		}
		if !alive {
			return
		}
		select {
		case <-deadline.C:
			return
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// startupSweepPodIDs is the set of pod ids the startup reap sweeps for
// descendants: every pod a reap record names that this run did not re-attach.
func startupSweepPodIDs(records []podProcRecord, adopted map[string]bool) []string {
	seen := make(map[string]bool)
	var out []string
	for _, rec := range records {
		if rec.PodID == "" || adopted[rec.PodID] || seen[rec.PodID] {
			continue
		}
		seen[rec.PodID] = true
		out = append(out, rec.PodID)
	}
	return out
}
