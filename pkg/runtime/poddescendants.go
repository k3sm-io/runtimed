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
	"os"
	"syscall"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
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
// it. libsandbox answers, for a pid, whether its policy allows an operation on
// a path (sandbox.ProbePolicy), so the pod's profile itself names its
// processes. The profile (sandbox.Generate) denies the whole pods root and the
// reap stores to every pod, and allows each pod a stat of its OWN pod dir, the
// literal <pods>/<id> (the ancestor grant that lets a tool walk down to its
// rootfs). A process is pod <id>'s when its policy says all of:
//
//   - it is sandboxed (an unsandboxed process answers "allowed" to everything);
//   - a stat of <pods>/<id> is ALLOWED: no other pod's profile names that
//     literal;
//   - a stat of the reap store root is DENIED: every pod profile denies it,
//     and a profile that lets its process stat the whole filesystem (an App
//     Sandbox app, a permissive profile) does not;
//   - a write to the pods root is DENIED, likewise.
//
// The probe RESOLVES its path (measured: a symlink answers for its target), so
// every node named here is one a pod process cannot replace: all three sit
// under the profile's pods-root and reap-store denies. The pod's rootfs, which
// the pod can remove and replace with a link to another pod's, is deliberately
// not part of the identity. A path that does not exist answers "denied", so
// each node must exist; when one does not, the identity is unavailable and
// nothing is signalled.
//
// The uid is never part of the identity: every pod runs as the same account.

// podPolicyProbe asks a process's Seatbelt policy whether it allows op on path
// (sandbox.ProbePolicy).
type podPolicyProbe func(pid int, op sandbox.PolicyOp, path string) (sandboxed, allowed, ok bool)

// podIdentity is what a process's policy must say to be one of a pod's
// processes: allow a stat of anchor (the pod's own dir), deny a stat of
// statCanary (the reap store root) and deny a write to writeCanary (the pods
// root).
type podIdentity struct {
	anchor, statCanary, writeCanary string
}

// valid reports whether the three nodes are set and distinct.
func (id podIdentity) valid() bool {
	return id.anchor != "" && id.statCanary != "" && id.writeCanary != "" &&
		id.anchor != id.statCanary && id.anchor != id.writeCanary && id.statCanary != id.writeCanary
}

// holds reports whether pid's policy is this pod's. Every doubt (a failed
// query, an unsandboxed process, a policy that allows a canary) answers false.
func (id podIdentity) holds(probe podPolicyProbe, pid int) bool {
	if probe == nil || !id.valid() || pid <= 1 {
		return false
	}
	if sb, own, ok := probe(pid, sandbox.PolicyReadMetadata, id.anchor); !ok || !sb || !own {
		return false
	}
	if sb, any, ok := probe(pid, sandbox.PolicyReadMetadata, id.statCanary); !ok || !sb || any {
		return false
	}
	sb, write, ok := probe(pid, sandbox.PolicyWriteData, id.writeCanary)
	return ok && sb && !write
}

// podIdentityFor derives podID's identity, or ok=false when it cannot be probed:
// an id that is not a legal pod id, or a node that is not a real directory.
func (r *Runtime) podIdentityFor(podID string) (podIdentity, bool) {
	pid, err := image.ParsePodID(podID)
	if err != nil {
		return podIdentity{}, false
	}
	id := podIdentity{anchor: r.cache.PodDir(pid), statCanary: r.podReapRoot(), writeCanary: r.cache.PodsRoot()}
	for _, dir := range []string{id.anchor, id.statCanary, id.writeCanary} {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			return podIdentity{}, false
		}
	}
	return id, id.valid()
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
	// Once more after the policy queries, so the instance the policy vouched
	// for is the one signalled.
	if st, ok := r.procStart(m.pid); !ok || st != m.start {
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
		r.log.Warn("pod descendant sweep skipped: the pod dir or a reap store is gone, so its processes cannot be identified",
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
