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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// Pod processes are POSIX_SPAWN_SETSID session leaders: when the daemon dies
// without teardown (`launchctl kickstart -k`, a crash) they reparent to launchd
// and keep running — holding ports and surviving uninstall. The startup pod
// reap (a sibling of the network startup reconcile) closes that hole: every
// spawned container's process group is recorded durably, and before the daemon
// serves CreatePod it reaps recorded-but-unowned groups. Kills are SIGKILL to
// the whole group with NO graceful-stop grace period — the orphans' supervising
// reapers died with the previous daemon, so there is no in-daemon stop path left
// to run (this is the same hard-kill semantics `launchctl kickstart -k` gives a
// running daemon's own pods).
//
// TRUST BOUNDARY: the records drive a root-privileged kill, so they must live
// where a confined pod cannot write them. They are stored under
// <root>/podreap/ (sandbox.PodReapSubdir), a daemon-private sibling of
// <root>/pods/ — not under a pod's own dir, which the pod's Seatbelt profile
// re-allows file-write* on. A store inside the pod tree would let a pod forge a
// record and drive the reap's kill(-pgid) at a process group of its choosing
// (DESIGN §8 default-deny). The SBPL generator emits a matching (deny ...) for
// the podreap root (sandbox.Generate) so an ancestor extra_write_path cannot
// re-open write access to it.
//
// The reap never identifies pods by name or path heuristics — only recorded
// pgids are considered, each guarded by an exact-INSTANCE identity check before
// any signal:
//   - pgid must be > 1 (a record can never authorize kill(-1), the POSIX
//     broadcast, nor kill(-0), the caller's own group);
//   - the live process GROUP is probed (kern.proc.pgrp) for its members; the
//     kill decision matches the LEADER member (Pid == pgid, which holds only
//     while the original SETSID leader lives) and kills iff that leader's start
//     time exactly equals the recorded leader start;
//   - a pgid the kernel recycled to a new leader (Pid == pgid but a different
//     immutable start) is dropped unsignaled.
//
// ceiling — keep-and-warn (leader dead, group alive via a grandchild): when the
// leader (Pid == pgid) is gone but a grandchild keeps the group alive, the reap
// can no longer PROVE the group is still ours (there is no leader start to match
// against the record), so it neither kills (a recycled pgid could host an
// unrelated leader's children — killing would be a wrong-target root SIGKILL)
// nor drops the record. It KEEPS the record and emits an alerting Warn every
// Serve. This is a deliberate, observable, bounded-safety trade: a permanent
// runbooked leak beats an unbounded wrong-kill. A future maintainer must not
// "recover" this into a heuristic kill.
//
// ceiling — setsid escape: a pod that double-fork+setsid's a child leaves the
// recorded process group entirely; kern.proc.pgrp and kill(-pgid) never see it,
// so the reap cannot catch it. This is an accepted limit of pgid-based
// tracking (the vm RuntimeClass is the isolation answer for untrusted tenancy).

// podProcRecord is the durable record of one spawned container process group,
// written at spawn under <root>/podreap/<podID>/<pgid>.json and removed when
// the group is observed empty. Records that survive a daemon death are the
// startup reap's input.
type podProcRecord struct {
	PodID     string `json:"podId"`
	Container string `json:"container"`
	// Pgid is the container's process-group id (== the session-leading child's
	// pid under POSIX_SPAWN_SETSID).
	Pgid int `json:"pgid"`
	// StartUnixNano is the leader's kernel-reported start time. It is the
	// record's exact-INSTANCE identity guard: the reap kills only when the live
	// group's leader member (Pid == Pgid) reports a start time equal to this. A
	// pgid recycled to a new leader has a strictly different immutable start, so
	// it never matches and is dropped unsignaled.
	StartUnixNano int64 `json:"startUnixNano"`
}

// containerID derives the container's published identity — ContainerStatus.
// container_id — from this record.
//
// It is a DERIVATION of the reap record's exact-instance identity, never a
// second identity scheme. (Pgid, StartUnixNano) is already the pair this daemon
// trusts to authorize a root SIGKILL of a process group, so an id computed from
// anything else could disagree with it, and a disagreement between "the id I
// published" and "the group I am willing to signal" is invisible until it aims a
// signal at a recycled pgid. Deriving both from one record makes that
// disagreement unreachable: a pgid the kernel recycled has a strictly different
// leader start, so it yields a different id.
//
// The derivation is one-way (sha256, hex) on purpose. A pod's status is readable
// by anyone holding pods/get, so publishing the host pgid verbatim would be host
// process-table disclosure from a root daemon. The hash is stable for the life of
// the incarnation, unique per (pod, container, incarnation), and reveals nothing
// about the host. It is an OPAQUE identifier — nothing may parse it back.
//
// The fields are NUL-separated so no pair of distinct inputs can concatenate to
// the same string (a container legitimately named "a\x00b" is impossible: names
// are validated k8s identifiers).
//
// A record whose StartUnixNano is 0 (the child died between spawn and record)
// still yields an id: the value is a display identity, and a container that never
// reached a stable incarnation is about to report terminated anyway.
func (rec podProcRecord) containerID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		rec.PodID,
		rec.Container,
		strconv.Itoa(rec.Pgid),
		strconv.FormatInt(rec.StartUnixNano, 10),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// procStartTime reports a live process's kernel start time in unix nanoseconds
// (the leader identity recorded at spawn). ok is false when the process does
// not exist or its start time cannot be read.
type procStartTime func(pid int) (startUnixNano int64, ok bool)

// procGroupInspector reports the live members (pid + start time) of process
// group pgid. ok is false only when the group cannot be inspected (a real
// syscall failure — the reap keeps the record and retries next start); an
// existing but empty group returns an empty slice with ok true (the group is
// dead — the reap drops the record).
type procGroupInspector func(pgid int) (members []supervisor.ProcMember, ok bool)

func (r *Runtime) podReapRoot() string {
	// The store-dir name is single-sourced from sandbox.PodReapSubdir so the
	// SBPL deny that protects the store (sandbox.Generate) can never drift away
	// from the actual on-disk store — a drift would deny a non-existent sibling
	// while the real store stayed writable (a forged-record → root-kill hole).
	return filepath.Join(r.cache.Root(), sandbox.PodReapSubdir)
}

// podReapDir returns a pod's reap-record dir. It returns an error for an id that
// is not a legal path component: this is the second derivation of pod_id into a
// path in the daemon, and its RemoveAll had no containment guard at all, so an
// unvalidated id here was the shortest route from a hostile CreatePod to an
// arbitrary recursive delete running as root.
func (r *Runtime) podReapDir(podID string) (string, error) {
	id, err := image.ParsePodID(podID)
	if err != nil {
		return "", err
	}
	return filepath.Join(r.podReapRoot(), id.String()), nil
}

// recordPodProc durably records a just-spawned container's process group before
// the spawn is acknowledged to the caller (CreatePod's return). Write failure
// fails the container start: an unrecorded pod process would be invisible to
// the startup reap, which is exactly the orphan class this file closes.
//
// It returns the record it wrote so the caller can derive the container's
// published identity (podProcRecord.containerID) from the very same
// (pgid, leader start) pair the reap will later match on. Returning it — rather
// than letting the caller re-probe the process table — is what makes a
// disagreement between the two structurally impossible.
func (r *Runtime) recordPodProc(podID, container string, pgid int) (podProcRecord, error) {
	if pgid <= 1 {
		return podProcRecord{}, fmt.Errorf("refusing to record pod %s process group with pgid %d (must be > 1)", podID, pgid)
	}
	start, ok := r.procStart(pgid)
	if !ok {
		// The child died between spawn and record; the exit path will surface
		// it. Record with zero identity so the reap drops the file unsignaled.
		start = 0
	}
	rec := podProcRecord{PodID: podID, Container: container, Pgid: pgid, StartUnixNano: start}
	dir, err := r.podReapDir(podID)
	if err != nil {
		return podProcRecord{}, fmt.Errorf("reap record dir for pod %s: %w", podID, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return podProcRecord{}, fmt.Errorf("create reap record dir for pod %s: %w", podID, err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return podProcRecord{}, fmt.Errorf("marshal reap record for pod %s: %w", podID, err)
	}
	final := filepath.Join(dir, strconv.Itoa(pgid)+".json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return podProcRecord{}, fmt.Errorf("write reap record for pod %s: %w", podID, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return podProcRecord{}, fmt.Errorf("commit reap record for pod %s: %w", podID, err)
	}
	return rec, nil
}

// removePodProcRecord drops a container's process-group record once its group
// is observed empty (best-effort: a leftover record is harmless — the reap's
// identity check drops it unsignaled).
func (r *Runtime) removePodProcRecord(podID string, pgid int) {
	dir, err := r.podReapDir(podID)
	if err != nil {
		return // an unvalidated id never produced a record
	}
	_ = os.Remove(filepath.Join(dir, strconv.Itoa(pgid)+".json"))
}

// removePodReapRecords drops every process-group record for a pod, on teardown
// (DeletePod) after its groups have been signalled. Best-effort.
func (r *Runtime) removePodReapRecords(podID string) {
	dir, err := r.podReapDir(podID)
	if err != nil {
		return // an unvalidated id never produced records
	}
	_ = os.RemoveAll(dir)
}

// listPodProcRecords loads every durable process-group record under
// <root>/podreap/. It degrades rather than fails the daemon on I/O faults over
// this best-effort orphan store (reaping is not a scheduling precondition):
//   - the reap ROOT missing is normal (no prior run) → returns empty, nil error;
//   - the reap ROOT present-but-unreadable returns an error, which the caller
//     (reapOrphanedPodsOnce) turns into an ALERT + skipped reap, not a Serve
//     failure — so an unreadable store never crash-loops the node;
//   - a per-pod SUBDIR that cannot be read is quarantine-skipped (warn +
//     continue), never a whole-enumeration failure;
//   - a record file that cannot be READ is retained (returned in neither slice)
//     so a transient I/O error never destroys a live pod's record;
//   - only a structurally-INVALID file (bad JSON / pgid <= 1) is returned to
//     quarantine for removal.
func (r *Runtime) listPodProcRecords() (records []podProcRecord, quarantine []string, err error) {
	root := r.podReapRoot()
	podDirs, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read reap root %s: %w", root, err)
	}
	for _, pd := range podDirs {
		if !pd.IsDir() {
			continue
		}
		dir := filepath.Join(root, pd.Name())
		entries, err := os.ReadDir(dir)
		if err != nil {
			// A single per-pod subdir being unreadable must not take down the
			// whole enumeration (and thus the daemon): skip it with an alert and
			// keep reaping the rest. The skipped subdir's records survive on disk
			// for a later start to retry once the fault clears.
			r.log.Warn("startup pod reap: skipping unreadable reap subdir", "dir", dir, "err", err)
			continue
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				// Transient read failure: retain (retry next start), do not
				// quarantine — deleting a live pod's record fails open.
				r.log.Warn("read reap record (retained)", "path", path, "err", err)
				continue
			}
			var rec podProcRecord
			if err := json.Unmarshal(data, &rec); err != nil || rec.Pgid <= 1 {
				quarantine = append(quarantine, path)
				continue
			}
			records = append(records, rec)
		}
	}
	return records, quarantine, nil
}

// startupPodReapDecision computes, from the durable records and a live process
// GROUP inspector, which recorded groups to kill, which records to drop without
// a signal, and which to keep-and-warn. It is a pure decision function (the unit
// gate, TestStartupPodReapDecision, drives it over a fake process table):
//
//   - a record whose pgid the runtime currently OWNS is kept (untouched) — on
//     the startup path owned is empty, but the guard keeps the decision correct
//     if pods exist before the first Serve (in-process library use);
//   - a zero-identity record (StartUnixNano == 0: the child died between spawn
//     and record) can never be matched to a live leader, so it can never
//     authorize a kill — it is dropped;
//   - a record whose group cannot be inspected (ok=false) is kept for the next
//     start to retry — never dropped, never blindly signalled;
//   - a record whose group is empty is dropped (nothing to signal);
//   - a record whose group's LEADER member (Pid == pgid) reports a start time
//     exactly equal to the recorded leader start is our orphaned pod group:
//     selected for kill (its record is removed only after the signal succeeds,
//     so a failed kill is retried by the next daemon start);
//   - a record whose group's leader member exists (Pid == pgid) but reports a
//     different start is a recycled pgid (a new leader took the number): dropped,
//     never signalled;
//   - a record whose non-empty group has NO leader member (Pid == pgid absent —
//     the leader exited, a grandchild keeps the group alive) is keep-and-warn:
//     kept and surfaced by the caller as an alerting Warn, never killed (see the
//     keep-and-warn ceiling in the file header);
//   - processes with no record are invisible here by construction — a bystander
//     can never be selected.
//
// why exact EQUALITY IS safe (and must not be loosened): the leader pid equals
// the pgid only while the original SETSID leader lives, and XNU's p_starttime is
// an immutable fork timestamp — an NTP step or clock adjustment never mutates a
// live process's recorded start. So a pgid the kernel later recycles to an
// unrelated leader always reports a strictly different start. A tolerance window
// ("start >= floor", or "within N ms") would re-open the recycled-pgid hole and
// let the reap SIGKILL an unrelated root process group. Do not soften this.
//
// kill, drop, and keepWarn are disjoint; an inspection-failed (retry) record
// appears in none.
func startupPodReapDecision(records []podProcRecord, owned map[int]bool, procGroup procGroupInspector) (kill, drop, keepWarn []podProcRecord) {
	for _, rec := range records {
		if rec.Pgid <= 1 {
			// Never possible from listPodProcRecords (it quarantines these),
			// but the kill path is root-privileged: refuse defensively.
			drop = append(drop, rec)
			continue
		}
		if owned[rec.Pgid] {
			continue
		}
		if rec.StartUnixNano == 0 {
			// No recorded identity: can never be proven ours, so never killable.
			drop = append(drop, rec)
			continue
		}
		members, ok := procGroup(rec.Pgid)
		if !ok {
			continue // keep: retry next start
		}
		if len(members) == 0 {
			drop = append(drop, rec)
			continue
		}
		leader, found := leaderMember(members, rec.Pgid)
		if !found {
			// Leader (Pid == pgid) gone, group alive via a grandchild: we cannot
			// prove the group is still ours. Keep-and-warn — never kill, never
			// drop (see the header ceiling).
			keepWarn = append(keepWarn, rec)
			continue
		}
		if leader.StartUnixNano != rec.StartUnixNano {
			// pgid recycled to a new leader (immutable start differs): not ours.
			drop = append(drop, rec)
			continue
		}
		kill = append(kill, rec)
	}
	return kill, drop, keepWarn
}

// leaderMember returns the group member that is the process-group LEADER
// (Pid == pgid) and whether such a member exists. The leader pid equals the pgid
// only while the original SETSID leader lives, so a matching Pid combined with a
// matching immutable start time is proof the group is still our exact recorded
// instance.
func leaderMember(members []supervisor.ProcMember, pgid int) (supervisor.ProcMember, bool) {
	for _, m := range members {
		if m.Pid == pgid {
			return m, true
		}
	}
	return supervisor.ProcMember{}, false
}

// groupIsRecordedInstance re-probes rec's group and reports whether its leader
// member still exactly matches the record (Pid == Pgid and start == recorded
// start). It runs immediately before signalGroup to shrink the probe→kill TOCTOU
// window to a single syscall: between the decision and the signal the leader
// could exit (and the pgid be recycled + repopulated), and an ESRCH observed
// after the signal cannot distinguish "already gone" from "recycled to an
// unrelated group", so this pre-check is the real narrowing.
func (r *Runtime) groupIsRecordedInstance(rec podProcRecord) bool {
	members, ok := r.procGroup(rec.Pgid)
	if !ok || len(members) == 0 {
		return false
	}
	leader, found := leaderMember(members, rec.Pgid)
	return found && leader.StartUnixNano == rec.StartUnixNano
}

// ReapOrphanedPods reaps pod process groups recorded by a previous daemon run,
// exactly once per Runtime, before CreatePod is served (a sibling of the network
// startup reconcile). Unlike that reconcile it degrades rather than fails
// closed: reaping a best-effort orphan store is not a scheduling precondition,
// so an unreadable store alerts + skips the reap and lets Serve continue rather
// than propagating an error that would exit main and launchd-crash-loop the
// node. It always returns nil (the once/sticky wrapper is retained for the
// exactly-once semantics). Kills are SIGKILL to the whole group with no grace
// period: the orphans' supervising reapers died with the previous daemon, so
// there is no graceful-stop path left to run.
//
// It is exported because it has two call sites: the standalone daemon's
// Server.Serve (grpcserver.go), and the embedded k3sm node path, which drives
// this Runtime by direct RPC and never runs Serve — the same reason the network
// startup reconcile needs an explicit call on the embedded path. The sticky
// exactly-once semantics make the two call sites safe to combine: whichever runs
// first performs the reap, the other observes the cached result.
func (r *Runtime) ReapOrphanedPods() error {
	r.podReapOnce.Do(func() {
		r.podReapErr = r.reapOrphanedPodsOnce()
	})
	return r.podReapErr
}

func (r *Runtime) reapOrphanedPodsOnce() error {
	// the VM sweep RIDES the same exactly-once-before-SERVE HOOK, and is
	// deliberately a separate store with a separate decision (pkg/sandbox's
	// vmReapDecision). The two policies are opposites — a host pod's processes
	// survive a daemon restart by design, a vm pod's helper must not — so
	// folding them into one record path would leave one mode flag between "every
	// guest survives unowned" and "every host pod on the node is killed by a
	// restart". It runs FIRST because an orphaned helper holds a whole machine,
	// and it never fails the daemon (it degrades exactly as this reap does).
	if err := r.vmBackend.ReapOrphanVMs(); err != nil {
		r.log.Error("startup vm orphan sweep failed; a previous run's guests may still be running", "err", err)
	}

	records, quarantine, err := r.listPodProcRecords()
	if err != nil {
		// The reap store ROOT is present but unreadable (a persistent I/O or
		// permission fault on a best-effort orphan store). Reaping is degraded,
		// but taking down every CreatePod indefinitely — main exits, launchd
		// KeepAlive respawns, the same fault recurs — is a whole-node outage far
		// worse than a leaked orphan. ALERT and skip the reap; Serve continues.
		r.log.Error("startup pod reap skipped: reap store root unreadable, orphaned pods may leak (reaping is best-effort, not a scheduling precondition)",
			"root", r.podReapRoot(), "err", err)
		return nil
	}
	r.mu.Lock()
	owned := make(map[int]bool)
	for _, p := range r.pods {
		for _, pid := range p.containerPIDs() {
			owned[pid] = true
		}
	}
	r.mu.Unlock()

	kill, drop, keepWarn := startupPodReapDecision(records, owned, r.procGroup)
	for _, rec := range kill {
		// Pre-signal re-probe (shrink TOCTOU): re-verify the exact
		// (Pid == Pgid && start == recorded) identity immediately before the
		// signal, so the probe→kill window is one syscall rather than the whole
		// decision+log loop. If the group no longer matches (the leader exited,
		// or the pgid was recycled since the decision) skip the signal and KEEP
		// the record for the next start to re-evaluate — never SIGKILL a group we
		// can no longer prove is ours.
		if !r.groupIsRecordedInstance(rec) {
			r.log.Warn("startup pod reap: skipping kill, group no longer matches recorded instance",
				"pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
			continue
		}
		r.log.Info("reaping orphaned pod process group",
			"pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
		// supervisor.SignalGroup returns nil for an already-gone group (ESRCH),
		// so a non-nil error is a real failure (e.g. EPERM under a posture
		// change that left the orphan owned by another uid): log it and KEEP
		// the record so the next daemon start retries. This is deliberately
		// fail-OPEN — an un-killable orphan must not brick the daemon.
		if err := r.signalGroup(rec.Pgid, killSignal); err != nil {
			r.log.Warn("reap orphaned pod process group",
				"pod", rec.PodID, "pgid", rec.Pgid, "err", err)
			continue
		}
		r.removePodProcRecord(rec.PodID, rec.Pgid)
	}
	for _, rec := range keepWarn {
		// keep-and-warn: the leader (Pid == pgid) is gone but the group is still
		// alive via a grandchild. We cannot prove the group is still ours, so we
		// neither kill (a recycled pgid may host an unrelated leader's children)
		// nor drop (the leak is real). The record is kept and re-warns every
		// Serve — an intentional, alerting, bounded-safety trade (header ceiling).
		r.log.Warn("orphaned pod process group leaked: leader gone but group still alive via a descendant (kept, not killed; will re-warn each start)",
			"pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
	}
	for _, rec := range drop {
		r.removePodProcRecord(rec.PodID, rec.Pgid)
	}
	for _, f := range quarantine {
		r.log.Warn("removing malformed reap record", "path", f)
		_ = os.Remove(f)
	}
	return nil
}
