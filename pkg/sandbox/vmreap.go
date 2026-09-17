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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"k3sm.io/runtimed/pkg/supervisor"
)

// the VM ORPHAN sweep, and why IT IS not pkg/runtime's POD REAP.
//
// A k3sm-vmhost helper is spawned POSIX_SPAWN_SETSID, so a daemon killed without
// teardown (`kill -9`, a panic) leaves it reparented to launchd, still holding a
// live virtual machine for a pod the cluster has forgotten. That is the same
// shape as the orphaned host-process pod groups pkg/runtime's podreap handles,
// and it is TEMPTING to reuse that decision function. Doing so would be a bug.
//
// the POLICIES are OPPOSITES. podreap exists inside a promise that native pod
// processes survive a daemon restart by design — `launchctl kickstart -k` must
// not kill the node's workloads — so it reaps only records whose pods are gone.
// A vm pod's helper carries the opposite contract, stated in cmd/k3sm-vmhost's
// own doc: "no VM outlives the binary that booted it". An orphaned helper cannot
// be adopted — the daemon has no handle on its Process, no log pump, no reaper,
// and no way to re-establish the readiness handshake — so the only correct action
// is to kill it. always KILL, never ADOPT.
//
// Sharing a decision function between two opposite policies would mean one
// function with a mode flag, and the day someone "simplifies" the flag away, one
// of the two policies silently becomes the other: either every vm pod's guest
// survives a daemon restart unowned, or every host pod on the node is killed by a
// restart. Two stores, two decisions, no shared mode.
//
// what IS deliberately shared IS the IDENTITY DISCIPLINE. A record authorizes a
// root SIGKILL of a process group, so it is matched exactly as podreap matches:
// pgid > 1, the live GROUP is probed, the kill fires only when the LEADER member
// (Pid == pgid, true only while the original SETSID leader lives) reports a start
// time exactly equal to the recorded one. XNU's p_starttime is an immutable fork
// timestamp, so a recycled pgid always reports a different start and is dropped
// unsignaled. Do not loosen that to a tolerance window.
//
// TRUST BOUNDARY: like podreap's, the records drive a root-privileged kill, so
// they live under <work-dir>/vmreap — a daemon-private sibling of the pods root,
// which no pod's generated profile re-allows.

// VMReapSubdir is the daemon-private vm-helper orphan-record store dir name, a
// sibling of PodReapSubdir under the runtime work-dir. It is an exported const
// for the same reason PodReapSubdir is: the SBPL generator's protected-prefix
// deny-set must name the same directory the store actually uses, and a drift
// would deny a non-existent sibling while the real store stayed writable. Both
// stores are named by ReapStoreSubdirs, which resolvePosture iterates, so the
// deny cannot exist for one and not the other.
//
// Be concrete about the harm a writable store does, because it is not the kill
// alone: a record the sweep resolves to `drop` also RemoveAlls the RunDir the
// record CARRIES, as root, and that path is stored verbatim. So a forged record
// would be a root recursive delete inside the daemon's own socket tree, on top
// of the root SIGKILL at a process group of the forger's choosing.
//
// Denying the write is the boundary. The delete is hardened SEPARATELY, and
// does not rely on it: containment to <stateRoot>/run is only defence in depth,
// so the directory must additionally carry a daemon-written owner marker naming
// the record's own pod id before anything is removed (see clearOrphanRunDir and
// vmOwnerMarkerName). A forged record can NAME a run dir; it cannot make that
// dir prove it is ours.
const VMReapSubdir = "vmreap"

// vmProcRecord is the durable record of one spawned vm host helper, written
// under <work-dir>/vmreap/<pgid>.json before the boot is acknowledged and removed
// once the helper's exit is observed.
//
// It is keyed by pgid, not by pod id, and the pod id is carried as a field for
// logging only. A pod-id-derived filename would be a third place in the daemon
// that turns wire input into a path, and this one drives a root SIGKILL and a
// recursive delete; a flat, integer-named store has no traversal question to get
// wrong. The paths it carries were validated by the caller that created them and
// are stored verbatim, so the sweep re-derives nothing.
type vmProcRecord struct {
	PodID string `json:"podId"`
	// Pgid is the helper's process-group id (== its pid under SETSID).
	Pgid int `json:"pgid"`
	// StartUnixNano is the leader's kernel start time: the exact-instance
	// identity guard. A zero value can never match a live leader, so such a
	// record can never authorize a kill.
	StartUnixNano int64 `json:"startUnixNano"`
	// AgentSocket and RunDir are the helper's runtimed-private socket and its
	// directory, recorded so the sweep can clear them without re-deriving a
	// layout that belongs to another package.
	AgentSocket string `json:"agentSocket"`
	RunDir      string `json:"runDir"`

	// path is the file this record was READ from, filled by the enumerator and
	// never serialized. The sweep retires a record by that path rather than by
	// re-deriving <pgid>.json: the enumerator accepts any *.json in the store,
	// so a file whose name did not match the derivation would be read forever
	// and never removed — an unbounded re-warn loop from a single stray file.
	// Deleting exactly what was read cannot drift.
	path string
}

// StateRoot returns the runtime work-dir this backend records its orphan store
// under (WithStateRoot), or "" when the store is disabled.
//
// It exists for one caller: the cross-package wiring pin in pkg/runtime, which
// asserts that the root the daemon hands this backend is the SAME path it hands
// the SBPL generator as Posture.WorkDir. Those two are wired in different
// statements of runtime.New, and if they ever diverged the emitted deny would
// protect a vmreap store at a directory the backend does not use — the exact
// drift the exported subdir consts exist to prevent, one level up. Reading the
// field is the only way to observe it from another package.
func (b *VMBackend) StateRoot() string { return b.stateRoot }

// vmReapRoot is the orphan store's directory. An empty StateRoot disables the
// store entirely (returning ""), which is the posture for a backend constructed
// without one: a test double that spawns nothing has nothing to reap.
func (b *VMBackend) vmReapRoot() string {
	if b.stateRoot == "" {
		return ""
	}
	return filepath.Join(b.stateRoot, VMReapSubdir)
}

// recordVMProc durably records a just-spawned helper.
//
// A write failure fails the boot. An unrecorded helper is invisible to the
// startup sweep, which is the whole orphan class this file closes — so a pod that
// cannot be recorded is a pod whose guest could outlive the daemon unnoticed, and
// refusing it is the fail-closed answer. (A backend with no state root records
// nothing and says so once at construction; see WithStateRoot.)
func (b *VMBackend) recordVMProc(vp *vmProc) error {
	root := b.vmReapRoot()
	if root == "" {
		return nil
	}
	if vp.pgid <= 1 {
		return fmt.Errorf("refusing to record vm helper for pod %s with pgid %d (must be > 1)", vp.podID, vp.pgid)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create the vm reap store %s: %w", root, err)
	}
	data, err := json.Marshal(vmProcRecord{
		PodID:         vp.podID,
		Pgid:          vp.pgid,
		StartUnixNano: vp.startUnixNano,
		AgentSocket:   vp.agentSocket,
		RunDir:        vp.runDir,
	})
	if err != nil {
		return fmt.Errorf("marshal the vm reap record for pod %s: %w", vp.podID, err)
	}
	final := filepath.Join(root, strconv.Itoa(vp.pgid)+".json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write the vm reap record for pod %s: %w", vp.podID, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit the vm reap record for pod %s: %w", vp.podID, err)
	}
	return nil
}

// removeVMProcRecord drops a LIVE helper's record once its exit has been
// observed, by the same name recordVMProc wrote. Best-effort: a leftover record
// is harmless, because the sweep's identity check drops an unmatchable one
// unsignaled.
func (b *VMBackend) removeVMProcRecord(pgid int) {
	root := b.vmReapRoot()
	if root == "" {
		return
	}
	_ = os.Remove(filepath.Join(root, strconv.Itoa(pgid)+".json"))
}

// retireVMProcRecord drops a record the sweep read, by the path it came from.
// See vmProcRecord.path for why the two removals differ.
func (b *VMBackend) retireVMProcRecord(rec vmProcRecord) {
	if rec.path != "" {
		_ = os.Remove(rec.path)
		return
	}
	b.removeVMProcRecord(rec.Pgid)
}

// listVMProcRecords loads every durable helper record.
//
// It degrades rather than fails: an absent store is the normal first-run case, a
// per-file read error retains the record for a later start to retry, and only a
// structurally invalid file (bad JSON, pgid <= 1) is quarantined for removal.
// Same posture as podreap's enumerator, for the same reason — an unreadable
// best-effort store must never crash-loop the node.
func (b *VMBackend) listVMProcRecords() (records []vmProcRecord, quarantine []string, err error) {
	root := b.vmReapRoot()
	if root == "" {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read the vm reap store %s: %w", root, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(root, e.Name())
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			b.logger().Warn("read a vm reap record (retained for the next start)", "path", path, "err", rerr)
			continue
		}
		var rec vmProcRecord
		if json.Unmarshal(data, &rec) != nil || rec.Pgid <= 1 {
			quarantine = append(quarantine, path)
			continue
		}
		rec.path = path
		records = append(records, rec)
	}
	return records, quarantine, nil
}

// vmReapDecision computes, from the durable records and a live process-GROUP
// inspector, which orphaned helpers to kill, which records to drop unsignaled,
// and which to keep and warn about. It is pure, so the whole policy is provable
// against a fake process table:
//
//   - pgid <= 1 is dropped defensively — a record must never be able to authorize
//     kill(-1) (the POSIX broadcast) or kill(-0) (the caller's own group);
//   - a zero-identity record (the helper died between spawn and probe) can never
//     be proven ours, so it is dropped, never signalled;
//   - a group that cannot be INSPECTED is kept for the next start to retry —
//     never blindly signalled, never dropped;
//   - an empty group is dropped: there is nothing left to kill;
//   - a group whose LEADER member (Pid == pgid) reports the recorded start time
//     exactly is an orphaned helper of ours: KILLED. Unconditionally — a live
//     VM cannot be re-handshaked, so there is no adopt branch and must never be
//     one (see the file header);
//   - a leader whose start DIFFERS is a recycled pgid: dropped, never signalled;
//   - a non-empty group with NO leader member (the helper exited, a descendant
//     keeps the group alive) is keep-and-warn — we cannot prove the group is
//     still ours, so killing risks a wrong-target root SIGKILL. This mirrors
//     podreap's documented ceiling and, like it, must not be "recovered" into a
//     heuristic kill.
//
// kill, drop and keepWarn are disjoint; an inspection-failed record is in none.
func vmReapDecision(records []vmProcRecord, procGroup func(pgid int) ([]supervisor.ProcMember, bool)) (kill, drop, keepWarn []vmProcRecord) {
	for _, rec := range records {
		if rec.Pgid <= 1 || rec.StartUnixNano == 0 {
			drop = append(drop, rec)
			continue
		}
		members, ok := procGroup(rec.Pgid)
		if !ok {
			continue // keep: retry on the next start
		}
		if len(members) == 0 {
			drop = append(drop, rec)
			continue
		}
		leader, found := vmLeaderMember(members, rec.Pgid)
		if !found {
			keepWarn = append(keepWarn, rec)
			continue
		}
		if leader.StartUnixNano != rec.StartUnixNano {
			drop = append(drop, rec)
			continue
		}
		kill = append(kill, rec)
	}
	return kill, drop, keepWarn
}

// vmLeaderMember returns the group's LEADER member (Pid == pgid) and whether one
// exists. The leader pid equals the pgid only while the original SETSID leader
// lives, so a matching pid plus a matching immutable start time is proof the
// group is the exact recorded instance.
func vmLeaderMember(members []supervisor.ProcMember, pgid int) (supervisor.ProcMember, bool) {
	for _, m := range members {
		if m.Pid == pgid {
			return m, true
		}
	}
	return supervisor.ProcMember{}, false
}

// ReapOrphanVMs kills every vm host helper recorded by a previous daemon run and
// clears the run dirs they left behind. It is called once, before the runtime
// serves CreatePod.
//
// Kills are SIGKILL to the whole group with NO grace, and that is the honest
// choice rather than a harsh one: the graceful path runs inside the helper (ask
// the guest, wait its budget, halt), and an orphan's daemon-side supervisor is
// long gone — there is nothing left to conduct a graceful stop, and SIGTERM to a
// helper nobody is waiting on would just add its grace budget to the node's
// startup before the kill happened anyway.
//
// It degrades like podreap: an unreadable store alerts and skips rather than
// failing the daemon, because reaping is not a scheduling precondition and a
// crash-looping node is far worse than a leaked helper. It always returns nil.
//
// A record is retired only once its run dir has been cleared or proven absent.
// A dir the sweep cannot prove is ours is left in place WITH its record (see
// clearOrphanRunDir), which costs a repeated warning and keeps the leak visible;
// a killed helper whose dir is unproven is still killed, and only its record
// survives.
func (b *VMBackend) ReapOrphanVMs() error {
	records, quarantine, err := b.listVMProcRecords()
	if err != nil {
		b.logger().Error("vm orphan sweep skipped: the reap store is unreadable, so a previous run's guests may still be running",
			"root", b.vmReapRoot(), "err", err)
		return nil
	}
	kill, drop, keepWarn := vmReapDecision(records, b.procGroup)

	for _, rec := range kill {
		// Pre-signal re-probe, shrinking the decision->kill TOCTOU window to one
		// syscall: between the decision and the signal the leader could exit and
		// the pgid be recycled, and an ESRCH seen after the signal cannot tell
		// "already gone" from "recycled to an unrelated group".
		if !b.groupIsRecordedVMInstance(rec) {
			b.logger().Warn("vm orphan sweep: skipping kill, the group no longer matches the recorded instance",
				"pod", rec.PodID, "pgid", rec.Pgid)
			continue
		}
		b.logger().Info("killing an orphaned vm host helper left by a previous daemon run",
			"pod", rec.PodID, "pgid", rec.Pgid)
		if serr := b.signal(rec.Pgid, vmKillSignal); serr != nil {
			// Fail-OPEN: an un-killable orphan (EPERM under a changed posture)
			// must not brick the daemon. Keep the record and retry next start.
			b.logger().Warn("could not kill an orphaned vm host helper",
				"pod", rec.PodID, "pgid", rec.Pgid, "err", serr)
			continue
		}
		// Clear FIRST and retire only on the clear's verdict: the record is the
		// only pointer to the run dir, so one retired beside a dir the sweep
		// refused to delete would leak that dir with nothing left to name it.
		if b.clearOrphanRunDir(rec) {
			b.retireVMProcRecord(rec)
		}
	}
	for _, rec := range keepWarn {
		b.logger().Warn("orphaned vm host helper leaked: its leader is gone but the group is alive via a descendant (kept, not killed; re-warns each start)",
			"pod", rec.PodID, "pgid", rec.Pgid)
	}
	for _, rec := range drop {
		if b.clearOrphanRunDir(rec) {
			b.retireVMProcRecord(rec)
		}
	}
	for _, f := range quarantine {
		b.logger().Warn("removing a malformed vm reap record", "path", f)
		_ = os.Remove(f)
	}
	return nil
}

// groupIsRecordedVMInstance re-probes rec's group immediately before the signal
// and reports whether its leader still matches the record exactly.
func (b *VMBackend) groupIsRecordedVMInstance(rec vmProcRecord) bool {
	members, ok := b.procGroup(rec.Pgid)
	if !ok || len(members) == 0 {
		return false
	}
	leader, found := vmLeaderMember(members, rec.Pgid)
	return found && leader.StartUnixNano == rec.StartUnixNano
}

// vmOwnerMarkerName is the provenance marker this daemon writes inside a vm
// pod's private run dir at spawn, holding exactly the pod id the record for that
// helper will carry.
//
// It exists because a record is DATA, and the classes that reach the delete —
// pgid <= 1, a zero start time, an empty process group — are the cheapest
// possible things for a forged record to satisfy. Containment says a path is in
// the right tree; only the marker says this daemon put it there.
const vmOwnerMarkerName = ".k3sm-vm-owner"

// writeVMOwnerMarker creates runDir and stamps it as podID's.
//
// It runs at spawn, BEFORE the record is written, so the implication the sweep
// depends on — a record exists ⇒ its run dir was stamped — holds at every
// instant, including a daemon killed between the two writes (which leaves a
// stamped dir and no record: a leak, never an unprovable delete).
//
// Pre-creating the directory does not get in the helper's way: the helper is
// posix_spawned with no id-resetting attribute and no credential drop, so it
// runs at exactly this daemon's euid/egid, and its own MkdirAll of the same path
// is a no-op on a directory that already exists.
//
// runDir must be absolute — it is derived from an AgentSocketPath validateVMSpec
// already proved absolute and clean, and a relative one would stamp a directory
// resolved against whatever the daemon's cwd happens to be.
func writeVMOwnerMarker(runDir, podID string) error {
	if podID == "" {
		return fmt.Errorf("refusing to stamp the vm run dir %q for an empty pod id", runDir)
	}
	if !filepath.IsAbs(runDir) {
		return fmt.Errorf("refusing to stamp the vm run dir %q for pod %s: not an absolute path", runDir, podID)
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return fmt.Errorf("create the vm run dir %s for pod %s: %w", runDir, podID, err)
	}
	marker := filepath.Join(runDir, vmOwnerMarkerName)
	if err := os.WriteFile(marker, []byte(podID), 0o600); err != nil {
		return fmt.Errorf("stamp the vm run dir %s for pod %s: %w", runDir, podID, err)
	}
	return nil
}

// vmRunDirIsOwnedBy reports whether runDir carries a marker naming podID.
//
// A missing, unreadable or mismatched marker is not an error to report upward —
// it IS the negative verdict, and the caller's whole response to it is to leave
// the directory alone. An empty podID can prove nothing and is refused outright,
// so a record with no pod id never gains a delete by matching an empty marker.
func vmRunDirIsOwnedBy(runDir, podID string) bool {
	if podID == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(runDir, vmOwnerMarkerName))
	if err != nil {
		return false
	}
	// Exactly one trailing newline is tolerated, because re-stamping a dir by
	// hand is an `echo` away and an operator should not lose a cluster's run
	// tree to a byte they cannot see. Nothing else is trimmed: padding, a second
	// line, or a different pod id does not match.
	return string(bytes.TrimSuffix(data, []byte("\n"))) == podID
}

// clearOrphanRunDir removes a retired record's private run dir and reports
// whether the record may now be retired.
//
// TWO gates, and the second is the one that matters. Containment bounds the
// delete to <state-root>/run — defence in depth, and it only ever proves the
// path is in the right tree. The directory must ALSO carry vmOwnerMarkerName
// naming this record's own pod id. Without that, "in-tree" would be the entire
// proof standing between a forged record and a root recursive delete at a path
// of the forger's choosing inside the daemon's socket tree.
//
// The verdict is RETURNED rather than assumed because the record is the only
// pointer to that directory. Retiring a record whose dir we refused to delete
// would leak the dir SILENTLY — nothing would name it again. Keeping it makes
// the next sweep re-warn, the keepWarn idiom vmReapDecision already uses for a
// group it cannot prove is ours.
//
// What the marker PROVES: this daemon created this directory for this pod id. It
// says nothing about the record that names it — whether a record could be forged
// at all is the store's write boundary (see VMReapSubdir), not this function's
// question.
//
// MIGRATION COST, plainly: run dirs created before this change carry no marker.
// An orphan record pointing at one is kept, its directory is left in place, and
// the warning repeats on every daemon start until an operator confirms the
// helper is dead and removes the directory by hand. That is bounded — only
// orphans predating this change can be in that state, because every run dir
// created from here on is stamped before its record exists.
func (b *VMBackend) clearOrphanRunDir(rec vmProcRecord) (retire bool) {
	if rec.RunDir == "" || b.stateRoot == "" {
		return true // nothing to clear, so nothing holds the record back
	}
	runRoot := filepath.Join(b.stateRoot, "run")
	clean := filepath.Clean(rec.RunDir)
	if clean != runRoot && !isAtOrUnderDir(clean, runRoot) {
		b.logger().Warn("vm reap record names a run dir outside this node's run tree: left in place, record kept (re-warns each start)",
			"pod", rec.PodID, "dir", rec.RunDir, "run_root", runRoot)
		return false
	}
	if _, err := os.Stat(clean); errors.Is(err, fs.ErrNotExist) {
		return true // already gone: nothing to prove, nothing to delete
	}
	if !vmRunDirIsOwnedBy(clean, rec.PodID) {
		b.logger().Warn("orphaned vm pod run dir has unproven provenance, left in place, record kept (re-warns each start)",
			"pod", rec.PodID, "dir", clean, "marker", vmOwnerMarkerName)
		return false
	}
	if err := os.RemoveAll(clean); err != nil {
		// Proven ours and still undeletable: keep the record so the next start
		// retries rather than losing the only pointer to a dir we mean to clear.
		b.logger().Warn("could not remove an orphaned vm pod's run dir (record kept for the next start)",
			"pod", rec.PodID, "dir", clean, "err", err)
		return false
	}
	return true
}
