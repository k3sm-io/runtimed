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
	"log/slog"
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

// PodReapRecord is the durable record of one spawned container process group,
// written at spawn under <root>/podreap/<podID>/<pgid>.json and removed when
// the group is observed empty. Records that survive a daemon death are the
// startup reap's input, AttachPod's, and — through ReadPodReapRecords — an
// uninstaller's, which must tear down every recorded group. It is exported so
// that last consumer reads this shape instead of copying its JSON.
type PodReapRecord struct {
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
	// RuntimeVersion is the build fingerprint of the daemon that spawned the
	// group (runtimeFingerprint: the spawning binary's code-directory hash).
	// AttachPod adopts a record only when it equals the running daemon's own:
	// a pod spawned by another binary runs under that binary's sandbox profile,
	// limits and launch sequence, and must not be supervised by a model that may
	// differ. A record without it (written before the field existed) is a
	// mismatch. It plays no part in the reap's kill decision.
	RuntimeVersion string `json:"runtimeVersion,omitempty"`
	// ProfileSHA256 is the hex sha256 of the SBPL profile the container was
	// spawned under (profileDigest). AttachPod recompiles the pod's profile from
	// its spec and this daemon's posture and adopts the pod only when every
	// adopted record carries exactly that digest, so a re-attached pod's
	// containers are re-spawned under the profile their siblings still run
	// under, never a drifted one. A record without it (written before the field
	// existed) never attaches. It plays no part in the reap's kill decision.
	ProfileSHA256 string `json:"profileSha256,omitempty"`
	// ShimDir is the container's resident-shim dir (<Root>/run/shim/<id>): its
	// socket and exit record. Empty for a container spawned without a shim. When
	// set, Pgid and StartUnixNano name the SHIM, the pod group's leader, and the
	// two fields below name the container it hosts.
	ShimDir string `json:"shimDir,omitempty"`
	// ChildPid and ChildStartUnixNano are the container's own identity under a
	// resident shim, recorded best-effort once the shim's Status has answered
	// (recordChild) — after the leader's record, which stays the synchronous,
	// pre-acknowledgement one. They are what a group whose shim died can still be
	// proven ours by (the leader is gone, the container is not). A daemon that
	// dies between the two writes leaves them empty, and such a group falls back
	// to the leader-only rules: a group kill rather than a graceful adopt.
	ChildPid           int   `json:"childPid,omitempty"`
	ChildStartUnixNano int64 `json:"childStartUnixNano,omitempty"`
}

// podProcRecord is the package's historical name for PodReapRecord.
type podProcRecord = PodReapRecord

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
// profileSHA is the digest of the profile the group was spawned under
// (profileDigest), recorded for AttachPod's identity check.
//
// It returns the record it wrote so the caller can derive the container's
// published identity (podProcRecord.containerID) from the very same
// (pgid, leader start) pair the reap will later match on. Returning it — rather
// than letting the caller re-probe the process table — is what makes a
// disagreement between the two structurally impossible.
func (r *Runtime) recordPodProc(podID, container string, pgid int, profileSHA, shimDir string) (podProcRecord, error) {
	if pgid <= 1 {
		return podProcRecord{}, fmt.Errorf("refusing to record pod %s process group with pgid %d (must be > 1)", podID, pgid)
	}
	start, ok := r.procStart(pgid)
	if !ok {
		// The child died between spawn and record; the exit path will surface
		// it. Record with zero identity so the reap drops the file unsignaled.
		start = 0
	}
	rec := podProcRecord{PodID: podID, Container: container, Pgid: pgid, StartUnixNano: start, RuntimeVersion: r.fingerprint, ProfileSHA256: profileSHA, ShimDir: shimDir}
	return rec, r.writePodProcRecord(rec)
}

// recordChild adds a resident shim's container identity to rec's file (the
// best-effort second write; see PodReapRecord.ChildPid) and returns the record.
// It goes through the same write as recordPodProc, so the file has one writer.
func (r *Runtime) recordChild(rec podProcRecord, child int, childStart int64) (podProcRecord, error) {
	rec.ChildPid, rec.ChildStartUnixNano = child, childStart
	return rec, r.writePodProcRecord(rec)
}

// writePodProcRecord writes rec to <podreap>/<podID>/<pgid>.json through a tmp
// file and a rename, so a reader sees the old record or the new one.
func (r *Runtime) writePodProcRecord(rec podProcRecord) error {
	podID, pgid := rec.PodID, rec.Pgid
	dir, err := r.podReapDir(podID)
	if err != nil {
		return fmt.Errorf("reap record dir for pod %s: %w", podID, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create reap record dir for pod %s: %w", podID, err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal reap record for pod %s: %w", podID, err)
	}
	final := filepath.Join(dir, strconv.Itoa(pgid)+".json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write reap record for pod %s: %w", podID, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit reap record for pod %s: %w", podID, err)
	}
	return nil
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
// <root>/podreap/ (see readPodReapStore for the degradation rules).
func (r *Runtime) listPodProcRecords() (records []podProcRecord, quarantine []string, err error) {
	return readPodReapStore(r.podReapRoot(), r.log)
}

// ReadPodReapRecords returns every well-formed pod process-group record under
// the runtime data root dataRoot (Config.Root; "" means image.DefaultRoot, as it
// does for the daemon) — the same files the startup reap reads. A missing store
// is an empty result with a nil error (no pod was ever spawned there). A file
// that cannot be read or does not parse is skipped, never deleted: this reader
// is for a caller that tears groups down (an uninstaller), and it must not
// mutate the store the daemon owns. Each record's (Pgid, StartUnixNano) is the
// exact-instance pair the reap matches before signalling; a caller that signals
// a group must re-check it against the live process table first.
func ReadPodReapRecords(dataRoot string) ([]PodReapRecord, error) {
	if dataRoot == "" {
		dataRoot = image.DefaultRoot
	}
	records, _, err := readPodReapStore(filepath.Join(dataRoot, sandbox.PodReapSubdir), slog.New(slog.DiscardHandler))
	return records, err
}

// readPodReapStore is the one reader of the podreap store, shared by the reap
// and ReadPodReapRecords. It degrades rather than fails on I/O faults over
// this best-effort orphan store (reaping is not a scheduling precondition):
//   - the store ROOT missing is normal (no prior run) → returns empty, nil error;
//   - the store ROOT present-but-unreadable returns an error, which the reap
//     (reapOrphanedPodsOnce) turns into an ALERT + skipped reap, not a Serve
//     failure — so an unreadable store never crash-loops the node;
//   - a per-pod SUBDIR that cannot be read is skipped with a warning, never a
//     whole-enumeration failure;
//   - a record file that cannot be READ is retained (returned in neither slice)
//     so a transient I/O error never destroys a live pod's record;
//   - only a structurally-INVALID file (bad JSON / pgid <= 1) is returned in
//     quarantine, for the reap to remove.
func readPodReapStore(root string, log *slog.Logger) (records []podProcRecord, quarantine []string, err error) {
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
			log.Warn("startup pod reap: skipping unreadable reap subdir", "dir", dir, "err", err)
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
				log.Warn("read reap record (retained)", "path", path, "err", err)
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
//   - a resident shim's record whose leader is gone but whose container member
//     is alive under EXACTLY the recorded ChildPid/ChildStartUnixNano is ours
//     by the container's identity: selected for kill (the shim crashed and
//     nothing re-attached the pod);
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
			// A resident shim's group whose shim died: the container's own
			// recorded identity, matched exactly, proves the group is still ours
			// without its leader.
			if childIsRecordedInstance(rec, members) {
				kill = append(kill, rec)
				continue
			}
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
	if !found {
		return childIsRecordedInstance(rec, members)
	}
	return leader.StartUnixNano == rec.StartUnixNano
}

// childIsRecordedInstance reports whether members include a resident shim's
// container under EXACTLY its recorded identity (ChildPid and
// ChildStartUnixNano, both recorded). It is the leader rule's exact-equality
// predicate applied to the container: the "do not soften" note on
// startupPodReapDecision holds for it unchanged.
func childIsRecordedInstance(rec podProcRecord, members []supervisor.ProcMember) bool {
	if rec.ShimDir == "" || rec.ChildPid <= 1 || rec.ChildStartUnixNano == 0 {
		return false
	}
	for _, m := range members {
		if m.Pid == rec.ChildPid {
			return m.StartUnixNano == rec.ChildStartUnixNano
		}
	}
	return false
}

// attachDecision splits the durable records into the ones AttachPod may adopt
// and the rest, which stay for ReapOrphanedPods. It is pure (the unit gate,
// TestAttachPopulatesOwnedBeforeTheStartupReap, drives it over a fake process
// table).
//
// A record is adoptable iff ALL of:
//   - startupPodReapDecision, run with nothing owned, puts it in the KILL bucket:
//     its leader (Pid == Pgid) is alive with EXACTLY the recorded StartUnixNano.
//     This is the reap's own predicate, reused rather than restated, so adoption
//     can never be looser than the kill it replaces — no window, no tolerance
//     (see the "do not soften" note on startupPodReapDecision). A keep-and-warn
//     group (leader gone), a recycled pgid, a dead group, a zero-identity record
//     and an uninspectable group are therefore never adopted;
//   - startTime(pgid), the per-pid probe recordPodProc used at spawn, reports
//     the same exact start: the two sysctl derivations are bit-identical, so a
//     disagreement means the leader changed between the probes;
//   - the record's RuntimeVersion equals fingerprint, and fingerprint is not
//     empty (a daemon that cannot name its own build adopts nothing).
//
// A resident shim's record whose shim died but whose container lives is not
// adoptable but DEGRADED: the reap's kill bucket admits it by the container's
// exact recorded identity (its leader is gone), the per-pid probe of ChildPid
// reports exactly ChildStartUnixNano, and the fingerprint matches. AttachPod
// watches such a container by that identity with no shim behind it.
//
// adopt, degraded and remaining partition records; nothing is dropped. The
// caller keys ownership by the record's Pgid, which is the adopted leader's pid —
// the same key space the reap's owned set is built in (containerPgids of the
// registered pods), so an attached group is excluded from the reap by
// construction.
func attachDecision(records []podProcRecord, procGroup procGroupInspector, startTime procStartTime, fingerprint string) (adopt, degraded, remaining []podProcRecord) {
	kill, _, _ := startupPodReapDecision(records, nil, procGroup)
	live := make(map[podProcRecord]bool, len(kill))
	for _, rec := range kill {
		live[rec] = true
	}
	for _, rec := range records {
		if fingerprint != "" && rec.RuntimeVersion == fingerprint && live[rec] {
			if start, ok := startTime(rec.Pgid); ok && start == rec.StartUnixNano {
				adopt = append(adopt, rec)
				continue
			}
			if leaderGone(rec, procGroup) {
				if start, ok := startTime(rec.ChildPid); ok && start == rec.ChildStartUnixNano && rec.ChildPid > 1 {
					degraded = append(degraded, rec)
					continue
				}
			}
		}
		remaining = append(remaining, rec)
	}
	return adopt, degraded, remaining
}

// leaderGone reports whether rec's group is inspectable and has no leader
// member: the shape in which only the container's identity can vouch for it.
func leaderGone(rec podProcRecord, procGroup procGroupInspector) bool {
	members, ok := procGroup(rec.Pgid)
	if !ok || len(members) == 0 {
		return false
	}
	_, found := leaderMember(members, rec.Pgid)
	return !found
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
//
// ORDERING INVARIANT (pod re-adoption): on the embedded path the provider calls
// AttachPod for every pod bound to this node BEFORE it calls this. A group a pod
// was attached to is owned — its pgid is in the owned set this reap skips — so it
// survives; every record nothing attached is reaped exactly as before. An
// AttachPod that arrives after this reap has begun is refused (podReapStarted),
// never raced against the kill.
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
	// From here on AttachPod refuses (see podReapStarted): the owned snapshot
	// below is the last moment an adopted pod can still be excluded.
	r.podReapStarted = true
	owned := make(map[int]bool)
	for _, p := range r.pods {
		for _, pgid := range p.containerPgids() {
			owned[pgid] = true
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
	r.sweepStaleSandboxProfiles()
	r.sweepStaleShimDirs()
	return nil
}

// sweepStaleShimDirs removes every resident-shim dir no registered pod owns. It
// runs where sweepStaleSandboxProfiles runs and for the same reason: after the
// reap, every shim a previous daemon started is either attached (its dir is in
// its pod's shimDirs) or killed or leaked, and a dir nothing owns is the
// leftover of a pod deleted while no daemon ran. Best-effort.
func (r *Runtime) sweepStaleShimDirs() {
	entries, err := os.ReadDir(r.shimRoot())
	if err != nil {
		return
	}
	owned := map[string]bool{}
	r.mu.Lock()
	pods := make([]*pod, 0, len(r.pods))
	for _, p := range r.pods {
		pods = append(pods, p)
	}
	r.mu.Unlock()
	for _, p := range pods {
		p.mu.Lock()
		for _, dir := range p.shimDirs {
			owned[dir] = true
		}
		p.mu.Unlock()
	}
	for _, e := range entries {
		dir := filepath.Join(r.shimRoot(), e.Name())
		if e.IsDir() && !owned[dir] {
			_ = os.RemoveAll(dir)
		}
	}
}

// ProfileSweeper is the optional seam a sandbox backend implements when it
// stages per-pod profiles on disk and can clear the ones a previous daemon
// incarnation left behind. *sandbox.ExecShimBackend satisfies it.
//
// It is deliberately NOT part of sandbox.Backend: staging is one backend's
// implementation detail (the vm rung stages nothing of the kind), and widening
// the spawn interface would force every test fake to grow a method that has
// nothing to do with what it fakes. The startup hook type-asserts and skips a
// backend that does not implement it.
type ProfileSweeper interface {
	// SweepStaleProfiles removes every staged profile left by a previous daemon
	// run and reports how many it removed. It logs nothing; the caller does.
	SweepStaleProfiles() (int, error)
}

// Ensure the staging backend satisfies the optional seam, so a signature change
// in pkg/sandbox is a compile error here rather than a silently skipped sweep.
var _ ProfileSweeper = (*sandbox.ExecShimBackend)(nil)

// sweepStaleSandboxProfiles clears the per-pod Seatbelt profiles a previous
// daemon incarnation staged and never removed. WrapCommand's cleanup closure
// removes a profile when the pod process exits, so a daemon killed without
// teardown (`launchctl kickstart -k`, `bootout`, a crash) leaks exactly one file
// per live pod, forever — nothing else on the node ever removes them.
//
// Everything present is stale BY CONSTRUCTION, which is why there is no mtime or
// age heuristic: this runs inside the exactly-once startup reap, AFTER the pod
// process reap above, so every process group a previous daemon spawned has been
// SIGKILLed or recorded as leaked (the keep-and-warn ceiling) — and a leaked
// shim cannot still need its profile, because the shim reads the file exactly
// once at the top of its main, before it applies the sandbox and execs. Nothing
// this daemon staged can be present either: the reap completes before CreatePod
// is served. Moving this call after that point would break the argument, not
// merely weaken it.
//
// It degrades rather than fails, exactly as the reap around it does: a sweep
// failure leaks disk, and taking the node down over it would be the larger
// outage.
func (r *Runtime) sweepStaleSandboxProfiles() {
	sweeper, ok := r.backend.(ProfileSweeper)
	if !ok {
		return
	}
	removed, err := sweeper.SweepStaleProfiles()
	if err != nil {
		r.log.Warn("startup sandbox-profile sweep incomplete; stale per-pod profiles may remain", "removed", removed, "err", err)
	}
	if removed > 0 {
		r.log.Info("swept stale per-pod sandbox profiles left by a previous daemon run", "removed", removed)
	}
}
