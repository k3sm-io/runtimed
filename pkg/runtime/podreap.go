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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// Pod processes are POSIX_SPAWN_SETSID session leaders: when the daemon dies
// without teardown (`launchctl kickstart -k`, a crash) they reparent to launchd
// and keep running — holding ports and surviving uninstall. The startup pod
// reap (a sibling of the network startup reconcile) closes that hole: every
// spawned container's process group is recorded durably, and before the daemon
// serves CreatePod it reaps recorded-but-unowned groups.
//
// TRUST BOUNDARY: the records drive a root-privileged kill, so they must live
// where a confined pod CANNOT write them. They are stored under
// <root>/podreap/, a daemon-private sibling of <root>/pods/ — NOT under a pod's
// own dir, which the pod's Seatbelt profile re-allows file-write* on. A store
// inside the pod tree would let a pod forge a record and drive the reap's
// kill(-pgid) at a process group of its choosing (DESIGN §8 default-deny).
//
// The reap NEVER identifies pods by name or path heuristics — only recorded
// pgids are considered, each guarded by identity checks before any signal:
//   - pgid must be > 1 (a record can never authorize kill(-1), the POSIX
//     broadcast, nor kill(-0), the caller's own group);
//   - the live process GROUP is probed (kern.proc.pgrp), not just the leader,
//     so grandchildren that outlive a reaped-zombie leader are still caught;
//   - a member must report a start time >= the recorded leader start, so a
//     pgid the kernel recycled to an unrelated group is dropped unsignaled.

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
	// record's identity guard: a reap candidate group must have a member whose
	// start time is >= this (a descendant forked at/after the recorded spawn),
	// or the pgid has been recycled and the record is dropped unsignaled.
	StartUnixNano int64 `json:"startUnixNano"`
}

// procStartTime reports a live process's kernel start time in unix nanoseconds
// (the leader identity recorded at spawn). ok is false when the process does
// not exist or its start time cannot be read.
type procStartTime func(pid int) (startUnixNano int64, ok bool)

// procGroupInspector reports the start times of the live members of process
// group pgid. ok is false ONLY when the group cannot be inspected (a real
// syscall failure — the reap keeps the record and retries next start); an
// existing but empty group returns an empty slice with ok true (the group is
// dead — the reap drops the record).
type procGroupInspector func(pgid int) (memberStartsNano []int64, ok bool)

// podReapSubdir is the daemon-private root (a sibling of the pods root) holding
// one <podID>/<pgid>.json record per live container process group. It is never
// re-allowed by any pod's Seatbelt profile.
const podReapSubdir = "podreap"

func (r *Runtime) podReapRoot() string {
	return filepath.Join(r.cache.Root(), podReapSubdir)
}

func (r *Runtime) podReapDir(podID string) string {
	return filepath.Join(r.podReapRoot(), podID)
}

// recordPodProc durably records a just-spawned container's process group BEFORE
// the spawn is acknowledged to the caller (CreatePod's return). Write failure
// fails the container start: an unrecorded pod process would be invisible to
// the startup reap, which is exactly the orphan class this file closes.
func (r *Runtime) recordPodProc(podID, container string, pgid int) error {
	if pgid <= 1 {
		return fmt.Errorf("refusing to record pod %s process group with pgid %d (must be > 1)", podID, pgid)
	}
	start, ok := r.procStart(pgid)
	if !ok {
		// The child died between spawn and record; the exit path will surface
		// it. Record with zero identity so the reap drops the file unsignaled.
		start = 0
	}
	rec := podProcRecord{PodID: podID, Container: container, Pgid: pgid, StartUnixNano: start}
	dir := r.podReapDir(podID)
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
	_ = os.Remove(filepath.Join(r.podReapDir(podID), strconv.Itoa(pgid)+".json"))
}

// removePodReapRecords drops every process-group record for a pod, on teardown
// (DeletePod) after its groups have been signalled. Best-effort.
func (r *Runtime) removePodReapRecords(podID string) {
	_ = os.RemoveAll(r.podReapDir(podID))
}

// listPodProcRecords loads every durable process-group record under
// <root>/podreap/. It is fail-CLOSED on enumeration: a directory that cannot be
// read (other than not-existing) returns an error so the daemon refuses to
// serve over an unknown orphan population, rather than silently under-counting
// the way filepath.Glob would. A record file that cannot be READ is retained
// (returned in neither slice) so a transient I/O error never destroys a live
// pod's record; only a structurally-INVALID file (bad JSON / pgid <= 1) is
// returned to quarantine.
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
			return nil, nil, fmt.Errorf("read reap dir %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				// Transient read failure: retain (retry next start), do NOT
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
// GROUP inspector, which recorded groups to kill and which records to drop
// without a signal. It is a pure decision function (the unit gate,
// TestStartupPodReapDecision, drives it over a fake process table):
//
//   - a record whose pgid the runtime currently OWNS is kept (untouched) — on
//     the startup path owned is empty, but the guard keeps the decision correct
//     if pods exist before the first Serve (in-process library use);
//   - a record whose group cannot be inspected (ok=false) is KEPT for the next
//     start to retry — never dropped, never blindly signalled;
//   - a record whose group is EMPTY is dropped (nothing to signal);
//   - a record whose group is non-empty AND has a member started at/after the
//     recorded leader start is an orphaned pod group: selected for kill (its
//     record is removed only after the signal succeeds, so a failed kill is
//     retried by the next daemon start);
//   - a record whose non-empty group has NO member at/after the recorded start
//     is a recycled pgid: dropped, NEVER signalled;
//   - processes with no record are invisible here by construction — a bystander
//     can never be selected.
//
// kill and drop are disjoint; a KEPT record appears in neither.
func startupPodReapDecision(records []podProcRecord, owned map[int]bool, procGroup procGroupInspector) (kill, drop []podProcRecord) {
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
		members, ok := procGroup(rec.Pgid)
		if !ok {
			continue // keep: retry next start
		}
		if len(members) == 0 {
			drop = append(drop, rec)
			continue
		}
		if rec.StartUnixNano == 0 || !anyStartAtOrAfter(members, rec.StartUnixNano) {
			drop = append(drop, rec)
			continue
		}
		kill = append(kill, rec)
	}
	return kill, drop
}

// anyStartAtOrAfter reports whether any member started at or after floor — a
// descendant forked at/after the recorded spawn, which a recycled pgid's
// unrelated group cannot exhibit for our recorded floor.
func anyStartAtOrAfter(starts []int64, floor int64) bool {
	for _, s := range starts {
		if s >= floor {
			return true
		}
	}
	return false
}

// reapOrphanedPods reaps pod process groups recorded by a previous daemon run,
// exactly once per Runtime, BEFORE CreatePod is served (a sibling of the
// network startup reconcile, and like it fail-closed: if the records cannot be
// enumerated the daemon does not serve over an unknown orphan population).
// Kills are SIGKILL to the whole group: the orphans' supervising reapers died
// with the previous daemon, so there is no graceful-stop path left to run.
func (r *Runtime) reapOrphanedPods() error {
	r.podReapOnce.Do(func() {
		r.podReapErr = r.reapOrphanedPodsOnce()
	})
	return r.podReapErr
}

func (r *Runtime) reapOrphanedPodsOnce() error {
	records, quarantine, err := r.listPodProcRecords()
	if err != nil {
		return err
	}
	r.mu.Lock()
	owned := make(map[int]bool)
	for _, p := range r.pods {
		for _, pid := range p.containerPIDs() {
			owned[pid] = true
		}
	}
	r.mu.Unlock()

	kill, drop := startupPodReapDecision(records, owned, r.procGroup)
	for _, rec := range kill {
		r.log.Info("reaping orphaned pod process group",
			"pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
		// supervisor.SignalGroup returns nil for an already-gone group (ESRCH),
		// so a non-nil error is a real failure (e.g. EPERM under a posture
		// change that left the orphan owned by another uid): log it and KEEP
		// the record so the next daemon start retries. This is deliberately
		// fail-OPEN — an un-killable orphan must not brick the daemon — and is
		// why m2.sh keeps its gate-side reap block as belt-and-braces.
		if err := r.signalGroup(rec.Pgid, killSignal); err != nil {
			r.log.Warn("reap orphaned pod process group",
				"pod", rec.PodID, "pgid", rec.Pgid, "err", err)
			continue
		}
		r.removePodProcRecord(rec.PodID, rec.Pgid)
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
