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
)

// ErrPodGroupStillAlive is returned (wrapped) by CreatePod for a pod id whose
// recorded process group may still be alive and is not owned by a pod this
// runtime has registered.
//
// Such a group comes from an earlier run or from this one. The startup reap
// leaves an earlier run's group running in several cases: its leader is gone
// but a descendant lives (keep-and-warn), the pre-signal re-probe no longer
// matched, the kill failed, or the reap store could not be read. Within one
// run, DeletePod unregisters the pod before it retires the pod's records, so
// a create racing a delete of the same id sees a group that is still exiting;
// and DeletePod keeps the record of a container whose tree left survivors, so
// a create of that id is refused while a survivor lives. A
// create for the same id clears the pod's rootfs, which those processes may
// still use, so the create is refused instead. Nothing is torn down and
// nothing is signalled; the create succeeds once the group is gone (or its
// record is removed, see docs/runbook-leaked-process-groups.md). The check is
// re-run on every create.
//
// FAIL CLOSED per pod id: a record directory for this id that exists but
// cannot be read, a record file in it that cannot be read, a recorded group
// that cannot be inspected, or a live leader under a record with no leader
// identity refuses too. A group with no record is invisible to this check by
// construction. The error names the record directory.
var ErrPodGroupStillAlive = errors.New("runtime: a recorded process group of the pod is still alive")

// liveRecordedGroup is one recorded group the create guard found alive.
type liveRecordedGroup struct {
	pgid      int
	container string
	// survivors are the recorded survivors still alive under their exact
	// recorded start.
	survivors []int
	// why names the evidence the group is alive.
	why string
}

// refuseBesideLiveNativeGroup returns ErrPodGroupStillAlive (wrapped) when a
// reap record for podID names a group no registered pod owns that is, or may
// be, still alive, and nil otherwise. The group may be an earlier run's, or
// this run's: still exiting under a delete in flight, or survivors kept after
// a delete. Refusing is the intended answer in every case (the rootfs may be
// in use) and the caller retries. It never signals anything.
//
// An id that is not a legal pod id is returned as that error, without
// ErrPodGroupStillAlive: retrying it cannot succeed.
//
// It must run before createPod: a createPod failure removes the pod dir, which
// would delete the rootfs the live group uses.
func (r *Runtime) refuseBesideLiveNativeGroup(podID string) error {
	dir, err := r.podReapDir(podID)
	if err != nil {
		return fmt.Errorf("create pod %s: reap record dir: %w", podID, err)
	}
	records, err := r.readPodReapRecordsIn(dir)
	if err != nil {
		r.log.Warn("not creating a pod whose process-group records cannot be read: a recorded group may still be alive",
			"pod", podID, "recordDir", dir, "err", err)
		return fmt.Errorf("create pod %s: records in %s: %w: %w", podID, dir, err, ErrPodGroupStillAlive)
	}
	if len(records) == 0 {
		return nil
	}
	owned := r.ownedPgids()
	for _, rec := range records {
		if owned[rec.Pgid] {
			continue
		}
		g, alive := r.recordedGroupAlive(rec)
		if !alive {
			continue
		}
		r.log.Warn("not creating a pod while a recorded process group of it is still alive (not signalled)",
			"pod", podID, "container", g.container, "pgid", g.pgid, "survivors", g.survivors, "why", g.why, "recordDir", dir)
		return fmt.Errorf("create pod %s: process group %d (%s), record in %s: %w", podID, g.pgid, g.why, dir, ErrPodGroupStillAlive)
	}
	return nil
}

// readPodReapRecordsIn returns the well-formed reap records in dir, one pod's
// reap record directory (podReapDir). A missing directory is no record. A directory, or a record file in it, that
// exists but cannot be read is an error: the caller treats it as a doubt. A
// file that does not parse, or names a pgid <= 1, identifies no group and is
// skipped (the startup reap quarantines it).
func (r *Runtime) readPodReapRecordsIn(dir string) ([]podProcRecord, error) {
	r.reapStoreMu.Lock()
	defer r.reapStoreMu.Unlock()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read reap record dir: %w", err)
	}
	var records []podProcRecord
	for _, e := range entries {
		if e.IsDir() || !isPodReapRecordName(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read reap record %s: %w", e.Name(), err)
		}
		var rec podProcRecord
		if err := json.Unmarshal(data, &rec); err != nil || rec.Pgid <= 1 {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

// ownedPgids is the set of process groups the runtime's registered pods own,
// the same set the startup reap skips.
func (r *Runtime) ownedPgids() map[int]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	owned := make(map[int]bool)
	for _, p := range r.pods {
		for _, pgid := range p.containerPgids() {
			owned[pgid] = true
		}
	}
	return owned
}

// recordedGroupAlive reports whether rec's group, or a survivor it names, is
// or may be alive. Unlike provenGroupMembers it does not need the leader: a
// non-empty group whose leader is gone is exactly the leaked shape this guard
// exists for, so it counts as alive. Only a live leader with a start other
// than a recorded, non-zero one, and no recorded container or survivor
// matching, is read as a recycled pgid that is not this pod's. A record with
// no leader start (recordPodProc writes 0 when the leader's start could not
// be read) cannot tell a recycled pgid from its own leader, so a live leader
// under it counts as alive.
func (r *Runtime) recordedGroupAlive(rec podProcRecord) (liveRecordedGroup, bool) {
	g := liveRecordedGroup{pgid: rec.Pgid, container: rec.Container}
	for _, s := range rec.Survivors {
		if s.Pid <= 1 || s.StartUnixNano == 0 {
			continue
		}
		if start, ok := r.procStart(s.Pid); ok && start == s.StartUnixNano {
			g.survivors = append(g.survivors, s.Pid)
		}
	}
	members, ok := r.procGroup(rec.Pgid)
	switch {
	case !ok:
		g.why = "group cannot be inspected"
		return g, true
	case len(members) == 0:
		if len(g.survivors) > 0 {
			g.why = "recorded survivors alive"
			return g, true
		}
		return g, false
	}
	leader, found := leaderMember(members, rec.Pgid)
	switch {
	case !found:
		g.why = "leader gone, group not empty"
		return g, true
	case rec.StartUnixNano == 0:
		g.why = "leader alive, no recorded leader identity"
		return g, true
	case leader.StartUnixNano == rec.StartUnixNano:
		g.why = "recorded leader alive"
		return g, true
	case childIsRecordedInstance(rec, members):
		g.why = "recorded container alive"
		return g, true
	case len(g.survivors) > 0:
		g.why = "recorded survivors alive"
		return g, true
	}
	// A live leader with another start: the kernel recycled the pgid.
	return g, false
}
