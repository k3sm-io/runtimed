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
// recorded process group, from an earlier run, may still be alive and is not
// owned by this runtime.
//
// The startup reap leaves such a group running in several cases: its leader
// is gone but a descendant lives (keep-and-warn), the pre-signal re-probe no
// longer matched, the kill failed, or the reap store could not be read. A
// create for the same id clears the pod's rootfs, which those processes may
// still use, so the create is refused instead. Nothing is torn down and
// nothing is signalled; the create succeeds once the group is gone (or its
// record is removed, see docs/runbook-leaked-process-groups.md). The check is
// re-run on every create.
//
// FAIL CLOSED per pod id: a record directory for this id that exists but
// cannot be read, a record file in it that cannot be read, or a recorded group
// that cannot be inspected refuses too. A group with no record is invisible to
// this check by construction.
var ErrPodGroupStillAlive = errors.New("runtime: a process group an earlier run started for the pod is still alive")

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
// reap record for podID names a group this runtime does not own that is, or
// may be, still alive, and nil otherwise. It never signals anything.
//
// It must run before createPod: a createPod failure removes the pod dir, which
// would delete the rootfs the live group uses.
func (r *Runtime) refuseBesideLiveNativeGroup(podID string) error {
	records, err := r.readPodReapRecordsFor(podID)
	if err != nil {
		r.log.Warn("not creating a pod whose process-group records cannot be read: a group an earlier run started may still be alive",
			"pod", podID, "err", err)
		return fmt.Errorf("create pod %s: %w: %w", podID, err, ErrPodGroupStillAlive)
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
		r.log.Warn("not creating a pod while a process group an earlier run started for it is still alive (not signalled)",
			"pod", podID, "container", g.container, "pgid", g.pgid, "survivors", g.survivors, "why", g.why)
		return fmt.Errorf("create pod %s: process group %d (%s): %w", podID, g.pgid, g.why, ErrPodGroupStillAlive)
	}
	return nil
}

// readPodReapRecordsFor returns the well-formed reap records of podID. A
// missing directory is no record. A directory, or a record file in it, that
// exists but cannot be read is an error: the caller treats it as a doubt. A
// file that does not parse, or names a pgid <= 1, identifies no group and is
// skipped (the startup reap quarantines it).
func (r *Runtime) readPodReapRecordsFor(podID string) ([]podProcRecord, error) {
	dir, err := r.podReapDir(podID)
	if err != nil {
		return nil, fmt.Errorf("reap record dir: %w", err)
	}
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
// than the recorded one, and no recorded container matching, is read as a
// recycled pgid that is not this pod's.
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
	case rec.StartUnixNano != 0 && leader.StartUnixNano == rec.StartUnixNano:
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
