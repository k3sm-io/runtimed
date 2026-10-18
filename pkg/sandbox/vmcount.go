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
	"fmt"

	"k3sm.io/runtimed/pkg/supervisor"
)

// VMHelperGroup is the exact-instance identity of one vm pod's k3sm-vmhost
// helper process group, as the orphan store recorded it at spawn. It is the
// read-only view of a store record a caller outside this package may hold: the
// pod it belongs to and the (Pgid, StartUnixNano) pair every use of the record
// matches before it acts.
type VMHelperGroup struct {
	// PodID is the pod the helper runs the guest of.
	PodID string
	// Pgid is the helper's process-group id (its pid, under SETSID).
	Pgid int
	// StartUnixNano is the helper leader's kernel start time; zero proves no
	// group.
	StartUnixNano int64
}

// VMHelperGroups returns the identity of every helper group the vm orphan store
// records, for a caller that counts what is still running (the runtime's
// per-pod process count). It reads the same files the orphan sweep and adoption
// read, by the same enumerator, and it never mutates the store: a structurally
// invalid record is skipped and left for the sweep to remove, and a record that
// cannot be read is skipped. A store that does not exist (or a backend with no
// state root) is an empty result; the error is the store root being unreadable.
func (b *VMBackend) VMHelperGroups() ([]VMHelperGroup, error) {
	records, _, err := b.listVMProcRecords()
	if err != nil {
		return nil, fmt.Errorf("list vm helper groups: %w", err)
	}
	groups := make([]VMHelperGroup, 0, len(records))
	for _, rec := range records {
		groups = append(groups, VMHelperGroup{PodID: rec.PodID, Pgid: rec.Pgid, StartUnixNano: rec.StartUnixNano})
	}
	return groups, nil
}

// VMHelperGroupMembers returns how many of members (the live members of
// g.Pgid's process group) belong to g's pod: all of them when the group is
// provably the recorded helper instance, else 0.
//
// The proof is the one the orphan sweep kills on and adoption claims on
// (vmGroupIsInstance): the group's leader is present and reports exactly the
// recorded start time. A recycled pgid, a zero-identity record, a pgid that
// could name the broadcast or the caller's own group, and a leaderless group
// (the helper exited, a descendant keeps the group alive) all prove nothing,
// so they contribute 0 rather than a stranger's processes.
func VMHelperGroupMembers(g VMHelperGroup, members []supervisor.ProcMember) uint64 {
	if g.Pgid <= 1 || g.StartUnixNano == 0 {
		return 0
	}
	if !vmGroupIsInstance(members, g.Pgid, g.StartUnixNano) {
		return 0
	}
	return uint64(len(members))
}
