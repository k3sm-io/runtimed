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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestVMHelperGroupsReadsTheStoreWithoutMutating pins the read side the
// runtime's per-pod process count rides on: every well-formed record's identity
// comes back, a malformed one is skipped and left in place for the sweep, and a
// backend with no store reports nothing.
func TestVMHelperGroupsReadsTheStoreWithoutMutating(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, VMReapSubdir)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"400.json": `{"schema":1,"podId":"pod-a","pgid":400,"startUnixNano":11}`,
		"500.json": `{"podId":"pod-b","pgid":500,"startUnixNano":22}`,
		"1.json":   `{"podId":"pod-q","pgid":1,"startUnixNano":5}`,
		"bad.json": `{`,
		"note.txt": `not a record`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(store, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := NewVMBackend(WithStateRoot(root)).VMHelperGroups()
	if err != nil {
		t.Fatalf("VMHelperGroups: %v", err)
	}
	slices.SortFunc(got, func(a, b VMHelperGroup) int { return a.Pgid - b.Pgid })
	want := []VMHelperGroup{
		{PodID: "pod-a", Pgid: 400, StartUnixNano: 11},
		{PodID: "pod-b", Pgid: 500, StartUnixNano: 22},
	}
	if !slices.Equal(got, want) {
		t.Errorf("VMHelperGroups = %+v, want %+v", got, want)
	}
	for name := range files {
		if _, err := os.Stat(filepath.Join(store, name)); err != nil {
			t.Errorf("the reader removed or lost %s: %v", name, err)
		}
	}

	none, err := NewVMBackend().VMHelperGroups()
	if err != nil || len(none) != 0 {
		t.Errorf("VMHelperGroups with no state root = (%v, %v), want (empty, nil)", none, err)
	}
}

// TestVMHelperGroupMembers pins the count's identity proof to the sweep's: a
// group counts all its members only while its leader reports the recorded
// start.
func TestVMHelperGroupMembers(t *testing.T) {
	m := func(pid int, start int64) supervisor.ProcMember {
		return supervisor.ProcMember{Pid: pid, StartUnixNano: start}
	}
	g := VMHelperGroup{PodID: "pod-a", Pgid: 400, StartUnixNano: 11}
	cases := []struct {
		name    string
		group   VMHelperGroup
		members []supervisor.ProcMember
		want    uint64
	}{
		{"the recorded leader is live: every member counts", g, []supervisor.ProcMember{m(400, 11), m(401, 12), m(402, 13)}, 3},
		{"an empty group counts 0", g, nil, 0},
		{"a recycled pgid counts 0", g, []supervisor.ProcMember{m(400, 99), m(401, 12)}, 0},
		{"a leaderless group counts 0", g, []supervisor.ProcMember{m(401, 12)}, 0},
		{"a zero-identity record counts 0", VMHelperGroup{PodID: "pod-a", Pgid: 400}, []supervisor.ProcMember{m(400, 0)}, 0},
		{"pgid 1 counts 0", VMHelperGroup{PodID: "pod-a", Pgid: 1, StartUnixNano: 11}, []supervisor.ProcMember{m(1, 11)}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := VMHelperGroupMembers(tc.group, tc.members); got != tc.want {
				t.Errorf("VMHelperGroupMembers = %d, want %d", got, tc.want)
			}
		})
	}
}
