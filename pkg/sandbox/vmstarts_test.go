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
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// TestVMContainerStartsRoundTrip pins the container-start file an adopting
// daemon seeds its statuses from: what the owning daemon records is what the
// next one reads for the same helper instance; nothing is read for a pod with
// no live helper, for a helper whose file is absent (the compatibility window),
// or for a file bound to another helper instance (a recycled pgid); the file is
// never read as a record; and it goes when the helper's record goes.
func TestVMContainerStartsRoundTrip(t *testing.T) {
	const pod, pgid, helperStart = "pod-a", 4242, int64(1792284512656831000)
	newBackend := func(t *testing.T) (*VMBackend, string) {
		t.Helper()
		root := t.TempDir()
		b := NewVMBackend(WithStateRoot(root))
		b.live = map[string]*vmProc{pod: {podID: pod, pgid: pgid, startUnixNano: helperStart}}
		if err := os.MkdirAll(filepath.Join(root, VMReapSubdir), 0o700); err != nil {
			t.Fatal(err)
		}
		return b, filepath.Join(root, VMReapSubdir)
	}
	app := VMContainerStart{Pid: 7, StartUnixNano: 1792284514000000000}
	side := VMContainerStart{Pid: 9, StartUnixNano: 1792284515000000000}

	t.Run("recorded starts are read back for the same helper", func(t *testing.T) {
		b, _ := newBackend(t)
		for name, s := range map[string]VMContainerStart{"app": {Pid: 3, StartUnixNano: 1}, "side": side} {
			if err := b.RecordVMContainerStart(pod, name, s); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.RecordVMContainerStart(pod, "app", app); err != nil { // a new run replaces the entry
			t.Fatal(err)
		}
		got := b.VMContainerStarts(pod)
		if len(got) != 2 || got["app"] != app || got["side"] != side {
			t.Fatalf("starts = %+v, want app=%+v side=%+v", got, app, side)
		}
		// A daemon restart: a fresh backend adopting the same helper instance.
		b2 := NewVMBackend(WithStateRoot(b.stateRoot))
		b2.live = map[string]*vmProc{pod: {podID: pod, pgid: pgid, startUnixNano: helperStart}}
		if got := b2.VMContainerStarts(pod); got["app"] != app || got["side"] != side {
			t.Fatalf("starts after a restart = %+v", got)
		}
	})
	t.Run("a helper with no file has no starts", func(t *testing.T) {
		b, _ := newBackend(t)
		if got := b.VMContainerStarts(pod); len(got) != 0 {
			t.Fatalf("starts = %+v, want none", got)
		}
	})
	t.Run("a pod with no live helper records and reads nothing", func(t *testing.T) {
		b, store := newBackend(t)
		if err := b.RecordVMContainerStart("pod-b", "app", app); err != nil {
			t.Fatal(err)
		}
		if got := b.VMContainerStarts("pod-b"); len(got) != 0 {
			t.Fatalf("starts = %+v, want none", got)
		}
		if entries, _ := os.ReadDir(store); len(entries) != 0 {
			t.Fatalf("store = %v, want empty", entries)
		}
	})
	t.Run("a file bound to another helper instance is not read", func(t *testing.T) {
		b, _ := newBackend(t)
		if err := b.RecordVMContainerStart(pod, "app", app); err != nil {
			t.Fatal(err)
		}
		b.live[pod] = &vmProc{podID: pod, pgid: pgid, startUnixNano: helperStart + 1}
		if got := b.VMContainerStarts(pod); len(got) != 0 {
			t.Fatalf("starts = %+v, want none for a recycled pgid", got)
		}
	})
	t.Run("a stale temp file is replaced and the write is durable", func(t *testing.T) {
		b, store := newBackend(t)
		tmp := filepath.Join(store, "4242.starts.tmp")
		if err := os.WriteFile(tmp, []byte("half a write"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := b.RecordVMContainerStart(pod, "app", app); err != nil {
			t.Fatalf("RecordVMContainerStart over a stale temp file: %v", err)
		}
		if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
			t.Fatalf("temp file after the write: %v, want gone", err)
		}
		if got := b.VMContainerStarts(pod); got["app"] != app {
			t.Fatalf("starts = %+v, want app=%+v", got, app)
		}
		fi, err := os.Lstat(filepath.Join(store, "4242.starts"))
		if err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
			t.Fatalf("start file = %v (%v), want a regular 0600 file", fi, err)
		}
	})
	t.Run("a symlinked temp file is refused and its target untouched", func(t *testing.T) {
		b, store := newBackend(t)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(store, "4242.starts.tmp")); err != nil {
			t.Fatal(err)
		}
		if err := b.RecordVMContainerStart(pod, "app", app); err == nil {
			t.Fatal("RecordVMContainerStart through a symlinked temp file succeeded, want a refusal")
		}
		if data, _ := os.ReadFile(target); string(data) != "keep" {
			t.Fatalf("symlink target = %q, want it untouched", data)
		}
		if _, err := os.Lstat(filepath.Join(store, "4242.starts")); !os.IsNotExist(err) {
			t.Fatalf("start file = %v, want none written", err)
		}
	})
	t.Run("the sweep removes stray temp files and starts without a record", func(t *testing.T) {
		b, store := newBackend(t)
		b.live = nil              // nothing adopted: the sweep owns the store
		files := map[string]bool{ // name -> kept
			"4242.starts.tmp": false,
			"4243.starts":     false, // its record is gone
			"4244.starts":     true,  // its record exists
		}
		for name := range files {
			if err := os.WriteFile(filepath.Join(store, name), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// A record the sweep keeps without inspecting a process: a group that
		// cannot be inspected is retried at the next start (vmReapDecision).
		if err := os.WriteFile(filepath.Join(store, "4244.json"), []byte(`{"podId":"x","pgid":4244,"startUnixNano":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		b.procGroup = func(int) ([]supervisor.ProcMember, bool) { return nil, false }
		if err := b.ReapOrphanVMs(); err != nil {
			t.Fatal(err)
		}
		for name, kept := range files {
			_, err := os.Lstat(filepath.Join(store, name))
			if kept != (err == nil) {
				t.Errorf("%s present=%v after the sweep, want %v", name, err == nil, kept)
			}
		}
	})
	t.Run("the file is not a record and goes with the record", func(t *testing.T) {
		b, store := newBackend(t)
		if err := b.RecordVMContainerStart(pod, "app", app); err != nil {
			t.Fatal(err)
		}
		recs, quarantine, err := b.listVMProcRecords()
		if err != nil || len(recs) != 0 || len(quarantine) != 0 {
			t.Fatalf("records = %v, quarantine = %v (%v): the start file must not read as a record", recs, quarantine, err)
		}
		b.removeVMProcRecord(pgid)
		if entries, _ := os.ReadDir(store); len(entries) != 0 {
			t.Fatalf("store = %v, want the start file removed with the record", entries)
		}
		if err := b.RecordVMContainerStart(pod, "app", app); err != nil {
			t.Fatal(err)
		}
		b.retireVMProcRecord(vmProcRecord{PodID: pod, Pgid: pgid, path: filepath.Join(store, "4242.json")})
		if entries, _ := os.ReadDir(store); len(entries) != 0 {
			t.Fatalf("store = %v, want the start file retired with the record", entries)
		}
	})
}
