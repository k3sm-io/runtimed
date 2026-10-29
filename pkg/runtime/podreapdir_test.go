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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"
)

const reapDirPod = "6f1c2a3b-0000-4000-8000-000000000001"

func reapDirExists(t *testing.T, rt *Runtime, podID string) bool {
	t.Helper()
	dir, err := rt.podReapDir(podID)
	if err != nil {
		t.Fatalf("podReapDir: %v", err)
	}
	_, err = os.Lstat(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lstat %s: %v", dir, err)
	}
	return err == nil
}

// TestPodReapDirRemovedWithLastRecord pins that a pod's reap-record directory
// goes with its last record, on every path that removes records, so empty
// podreap/<id> dirs no longer accumulate. It also pins that an empty dir left
// by an older build no longer reads as a durable process record.
func TestPodReapDirRemovedWithLastRecord(t *testing.T) {
	t.Run("per-pgid removal keeps the dir until the last record", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{ProcStartTime: func(int) (int64, bool) { return 9, true }})
		for _, pgid := range []int{100, 200} {
			if _, err := rt.recordPodProc(reapDirPod, "c", pgid, "", ""); err != nil {
				t.Fatalf("recordPodProc: %v", err)
			}
		}
		rt.removePodProcRecord(reapDirPod, 100)
		if !reapDirExists(t, rt, reapDirPod) {
			t.Fatal("dir removed while a record (200) remains")
		}
		rt.removePodProcRecord(reapDirPod, 200)
		if reapDirExists(t, rt, reapDirPod) {
			t.Fatal("dir left behind after its last record was removed")
		}
	})

	t.Run("a stray tmp file does not keep the dir", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{ProcStartTime: func(int) (int64, bool) { return 9, true }})
		if _, err := rt.recordPodProc(reapDirPod, "c", 100, "", ""); err != nil {
			t.Fatal(err)
		}
		dir, _ := rt.podReapDir(reapDirPod)
		if err := os.WriteFile(filepath.Join(dir, "300.json.tmp"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		rt.removePodProcRecord(reapDirPod, 100)
		if reapDirExists(t, rt, reapDirPod) {
			t.Fatal("an interrupted write's tmp file kept an otherwise empty dir")
		}
	})

	t.Run("retire with survivors keeps the dir, then the last removal drops it", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{ProcStartTime: func(int) (int64, bool) { return 9, true }})
		for _, pgid := range []int{100, 200} {
			if _, err := rt.recordPodProc(reapDirPod, "c", pgid, "", ""); err != nil {
				t.Fatal(err)
			}
		}
		rt.retirePodReapRecords(reapDirPod, map[int]keptSurvivors{
			200: {container: "c", survivors: []ReapSurvivor{{Pid: 4321, StartUnixNano: 1}}},
		})
		if !reapDirExists(t, rt, reapDirPod) {
			t.Fatal("dir removed while a survivor record is kept")
		}
		rt.removePodProcRecord(reapDirPod, 200)
		if reapDirExists(t, rt, reapDirPod) {
			t.Fatal("dir left behind after the kept record was removed")
		}
	})

	t.Run("startup reap drops dead records and pre-existing empty dirs", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{
			ProcStartTime: func(int) (int64, bool) { return 5, true },
			ProcGroup:     fakeGroups{members: map[int][]supervisor.ProcMember{}}.inspect,
			SignalGroup:   func(int, os.Signal) error { return nil },
		})
		seedPodProcRecord(t, rt, podProcRecord{PodID: reapDirPod, Container: "c", Pgid: 400, StartUnixNano: 8})
		const emptyPod = "6f1c2a3b-0000-4000-8000-000000000002"
		emptyDir, _ := rt.podReapDir(emptyPod)
		if err := os.MkdirAll(emptyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		const badPod = "6f1c2a3b-0000-4000-8000-000000000003"
		badDir, _ := rt.podReapDir(badPod)
		if err := os.MkdirAll(badDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(badDir, "9.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := rt.ReapOrphanedPods(); err != nil {
			t.Fatalf("ReapOrphanedPods: %v", err)
		}
		for _, id := range []string{reapDirPod, emptyPod, badPod} {
			if reapDirExists(t, rt, id) {
				t.Errorf("reap dir for %s survived the startup reap with no record in it", id)
			}
		}
	})

	t.Run("an empty dir is not a durable record to podUntracked", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		rt.mu.Lock()
		rt.podReapStarted = true
		rt.mu.Unlock()
		id, err := image.ParsePodID(reapDirPod)
		if err != nil {
			t.Fatal(err)
		}
		dir, _ := rt.podReapDir(reapDirPod)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if !rt.podUntracked(id) {
			t.Fatal("an empty reap dir kept the pod tracked")
		}
		if err := os.WriteFile(filepath.Join(dir, "100.json"), []byte(`{"pgid":100}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if rt.podUntracked(id) {
			t.Fatal("a pod with a reap record file read as untracked")
		}
	})

	t.Run("concurrent writes and removals never lose a committed record", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{ProcStartTime: func(int) (int64, bool) { return 9, true }})
		var wg sync.WaitGroup
		errs := make(chan error, 200)
		for i := range 100 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if _, err := rt.recordPodProc(reapDirPod, "c", 1000+i, "", ""); err != nil {
					errs <- err
				}
			}()
			go func() {
				defer wg.Done()
				rt.removePodProcRecord(reapDirPod, 5000+i)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("recordPodProc raced a dir removal: %v", err)
		}
		records, _, err := rt.listPodProcRecords()
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 100 {
			t.Fatalf("records = %d, want 100", len(records))
		}
	})
}
