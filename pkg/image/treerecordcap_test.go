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

package image

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestTreeRecordWriterRefusesWhatItsReaderRefuses pins one size cap for a tree
// record at its writer (writeTreeRecord) and both readers (readTreeRecord,
// Unpacker.openCommitted). treeRecordLimit is lowered to the size of a real
// record rather than building a 5 MiB one, so the boundary is exact: a record
// at the cap round-trips, one byte over is refused before anything is written,
// and an over-cap record planted on disk is refused by both readers. The
// symlink and FIFO rows prove openCommitted's open does not follow a final
// symlink and does not block on a FIFO, and the symlinked-directory row proves
// both readers, anchored at the store, refuse a tree directory that leads out
// of it.
func TestTreeRecordWriterRefusesWhatItsReaderRefuses(t *testing.T) {
	key := treeDigest("a")
	policy := NativeUnpackPolicy()
	rec := treeRecord{
		Version: treeRecordVersion,
		Key:     key,
		Policy:  policy,
		Config:  treeDigest("c"),
		Layers:  []string{treeDigest("1"), treeDigest("2")},
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(buf))

	tests := []struct {
		name string
		// limit is the treeRecordLimit the row runs under.
		limit int64
		// place puts the record at path: "write" through writeTreeRecord,
		// "plant" with os.WriteFile, "symlink" as a link to a valid record,
		// "fifo" as a named pipe, "symlinkdir" as a valid record (and rootfs)
		// in a directory outside the store, the tree directory a link to it.
		place string
		// wantWriteErr is the sentinel writeTreeRecord must return ("write" rows).
		wantWriteErr error
		// wantOK is whether both readers accept what is at path.
		wantOK bool
	}{
		{name: "at the cap is written and read", limit: size, place: "write", wantOK: true},
		{name: "one byte over is refused by the writer", limit: size - 1, place: "write", wantWriteErr: ErrTreeRecordTooLarge},
		{name: "planted over the cap is refused by both readers", limit: size - 1, place: "plant"},
		{name: "symlink at the record path is refused", limit: size, place: "symlink"},
		{name: "fifo at the record path is refused without blocking", limit: size, place: "fifo"},
		{name: "symlinked tree directory out of the store is refused", limit: size, place: "symlinkdir"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saved := treeRecordLimit
			treeRecordLimit = tc.limit
			t.Cleanup(func() { treeRecordLimit = saved })

			tmp := t.TempDir()
			store := filepath.Join(tmp, "store")
			dir := filepath.Join(store, "tree")
			if tc.place == "symlinkdir" {
				outside := filepath.Join(tmp, "outside")
				if err := os.MkdirAll(filepath.Join(outside, TreeRootfsName), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := writeTreeRecord(filepath.Join(outside, TreeRecordName), rec); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(store, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, dir); err != nil {
					t.Fatal(err)
				}
			} else if err := os.MkdirAll(filepath.Join(dir, TreeRootfsName), 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, TreeRecordName)

			switch tc.place {
			case "write":
				err := writeTreeRecord(path, rec)
				if tc.wantWriteErr != nil {
					if !errors.Is(err, tc.wantWriteErr) {
						t.Fatalf("writeTreeRecord = %v, want %v", err, tc.wantWriteErr)
					}
					if _, serr := os.Lstat(path); !errors.Is(serr, fs.ErrNotExist) {
						t.Fatalf("refused record left something on disk: Lstat = %v", serr)
					}
					return
				}
				if err != nil {
					t.Fatalf("writeTreeRecord = %v, want nil", err)
				}
			case "plant":
				if err := os.WriteFile(path, buf, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(tmp, "elsewhere.json")
				if err := os.WriteFile(target, buf, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			root, err := os.OpenRoot(store)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			_, rerr := readTreeRecord(root, filepath.Join("tree", TreeRecordName), key)
			if (rerr == nil) != tc.wantOK {
				t.Errorf("readTreeRecord = %v, want ok=%v", rerr, tc.wantOK)
			}

			type result struct {
				ok  bool
				err error
			}
			done := make(chan result, 1)
			go func() {
				u := &Unpacker{}
				_, ok, err := u.openCommitted(treeLocation{dir: dir, storeRoot: store, key: key, recordName: TreeRecordName}, policy)
				done <- result{ok, err}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				// Unblock the stuck open so the goroutine does not outlive the
				// test: a writer opening the FIFO releases the reader to EOF.
				if w, werr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); werr == nil {
					w.Close()
				}
				t.Fatal("openCommitted blocked on the record path")
			}
			if tc.wantOK {
				if got.err != nil || !got.ok {
					t.Fatalf("openCommitted = (%v, %v), want a hit", got.ok, got.err)
				}
				return
			}
			if !errors.Is(got.err, ErrTreeInconsistent) {
				t.Fatalf("openCommitted = (%v, %v), want ErrTreeInconsistent", got.ok, got.err)
			}
		})
	}
}
