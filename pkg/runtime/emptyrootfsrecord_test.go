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
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"
)

// emptyRecord is the exact bytes EnsurePodReferences writes for a pod with no
// image roots.
const emptyRecord = `{"images":[]}`

// staleRecord is a reachability record an earlier life of the pod id wrote
// after a pull: one image root with parseable digests.
const staleRecord = `{"images":[{"reference":"example.test/app:v1",` +
	`"config":"sha256:1111111111111111111111111111111111111111111111111111111111111111",` +
	`"layers":["sha256:2222222222222222222222222222222222222222222222222222222222222222"]}]}`

// TestCreatePodReachabilityRecordAcrossTheRootfsClear pins what the image GC's
// reachability record (<pod dir>/images.json) holds after a create that starts
// from an empty rootfs, for each state an earlier life of the pod id can leave
// it in: the rootfs clear never touches the record; an absent record is
// written empty; an existing valid one is kept byte for byte. An existing entry
// the GC would refuse (a directory, a symlink, malformed JSON) fails the create
// with image.ErrPodReferencesInvalid and a path-free message; the failed
// create's cleanup removes the pod dir, the GC's enumeration then succeeds, and
// a retry of the same pod id succeeds with a fresh empty record.
func TestCreatePodReachabilityRecordAcrossTheRootfsClear(t *testing.T) {
	tests := []struct {
		name string
		// seed prepares the pod dir; it runs with the stale rootfs in place.
		seed func(t *testing.T, record string)
		// check inspects the record after the create.
		check func(t *testing.T, rt *Runtime, record string)
		// refused is whether the create must fail on the record; check then
		// runs after the failed create, before the retry.
		refused bool
	}{
		{
			name: "no earlier life writes an empty record",
			seed: func(t *testing.T, record string) {
				if err := os.RemoveAll(filepath.Dir(record)); err != nil {
					t.Fatal(err)
				}
			},
			check: wantRecordBytes(emptyRecord),
		},
		{
			name:  "stale rootfs without a record gets an empty record",
			seed:  func(t *testing.T, record string) {},
			check: wantRecordBytes(emptyRecord),
		},
		{
			name: "stale record with an image root is kept",
			seed: func(t *testing.T, record string) {
				writeFile(t, record, staleRecord)
			},
			check: func(t *testing.T, rt *Runtime, record string) {
				wantRecordBytes(staleRecord)(t, rt, record)
				pid, err := image.ParsePodID(filepath.Base(filepath.Dir(record)))
				if err != nil {
					t.Fatal(err)
				}
				roots, err := rt.cache.PodImageRoots(pid)
				if err != nil || len(roots) != 1 || roots[0].Reference != "example.test/app:v1" {
					t.Errorf("PodImageRoots = (%v, %v), want the one stale root", roots, err)
				}
			},
		},
		{
			name: "stale empty record is kept",
			seed: func(t *testing.T, record string) {
				writeFile(t, record, emptyRecord)
			},
			check: wantRecordBytes(emptyRecord),
		},
		{
			name: "malformed record is refused and the failed create removes it",
			seed: func(t *testing.T, record string) {
				writeFile(t, record, "not json")
			},
			check:   wantPodDirGone,
			refused: true,
		},
		{
			name: "record that is a directory is refused and the failed create removes it",
			seed: func(t *testing.T, record string) {
				if err := os.Mkdir(record, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			check:   wantPodDirGone,
			refused: true,
		},
		{
			name: "record that is a symlink to a valid record is refused and its target untouched",
			seed: func(t *testing.T, record string) {
				target := filepath.Join(t.TempDir(), "target.json")
				writeFile(t, target, staleRecord)
				if err := os.Symlink(target, record); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { wantRecordBytes(staleRecord)(t, nil, target) })
			},
			check:   wantPodDirGone,
			refused: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const podID = "pod-record-clear"
			rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
			podDir, err := rt.podDir(podID)
			if err != nil {
				t.Fatal(err)
			}
			rootfs := filepath.Join(podDir, "rootfs")
			stale := filepath.Join(rootfs, "stale")
			if err := os.MkdirAll(rootfs, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, stale, "old")
			record := filepath.Join(podDir, image.PodReferencesName)
			tc.seed(t, record)

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
			if tc.refused {
				if err != nil || resp.GetError() == nil {
					t.Fatalf("CreatePod = (%v, %v), want a create failure", resp, err)
				}
				msg := resp.GetError().GetMessage()
				if !strings.Contains(msg, image.ErrPodReferencesInvalid.Error()) {
					t.Errorf("create failure %q, want it to carry %q", msg, image.ErrPodReferencesInvalid)
				}
				if strings.Contains(msg, rt.cache.Root()) || strings.Contains(msg, os.TempDir()) {
					t.Errorf("create failure %q names a host path", msg)
				}
				tc.check(t, rt, record)
				if _, err := rt.cache.Roots(); err != nil {
					t.Errorf("Roots after the failed create = %v, want nil", err)
				}
				resp, err = rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
				if err != nil || resp.GetError() != nil {
					t.Fatalf("retry CreatePod = (%v, %v), want success", resp, err)
				}
				wantRecordBytes(emptyRecord)(t, rt, record)
				if _, err := rt.cache.Roots(); err != nil {
					t.Errorf("Roots after the retry = %v, want nil", err)
				}
				return
			}
			if err != nil || resp.GetError() != nil {
				t.Fatalf("CreatePod = (%v, %v), want success", resp, err)
			}
			if _, err := os.Lstat(stale); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("stale rootfs file after create: %v, want it cleared", err)
			}
			tc.check(t, rt, record)

			if _, err := rt.cache.Roots(); err != nil {
				t.Errorf("Roots err = %v, want nil", err)
			}
		})
	}
}

// wantPodDirGone checks that a failed create's cleanup removed the pod dir,
// the refused record with it.
func wantPodDirGone(t *testing.T, _ *Runtime, record string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Dir(record)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("pod dir after the failed create: %v, want it removed", err)
	}
}

// recordProbeSpawner reports, at Spawn, whether the pod's reachability record
// exists and what it holds. Spawn is the first step of a create that runs a
// process, so it stands for "before anything of the pod runs".
type recordProbeSpawner struct {
	fakeSpawner
	record string

	mu      sync.Mutex
	seen    bool
	content []byte
	err     error
}

func (s *recordProbeSpawner) Spawn(ctx context.Context, spec supervisor.SpawnSpec) (int, error) {
	s.mu.Lock()
	if !s.seen {
		s.seen = true
		s.content, s.err = os.ReadFile(s.record)
	}
	s.mu.Unlock()
	return s.fakeSpawner.Spawn(ctx, spec)
}

// TestCreatePodWritesTheRecordBeforeSpawn pins when the record is written: it
// already exists, empty, when the create spawns the pod's first process.
func TestCreatePodWritesTheRecordBeforeSpawn(t *testing.T) {
	const podID = "pod-record-early"
	sp := &recordProbeSpawner{}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	sp.record = filepath.Join(podDir, image.PodReferencesName)

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod = (%v, %v), want success", resp, err)
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if !sp.seen {
		t.Fatal("the create never spawned, so the probe never ran")
	}
	if sp.err != nil || string(sp.content) != emptyRecord {
		t.Errorf("record at spawn = (%q, %v), want %q", sp.content, sp.err, emptyRecord)
	}
}

// TestFailedCreateRemovesTheRecord pins what a failed create leaves: the whole
// pod dir is removed, the record with it, including one an earlier life of the
// pod id wrote, and the GC's enumeration then succeeds without it.
func TestFailedCreateRemovesTheRecord(t *testing.T) {
	tests := []struct {
		name string
		seed string // record content before the create; "" seeds none
	}{
		{name: "record the create wrote", seed: ""},
		{name: "record an earlier life wrote", seed: staleRecord},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const podID = "pod-record-fail"
			rt := newTestRuntime(t, Deps{
				Spawner: &fakeSpawner{err: errors.New("spawn refused")},
				Waiter:  newBlockingWaiter(),
			})
			podDir, err := rt.podDir(podID)
			if err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(podDir, image.PodReferencesName)
			if tc.seed != "" {
				writeFile(t, record, tc.seed)
			}

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
			if err != nil || resp.GetError() == nil {
				t.Fatalf("CreatePod = (%v, %v), want a create failure", resp, err)
			}
			if _, err := os.Lstat(record); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("record after a failed create: %v, want it removed", err)
			}
			if _, err := os.Lstat(podDir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("pod dir after a failed create: %v, want it removed", err)
			}
			if _, err := rt.cache.Roots(); err != nil {
				t.Errorf("Roots after a failed create = %v, want nil", err)
			}
		})
	}
}

// TestRecordPodReferencesRefusals pins the record writer the create calls
// right after the rootfs clear: an id that is not a pod id is refused as an
// invalid pod box with nothing written; a record that cannot be written
// (pod dir not writable) is an error and leaves no record; and an existing
// record is a no-op even where a write would fail.
func TestRecordPodReferencesRefusals(t *testing.T) {
	unwritable := func(t *testing.T, podDir string) {
		if os.Geteuid() == 0 {
			t.Skip("root writes into a mode-0555 directory")
		}
		if err := os.Chmod(podDir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(podDir, 0o755) })
	}
	tests := []struct {
		name        string
		podID       string
		seed        func(t *testing.T, podDir string)
		wantErr     bool
		wantInvalid bool
		wantRefused bool   // errors.Is(err, image.ErrPodReferencesInvalid)
		wantRecord  string // "" wants no record
	}{
		{
			name:        "invalid pod id",
			podID:       "../escape",
			wantErr:     true,
			wantInvalid: true,
		},
		{
			name:    "pod dir not writable and no record",
			podID:   "pod-ro",
			seed:    unwritable,
			wantErr: true,
		},
		{
			name:  "pod dir not writable with a record",
			podID: "pod-ro-kept",
			seed: func(t *testing.T, podDir string) {
				writeFile(t, filepath.Join(podDir, image.PodReferencesName), staleRecord)
				unwritable(t, podDir)
			},
			wantRecord: staleRecord,
		},
		{
			name:  "malformed record is refused and left",
			podID: "pod-bad-record",
			seed: func(t *testing.T, podDir string) {
				writeFile(t, filepath.Join(podDir, image.PodReferencesName), "not json")
			},
			wantErr:     true,
			wantRefused: true,
			wantRecord:  "not json",
		},
		{
			name:       "writable pod dir and no record",
			podID:      "pod-rw",
			wantRecord: emptyRecord,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{})
			var podDir string
			if pid, err := image.ParsePodID(tc.podID); err == nil {
				podDir = rt.cache.PodDir(pid)
				if err := os.MkdirAll(podDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if tc.seed != nil {
					tc.seed(t, podDir)
				}
			}

			err := rt.recordPodReferences(tc.podID)
			if (err != nil) != tc.wantErr {
				t.Fatalf("recordPodReferences = %v, want error %v", err, tc.wantErr)
			}
			if got := errors.Is(err, errInvalidPodBox); got != tc.wantInvalid {
				t.Errorf("errors.Is(err, errInvalidPodBox) = %v, want %v (err %v)", got, tc.wantInvalid, err)
			}
			if got := errors.Is(err, image.ErrPodReferencesInvalid); got != tc.wantRefused {
				t.Errorf("errors.Is(err, image.ErrPodReferencesInvalid) = %v, want %v (err %v)", got, tc.wantRefused, err)
			}
			if tc.wantRefused && strings.Contains(err.Error(), podDir) {
				t.Errorf("err %q names the host path %s", err, podDir)
			}
			if tc.wantErr && !tc.wantInvalid && !strings.Contains(err.Error(), "record image references for pod "+tc.podID) {
				t.Errorf("err = %v, want it to name the pod's record", err)
			}
			if podDir == "" {
				entries, rerr := os.ReadDir(rt.cache.PodsRoot())
				if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
					t.Errorf("read pods root: %v", rerr)
				}
				if len(entries) != 0 {
					t.Errorf("pods root holds %d entries after a refused id, want none", len(entries))
				}
				escaped := filepath.Join(rt.cache.PodsRoot(), tc.podID)
				for _, p := range []string{escaped, filepath.Join(escaped, image.PodReferencesName)} {
					if _, serr := os.Lstat(p); !errors.Is(serr, fs.ErrNotExist) {
						t.Errorf("escape path %s exists after a refused id (stat err %v), want not-exist", p, serr)
					}
				}
				return
			}
			b, rerr := os.ReadFile(filepath.Join(podDir, image.PodReferencesName))
			switch {
			case tc.wantRecord == "" && !errors.Is(rerr, fs.ErrNotExist):
				t.Errorf("record = (%q, %v), want none", b, rerr)
			case tc.wantRecord != "" && (rerr != nil || !bytes.Equal(b, []byte(tc.wantRecord))):
				t.Errorf("record = (%q, %v), want %q", b, rerr, tc.wantRecord)
			}
		})
	}
}

// wantRecordBytes returns a check that the record holds exactly want.
func wantRecordBytes(want string) func(t *testing.T, rt *Runtime, record string) {
	return func(t *testing.T, _ *Runtime, record string) {
		t.Helper()
		b, err := os.ReadFile(record)
		if err != nil || string(b) != want {
			t.Errorf("record = (%q, %v), want %q", b, err, want)
		}
	}
}

// writeRecordFixture writes content to path, creating its parent.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
