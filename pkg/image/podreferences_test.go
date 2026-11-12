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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestEnsurePodReferencesRecordValidation pins what EnsurePodReferences
// accepts as an existing record: only a regular file, judged without
// following a link, that decodes as the record. Anything else is refused with
// ErrPodReferencesInvalid, a message naming no host path, and the entry (and a
// link's target) left byte for byte as found.
func TestEnsurePodReferencesRecordValidation(t *testing.T) {
	const valid = `{"images":[{"reference":"example.test/app:v1","config":"sha256:` +
		`1111111111111111111111111111111111111111111111111111111111111111","layers":[]}]}`
	// Decodes as the record, but its layer digest is not one this store can map
	// to a path, so Roots would refuse it.
	const unusableDigest = `{"images":[{"reference":"example.test/app:v1","config":"sha256:` +
		`1111111111111111111111111111111111111111111111111111111111111111","layers":["sha256:not-hex"]}]}`
	tests := []struct {
		name string
		// seed plants the entry at record; outside is a scratch dir off the pod tree.
		seed    func(t *testing.T, record, outside string)
		wantErr bool
		// check runs after the ensure.
		check func(t *testing.T, record, outside string)
	}{
		{
			name:  "absent record is written empty",
			seed:  func(t *testing.T, record, outside string) {},
			check: wantFile(`{"images":[]}`),
		},
		{
			name: "valid record is kept byte for byte",
			seed: func(t *testing.T, record, outside string) {
				mustWrite(t, record, valid, 0o644)
			},
			check: wantFile(valid),
		},
		{
			name: "directory is refused and left",
			seed: func(t *testing.T, record, outside string) {
				if err := os.Mkdir(record, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
			check: func(t *testing.T, record, outside string) {
				if fi, err := os.Lstat(record); err != nil || !fi.IsDir() {
					t.Errorf("Lstat(record) = (%v, %v), want the seeded directory", fi, err)
				}
			},
		},
		{
			name: "symlink to a valid record is refused and its target untouched",
			seed: func(t *testing.T, record, outside string) {
				target := filepath.Join(outside, "target.json")
				mustWrite(t, target, valid, 0o644)
				if err := os.Symlink(target, record); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
			check: func(t *testing.T, record, outside string) {
				if fi, err := os.Lstat(record); err != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Errorf("Lstat(record) = (%v, %v), want the seeded symlink", fi, err)
				}
				wantFile(valid)(t, filepath.Join(outside, "target.json"), outside)
			},
		},
		{
			name: "malformed regular file is refused and left",
			seed: func(t *testing.T, record, outside string) {
				mustWrite(t, record, "not json", 0o644)
			},
			wantErr: true,
			check:   wantFile("not json"),
		},
		{
			name: "oversized regular file is refused and left",
			seed: func(t *testing.T, record, outside string) {
				f, err := os.Create(record)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(maxPodReferencesBytes + 1); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
			check: func(t *testing.T, record, outside string) {
				if fi, err := os.Lstat(record); err != nil || fi.Size() != maxPodReferencesBytes+1 {
					t.Errorf("Lstat(record) = (%v, %v), want the seeded oversized file", fi, err)
				}
			},
		},
		{
			name: "record with an unusable digest is refused and left",
			seed: func(t *testing.T, record, outside string) {
				mustWrite(t, record, unusableDigest, 0o644)
			},
			wantErr: true,
			check:   wantFile(unusableDigest),
		},
		{
			name: "fifo is refused without blocking and left",
			seed: func(t *testing.T, record, outside string) {
				if err := syscall.Mkfifo(record, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
			check:   wantFIFO,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			cache, err := NewCache(filepath.Join(base, "cache"))
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside")
			if err := os.MkdirAll(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			pid, err := ParsePodID("pod-ensure")
			if err != nil {
				t.Fatal(err)
			}
			podDir := cache.PodDir(pid)
			if err := os.MkdirAll(podDir, 0o755); err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(podDir, PodReferencesName)
			tc.seed(t, record, outside)

			err = withTimeout(t, func() error { return cache.EnsurePodReferences(pid) }, record)
			if got := errors.Is(err, ErrPodReferencesInvalid); got != tc.wantErr {
				t.Fatalf("EnsurePodReferences = %v, want ErrPodReferencesInvalid %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), base) {
				t.Errorf("err %q names the host path %s", err, base)
			}
			tc.check(t, record, outside)
		})
	}
}

func wantFile(want string) func(t *testing.T, path, _ string) {
	return func(t *testing.T, path, _ string) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			t.Errorf("%s = (%q, %v), want %q", filepath.Base(path), b, err, want)
		}
	}
}

// TestCheckPodReferencesFIFONonBlocking pins the descriptor-side half of the
// FIFO refusal: a FIFO swapped in after EnsurePodReferences' Lstat reaches the
// open itself, and that open must return (to be refused by the regular-file
// check on the descriptor) instead of blocking for a writer that never comes.
func TestCheckPodReferencesFIFONonBlocking(t *testing.T) {
	base := t.TempDir()
	record := filepath.Join(base, PodReferencesName)
	if err := syscall.Mkfifo(record, 0o644); err != nil {
		t.Fatal(err)
	}
	err := withTimeout(t, func() error { return checkPodReferences(record) }, record)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("checkPodReferences(fifo) = %v, want a not-a-regular-file refusal", err)
	}
	if strings.Contains(err.Error(), base) {
		t.Errorf("err %q names the host path %s", err, base)
	}
	wantFIFO(t, record, "")
}

// withTimeout runs fn and fails the test if it has not returned within a few
// seconds, so a regression that blocks (an open on a FIFO with no writer)
// fails instead of hanging the run. On timeout it opens record for writing to
// release a reader blocked on a FIFO there, so the goroutine does not leak.
func withTimeout(t *testing.T, fn func() error, record string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		if w, err := os.OpenFile(record, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatalf("call did not return within 5s: blocked on %s", filepath.Base(record))
		return nil
	}
}

func wantFIFO(t *testing.T, path, _ string) {
	t.Helper()
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("Lstat(%s) = (%v, %v), want the seeded fifo", filepath.Base(path), fi, err)
	}
}
