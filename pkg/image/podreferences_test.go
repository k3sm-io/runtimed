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
	"testing"
)

// TestEnsurePodReferencesRecordValidation pins what EnsurePodReferences
// accepts as an existing record: only a regular file, judged without
// following a link, that decodes as the record. Anything else is refused with
// ErrPodReferencesInvalid, a message naming no host path, and the entry (and a
// link's target) left byte for byte as found.
func TestEnsurePodReferencesRecordValidation(t *testing.T) {
	const valid = `{"images":[{"reference":"example.test/app:v1","config":"sha256:` +
		`1111111111111111111111111111111111111111111111111111111111111111","layers":[]}]}`
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

			err = cache.EnsurePodReferences(pid)
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
