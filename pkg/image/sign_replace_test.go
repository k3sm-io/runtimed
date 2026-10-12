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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestSignByReplaceFailureLeavesPathAlone pins the error contract: a failed sign,
// or a path that is not a regular file, leaves the original untouched and no temp
// file behind.
func TestSignByReplaceFailureLeavesPathAlone(t *testing.T) {
	errSign := errors.New("sign failed")
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		sign    func(ctx context.Context, path, ident string) error
		wantErr error
		entries int
	}{
		{
			name: "sign-error-removes-temp",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "bin")
				if err := os.WriteFile(p, []byte("orig"), 0o755); err != nil {
					t.Fatal(err)
				}
				return p
			},
			sign:    func(context.Context, string, string) error { return errSign },
			wantErr: errSign,
			entries: 1,
		},
		{
			name: "symlink-is-refused",
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("orig"), 0o755); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(dir, "bin")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			sign: func(context.Context, string, string) error {
				t.Error("sign called for a symlink")
				return nil
			},
			entries: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := tc.setup(t, dir)
			err := signByReplace(context.Background(), p, tc.sign)
			if err == nil {
				t.Fatal("signByReplace succeeded, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			got, err := os.ReadFile(p)
			if err != nil || string(got) != "orig" {
				t.Errorf("path content = %q, %v; want the original", got, err)
			}
			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(ents) != tc.entries {
				t.Errorf("dir holds %d entries, want %d (temp left behind?)", len(ents), tc.entries)
			}
		})
	}
}
