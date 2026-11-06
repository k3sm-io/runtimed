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

package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
)

// TestArtifactPartialDirMustBeTheCacheChild pins where partials may live: the
// one daemon-private child of the cache root the work-dir deny-set names. A
// partial dir anywhere else is outside that deny, so a pod could read weights
// mid-transfer or poison a resume.
func TestArtifactPartialDirMustBeTheCacheChild(t *testing.T) {
	e := newEnv(t)
	store := e.cache.Root()
	deps := Deps{Blobs: e.cache, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: e.fetch}
	for _, tc := range []struct {
		name           string
		partial, store string
		ok             bool
	}{
		{"the cache child", filepath.Join(store, sandbox.ArtifactPartialSubdir), store, true},
		{"the cache child with a trailing slash", filepath.Join(store, sandbox.ArtifactPartialSubdir) + "/", store, true},
		{"a dir outside the cache", filepath.Join(t.TempDir(), sandbox.ArtifactPartialSubdir), store, false},
		{"another cache child", filepath.Join(store, "ingest"), store, false},
		{"a grandchild", filepath.Join(store, sandbox.ArtifactPartialSubdir, "x"), store, false},
		{"the cache root itself", store, store, false},
		{"no store path", filepath.Join(store, sandbox.ArtifactPartialSubdir), "", false},
		{"a relative pair", sandbox.ArtifactPartialSubdir, ".", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{RegistryHost: testHost, PartialDir: tc.partial, StorePath: tc.store}, deps)
			if tc.ok && err != nil {
				t.Fatalf("New: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrPartialDir) {
				t.Fatalf("New err = %v, want ErrPartialDir", err)
			}
		})
	}
}

// TestArtifactPartialDirMustBePrivate pins the open-time check: a partial dir
// that is not a directory (a file, a symlink) or is writable by group or other
// is refused before any partial is opened in it, as the artifact index refuses
// its own directory.
func TestArtifactPartialDirMustBePrivate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, dir string)
	}{
		{"a regular file", func(t *testing.T, dir string) {
			if err := os.WriteFile(dir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a symlink to a private dir", func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), dir); err != nil {
				t.Fatal(err)
			}
		}},
		{"group writable", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
		}},
		{"other writable", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o703); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.fetch.publishModel(testRef, modelLayer("a.safetensors", "weights"))
			tc.prepare(t, e.partial)
			_, err := e.puller(t).PullArtifact(context.Background(), testRef, nil, volume, nil)
			if !errors.Is(err, ErrPartialDir) {
				t.Fatalf("PullArtifact err = %v, want ErrPartialDir", err)
			}
		})
	}
}
