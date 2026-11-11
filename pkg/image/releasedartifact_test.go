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
	"reflect"
	"strings"
	"testing"
)

// TestReleasedArtifact pins the strict released-copy reader: a copy for the
// manifest is found with its config and layers; no copy, or no released
// directory, is not found and no error; an undecodable copy, a symlink and a
// directory named like a copy are each ErrIndexEntryCorrupt.
func TestReleasedArtifact(t *testing.T) {
	t.Parallel()
	newFixture := func(t *testing.T) *sharedFixture {
		f := newGCFixture(t)
		return &sharedFixture{t: t, cache: f.cache, idx: &FileIndex{dir: f.cache.IndexRoot()}}
	}
	m, cfg, l1, l2 := fakeDigest('a'), fakeDigest('b'), fakeDigest('c'), fakeDigest('d')

	t.Run("found", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.releasedFile("", f.recordBytes("art@t", m, cfg, l1, l2))
		f.releasedFile("", f.recordBytes("other@t", fakeDigest('e'), fakeDigest('f')))
		gotM, blobs, found, err := f.idx.ReleasedArtifact(m)
		if err != nil || !found || gotM != m {
			t.Fatalf("ReleasedArtifact = %q, %v, %v, %v; want %q, found, nil", gotM, blobs, found, err, m)
		}
		if want := []string{cfg, l1, l2}; !reflect.DeepEqual(blobs, want) {
			t.Errorf("blobs = %v; want %v", blobs, want)
		}
	})
	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		if gotM, blobs, found, err := f.idx.ReleasedArtifact(m); err != nil || found || gotM != "" || blobs != nil {
			t.Fatalf("no released dir: ReleasedArtifact = %q, %v, %v, %v; want not found, nil", gotM, blobs, found, err)
		}
		f.releasedFile("", f.recordBytes("other@t", fakeDigest('e'), fakeDigest('f')))
		if gotM, blobs, found, err := f.idx.ReleasedArtifact(m); err != nil || found || gotM != "" || blobs != nil {
			t.Fatalf("other copy only: ReleasedArtifact = %q, %v, %v, %v; want not found, nil", gotM, blobs, found, err)
		}
	})
	name := strings.Repeat("0", 64) + ".json"
	for _, tc := range []struct {
		name  string
		plant func(f *sharedFixture)
	}{
		{"undecodable", func(f *sharedFixture) { f.releasedFile("", []byte("{not json")) }},
		{"symlink", func(f *sharedFixture) {
			f.plantSymlink(ArtifactReleasedIndexSubdir, name, f.recordBytes("art@t", m, cfg, l1))
		}},
		{"directory", func(f *sharedFixture) { f.plantDir(ArtifactReleasedIndexSubdir, name) }},
	} {
		t.Run("corrupt "+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.releasedFile("", f.recordBytes("art@t", m, cfg, l1))
			tc.plant(f)
			gotM, blobs, found, err := f.idx.ReleasedArtifact(m)
			if !errors.Is(err, ErrIndexEntryCorrupt) || found || gotM != "" || blobs != nil {
				t.Fatalf("ReleasedArtifact = %q, %v, %v, %v; want not found, ErrIndexEntryCorrupt", gotM, blobs, found, err)
			}
		})
	}
	t.Run("malformed manifest", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		if _, _, found, err := f.idx.ReleasedArtifact("sha256:nope"); err == nil || found {
			t.Fatalf("ReleasedArtifact(malformed) = %v, %v; want an error", found, err)
		}
	})
}
