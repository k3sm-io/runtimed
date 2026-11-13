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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeDigest is a well-formed sha256 digest made of one repeated hex char.
func fakeDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// sharedFixture writes index entries, artifact records and released copies
// straight into one cache's index.
type sharedFixture struct {
	t     *testing.T
	cache *Cache
	idx   *FileIndex
}

// entry records ref under the manifest tagged tag, naming cfg and layers, and
// returns its manifest digest. A nil-descriptor entry is recorded with noDesc.
func (f *sharedFixture) entry(ref, tag string, noDesc bool, cfg string, layers ...string) string {
	f.t.Helper()
	m := &runtimev1.ImageManifest{Reference: ref, Config: &runtimev1.Descriptor{Digest: cfg, Size: 1}}
	for _, l := range layers {
		m.Layers = append(m.Layers, &runtimev1.Descriptor{Digest: l, Size: 1})
	}
	e := IndexEntry{Reference: ref, Platform: Platform{OS: "linux", Architecture: "arm64"}, Manifest: m}
	if !noDesc {
		e.ManifestRaw, e.Descriptor = manifestBytes(tag)
	}
	if err := f.idx.Record(context.Background(), e); err != nil {
		f.f(err)
	}
	return e.Descriptor.GetDigest()
}

// recordBytes is an artifact record in pkg/artifact's shape.
func (f *sharedFixture) recordBytes(key, manifest, cfg string, layers ...string) []byte {
	buf, err := json.Marshal(map[string]any{
		"schema": 1, "key": key, "reference": key, "manifestDigest": manifest,
		"configDigest": cfg, "layerDigests": layers,
	})
	if err != nil {
		f.f(err)
	}
	return buf
}

// record writes a live artifact record.
func (f *sharedFixture) record(key, manifest, cfg string, layers ...string) {
	f.t.Helper()
	if err := f.idx.PutArtifactRecord(context.Background(), key, f.recordBytes(key, manifest, cfg, layers...)); err != nil {
		f.f(err)
	}
}

// releasedFile writes buf into the released directory under name ("" is the
// copy's own name).
func (f *sharedFixture) releasedFile(name string, buf []byte) {
	f.t.Helper()
	dir := filepath.Join(f.cache.IndexRoot(), ArtifactReleasedIndexSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.f(err)
	}
	if name == "" {
		name = releasedName(buf)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf, 0o600); err != nil {
		f.f(err)
	}
}

// plantSymlink makes name in the index subdirectory sub a relative symlink to
// a regular file holding buf beside it. The target is a dot name the scan
// skips and stays inside sub, so only the regular-file check refuses the link.
func (f *sharedFixture) plantSymlink(sub, name string, buf []byte) {
	f.t.Helper()
	dir := filepath.Join(f.cache.IndexRoot(), sub)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.f(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".link-target"), buf, 0o600); err != nil {
		f.f(err)
	}
	if err := os.Symlink(".link-target", filepath.Join(dir, name)); err != nil {
		f.f(err)
	}
}

// plantDir makes name in the index subdirectory sub a directory.
func (f *sharedFixture) plantDir(sub, name string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.cache.IndexRoot(), sub, name), 0o700); err != nil {
		f.f(err)
	}
}

func (f *sharedFixture) f(err error) {
	f.t.Helper()
	f.t.Fatal(err)
}

// TestEvictSharedSet pins the others set PlanEvict is handed: every blob a
// manifest other than the target names, from the image index, the live
// artifact records and the released copies, and never the target's own; and
// fail-closed, so any entry that cannot be read or decoded is an error with
// no set.
func TestEvictSharedSet(t *testing.T) {
	cfgA, ownA, shared := fakeDigest('a'), fakeDigest('b'), fakeDigest('c')
	cfgB, ownB := fakeDigest('d'), fakeDigest('e')
	cfgR, layR := fakeDigest('1'), fakeDigest('2')
	_, descA := manifestBytes("A")
	_, descB := manifestBytes("B")
	mA, mB := descA.GetDigest(), descB.GetDigest()
	mR := fakeDigest('9')

	tests := []struct {
		name    string
		target  string
		blobs   []string // the target's own blobs; nil uses the target's default
		setup   func(f *sharedFixture)
		want    []string
		wantErr error // nil with wantAnyErr unset means success
		anyErr  bool
	}{
		{
			name:   "empty store names nothing",
			target: mA,
			setup:  func(*sharedFixture) {},
		},
		{
			name:   "target sharing one blob with another image",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("a", "A", false, cfgA, ownA, shared)
				f.entry("b", "B", false, cfgB, ownB, shared)
			},
			want: []string{mB, cfgB, ownB, shared},
		},
		{
			name:   "every reference to the target manifest is the target",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("a", "A", false, cfgA, ownA)
				f.entry("a-alias", "A", false, cfgA, ownA)
			},
		},
		{
			name:   "entry without a descriptor counts as other",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("a", "A", false, cfgA, ownA)
				f.entry("old", "", true, cfgA, ownA)
			},
			want: []string{cfgA, ownA},
		},
		{
			name:   "live record of the target is excluded, others included",
			target: mR,
			setup: func(f *sharedFixture) {
				f.record("r@t", mR, cfgR, layR)
				f.record("s@t", mB, cfgB, shared)
				f.record("legacy@t", "", ownB)
			},
			want: []string{mB, cfgB, shared, ownB},
		},
		{
			name:   "released copy of the target is excluded, others included",
			target: mR,
			setup: func(f *sharedFixture) {
				f.releasedFile("", f.recordBytes("r@t", mR, cfgR, layR))
				f.releasedFile("", f.recordBytes("s@t", mB, cfgB, shared))
				f.releasedFile(".index-123", []byte("temp in flight"))
				f.releasedFile("notes.txt", []byte("not a record"))
			},
			want: []string{mB, cfgB, shared},
		},
		{
			name:   "corrupt index entry fails closed",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("b", "B", false, cfgB, ownB)
				writeEntryFile(f.t, f.cache, strings.Repeat("0", 64)+".json", []byte("{not json"))
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "symlink named like an index entry fails closed",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("b", "B", false, cfgB, ownB)
				dst := filepath.Join(f.cache.IndexRoot(), "elsewhere")
				if err := os.WriteFile(dst, []byte("{}"), 0o600); err != nil {
					f.f(err)
				}
				if err := os.Symlink("elsewhere", filepath.Join(f.cache.IndexRoot(), "x.json")); err != nil {
					f.f(err)
				}
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "directory named like an index entry fails closed",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("b", "B", false, cfgB, ownB)
				if err := os.Mkdir(filepath.Join(f.cache.IndexRoot(), "x.json"), 0o700); err != nil {
					f.f(err)
				}
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "index temps and non-record names are skipped",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("b", "B", false, cfgB, ownB)
				writeEntryFile(f.t, f.cache, ".index-123", []byte("temp in flight"))
				writeEntryFile(f.t, f.cache, "notes.txt", []byte("not a record"))
			},
			want: []string{mB, cfgB, ownB},
		},
		{
			name:   "index entry labelled with the target cannot hide another blob",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("a", "A", false, cfgA, ownA, shared)
				f.entry("a-planted", "A", false, cfgA, ownA, ownB)
			},
			want: []string{ownB},
		},
		{
			name:   "live record labelled with the target cannot hide another blob",
			target: mR,
			setup: func(f *sharedFixture) {
				f.record("r@t", mR, cfgR, layR)
				f.record("planted@t", mR, cfgR, layR, ownB)
			},
			want: []string{ownB},
		},
		{
			name:   "released copy labelled with the target cannot hide another blob",
			target: mR,
			setup: func(f *sharedFixture) {
				f.releasedFile("", f.recordBytes("planted@t", mR, cfgB, layR))
			},
			want: []string{cfgB},
		},
		{
			name:   "empty target blob set protects every blob a target-labelled entry names",
			target: mR,
			blobs:  []string{},
			setup: func(f *sharedFixture) {
				f.record("r@t", mR, cfgR, layR)
			},
			want: []string{cfgR, layR},
		},
		{
			// The availability trade-off: one bad record makes the whole set
			// unreadable, so eviction stops rather than guessing.
			name:   "one malformed artifact record blocks the whole read",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("b", "B", false, cfgB, ownB, shared)
				f.record("s@t", mB, cfgB, shared)
				f.releasedFile("", f.recordBytes("s@t", mB, cfgB, shared))
				if err := f.idx.PutArtifactRecord(context.Background(), "bad@t", []byte("{not json")); err != nil {
					f.f(err)
				}
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "undecodable artifact record fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.record("s@t", mB, cfgB, shared)
				if err := f.idx.PutArtifactRecord(context.Background(), "bad@t", []byte(`{"configDigest":"nope"}`)); err != nil {
					f.f(err)
				}
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "undecodable released copy fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.releasedFile("", f.recordBytes("s@t", mB, cfgB, shared))
				f.releasedFile("", []byte("{not json"))
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "released record name that is not a copy's fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.releasedFile("planted.json", f.recordBytes("s@t", mB, cfgB, shared))
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "symlink named like a released copy fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.releasedFile("", f.recordBytes("s@t", mB, cfgB, shared))
				f.plantSymlink(ArtifactReleasedIndexSubdir, strings.Repeat("0", 64)+".json", f.recordBytes("r@t", mR, cfgR, ownB))
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "directory named like a released copy fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.releasedFile("", f.recordBytes("s@t", mB, cfgB, shared))
				f.plantDir(ArtifactReleasedIndexSubdir, strings.Repeat("0", 64)+".json")
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "symlink named like an artifact record fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.record("s@t", mB, cfgB, shared)
				f.plantSymlink(ArtifactIndexSubdir, "x.json", f.recordBytes("r@t", mR, cfgR, ownB))
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "directory named like an artifact record fails closed",
			target: mR,
			setup: func(f *sharedFixture) {
				f.record("s@t", mB, cfgB, shared)
				f.plantDir(ArtifactIndexSubdir, "x.json")
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "index entry under another entry's name fails closed",
			target: mA,
			setup: func(f *sharedFixture) {
				f.entry("b", "B", false, cfgB, ownB)
				src := filepath.Join(f.cache.IndexRoot(), entryName("b", Platform{OS: "linux", Architecture: "arm64"}))
				buf, err := os.ReadFile(src)
				if err != nil {
					f.f(err)
				}
				if err := os.Remove(src); err != nil {
					f.f(err)
				}
				writeEntryFile(f.t, f.cache, strings.Repeat("0", 64)+".json", buf)
			},
			wantErr: ErrIndexEntryCorrupt,
		},
		{
			name:   "malformed target is an error",
			target: "sha256:short",
			setup:  func(*sharedFixture) {},
			anyErr: true,
		},
		{
			name:   "empty target is an error",
			target: "",
			setup:  func(*sharedFixture) {},
			anyErr: true,
		},
	}
	defaults := map[string][]string{mA: {cfgA, ownA, shared}, mR: {cfgR, layR}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, idx := newIndexedCache(t)
			f := &sharedFixture{t: t, cache: cache, idx: idx}
			tc.setup(f)
			blobs := tc.blobs
			if blobs == nil {
				blobs = defaults[tc.target]
			}
			own := make(map[string]struct{}, len(blobs))
			for _, d := range blobs {
				own[d] = struct{}{}
			}
			got, err := cache.evictSharedSet(context.Background(), tc.target, own)
			if tc.wantErr != nil || tc.anyErr {
				if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
					t.Fatalf("evictSharedSet = %v, %v; want error %v", got, err, tc.wantErr)
				}
				if got != nil {
					t.Errorf("evictSharedSet returned a set %v with its error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("evictSharedSet: %v", err)
			}
			var names []string
			for d := range got {
				names = append(names, d)
			}
			sort.Strings(names)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(nilIfEmpty(names), nilIfEmpty(want)) {
				t.Errorf("shared set = %v; want %v", names, want)
			}
		})
	}
}

// TestEvictSharedSetHonoursCancel pins each of evictSharedSet's three
// cancellation checks on its own: with every leg populated, a context
// cancelled before the call, before the artifact records or before the
// released copies returns no set, and the phases after the cancellation never
// start. It sets a package seam, so it must not run in parallel.
func TestEvictSharedSetHonoursCancel(t *testing.T) {
	cfgB, ownB, shared := fakeDigest('d'), fakeDigest('e'), fakeDigest('c')
	_, descB := manifestBytes("B")
	mB := descB.GetDigest()
	tests := []struct {
		name     string
		cancelAt string // "" cancels before the call
		wantSeen []string
	}{
		{name: "cancelled before the call", cancelAt: "", wantSeen: nil},
		{name: "cancelled before the artifact records", cancelAt: "records", wantSeen: []string{"records"}},
		{name: "cancelled before the released copies", cancelAt: "released", wantSeen: []string{"records", "released"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, idx := newIndexedCache(t)
			f := &sharedFixture{t: t, cache: cache, idx: idx}
			f.entry("b", "B", false, cfgB, ownB, shared)
			f.record("s@t", mB, cfgB, shared)
			f.releasedFile("", f.recordBytes("s@t", mB, cfgB, shared))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelAt == "" {
				cancel()
			}
			var seen []string
			evictSharedPhaseHook = func(phase string) {
				seen = append(seen, phase)
				if phase == tc.cancelAt {
					cancel()
				}
			}
			t.Cleanup(func() { evictSharedPhaseHook = nil })

			got, err := cache.evictSharedSet(ctx, fakeDigest('a'), nil)
			if !errors.Is(err, context.Canceled) || got != nil {
				t.Fatalf("evictSharedSet = %v, %v; want nil, context.Canceled", got, err)
			}
			if !reflect.DeepEqual(seen, tc.wantSeen) {
				t.Errorf("phases started = %v; want %v", seen, tc.wantSeen)
			}
		})
	}
}
