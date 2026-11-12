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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestIndexRefusesNonCanonicalBlobDigests pins that a recorded entry whose
// config or layer digest is not in the canonical form parseBlobDigest accepts
// reads back as ErrIndexEntryCorrupt, through both decode callers (Get and
// List). Those digests become lease keys (Puller.presentLocally ->
// manifestDigests -> Cache.AcquireLease), and the lease is compared as a plain
// string, so a non-canonical spelling would lease a key that protects nothing.
//
// Record refuses these digests too (TestRecordRefusesNonCanonicalBlobDigests),
// so the bad record is planted on disk instead: a valid placeholder digest is
// recorded through the normal write path and then rewritten in the entry file,
// which is exactly the shape a record written by an older daemon, or damaged
// on disk, reaches the read boundary in.
func TestIndexRefusesNonCanonicalBlobDigests(t *testing.T) {
	const ref = "example.com/app:v1"
	p := Platform{OS: "darwin", Architecture: "arm64"}
	valid := "sha256:" + strings.Repeat("ab", 32)
	other := "sha256:" + strings.Repeat("cd", 32)
	// placeholder is recorded in the position under test and then replaced in
	// the entry file by the digest under test; it appears nowhere else.
	placeholder := "sha256:" + strings.Repeat("ef", 32)

	digests := []struct {
		name    string
		digest  string
		wantErr bool
	}{
		{name: "upper-case hex", digest: "sha256:" + strings.Repeat("AB", 32), wantErr: true},
		{name: "missing algorithm", digest: strings.Repeat("ab", 32), wantErr: true},
		{name: "unknown algorithm", digest: "md5:" + strings.Repeat("ab", 16), wantErr: true},
		{name: "short digest", digest: "sha256:" + strings.Repeat("ab", 31), wantErr: true},
		{name: "valid", digest: valid, wantErr: false},
	}
	positions := []struct {
		name  string
		build func(d string) *runtimev1.ImageManifest
	}{
		{name: "config", build: func(d string) *runtimev1.ImageManifest {
			return &runtimev1.ImageManifest{
				Reference: ref,
				Config:    &runtimev1.Descriptor{Digest: d, Size: 1},
				Layers:    []*runtimev1.Descriptor{{Digest: other, Size: 1}},
			}
		}},
		{name: "layer", build: func(d string) *runtimev1.ImageManifest {
			return &runtimev1.ImageManifest{
				Reference: ref,
				Config:    &runtimev1.Descriptor{Digest: other, Size: 1},
				// The digest under test is the SECOND layer, so a check that only
				// looked at the first would not pass this row.
				Layers: []*runtimev1.Descriptor{{Digest: other, Size: 1}, {Digest: d, Size: 1}},
			}
		}},
	}

	for _, pos := range positions {
		for _, tc := range digests {
			t.Run(pos.name+"/"+tc.name, func(t *testing.T) {
				cache, idx := newIndexedCache(t)
				if err := idx.Record(context.Background(), IndexEntry{
					Reference: ref, Platform: p, Manifest: pos.build(placeholder),
				}); err != nil {
					t.Fatalf("Record: %v", err)
				}
				name := entryName(ref, p)
				buf := readEntryFile(t, cache, name)
				if bytes.Count(buf, []byte(placeholder)) != 1 {
					t.Fatalf("entry %s names the placeholder digest %d times, want 1",
						name, bytes.Count(buf, []byte(placeholder)))
				}
				writeEntryFile(t, cache, name, bytes.Replace(buf, []byte(placeholder), []byte(tc.digest), 1))

				// A refused entry must be findable: the error names the record's
				// reference and platform, not only the hashed file name.
				findable := func(op string, err error) {
					t.Helper()
					for _, want := range []string{ref, p.String(), pos.name} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("%s error %q does not name %q", op, err, want)
						}
					}
				}
				got, ok, err := idx.Get(context.Background(), ref, p)
				if tc.wantErr {
					if !errors.Is(err, ErrIndexEntryCorrupt) {
						t.Errorf("Get = (%v, %v, %v), want ErrIndexEntryCorrupt", got, ok, err)
					} else {
						findable("Get", err)
					}
				} else if err != nil || !ok {
					t.Errorf("Get = (%v, %v, %v), want the entry", got, ok, err)
				}

				list, err := idx.List(context.Background())
				if tc.wantErr {
					if !errors.Is(err, ErrIndexEntryCorrupt) {
						t.Errorf("List = (%v, %v), want ErrIndexEntryCorrupt", list, err)
					} else {
						findable("List", err)
						if !strings.Contains(err.Error(), name) {
							t.Errorf("List error %q does not name the entry file %q", err, name)
						}
					}
				} else if err != nil || len(list) != 1 {
					t.Errorf("List = (%v, %v), want the one entry", list, err)
				}
			})
		}
	}
}

// TestRecordRefusesNonCanonicalBlobDigests pins the write side of the same
// rule: Record refuses a manifest whose config or layer digest is not
// canonical, with ErrInvalidDigest, and writes nothing — so such a record can
// no longer be written only to be refused on every later read.
func TestRecordRefusesNonCanonicalBlobDigests(t *testing.T) {
	const ref = "example.com/app:v1"
	p := Platform{OS: "darwin", Architecture: "arm64"}
	other := "sha256:" + strings.Repeat("cd", 32)

	digests := []struct {
		name   string
		digest string
	}{
		{name: "upper-case hex", digest: "sha256:" + strings.Repeat("AB", 32)},
		{name: "missing algorithm", digest: strings.Repeat("ab", 32)},
		{name: "unknown algorithm", digest: "md5:" + strings.Repeat("ab", 16)},
		{name: "short digest", digest: "sha256:" + strings.Repeat("ab", 31)},
	}
	positions := []struct {
		name  string
		build func(d string) *runtimev1.ImageManifest
	}{
		{name: "config", build: func(d string) *runtimev1.ImageManifest {
			return &runtimev1.ImageManifest{
				Reference: ref,
				Config:    &runtimev1.Descriptor{Digest: d, Size: 1},
				Layers:    []*runtimev1.Descriptor{{Digest: other, Size: 1}},
			}
		}},
		{name: "layer", build: func(d string) *runtimev1.ImageManifest {
			return &runtimev1.ImageManifest{
				Reference: ref,
				Config:    &runtimev1.Descriptor{Digest: other, Size: 1},
				// The SECOND layer, so a check of the first alone would not pass.
				Layers: []*runtimev1.Descriptor{{Digest: other, Size: 1}, {Digest: d, Size: 1}},
			}
		}},
	}

	for _, pos := range positions {
		for _, tc := range digests {
			t.Run(pos.name+"/"+tc.name, func(t *testing.T) {
				_, idx := newIndexedCache(t)
				err := idx.Record(context.Background(), IndexEntry{
					Reference: ref, Platform: p, Manifest: pos.build(tc.digest),
				})
				if !errors.Is(err, ErrInvalidDigest) {
					t.Fatalf("Record = %v, want ErrInvalidDigest", err)
				}
				if errors.Is(err, ErrIndexEntryCorrupt) {
					t.Errorf("Record = %v, a write refusal must not read as a corrupt entry", err)
				}
				if !strings.Contains(err.Error(), pos.name) {
					t.Errorf("Record = %v, want it to name the %s position", err, pos.name)
				}
				got, ok, err := idx.Get(context.Background(), ref, p)
				if err != nil || ok {
					t.Errorf("Get after refused Record = (%v, %v, %v), want absent", got, ok, err)
				}
				list, err := idx.List(context.Background())
				if err != nil || len(list) != 0 {
					t.Errorf("List after refused Record = (%v, %v), want empty", list, err)
				}
			})
		}
	}
}
