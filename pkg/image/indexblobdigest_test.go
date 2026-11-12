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
// Record does not validate these digests, so the bad record is written through
// the normal write path and the refusal is observed at the read boundary,
// which is where an on-disk record enters the daemon.
func TestIndexRefusesNonCanonicalBlobDigests(t *testing.T) {
	const ref = "example.com/app:v1"
	p := Platform{OS: "darwin", Architecture: "arm64"}
	valid := "sha256:" + strings.Repeat("ab", 32)
	other := "sha256:" + strings.Repeat("cd", 32)

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
				_, idx := newIndexedCache(t)
				if err := idx.Record(context.Background(), IndexEntry{
					Reference: ref, Platform: p, Manifest: pos.build(tc.digest),
				}); err != nil {
					t.Fatalf("Record: %v", err)
				}

				got, ok, err := idx.Get(context.Background(), ref, p)
				if tc.wantErr {
					if !errors.Is(err, ErrIndexEntryCorrupt) {
						t.Errorf("Get = (%v, %v, %v), want ErrIndexEntryCorrupt", got, ok, err)
					}
				} else if err != nil || !ok {
					t.Errorf("Get = (%v, %v, %v), want the entry", got, ok, err)
				}

				list, err := idx.List(context.Background())
				if tc.wantErr {
					if !errors.Is(err, ErrIndexEntryCorrupt) {
						t.Errorf("List = (%v, %v), want ErrIndexEntryCorrupt", list, err)
					}
				} else if err != nil || len(list) != 1 {
					t.Errorf("List = (%v, %v), want the one entry", list, err)
				}
			})
		}
	}
}
