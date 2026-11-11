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
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// orphanRecords is a RecordStore serving fixed raw records, or err.
type orphanRecords struct {
	raws [][]byte
	err  error
}

func (r orphanRecords) ArtifactRecords(context.Context) ([][]byte, error) { return r.raws, r.err }

func (r orphanRecords) ArtifactRecord(context.Context, string) ([]byte, bool, error) {
	return nil, false, errors.New("not used")
}

func (r orphanRecords) RemoveArtifactRecordIf(context.Context, string, func([]byte) bool) (bool, error) {
	return false, errors.New("not used")
}

// orphanHolds is a HoldReader serving a fixed hold set, or err.
type orphanHolds struct {
	held map[string]bool
	err  error
}

func (h orphanHolds) HeldManifests(context.Context) (map[string]bool, error) { return h.held, h.err }

func recordNaming(t *testing.T, mdigest string) []byte {
	t.Helper()
	raw, err := json.Marshal(Record{Schema: recordSchema, Key: "k", Reference: "r", ManifestDigest: mdigest})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestRemoveIfOrphan pins the single-manifest removal: it removes the target
// manifest's views only when no record and no hold names it, keeps them and
// returns the error when either cannot be read, refuses a digest that is not
// sha256 or a cancelled context before touching anything, treats an absent
// views directory as a no-op, and never touches another manifest's views.
func TestRemoveIfOrphan(t *testing.T) {
	target := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	errRead := errors.New("read failed")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	type tc struct {
		name     string
		ctx      context.Context
		digest   string
		records  func(t *testing.T) orphanRecords
		holds    HoldReader
		noTarget bool // the target's views directory is absent
		wantErr  error
		anyErr   bool
		removed  bool
	}
	none := func(*testing.T) orphanRecords { return orphanRecords{} }
	cases := []tc{
		{name: "orphan removed", digest: target, records: none, removed: true},
		{name: "orphan removed with an empty hold set", digest: target, records: none, holds: orphanHolds{held: map[string]bool{}}, removed: true},
		{name: "a record naming another manifest does not keep it", digest: target,
			records: func(t *testing.T) orphanRecords { return orphanRecords{raws: [][]byte{recordNaming(t, other)}} }, removed: true},
		{name: "live record keeps", digest: target,
			records: func(t *testing.T) orphanRecords { return orphanRecords{raws: [][]byte{recordNaming(t, target)}} }},
		{name: "pod hold keeps", digest: target, records: none, holds: orphanHolds{held: map[string]bool{target: true}}},
		{name: "unreadable holds keep", digest: target, records: none, holds: orphanHolds{err: errRead}, wantErr: errRead},
		{name: "unreadable records keep", digest: target,
			records: func(*testing.T) orphanRecords { return orphanRecords{err: errRead} }, wantErr: errRead},
		{name: "undecodable record keeps", digest: target,
			records: func(*testing.T) orphanRecords { return orphanRecords{raws: [][]byte{[]byte("{")}} }, anyErr: true},
		{name: "malformed digest", digest: "sha256:zz", records: none, wantErr: ErrManifestInvalid},
		{name: "non-sha256 digest", digest: "sha512:" + strings.Repeat("a", 128), records: none, wantErr: ErrManifestInvalid},
		{name: "bare hex digest", digest: strings.Repeat("a", 64), records: none, wantErr: ErrManifestInvalid},
		{name: "uppercase digest", digest: "sha256:" + strings.Repeat("A", 64), records: none, wantErr: ErrManifestInvalid},
		{name: "path traversal digest", digest: "sha256:../" + strings.Repeat("a", 61), records: none, wantErr: ErrManifestInvalid},
		{name: "cancelled context", ctx: cancelled, digest: target, records: none, wantErr: context.Canceled},
		{name: "absent view is a no-op", digest: target, records: none, noTarget: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			v := &Views{root: root, records: c.records(t), log: slog.New(slog.DiscardHandler)}
			if c.holds != nil {
				v.holds = c.holds
			}
			tdir := filepath.Join(root, strings.TrimPrefix(target, "sha256:"))
			odir := filepath.Join(root, strings.TrimPrefix(other, "sha256:"))
			for _, d := range []string{tdir, odir} {
				if d == tdir && c.noTarget {
					continue
				}
				if err := os.MkdirAll(filepath.Join(d, strings.Repeat("c", 64)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, strings.Repeat("c", 64), "f"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx := c.ctx
			if ctx == nil {
				ctx = context.Background()
			}

			err := v.RemoveIfOrphan(ctx, c.digest)

			switch {
			case c.wantErr != nil:
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("RemoveIfOrphan err = %v, want %v", err, c.wantErr)
				}
			case c.anyErr:
				if err == nil {
					t.Fatal("RemoveIfOrphan err = nil, want an error")
				}
			default:
				if err != nil {
					t.Fatalf("RemoveIfOrphan: %v", err)
				}
			}
			if !c.noTarget {
				_, serr := os.Lstat(tdir)
				switch {
				case c.removed && !errors.Is(serr, fs.ErrNotExist):
					t.Errorf("the orphan's views survived: %v", serr)
				case !c.removed && serr != nil:
					t.Errorf("the target's views were removed: %v", serr)
				}
			}
			if _, err := os.Lstat(filepath.Join(odir, strings.Repeat("c", 64), "f")); err != nil {
				t.Errorf("another manifest's views were touched: %v", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if c.removed || c.noTarget {
				want = 1
			}
			if len(entries) != want {
				t.Errorf("views root holds %d entries, want %d", len(entries), want)
			}
		})
	}
}
