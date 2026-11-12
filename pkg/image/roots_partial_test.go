package image

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRootsReturnsNothingOnABadDigest pins that one unusable digest anywhere in
// the pods tree yields ErrRootsIncomplete with a nil root set: no image from the
// offending record, and none from any other record, escapes alongside the
// refusal. A partial set is worse than none, because a prune deletes what no
// root names.
func TestRootsReturnsNothingOnABadDigest(t *testing.T) {
	t.Parallel()

	good := func(ref, c string) ImageRoot {
		return ImageRoot{
			Reference: ref,
			Config:    "sha256:" + strings.Repeat(c, 64),
			Layers:    []string{"sha256:" + strings.Repeat(c, 63) + "0"},
		}
	}
	bad := ImageRoot{Reference: "bad:v1", Config: "sha256:not-hex", Layers: []string{}}

	cases := []struct {
		name    string
		records map[string][]ImageRoot
		wantErr bool
		want    int
	}{
		{
			name: "one record, valid image then an unusable digest",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), bad},
			},
			wantErr: true,
		},
		{
			name: "two records, the first valid and the second with an unusable digest",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), good("b:v1", "2")},
				"pod-b": {bad},
			},
			wantErr: true,
		},
		{
			name: "control: both records valid returns every image",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), good("b:v1", "2")},
				"pod-b": {good("c:v1", "3")},
			},
			want: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			for name, images := range tc.records {
				pid := f.pod(name)
				// Written directly: RecordPodImage refuses an unusable digest, and
				// the state under test is a record already on disk holding one.
				body, err := json.Marshal(podReferences{Images: images})
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				if err := os.WriteFile(filepath.Join(f.cache.PodDir(pid), PodReferencesName), body, 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
			}

			roots, err := f.cache.Roots()
			if tc.wantErr {
				if !errors.Is(err, ErrRootsIncomplete) {
					t.Fatalf("Roots err = %v; want ErrRootsIncomplete", err)
				}
				if roots != nil {
					t.Fatalf("Roots returned %v alongside the refusal; want nil", roots)
				}
				return
			}
			if err != nil {
				t.Fatalf("Roots: %v", err)
			}
			if len(roots) != tc.want {
				t.Fatalf("Roots = %v; want %d images", roots, tc.want)
			}
			got := map[string]bool{}
			for _, r := range roots {
				got[r.Reference] = true
			}
			for _, images := range tc.records {
				for _, im := range images {
					if !got[im.Reference] {
						t.Errorf("Roots is missing %q", im.Reference)
					}
				}
			}
		})
	}
}
