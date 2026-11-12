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
	// badLayer has a usable Config, so only the Layers walk can catch it.
	badLayer := good("badlayer:v1", "4")
	badLayer.Layers = append(badLayer.Layers, "sha256:not-hex")
	noColon := ImageRoot{Reference: "nocolon:v1", Config: strings.Repeat("5", 64)}
	// sha512 is well formed but outside the store's closed allowlist.
	unsupported := ImageRoot{Reference: "sha512:v1", Config: "sha512:" + strings.Repeat("6", 128)}
	operator := good("op:v1", "7")

	cases := []struct {
		name    string
		records map[string][]ImageRoot
		// operator, when set, is recorded as an operator root: a non-pod root
		// that Roots unions into the same returned set.
		operator *ImageRoot
		wantErr  bool
		// wantPod is the pod the refusal must name.
		wantPod string
		want    int
	}{
		{
			name: "one record, valid image then an unusable digest",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), bad},
			},
			wantErr: true,
			wantPod: "pod-a",
		},
		{
			name: "two records, the first valid and the second with an unusable digest",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), good("b:v1", "2")},
				"pod-b": {bad},
			},
			wantErr: true,
			wantPod: "pod-b",
		},
		{
			name: "valid config digest, unusable layer digest",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), badLayer},
			},
			wantErr: true,
			wantPod: "pod-a",
		},
		{
			name: "digest with no colon",
			records: map[string][]ImageRoot{
				"pod-a": {noColon},
			},
			wantErr: true,
			wantPod: "pod-a",
		},
		{
			name: "digest with an unsupported algorithm",
			records: map[string][]ImageRoot{
				"pod-a": {unsupported},
			},
			wantErr: true,
			wantPod: "pod-a",
		},
		{
			name: "two records, the first in sorted order unusable and the second valid",
			records: map[string][]ImageRoot{
				"pod-a": {bad},
				"pod-b": {good("b:v1", "2")},
			},
			wantErr: true,
			wantPod: "pod-a",
		},
		{
			name: "operator root present alongside an unusable pod digest",
			records: map[string][]ImageRoot{
				"pod-a": {bad},
			},
			operator: &operator,
			wantErr:  true,
			wantPod:  "pod-a",
		},
		{
			name: "control: both records valid returns every image",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), good("b:v1", "2")},
				"pod-b": {good("c:v1", "3")},
			},
			want: 3,
		},
		{
			name: "control: a valid record and an operator root returns both",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1")},
			},
			operator: &operator,
			want:     2,
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

			if tc.operator != nil {
				platform := Platform{OS: "darwin", Architecture: "arm64"}
				if err := f.cache.RecordOperatorImage(tc.operator.Reference, platform, *tc.operator); err != nil {
					t.Fatalf("RecordOperatorImage: %v", err)
				}
			}

			roots, err := f.cache.Roots()
			if tc.wantErr {
				if !errors.Is(err, ErrRootsIncomplete) {
					t.Fatalf("Roots err = %v; want ErrRootsIncomplete", err)
				}
				// nil covers the operator root too: Roots unions it into this
				// same set, so it must not escape alongside the refusal either.
				if roots != nil {
					t.Fatalf("Roots returned %v alongside the refusal; want nil", roots)
				}
				if want := `pod "` + tc.wantPod + `"`; !strings.Contains(err.Error(), want) {
					t.Fatalf("Roots err = %q; want it to name %s", err, want)
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
			if tc.operator != nil && !got[tc.operator.Reference] {
				t.Errorf("Roots is missing operator root %q", tc.operator.Reference)
			}
		})
	}
}
