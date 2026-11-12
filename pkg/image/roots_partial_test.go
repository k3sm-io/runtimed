package image

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
		// wantCause, when set, is text the refusal must also contain: the
		// distinguishing words of the parseBlobDigest branch that produced it.
		// Roots renders the cause with %v, so only the text is matchable.
		wantCause string
		// wantNoCause, when set, is text the refusal must not contain, to tell
		// two branches that share a sentinel apart.
		wantNoCause string
		// wantSuffix, when set, is the exact tail the refusal must end with. Roots
		// appends nothing after the cause, so this pins the bare-sentinel branch
		// of parseBlobDigest, whose sentinel directly follows the quoted digest
		// where the hash-parse branch puts the parser's text between them.
		wantSuffix string
		want       int
	}{
		{
			name: "one record, valid image then an unusable digest",
			records: map[string][]ImageRoot{
				"pod-a": {good("a:v1", "1"), bad},
			},
			wantErr:     true,
			wantPod:     "pod-a",
			wantCause:   ErrInvalidDigest.Error(),
			wantNoCause: ErrUnsupportedDigestAlgorithm.Error(),
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
			wantErr:    true,
			wantPod:    "pod-a",
			wantCause:  ErrInvalidDigest.Error(),
			wantSuffix: "digest " + QuoteBounded(noColon.Config, maxDigestLen) + ": " + ErrInvalidDigest.Error(),
		},
		{
			name: "digest with an unsupported algorithm",
			records: map[string][]ImageRoot{
				"pod-a": {unsupported},
			},
			wantErr:   true,
			wantPod:   "pod-a",
			wantCause: ErrUnsupportedDigestAlgorithm.Error(),
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
				if tc.wantCause != "" && !strings.Contains(err.Error(), tc.wantCause) {
					t.Fatalf("Roots err = %q; want it to carry the cause %q", err, tc.wantCause)
				}
				if tc.wantNoCause != "" && strings.Contains(err.Error(), tc.wantNoCause) {
					t.Fatalf("Roots err = %q; must not carry %q", err, tc.wantNoCause)
				}
				if tc.wantSuffix != "" && !strings.HasSuffix(err.Error(), tc.wantSuffix) {
					t.Fatalf("Roots err = %q; want it to end with %q", err, tc.wantSuffix)
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

// TestRootsReadRefusesAFIFOWithoutBlocking pins that the Roots read of a pod
// record opens it the way the ensure-time check does: non-blocking, so a FIFO
// planted at PodReferencesName is refused on its descriptor instead of hanging
// the read (and reclaim with it) waiting for a writer; and bounded, so a record
// past maxPodReferencesBytes is refused rather than read whole. Both fail
// closed: ErrRootsIncomplete, no roots, and a cause that names which refusal.
func TestRootsReadRefusesAFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		plant     func(t *testing.T, path string)
		wantCause string
	}{
		{
			name: "fifo at the record name",
			plant: func(t *testing.T, path string) {
				if err := unix.Mkfifo(path, 0o644); err != nil {
					t.Fatalf("mkfifo: %v", err)
				}
			},
			wantCause: "not a regular file",
		},
		{
			name: "regular file one byte over the cap",
			plant: func(t *testing.T, path string) {
				// JSON whitespace: under the cap it would decode as an empty
				// document, so only the bound can produce the wanted cause.
				body := make([]byte, maxPodReferencesBytes+1)
				for i := range body {
					body[i] = ' '
				}
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
			},
			wantCause: "exceeds",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			pid := f.pod("pod-a")
			path := filepath.Join(f.cache.PodDir(pid), PodReferencesName)
			// f.pod wrote a valid record; the planted entry replaces it.
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove record: %v", err)
			}
			tc.plant(t, path)

			type result struct {
				roots []ImageRoot
				err   error
			}
			done := make(chan result, 1)
			go func() {
				roots, err := f.cache.Roots()
				done <- result{roots, err}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(5 * time.Second):
				// Release a reader blocked on the FIFO so the goroutine ends.
				if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = w.Close()
				}
				t.Fatalf("Roots did not return within 5s: the record read blocked")
			}
			if !errors.Is(got.err, ErrRootsIncomplete) {
				t.Fatalf("Roots err = %v; want ErrRootsIncomplete", got.err)
			}
			if got.roots != nil {
				t.Fatalf("Roots returned %v alongside the refusal; want nil", got.roots)
			}
			if !strings.Contains(got.err.Error(), `pod "pod-a"`) || !strings.Contains(got.err.Error(), tc.wantCause) {
				t.Fatalf("Roots err = %q; want it to name pod \"pod-a\" and carry %q", got.err, tc.wantCause)
			}
		})
	}
}

// TestPodImageRootsRefusesAFIFOWithoutBlocking pins that PodImageRoots opens a
// pod's record the way Roots does: non-blocking, so a FIFO planted at
// PodReferencesName is refused on its descriptor instead of hanging the caller
// waiting for a writer; and bounded, so a record past maxPodReferencesBytes is
// refused rather than read whole. Each returns an error carrying the refusal's
// cause and no roots.
func TestPodImageRootsRefusesAFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		plant     func(t *testing.T, path string)
		wantCause string
	}{
		{
			name: "fifo at the record name",
			plant: func(t *testing.T, path string) {
				if err := unix.Mkfifo(path, 0o644); err != nil {
					t.Fatalf("mkfifo: %v", err)
				}
			},
			wantCause: "not a regular file",
		},
		{
			name: "regular file one byte over the cap",
			plant: func(t *testing.T, path string) {
				// JSON whitespace: under the cap it would fail to decode with a
				// different cause, so only the bound can produce the wanted one.
				body := make([]byte, maxPodReferencesBytes+1)
				for i := range body {
					body[i] = ' '
				}
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
			},
			wantCause: "exceeds",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			pid := f.pod("pod-a")
			path := filepath.Join(f.cache.PodDir(pid), PodReferencesName)
			// f.pod wrote a valid record; the planted entry replaces it.
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove record: %v", err)
			}
			tc.plant(t, path)

			type result struct {
				roots []ImageRoot
				err   error
			}
			done := make(chan result, 1)
			go func() {
				roots, err := f.cache.PodImageRoots(pid)
				done <- result{roots, err}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(5 * time.Second):
				// Release a reader blocked on the FIFO so the goroutine ends.
				if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = w.Close()
				}
				t.Fatalf("PodImageRoots did not return within 5s: the record read blocked")
			}
			if got.err == nil {
				t.Fatalf("PodImageRoots err = nil, roots = %v; want a refusal", got.roots)
			}
			if got.roots != nil {
				t.Fatalf("PodImageRoots returned %v alongside the refusal; want nil", got.roots)
			}
			if !strings.Contains(got.err.Error(), tc.wantCause) {
				t.Fatalf("PodImageRoots err = %q; want it to carry %q", got.err, tc.wantCause)
			}
		})
	}
}
