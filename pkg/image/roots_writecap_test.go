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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPodReferencesRefusesOversizedRecord pins that the writer refuses a record
// its own readers would refuse. A record past maxPodReferencesBytes on disk makes
// Roots fail closed for the whole node, so the write must be refused before it
// lands: the pod's existing record stays byte-for-byte as it was and still
// reads, and Roots over that pod and a second healthy pod still succeeds.
func TestPodReferencesRefusesOversizedRecord(t *testing.T) {
	t.Parallel()

	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	podA, err := ParsePodID("pod-a")
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	podB, err := ParsePodID("pod-b")
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}

	small := func(ref, ch string) ImageRoot {
		return ImageRoot{
			Reference: ref,
			Config:    "sha256:" + strings.Repeat(ch, 64),
			Layers:    []string{"sha256:" + strings.Repeat(ch, 63) + "0"},
		}
	}
	if err := c.RecordPodImage(podA, small("a:v1", "1")); err != nil {
		t.Fatalf("RecordPodImage(pod-a, small): %v", err)
	}
	if err := c.RecordPodImage(podB, small("b:v1", "2")); err != nil {
		t.Fatalf("RecordPodImage(pod-b, small): %v", err)
	}
	recA := filepath.Join(c.PodDir(podA), PodReferencesName)
	before, err := os.ReadFile(recA)
	if err != nil {
		t.Fatalf("read pod-a record: %v", err)
	}

	// Each layer digest serializes to about 74 bytes, so this many layers puts
	// the record well past the cap with well-formed digests only: size is the
	// one reason the record could be refused.
	n := maxPodReferencesBytes/70 + 1
	huge := ImageRoot{Reference: "huge:v1", Config: "sha256:" + strings.Repeat("3", 64)}
	huge.Layers = make([]string, n)
	for i := range huge.Layers {
		huge.Layers[i] = fmt.Sprintf("sha256:%064x", i)
	}

	err = c.RecordPodImage(podA, huge)
	if !errors.Is(err, ErrPodReferencesTooLarge) {
		t.Fatalf("RecordPodImage(pod-a, huge) = %v, want ErrPodReferencesTooLarge", err)
	}
	if strings.Contains(err.Error(), c.PodDir(podA)) {
		t.Errorf("refusal names a host path: %v", err)
	}

	after, err := os.ReadFile(recA)
	if err != nil {
		t.Fatalf("read pod-a record after refusal: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("pod-a record changed on a refused write: %d bytes before, %d after", len(before), len(after))
	}
	got, err := c.PodImageRoots(podA)
	if err != nil {
		t.Fatalf("PodImageRoots(pod-a) after refusal: %v", err)
	}
	if len(got) != 1 || got[0].Reference != "a:v1" {
		t.Errorf("PodImageRoots(pod-a) = %+v, want the one a:v1 root", got)
	}
	entries, err := os.ReadDir(c.PodDir(podA))
	if err != nil {
		t.Fatalf("ReadDir(pod-a): %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".images-") {
			t.Errorf("refused write left a temp file %q", e.Name())
		}
	}

	roots, err := c.Roots()
	if err != nil {
		t.Fatalf("Roots after refusal: %v", err)
	}
	refs := map[string]bool{}
	for _, r := range roots {
		refs[r.Reference] = true
	}
	if !refs["a:v1"] || !refs["b:v1"] || refs["huge:v1"] {
		t.Errorf("Roots references = %v, want a:v1 and b:v1 and no huge:v1", refs)
	}
}
