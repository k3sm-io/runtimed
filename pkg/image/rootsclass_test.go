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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// rootsFixture is a store carrying one root of every kind the reader unions
// (a pod record, an operator root, an artifact record, a pod's artifact hold),
// a blob two kinds share, and an unrooted blob.
type rootsFixture struct {
	f                    *gcFixture
	pod                  PodID
	podCfg, podLayer     string
	opCfg, opLayer       string
	artCfg, artLayer     string
	holdCfg, holdLayer   string
	holdManifest, shared string
	orphan               string
}

func newRootsFixture(t *testing.T) *rootsFixture {
	t.Helper()
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	r := &rootsFixture{f: f}
	r.podCfg = f.blob("pod config", time.Hour)
	r.podLayer = f.blob("pod layer", time.Hour)
	r.opCfg = f.blob("operator config", time.Hour)
	r.opLayer = f.blob("operator layer", time.Hour)
	r.artCfg = f.blob("artifact config", time.Hour)
	r.artLayer = f.blob("artifact weights", time.Hour)
	r.holdCfg = f.blob("held config", time.Hour)
	r.holdLayer = f.blob("held weights", time.Hour)
	r.holdManifest = f.blob("held manifest", time.Hour)
	r.shared = f.blob("pod and operator layer", time.Hour)
	r.orphan = f.blob("orphan", time.Hour)

	r.pod = f.pod("pod-a", ImageRoot{Reference: "app:v1", Config: r.podCfg, Layers: []string{r.podLayer, r.shared}})
	if err := f.cache.RecordOperatorImage("op:v1", darwinPlatform, ImageRoot{
		Reference: "op:v1", Config: r.opCfg, Layers: []string{r.opLayer, r.shared},
	}); err != nil {
		t.Fatalf("RecordOperatorImage: %v", err)
	}
	putArtifact(t, x, "art@type", r.artCfg, r.artLayer)
	if err := x.AddArtifactHoldManifest(context.Background(), r.pod, HeldManifest{
		Digest: r.holdManifest, Config: r.holdCfg, Layers: []string{r.holdLayer},
	}); err != nil {
		t.Fatalf("AddArtifactHoldManifest: %v", err)
	}
	return r
}

// TestRootsReaderSplitKeepsPrunePlan pins that the roots reader, however it is
// arranged inside, still yields the union prune has always planned over: per-pod
// records first, then operator roots, artifact records and pod holds, in that
// order. The expected set is rebuilt from each source's own reader, and both the
// root set and PlanPrune's plan over it are compared byte for byte.
func TestRootsReaderSplitKeepsPrunePlan(t *testing.T) {
	t.Parallel()
	r := newRootsFixture(t)
	c := r.f.cache

	pods, err := c.PodImageRoots(r.pod)
	if err != nil {
		t.Fatalf("PodImageRoots: %v", err)
	}
	operator, err := c.OperatorImageRoots()
	if err != nil {
		t.Fatalf("OperatorImageRoots: %v", err)
	}
	artifacts, err := c.artifactRoots()
	if err != nil {
		t.Fatalf("artifactRoots: %v", err)
	}
	held, err := c.artifactHoldRoots()
	if err != nil {
		t.Fatalf("artifactHoldRoots: %v", err)
	}
	want := append(append(append(append([]ImageRoot(nil), pods...), operatorRootSet(operator)...), artifacts...), held...)

	got, err := c.Roots()
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if g, w := fmt.Sprintf("%#v", got), fmt.Sprintf("%#v", want); g != w {
		t.Fatalf("Roots changed:\n got %s\nwant %s", g, w)
	}
	gotUntracked, skipped, err := c.roots(func(PodID) bool { return true })
	if err != nil {
		t.Fatalf("roots: %v", err)
	}
	if g, w := fmt.Sprintf("%#v", gotUntracked), fmt.Sprintf("%#v", want); g != w || len(skipped) != 0 {
		t.Fatalf("roots(untracked) changed:\n got %s skipped %v\nwant %s", g, skipped, w)
	}

	nodes, err := c.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	trees, err := c.EnumerateTrees()
	if err != nil {
		t.Fatalf("EnumerateTrees: %v", err)
	}
	gotPlan, err := PlanPrune(nodes, trees, got, nil, time.Minute, r.f.clock)
	if err != nil {
		t.Fatalf("PlanPrune(Roots): %v", err)
	}
	wantPlan, err := PlanPrune(nodes, trees, want, nil, time.Minute, r.f.clock)
	if err != nil {
		t.Fatalf("PlanPrune(want): %v", err)
	}
	if g, w := fmt.Sprintf("%#v", gotPlan), fmt.Sprintf("%#v", wantPlan); g != w {
		t.Fatalf("prune plan changed:\n got %s\nwant %s", g, w)
	}
	if len(gotPlan.Delete) != 2 {
		// The orphan and the held manifest blob: a hold roots the manifest's
		// config and layers, never the manifest blob itself.
		t.Errorf("plan deletes %d blobs; want 2 (orphan, held manifest): %#v", len(gotPlan.Delete), gotPlan.Delete)
	}

	set, err := c.classifiedRoots(nil)
	if err != nil {
		t.Fatalf("classifiedRoots: %v", err)
	}
	if g, w := fmt.Sprintf("%#v", set.flatten()), fmt.Sprintf("%#v", want); g != w {
		t.Fatalf("flatten differs from Roots:\n got %s\nwant %s", g, w)
	}
	if g, w := fmt.Sprintf("%#v", set.flatten()), fmt.Sprintf("%#v", want); g != w {
		t.Fatalf("second flatten differs:\n got %s\nwant %s", g, w)
	}
}

// TestClassifiedRootsSplitsRootedFromInUse pins the two classes: operator roots
// and artifact records are rooted, per-pod records and pod holds are in use, a
// blob two kinds name is in both, and an unrooted blob is in neither.
func TestClassifiedRootsSplitsRootedFromInUse(t *testing.T) {
	t.Parallel()
	r := newRootsFixture(t)
	set, err := r.f.cache.classifiedRoots(nil)
	if err != nil {
		t.Fatalf("classifiedRoots: %v", err)
	}
	asSet := func(ds ...string) map[string]struct{} {
		out := make(map[string]struct{}, len(ds))
		for _, d := range ds {
			out[d] = struct{}{}
		}
		return out
	}
	if got, want := set.rootedDigests(), asSet(r.opCfg, r.opLayer, r.shared, r.artCfg, r.artLayer); !reflect.DeepEqual(got, want) {
		t.Errorf("rootedDigests = %v; want %v", got, want)
	}
	if got, want := set.inUseDigests(), asSet(r.podCfg, r.podLayer, r.shared, r.holdCfg, r.holdLayer); !reflect.DeepEqual(got, want) {
		t.Errorf("inUseDigests = %v; want %v", got, want)
	}
	var none *rootSet
	if none.rootedDigests() != nil || none.inUseDigests() != nil {
		t.Error("a nil root set named digests")
	}

	// Fail-closed exactly as Roots: an incomplete read returns no set at all.
	if err := os.MkdirAll(filepath.Join(r.f.cache.PodsRoot(), "pod-b"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if got, err := r.f.cache.classifiedRoots(nil); !errors.Is(err, ErrRootsIncomplete) || got != nil {
		t.Fatalf("classifiedRoots = %v, %v; want nil, ErrRootsIncomplete", got, err)
	}
}
