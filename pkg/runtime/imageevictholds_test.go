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

package runtime

import (
	"context"
	"testing"

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/image"
)

// TestEvictViewEvictorHasHoldSource pins that the Runtime the production
// constructor (New, through newTestRuntime) builds wires a non-nil view
// evictor, and that its Views reports a hold source, so the view removal of a
// forced EvictImage consults pod holds.
func TestEvictViewEvictorHasHoldSource(t *testing.T) {
	_, rt := imagesTestClient(t)
	if rt.views == nil {
		t.Fatalf("artifact views disabled in the test runtime: %v", rt.viewsErr)
	}
	if !rt.views.HasHoldSource() {
		t.Error("the constructor's Views has no hold source")
	}
	if rt.viewEvictor() == nil {
		t.Error("the constructor's Runtime has a nil view evictor")
	}
}

// TestEvictViewEvictorNilWithoutHoldSource pins the guard: over a Views built
// without a hold source the view evictor is nil, and a forced eviction wired
// as EvictImage wires it (ReclaimConfig.EvictDerived = viewEvictor()) then
// still unlinks the target's own blobs but removes no view. Cache.Evict is
// driven directly over a Runtime holding that Views, because swapping the
// views of a serving Runtime races its startup.
func TestEvictViewEvictorNilWithoutHoldSource(t *testing.T) {
	s := newEvictRPCScene(t)
	v, err := artifact.NewViews(context.Background(), artifact.ViewsConfig{StorePath: s.rt.cache.Root()}, s.rt.cache, s.rt.index)
	if err != nil {
		t.Fatalf("NewViews: %v", err)
	}
	if v.HasHoldSource() {
		t.Fatal("a Views built without Holds reports a hold source")
	}
	hook := (&Runtime{views: v, index: s.rt.index}).viewEvictor()
	if hook != nil {
		t.Fatal("view evictor is non-nil over a Views with no hold source")
	}
	// NewViews reaps views no record names; plant A's and B's again.
	s.viewA, s.viewB = s.view(s.manA), s.view(s.manB)
	if _, err := s.rt.cache.Evict(context.Background(), s.manA, []string{s.cfgA, s.ownA, s.shared}, image.ReclaimConfig{
		Log: s.rt.log, UntrackedPod: s.rt.podUntracked, EvictDerived: hook,
	}); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	want := wantEvicted()
	want["view A"] = true
	diffState(t, "after a forced eviction with no hold source", s.state(), want)
}
