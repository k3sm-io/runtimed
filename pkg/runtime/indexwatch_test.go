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
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// watchObserver records the index changes the daemon announces. It is
// mutex-guarded because it is reached from whichever goroutine served the RPC.
type watchObserver struct {
	mu      sync.Mutex
	changes []image.IndexChange
}

func (o *watchObserver) ImageIndexChanged(c image.IndexChange) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.changes = append(o.changes, c)
}

func (o *watchObserver) snapshot() []image.IndexChange {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]image.IndexChange(nil), o.changes...)
}

// refsOf renders the announced changes for a failure message.
func refsOf(changes []image.IndexChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Op.String()+" "+c.Reference)
	}
	return out
}

// TestImageIndexObserverCoversEveryMutationSite drives Deps.ImageIndexObserver
// through a write to the daemon's own index.
//
// It is the row that fails if the seam is threaded to nothing: the pkg/image
// rows attach an observer to an index they construct themselves, so all of them
// stay green against a runtime that never passes image.WithIndexObserver. The
// pull site, the one a running node exercises, is TestPullNotifiesTheIndexObserver.
func TestImageIndexObserverCoversEveryMutationSite(t *testing.T) {
	obs := &watchObserver{}
	_, rt := imagesTestClientDeps(t, Deps{ImageIndexObserver: obs})
	ctx := context.Background()

	// An ingest into the daemon's index (image.Loader -> FileIndex.Record).
	loadFixture(t, rt, verbRef)
	got := obs.snapshot()
	if len(got) != 1 || got[0].Op != image.IndexRecorded || got[0].Reference != verbRef {
		t.Fatalf("after the ingest changes = %v, want one recorded %q", refsOf(got), verbRef)
	}

	// The SNAPSHOT accessor is the authority the observer is only a hint about.
	entries, err := rt.ImageIndexSnapshot(ctx)
	if err != nil {
		t.Fatalf("ImageIndexSnapshot: %v", err)
	}
	if len(entries) != 1 || entries[0].Reference != verbRef {
		t.Fatalf("snapshot = %+v, want only %q", entries, verbRef)
	}
	// The change's key is one the snapshot's entries can be matched on.
	if entries[0].Platform != got[0].Platform {
		t.Errorf("snapshot platform %s != the announced key %s", entries[0].Platform, got[0].Platform)
	}
}

// TestPullNotifiesTheIndexObserver covers the pull mutation site — a pod-driven
// pull through the daemon's OWN puller, against a real in-process registry — in
// the same wiring a running node uses.
func TestPullNotifiesTheIndexObserver(t *testing.T) {
	host := testRegistryHost(t)
	pushPlatformImage(t, host, "team/app", "darwin", "arm64")
	ref := host + "/team/app:v1"

	obs := &watchObserver{}
	rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{ImageIndexObserver: obs}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := &pod{box: hostBinBox(rt, "pod-indexwatch"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	c := &runtimev1.Container{Name: "app", Image: ref, Command: []string{"/app"}}
	if _, err := rt.resolveBinary(context.Background(), p, t.TempDir(), c); err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}
	got := obs.snapshot()
	if len(got) != 1 || got[0].Op != image.IndexRecorded || got[0].Reference != ref {
		t.Fatalf("changes = %v, want one recorded %q", refsOf(got), ref)
	}
	if got[0].Descriptor.GetDigest() == "" {
		t.Errorf("the pull's change carried no manifest descriptor: %+v", got[0])
	}
}

// TestNoIndexObserverIsTheDefault: an unwired daemon behaves exactly as before —
// every verb still works, and the snapshot accessor still answers.
func TestNoIndexObserverIsTheDefault(t *testing.T) {
	_, rt := imagesTestClient(t)
	loadFixture(t, rt, verbRef)
	entries, err := rt.ImageIndexSnapshot(context.Background())
	if err != nil {
		t.Fatalf("ImageIndexSnapshot: %v", err)
	}
	if len(entries) != 1 || entries[0].Reference != verbRef {
		t.Fatalf("snapshot = %+v, want only %q", entries, verbRef)
	}
}
