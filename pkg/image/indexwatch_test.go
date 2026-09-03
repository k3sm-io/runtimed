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
	"log/slog"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// recordingObserver captures every change it is handed. It is mutex-guarded
// because the -race rows drive concurrent mutations through it, and because an
// observer in production is reached from whichever goroutine served the RPC.
type recordingObserver struct {
	mu      sync.Mutex
	changes []IndexChange
	// reenter, when set, calls back into the index from inside the callback.
	// FileIndex takes no lock, so this must not deadlock — which is the property
	// IndexObserver documents and this proves.
	reenter func()
}

func (o *recordingObserver) ImageIndexChanged(c IndexChange) {
	if o.reenter != nil {
		o.reenter()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.changes = append(o.changes, c)
}

func (o *recordingObserver) snapshot() []IndexChange {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]IndexChange(nil), o.changes...)
}

// watchedIndex builds a real on-disk FileIndex with an observer attached.
func watchedIndex(t *testing.T) (*Cache, *FileIndex, *recordingObserver) {
	t.Helper()
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	obs := &recordingObserver{}
	x, err := NewFileIndex(cache, WithIndexObserver(obs))
	if err != nil {
		t.Fatalf("NewFileIndex: %v", err)
	}
	return cache, x, obs
}

// watchedPlatform is the NORMALISED native key. It is normalised in the fixture
// because that is the key Record files under (it normalises before it hashes the
// name) while Remove unlinks the key it is handed verbatim — so a row that mixed
// the two spellings would be asserting an asymmetry, not the seam.
var watchedPlatform = Platform{OS: "darwin", Architecture: "arm64"}.Normalize()

// watchEntry is a minimal recordable entry for ref.
func watchEntry(ref string) IndexEntry {
	return IndexEntry{
		Reference: ref,
		Platform:  watchedPlatform,
		Manifest: &runtimev1.ImageManifest{
			Reference: ref,
			Config:    &runtimev1.Descriptor{Digest: "sha256:" + zeroHex, Size: 2},
		},
	}
}

const zeroHex = "0000000000000000000000000000000000000000000000000000000000000000"

// TestIndexObserverSeesEveryCommittedChange is the gate for slice 3, driven at
// the index itself: every mutation the daemon has is Record or Remove, so the
// four call sites (pull, load, tag, untag) are covered by covering these two.
func TestIndexObserverSeesEveryCommittedChange(t *testing.T) {
	ctx := context.Background()
	native := watchedPlatform

	t.Run("a record notifies with the key it wrote", func(t *testing.T) {
		_, x, obs := watchedIndex(t)
		e := watchEntry("example.com/app:v1")
		if err := x.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
		got := obs.snapshot()
		if len(got) != 1 {
			t.Fatalf("changes = %+v, want exactly 1", got)
		}
		if got[0].Op != IndexRecorded || got[0].Reference != e.Reference || got[0].Platform != native {
			t.Errorf("change = %+v, want {recorded %q %s}", got[0], e.Reference, native)
		}
	})

	t.Run("a REPLACEMENT of an existing key notifies too", func(t *testing.T) {
		// A replacement re-points a name. An observer that treated it as a no-op
		// would keep serving the previous manifest for a name that now resolves
		// elsewhere.
		_, x, obs := watchedIndex(t)
		e := watchEntry("example.com/app:v1")
		for i := 0; i < 2; i++ {
			if err := x.Record(ctx, e); err != nil {
				t.Fatalf("Record %d: %v", i, err)
			}
		}
		if got := obs.snapshot(); len(got) != 2 {
			t.Errorf("changes = %+v, want 2", got)
		}
	})

	t.Run("a removal notifies with the key it unlinked", func(t *testing.T) {
		_, x, obs := watchedIndex(t)
		e := watchEntry("example.com/app:v1")
		if err := x.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
		removed, err := x.Remove(ctx, e.Reference, native)
		if err != nil || !removed {
			t.Fatalf("Remove = %v, %v; want true, nil", removed, err)
		}
		got := obs.snapshot()
		if len(got) != 2 {
			t.Fatalf("changes = %+v, want 2 (the record and the removal)", got)
		}
		if got[1].Op != IndexRemoved || got[1].Reference != e.Reference || got[1].Platform != native {
			t.Errorf("change = %+v, want {removed %q %s}", got[1], e.Reference, native)
		}
		// A removal is keyed, so it does not read back what it deleted.
		if got[1].Descriptor != nil {
			t.Errorf("removal carried a descriptor %+v; it is documented always nil", got[1].Descriptor)
		}
	})

	t.Run("a removal that removed NOTHING is not a change", func(t *testing.T) {
		_, x, obs := watchedIndex(t)
		removed, err := x.Remove(ctx, "example.com/absent:v1", native)
		if err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if removed {
			t.Fatal("Remove reported an absent key as removed")
		}
		if got := obs.snapshot(); len(got) != 0 {
			t.Errorf("changes = %+v, want none — a change that never happened must not be announced", got)
		}
	})

	t.Run("a FAILED record is not a change", func(t *testing.T) {
		_, x, obs := watchedIndex(t)
		bad := watchEntry("example.com/app:v1")
		bad.Manifest.Reference = "example.com/other:v1" // the manifest disagrees with the key
		if err := x.Record(ctx, bad); err == nil {
			t.Fatal("Record accepted a manifest naming a different reference")
		}
		if got := obs.snapshot(); len(got) != 0 {
			t.Errorf("changes = %+v, want none after a refused write", got)
		}
	})

	t.Run("a nil observer is the default and nothing is called", func(t *testing.T) {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		x, err := NewFileIndex(cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		e := watchEntry("example.com/app:v1")
		if err := x.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if _, err := x.Remove(ctx, e.Reference, native); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	})

	t.Run("the observer may call back into the index", func(t *testing.T) {
		// FileIndex holds no lock across the notification, which is what lets an
		// observer take a snapshot on receipt. A re-entrant List that deadlocked
		// would hang this row rather than fail it — which is the point: a hang is
		// the failure this property exists to rule out.
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		obs := &recordingObserver{}
		var x *FileIndex
		x, err = NewFileIndex(cache, WithIndexObserver(obs))
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		var seen int
		obs.reenter = func() {
			entries, lerr := x.List(ctx)
			if lerr != nil {
				t.Errorf("List from inside the callback: %v", lerr)
			}
			seen = len(entries)
		}
		if err := x.Record(ctx, watchEntry("example.com/app:v1")); err != nil {
			t.Fatalf("Record: %v", err)
		}
		// The change is announced AFTER the commit, so the re-entrant read sees
		// at least the entry it was told about.
		if seen != 1 {
			t.Errorf("the callback's List saw %d entries, want the just-committed 1", seen)
		}
	})
}

// TestIndexObserverUnderConcurrentWrites drives the seam from several goroutines
// so `go test -race` has something to inspect: the observer field is set once at
// construction and read on every mutation, and notification runs outside any
// handle the write held.
func TestIndexObserverUnderConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	_, x, obs := watchedIndex(t)
	const n = 16
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := "example.com/app:v" + string(rune('a'+i))
			if err := x.Record(ctx, watchEntry(ref)); err != nil {
				t.Errorf("Record %s: %v", ref, err)
			}
		}(i)
	}
	wg.Wait()
	if got := obs.snapshot(); len(got) != n {
		t.Errorf("changes = %d, want %d", len(got), n)
	}
}

// TestPullNotifiesTheObserver covers the PULL mutation site through the real
// Puller and a real on-disk index — the site a fake LocalIndex in every other
// pull row deliberately bypasses.
func TestPullNotifiesTheObserver(t *testing.T) {
	cache, x, obs := watchedIndex(t)
	logs := &bytes.Buffer{}
	p, err := NewPuller(cache, (&stubFetch{img: nativeImage(t)}).fetch, x,
		WithFreeBytes(fixedFreeBytes(64<<30)),
		WithPullLogger(slog.New(slog.NewTextHandler(logs, nil))))
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	const ref = "example.com/app:v1"
	if _, err := p.Pull(context.Background(), ref, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	got := obs.snapshot()
	if len(got) != 1 || got[0].Op != IndexRecorded || got[0].Reference != ref {
		t.Fatalf("changes = %+v, want one recorded %q", got, ref)
	}
	// A pull records the manifest descriptor, so the change carries it — this is
	// the half a removal cannot report.
	if got[0].Descriptor.GetDigest() == "" {
		t.Errorf("the pull's change carried no manifest descriptor: %+v", got[0])
	}
}
