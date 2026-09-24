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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestFileIndexCommitConcurrentSameKey is the gate for concurrent writers of ONE
// (reference x platform) key. Two pulls of the same image on one node both end
// in Record for the same key, and every such commit goes through the same
// ".index-<name>" temp. Unserialized, one writer's rename moves the temp out
// from under the other (whose rename then fails ENOENT, failing its pull), and a
// writer that committed first can notify last, leaving an observer believing a
// resolution the disk no longer holds.
//
// Each writer records a DIFFERENT manifest, so both properties are observable:
// every Record returns nil, and the last notification the observer received for
// the key names the descriptor a Lookup then reads back. slowObserver adds the
// in-callback read-back that makes the ordering half fail reliably, rather than
// by scheduler luck, if a notification ever escapes the key's writer stripe.
func TestFileIndexCommitConcurrentSameKey(t *testing.T) {
	const (
		writers    = 8
		iterations = 25
	)
	ctx := context.Background()
	want, err := Candidates(nativePolicy())
	if err != nil || len(want) == 0 {
		t.Fatalf("Candidates(native) = %v, %v", want, err)
	}
	platform := want[0]
	const ref = "example.com/app:v1"

	for iter := 0; iter < iterations; iter++ {
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatalf("NewCache: %v", err)
		}
		obs := &slowObserver{ref: ref, p: platform}
		x, err := NewFileIndex(cache, WithIndexObserver(obs))
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		// Set before any writer starts; the goroutine start below orders it.
		obs.x = x

		recorded := make(map[string]bool, writers)
		entries := make([]IndexEntry, writers)
		for g := range entries {
			entries[g] = concurrentEntry(ref, platform, iter, g)
			recorded[entries[g].Descriptor.GetDigest()] = true
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, writers)
		for g := range entries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[g] = x.Record(ctx, entries[g])
			}()
		}
		close(start)
		wg.Wait()

		for g, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d: writer %d: Record: %v", iter, g, err)
			}
		}

		got, ok, err := x.Lookup(ctx, ref, nativePolicy())
		if err != nil || !ok {
			t.Fatalf("iteration %d: Lookup after the race = ok %v, err %v; want the committed entry", iter, ok, err)
		}
		if got.Reference != ref || got.Platform != platform {
			t.Fatalf("iteration %d: Lookup returned key (%q, %s), want (%q, %s)", iter, got.Reference, got.Platform, ref, platform)
		}
		if got.Descriptor == nil || !recorded[got.Descriptor.GetDigest()] {
			t.Fatalf("iteration %d: Lookup returned descriptor %v, which no writer recorded", iter, got.Descriptor)
		}
		if got.Manifest.GetReference() != ref {
			t.Fatalf("iteration %d: recorded manifest names %q, want %q", iter, got.Manifest.GetReference(), ref)
		}

		obs.mu.Lock()
		stale := append([]string(nil), obs.stale...)
		obs.mu.Unlock()
		if len(stale) > 0 {
			t.Fatalf("iteration %d: a same-key commit landed while a notification was being delivered: %v", iter, stale)
		}

		changes := obs.snapshot()
		if len(changes) != writers {
			t.Fatalf("iteration %d: observer saw %d changes, want %d (one per successful Record)", iter, len(changes), writers)
		}
		last := changes[len(changes)-1]
		if last.Op != IndexRecorded || last.Reference != ref || last.Platform != platform {
			t.Fatalf("iteration %d: last change %+v is not a record of the raced key", iter, last)
		}
		if last.Descriptor.GetDigest() != got.Descriptor.GetDigest() {
			t.Fatalf("iteration %d: the last notification named %s but the index holds %s: a writer notified out of commit order",
				iter, last.Descriptor.GetDigest(), got.Descriptor.GetDigest())
		}

		// No writer's temp outlives the race: each commit renamed its temp away
		// or removed it, so the crash-reuse bound is the only way one survives.
		names, err := os.ReadDir(cache.IndexRoot())
		if err != nil {
			t.Fatalf("iteration %d: read index dir: %v", iter, err)
		}
		for _, n := range names {
			if strings.HasPrefix(n.Name(), ".index-") {
				t.Fatalf("iteration %d: temp %s left behind after every Record returned", iter, n.Name())
			}
		}
	}
}

// slowObserver records every change and, on the FIRST notification it is
// handed, waits and then reads the key back to check the index still holds what
// the notification announced.
//
// That read is what makes the ordering half of the gate non-vacuous. Under the
// stripe no same-key writer can commit while a notification runs, so the key
// holds the notified descriptor for the whole callback, however long it takes.
// Were a notification to run outside the stripe, the next writer would commit
// during the wait (it is several commits long), and the read would catch the
// index already holding a different resolution than the one just announced: the
// same window that lets a stale notification arrive last. Waiting on the first
// call only bounds the cost to one delay per iteration.
type slowObserver struct {
	x   *FileIndex
	ref string
	p   Platform

	mu    sync.Mutex
	calls int
	// changes is every notification, in the order this observer received it.
	changes []IndexChange
	// stale records a notification whose key, read back from inside the
	// callback, held something other than the announced descriptor.
	stale []string
}

// firstNotifyDelay is long against one commit (a small write plus an fsync) so
// an out-of-stripe commit lands inside it as a matter of course, not a
// scheduler accident, and short enough that 25 iterations stay under a second.
const firstNotifyDelay = 20 * time.Millisecond

func (o *slowObserver) ImageIndexChanged(c IndexChange) {
	o.mu.Lock()
	o.calls++
	first := o.calls == 1
	o.mu.Unlock()
	if first {
		time.Sleep(firstNotifyDelay)
		// Readers take no lock, so this read is legal from the callback (see
		// IndexObserver) and sees whatever is committed right now.
		got, ok, err := o.x.Get(context.Background(), o.ref, o.p)
		if err != nil || !ok || got.Descriptor.GetDigest() != c.Descriptor.GetDigest() {
			o.mu.Lock()
			o.stale = append(o.stale, fmt.Sprintf("notified %s, index held %s (ok %v, err %v)",
				c.Descriptor.GetDigest(), got.Descriptor.GetDigest(), ok, err))
			o.mu.Unlock()
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.changes = append(o.changes, c)
}

func (o *slowObserver) snapshot() []IndexChange {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]IndexChange(nil), o.changes...)
}

// concurrentEntry is a recordable entry for ref whose manifest bytes (and so
// digest) are unique to (iter, writer), so the winner of a race is identifiable.
func concurrentEntry(ref string, p Platform, iter, writer int) IndexEntry {
	raw := []byte(fmt.Sprintf(`{"schemaVersion":2,"iteration":%d,"writer":%d}`, iter, writer))
	sum := sha256.Sum256(raw)
	return IndexEntry{
		Reference: ref,
		Platform:  p,
		Manifest: &runtimev1.ImageManifest{
			Reference: ref,
			Config:    &runtimev1.Descriptor{Digest: "sha256:" + zeroHex, Size: 2},
		},
		Descriptor: &runtimev1.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    "sha256:" + hex.EncodeToString(sum[:]),
			Size:      int64(len(raw)),
		},
		ManifestRaw: raw,
	}
}
