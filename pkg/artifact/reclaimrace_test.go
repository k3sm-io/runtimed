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
	"errors"
	"os"
	"testing"

	"k3sm.io/runtimed/pkg/image"
)

// TestPullRefetchesBlobUnlinkedBeforeHold: a cache-hit pull whose presence
// check passed can still lose a blob to a reclaim pass that planned it before
// the pull's lease existed. The pull must not hand back a record (and a pod
// hold) naming an absent blob: it re-checks once the hold is written and
// refetches what is gone.
func TestPullRefetchesBlobUnlinkedBeforeHold(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("config.json", "{\"a\":1}"), modelLayer("w/model.safetensors", "weights"))
	p := e.puller(t)
	ctx := context.Background()

	// Warm the cache, so the next pull is a pure cache hit.
	warm, err := p.PullForPod(ctx, testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("warm PullForPod: %v", err)
	}
	warm.Lease.Release()

	victim := digestOfBytes([]byte("weights"))
	if !e.cache.Has(victim) {
		t.Fatalf("warm pull did not commit %s", victim)
	}
	unlinked := 0
	p.afterPresence = func() {
		if unlinked > 0 {
			return
		}
		unlinked++
		path, err := e.cache.BlobPath(victim)
		if err != nil {
			t.Errorf("BlobPath: %v", err)
			return
		}
		if err := os.Remove(path); err != nil {
			t.Errorf("unlink %s: %v", victim, err)
		}
	}

	res, err := p.PullForPod(ctx, testRef, nil, volume, nil)
	if err != nil {
		t.Fatalf("PullForPod after the unlink: %v", err)
	}
	defer res.Lease.Release()
	if unlinked != 1 {
		t.Fatalf("the hook ran %d times, want 1", unlinked)
	}
	for _, d := range append([]string{res.ConfigDigest}, res.LayerDigests...) {
		if !e.cache.Has(d) {
			t.Errorf("blob %s the result names is absent after the pull", d)
		}
	}
}

// TestPullHoldRunsBeforeRecheck: WithHold's callback runs after the record
// and before the re-check, so a blob unlinked before the hold is refetched
// once the hold names it.
func TestPullHoldRunsBeforeRecheck(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w/model.safetensors", "weights"))
	p := e.puller(t)
	ctx := context.Background()
	warm, err := p.PullForPod(ctx, testRef, nil, volume, nil)
	if err != nil {
		t.Fatal(err)
	}
	warm.Lease.Release()

	victim := digestOfBytes([]byte("weights"))
	p.afterPresence = func() {
		path, _ := e.cache.BlobPath(victim)
		_ = os.Remove(path)
	}
	var sawAbsent, called bool
	res, err := p.PullForPod(ctx, testRef, nil, volume, nil, WithHold(func(_ context.Context, r *Result) error {
		called = true
		sawAbsent = !e.cache.Has(victim)
		if _, ok, err := p.LookupRecord(ctx, testRef, r.ArtifactType); err != nil || !ok {
			t.Errorf("hold ran before the record: %v %v", ok, err)
		}
		return nil
	}))
	if err != nil {
		t.Fatalf("PullForPod: %v", err)
	}
	defer res.Lease.Release()
	if !called || !sawAbsent {
		t.Fatalf("hold called %v, saw the blob absent %v; want the hold before the re-check", called, sawAbsent)
	}
	if !e.cache.Has(victim) || !res.Fetched {
		t.Fatalf("blob present %v, fetched %v after the re-check", e.cache.Has(victim), res.Fetched)
	}
}

// TestPullHoldErrorFailsPull: a failed hold fails the pull with its error.
func TestPullHoldErrorFailsPull(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w/model.safetensors", "weights"))
	p := e.puller(t)
	boom := errors.New("hold refused")
	_, err := p.PullForPod(context.Background(), testRef, nil, volume, nil, WithHold(func(context.Context, *Result) error { return boom }))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the hold's error", err)
	}
}

// vanishingBlobs reports one digest absent forever, as if every commit of it
// were reclaimed at once.
type vanishingBlobs struct {
	*image.Cache
	digest string
}

func (v vanishingBlobs) Has(d string) bool { return d != v.digest && v.Cache.Has(d) }

// TestPullRefetchIsBounded: a blob still absent after one refetch fails the
// pull with ErrBlobReclaimed rather than looping.
func TestPullRefetchIsBounded(t *testing.T) {
	e := newEnv(t)
	e.fetch.publishModel(testRef, modelLayer("w/model.safetensors", "weights"))
	victim := digestOfBytes([]byte("weights"))
	p, err := New(Config{
		RegistryHost: testHost,
		PartialDir:   e.partial,
		StorePath:    e.cache.Root(),
		FreeBytes:    func(string) (uint64, error) { return e.free.Load(), nil },
		FloorBytes:   100,
	}, Deps{Blobs: vanishingBlobs{Cache: e.cache, digest: victim}, Leases: e.cache, Reclaimer: e.reclaim, Index: e.index, Fetcher: e.fetch})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.PullForPod(context.Background(), testRef, nil, volume, nil)
	if !errors.Is(err, ErrBlobReclaimed) {
		t.Fatalf("err = %v, want ErrBlobReclaimed", err)
	}
}
