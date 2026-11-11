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
	"os"
	"testing"
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
