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
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPullRecordsIndexDigest drives the production fetch (RemoteFetch) and the
// real ingest against an in-process registry and a real FileIndex: a tag that
// resolves to a multi-platform index records that index's digest on the
// manifest (ImageManifest.index_digest), the cached entry carries it, and a warm
// serve from the cache reports it again. A single-manifest tag records none.
func TestPullRecordsIndexDigest(t *testing.T) {
	host := testRegistry(t)
	darwinARM64 := testImage(t, "darwin", "arm64", "")
	linuxAMD64 := testImage(t, "linux", "amd64", "")

	headDigest := func(t *testing.T, ref string) string {
		t.Helper()
		r, err := name.ParseReference(ref)
		if err != nil {
			t.Fatal(err)
		}
		d, err := remote.Head(r)
		if err != nil {
			t.Fatalf("head %s: %v", ref, err)
		}
		return d.Digest.String()
	}

	newPuller := func(t *testing.T) (*Puller, *FileIndex) {
		t.Helper()
		cache, err := NewCache(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		idx, err := NewFileIndex(cache)
		if err != nil {
			t.Fatal(err)
		}
		return mustPullerIndex(t, cache, RemoteFetch, idx), idx
	}

	pull := func(t *testing.T, p *Puller, ref string, policy runtimev1.ImagePullPolicy) *PullResult {
		t.Helper()
		res, err := p.Pull(context.Background(), ref, nil, nativePolicy(), policy)
		if err != nil {
			t.Fatalf("Pull(%s): %v", ref, err)
		}
		res.Lease.Release()
		return res
	}

	lookup := func(t *testing.T, idx *FileIndex, ref string) IndexEntry {
		t.Helper()
		e, ok, err := idx.Lookup(context.Background(), ref, nativePolicy())
		if err != nil || !ok {
			t.Fatalf("Lookup(%s) = ok %v, err %v; want the recorded entry", ref, ok, err)
		}
		return e
	}

	t.Run("a tag resolving to an index records the index digest", func(t *testing.T) {
		ref := pushIndex(t, host, "multiidx",
			child(linuxAMD64, ggcrPlatform("linux", "amd64", "")),
			child(darwinARM64, ggcrPlatform("darwin", "arm64", "")),
		)
		want := headDigest(t, ref)
		p, idx := newPuller(t)

		res := pull(t, p, ref, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if got := res.Manifest.GetIndexDigest(); got != want {
			t.Errorf("pull result index_digest = %q, want the index digest %q", got, want)
		}
		if got := res.Descriptor.GetDigest(); got != mustDigest(t, darwinARM64) || got == want {
			t.Errorf("manifest descriptor digest = %q, want the selected child %q", got, mustDigest(t, darwinARM64))
		}
		if got := lookup(t, idx, ref).Manifest.GetIndexDigest(); got != want {
			t.Errorf("cached entry index_digest = %q, want %q", got, want)
		}

		warm := pull(t, p, ref, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT)
		if warm.Fetched {
			t.Fatal("the IfNotPresent pull contacted the registry; want a serve from the cache")
		}
		if got := warm.Manifest.GetIndexDigest(); got != want {
			t.Errorf("warm serve index_digest = %q, want %q", got, want)
		}
	})

	t.Run("a reference pinned to an index records that digest", func(t *testing.T) {
		tagged := pushIndex(t, host, "pinnedidx",
			child(darwinARM64, ggcrPlatform("darwin", "arm64", "")),
		)
		want := headDigest(t, tagged)
		ref := host + "/pinnedidx@" + want
		p, idx := newPuller(t)

		res := pull(t, p, ref, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if got := res.Manifest.GetIndexDigest(); got != want {
			t.Errorf("pull result index_digest = %q, want the pinned index digest %q", got, want)
		}
		if got := lookup(t, idx, ref).Manifest.GetIndexDigest(); got != want {
			t.Errorf("cached entry index_digest = %q, want %q", got, want)
		}
	})

	t.Run("a single-manifest tag records no index digest", func(t *testing.T) {
		ref := pushImage(t, host, "singlemf", darwinARM64)
		p, idx := newPuller(t)

		res := pull(t, p, ref, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if got := res.Manifest.GetIndexDigest(); got != "" {
			t.Errorf("pull result index_digest = %q for a single manifest, want empty", got)
		}
		if got, want := res.Descriptor.GetDigest(), headDigest(t, ref); got != want {
			t.Errorf("manifest descriptor digest = %q, want the served manifest %q", got, want)
		}
		if got := lookup(t, idx, ref).Manifest.GetIndexDigest(); got != "" {
			t.Errorf("cached entry index_digest = %q for a single manifest, want empty", got)
		}
	})
}
