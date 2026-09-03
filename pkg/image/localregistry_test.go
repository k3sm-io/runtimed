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
	"errors"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// nodeRegistry is the node's own ingest registry authority in these rows.
const nodeRegistry = "localhost:6450"

// refFetch is a FetchFunc answering per REFERENCE, so a row states which
// registry holds which content and then asserts exactly which references were
// asked for, in order. It is the only way to see the attempt ORDER, which is the
// whole of what this slice adds.
type refFetch struct {
	byRef map[string]ggcrv1.Image
	// miss is what an unknown reference answers with. A 404 is the default; a
	// row that needs a definitive answer sets its own.
	miss  error
	asked []string
	creds []*RegistryCredential
}

func newRefFetch() *refFetch {
	return &refFetch{byRef: make(map[string]ggcrv1.Image)}
}

func (f *refFetch) fetch(_ context.Context, ref string, cred *RegistryCredential, _ PlatformPolicy) (ggcrv1.Image, error) {
	f.asked = append(f.asked, ref)
	f.creds = append(f.creds, cred)
	if img, ok := f.byRef[ref]; ok {
		return img, nil
	}
	if f.miss != nil {
		return nil, f.miss
	}
	return nil, registryStatus(http.StatusNotFound)
}

// localPuller builds a Puller with the node's ingest registry wired.
func localPuller(t *testing.T, cache *Cache, index LocalIndex, fetch FetchFunc, host string, src MirrorSource, mf MirrorFetchFunc, logs *bytes.Buffer) *Puller {
	t.Helper()
	opts := []PullerOption{
		WithFreeBytes(fixedFreeBytes(64 << 30)),
		WithPullLogger(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	}
	if host != "" {
		opts = append(opts, WithLocalRegistry(host))
	}
	if src != nil || mf != nil {
		opts = append(opts, WithMirrors(src, mf))
	}
	p, err := NewPuller(cache, fetch, index, opts...)
	if err != nil {
		t.Fatalf("NewPuller: %v", err)
	}
	return p
}

// TestBareNameGate pins WHICH references the local-first attempt applies to.
// The complement matters as much as the set: any reference that names a registry
// of its own must be untouched, or a manifest that says where it wants its image
// from stops getting it.
func TestBareNameGate(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		want bool
		why  string
	}{
		{"app", true, "no registry, no repository path"},
		{"app:v1", true, "a tag is not a registry"},
		{"team/app:v1", true, "'team' has no '.' and no ':', so ggcr reads it as a repository element"},
		{"team/sub/app:v1", true, "still no registry component"},
		{"localhost/team/app:v1", true, "bare 'localhost' is a repository element to ggcr, not this node"},
		{"app@sha256:1111111111111111111111111111111111111111111111111111111111111111", true, "a digest is not a registry"},
		{"docker.io/library/nginx:1.27", false, "an explicit registry is honoured verbatim"},
		{"localhost:6450/team/app:v1", false, "already names this node"},
		{"ghcr.io/k3sm-io/app:v1", false, "an explicit registry"},
		{"registry.example:5000/app", false, "an explicit registry with a port"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			if got := bareName(tc.ref); got != tc.want {
				t.Errorf("bareName(%q) = %v, want %v — %s", tc.ref, got, tc.want, tc.why)
			}
		})
	}
}

// TestLocalRegistryAttemptOrder is the behavioural gate for slice 2: what is
// asked for, in what order, and — the half that matters more — every failure
// class on which the upstream reference must NOT be consulted.
func TestLocalRegistryAttemptOrder(t *testing.T) {
	const bare = "app:v1"
	localSpelling := nodeRegistry + "/" + bare

	t.Run("the node's registry is asked FIRST and answers", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		f := newRefFetch()
		f.byRef[localSpelling] = nativeImage(t)
		// Upstream ALSO has an image of the same name. The row is meaningless
		// without it: it is what makes "first" observable.
		f.byRef[bare] = nativeImage(t)

		p := localPuller(t, cache, index, f.fetch, nodeRegistry, nil, nil, logs)
		res, err := p.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("Pull(%q): %v", bare, err)
		}
		if len(f.asked) != 1 || f.asked[0] != localSpelling {
			t.Fatalf("fetches = %v, want exactly [%q] — the upstream reference must not be touched on a local hit", f.asked, localSpelling)
		}
		// The index records what the USER wrote, so IfNotPresent finds it and a
		// listing shows it under that name.
		if got := res.Manifest.GetReference(); got != bare {
			t.Errorf("recorded reference = %q, want the user's original %q", got, bare)
		}
		if _, ok := index.refs[bare]; !ok {
			t.Errorf("index recorded %v, want %q", keysOf(index.refs), bare)
		}
		if _, ok := index.refs[localSpelling]; ok {
			t.Errorf("index recorded the rewritten spelling %q; the node registry is transport, not identity", localSpelling)
		}
	})

	t.Run("a miss falls through to the upstream reference, unchanged", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			miss error
		}{
			{"404 — the miss this exists for", registryStatus(http.StatusNotFound)},
			{"500 — the registry is present but not serving", registryStatus(http.StatusInternalServerError)},
			{"503 — starting or wedged", registryStatus(http.StatusServiceUnavailable)},
			{"connection refused — nothing is listening", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cache, index, logs := newFixtureStore(t)
				f := newRefFetch()
				f.miss = tc.miss
				f.byRef[bare] = nativeImage(t)

				p := localPuller(t, cache, index, f.fetch, nodeRegistry, nil, nil, logs)
				res, err := p.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
				if err != nil {
					t.Fatalf("Pull(%q): %v", bare, err)
				}
				want := []string{localSpelling, bare}
				if len(f.asked) != 2 || f.asked[0] != want[0] || f.asked[1] != want[1] {
					t.Fatalf("fetches = %v, want %v", f.asked, want)
				}
				if got := res.Manifest.GetReference(); got != bare {
					t.Errorf("recorded reference = %q, want %q", got, bare)
				}
			})
		}
	})

	t.Run("a DEFINITIVE answer from the node registry stands", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			miss error
		}{
			{"401 — the reference exists and this node is not allowed it", registryStatus(http.StatusUnauthorized)},
			{"403", registryStatus(http.StatusForbidden)},
			{"a DENIED diagnostic under a 404", registryDiagnostic(http.StatusNotFound, transport.DeniedErrorCode)},
			{"400 — the request itself is wrong", registryStatus(http.StatusBadRequest)},
			{"429 — come back to the SAME registry later", registryStatus(http.StatusTooManyRequests)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cache, index, logs := newFixtureStore(t)
				f := newRefFetch()
				f.miss = tc.miss
				// Upstream HAS the image. If the fall-through were a bare
				// "if err != nil" this pull would succeed, which is exactly the
				// confused-deputy move the taxonomy exists to prevent.
				f.byRef[bare] = nativeImage(t)

				p := localPuller(t, cache, index, f.fetch, nodeRegistry, nil, nil, logs)
				if _, err := p.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err == nil {
					t.Fatal("pull succeeded upstream after the node's own registry gave a definitive answer")
				}
				if len(f.asked) != 1 || f.asked[0] != localSpelling {
					t.Errorf("fetches = %v, want only [%q]", f.asked, localSpelling)
				}
			})
		}
	})

	t.Run("the sentinel never escapes to the caller", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		f := newRefFetch() // both references miss
		p := localPuller(t, cache, index, f.fetch, nodeRegistry, nil, nil, logs)
		_, err := p.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err == nil {
			t.Fatal("pull succeeded with the image on neither registry")
		}
		if errors.Is(err, errLocalRegistryMiss) {
			t.Errorf("pull error = %v; the internal fall-through signal must not reach the caller", err)
		}
	})

	t.Run("no CREDENTIAL is replayed to the node's registry", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		f := newRefFetch()
		f.byRef[bare] = nativeImage(t)
		cred := &RegistryCredential{Username: "u", Password: "p"}

		p := localPuller(t, cache, index, f.fetch, nodeRegistry, nil, nil, logs)
		if _, err := p.Pull(context.Background(), bare, cred, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS); err != nil {
			t.Fatalf("Pull: %v", err)
		}
		if len(f.creds) != 2 {
			t.Fatalf("fetches = %v, want the local attempt then the upstream one", f.asked)
		}
		// The imagePullSecret was resolved for a BARE name — a Docker Hub
		// credential. Sending it to this node's registry would send a secret
		// scoped to one host to a host the pod's author never named.
		if f.creds[0] != nil {
			t.Errorf("the node-registry attempt carried a credential (%+v); it must be anonymous", f.creds[0])
		}
		// ...and the upstream attempt still gets it.
		if f.creds[1] != cred {
			t.Errorf("the upstream attempt credential = %+v, want the caller's %+v", f.creds[1], cred)
		}
	})
}

// TestLocalRegistryOffIsIdentical is the feature-off control: with no local
// registry configured, a bare name resolves through exactly one fetch of exactly
// the reference the caller passed, and the result is indistinguishable from a
// puller that has never heard of this option.
func TestLocalRegistryOffIsIdentical(t *testing.T) {
	const bare = "app:v1"

	offCache, offIndex, offLogs := newFixtureStore(t)
	off := newRefFetch()
	img := nativeImage(t)
	off.byRef[bare] = img
	offP := localPuller(t, offCache, offIndex, off.fetch, "", nil, nil, offLogs)
	offRes, err := offP.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if err != nil {
		t.Fatalf("pull with no local registry: %v", err)
	}
	if len(off.asked) != 1 || off.asked[0] != bare {
		t.Fatalf("fetches = %v, want exactly [%q] — an unconfigured node must not rewrite anything", off.asked, bare)
	}

	// The same pull on a node whose registry misses must produce the identical
	// result: the fall-through is transparent, not merely eventually successful.
	onCache, onIndex, onLogs := newFixtureStore(t)
	on := newRefFetch()
	on.byRef[bare] = img
	onP := localPuller(t, onCache, onIndex, on.fetch, nodeRegistry, nil, nil, onLogs)
	onRes, err := onP.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
	if err != nil {
		t.Fatalf("pull with a missing local registry: %v", err)
	}
	if offRes.Descriptor.GetDigest() != onRes.Descriptor.GetDigest() {
		t.Errorf("image id differs: %s off, %s on", offRes.Descriptor.GetDigest(), onRes.Descriptor.GetDigest())
	}
	if offRes.Manifest.GetReference() != onRes.Manifest.GetReference() {
		t.Errorf("reference differs: %q vs %q", offRes.Manifest.GetReference(), onRes.Manifest.GetReference())
	}
	if offRes.Platform != onRes.Platform || offIndex.records != onIndex.records {
		t.Errorf("result differs: %+v (%d records) vs %+v (%d records)", offRes, offIndex.records, onRes, onIndex.records)
	}
}

// TestLocalRegistryBrokersToMirrors: the node's registry is cluster-local by
// construction, so a miss against it consults the peers before the pull gives up
// on the cluster and goes upstream — and the peer's spelling still never becomes
// the image's identity.
func TestLocalRegistryBrokersToMirrors(t *testing.T) {
	const bare = "app:v1"
	peer := Mirror{Host: "100.64.1.1:6450", PlainHTTP: true}

	t.Run("a peer answers the bare name and the user's reference is recorded", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		f := newRefFetch() // neither the node registry nor upstream has it
		src := &fixedMirrors{list: []Mirror{peer}}
		mf := newMirrorFetcher()
		mf.byRef[peer.Host+"/"+bare] = nativeImage(t)

		p := localPuller(t, cache, index, f.fetch, nodeRegistry, src, mf.fetch, logs)
		res, err := p.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("Pull(%q): %v", bare, err)
		}
		if len(mf.asked) != 1 || mf.asked[0] != peer.Host+"/"+bare {
			t.Errorf("peer was asked for %v, want [%q]", mf.asked, peer.Host+"/"+bare)
		}
		if got := res.Manifest.GetReference(); got != bare {
			t.Errorf("recorded reference = %q, want the user's original %q", got, bare)
		}
		if _, ok := index.refs[peer.Host+"/"+bare]; ok {
			t.Errorf("index recorded the PEER spelling; a mirror is transport, not identity")
		}
		// Upstream was never reached: the cluster answered.
		if len(f.asked) != 1 {
			t.Errorf("fetches = %v, want only the node-registry attempt", f.asked)
		}
	})

	t.Run("peers that also miss still fall through upstream", func(t *testing.T) {
		cache, index, logs := newFixtureStore(t)
		f := newRefFetch()
		f.byRef[bare] = nativeImage(t)
		src := &fixedMirrors{list: []Mirror{peer}}
		mf := newMirrorFetcher() // the peer has nothing

		p := localPuller(t, cache, index, f.fetch, nodeRegistry, src, mf.fetch, logs)
		res, err := p.Pull(context.Background(), bare, nil, nativePolicy(), runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS)
		if err != nil {
			t.Fatalf("Pull(%q): %v", bare, err)
		}
		if len(f.asked) != 2 || f.asked[1] != bare {
			t.Errorf("fetches = %v, want the node registry then the upstream reference", f.asked)
		}
		if got := res.Manifest.GetReference(); got != bare {
			t.Errorf("recorded reference = %q, want %q", got, bare)
		}
	})
}

// TestNewPullerValidatesLocalRegistry: the host must be one this node can
// legitimately call its own, checked at construction.
func TestNewPullerValidatesLocalRegistry(t *testing.T) {
	cache, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts []PullerOption
		ok   bool
	}{
		{"no local registry is the default", nil, true},
		{"a loopback name", []PullerOption{WithLocalRegistry("localhost:6450")}, true},
		{"a loopback address", []PullerOption{WithLocalRegistry("127.0.0.1:6450")}, true},
		{
			"an authority admitted as a cluster registry",
			[]PullerOption{
				WithClusterRegistries([]string{"registry.k3sm-system.svc.cluster.local:6450"}, RemoteInsecureFetch),
				WithLocalRegistry("registry.k3sm-system.svc.cluster.local:6450"),
			},
			true,
		},
		{"a malformed authority", []PullerOption{WithLocalRegistry("registry")}, false},
		{"an authority carrying a path", []PullerOption{WithLocalRegistry("localhost:6450/evil")}, false},
		{
			"a registry this node was never told is its own",
			[]PullerOption{WithLocalRegistry("registry.example:5000")},
			false,
		},
		{
			"an admitted authority on a DIFFERENT port",
			[]PullerOption{
				WithClusterRegistries([]string{"registry.svc:6450"}, RemoteInsecureFetch),
				WithLocalRegistry("registry.svc:5000"),
			},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPuller(cache, RemoteFetch, NoLocalIndex{}, tc.opts...)
			if tc.ok && err != nil {
				t.Fatalf("NewPuller: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("NewPuller returned %+v, want a refusal", p)
			}
		})
	}
}
