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

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// staticMirrors is a MirrorSource answering with one fixed peer list — the shape
// the embedding control plane supplies once it knows the cluster's peers.
type staticMirrors struct {
	list  []image.Mirror
	calls int
}

func (s *staticMirrors) Mirrors(string) []image.Mirror {
	s.calls++
	return s.list
}

// TestDefaultPullerConsultsClusterMirrors exercises Deps.ImageMirrors through
// the puller runtime.New builds when Deps.Puller is absent — the DAEMON'S own
// wiring, against two in-process registries on loopback.
//
// It is the one test that can fail if the seam is threaded to nothing: every
// unit-level mirror test in pkg/image fakes both fetchers, so all of them stay
// green against a runtime that never passes image.WithMirrors at all. It is also
// the only place the eligibility rule meets a REAL registry answer — the primary
// here returns go-containerregistry's own transport.Error for an absent
// repository, not a hand-built one — so a classification that only matched the
// fixture would show up here.
//
// The negative control is what gives the positive case its meaning: with the
// same two registries and no MirrorSource, the pull must fail.
func TestDefaultPullerConsultsClusterMirrors(t *testing.T) {
	// Both registries are httptest servers on 127.0.0.1, so the primary is a
	// loopback spelling — exactly the "this node's own ingest registry" shape the
	// fallback is gated on — and no external network is touched.
	primaryHost := testRegistryHost(t)
	peerHost := testRegistryHost(t)
	// The image exists ONLY on the peer. The reference the pod asks for names
	// the same repository on this node's own registry, which has never been fed.
	pushPlatformImage(t, peerHost, "team/app", "darwin", "arm64")
	podRef := primaryHost + "/team/app:v1"

	t.Run("with peers wired, the pull is served by the peer", func(t *testing.T) {
		src := &staticMirrors{list: []image.Mirror{{Host: peerHost, PlainHTTP: true}}}
		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{ImageMirrors: src}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		p := &pod{box: hostBinBox(rt, "pod-mirror"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		c := &runtimev1.Container{Name: "app", Image: podRef, Command: []string{"/app"}}
		if _, err := rt.resolveBinary(context.Background(), p, t.TempDir(), c); err != nil {
			t.Fatalf("resolveBinary through a cluster mirror: %v", err)
		}
		if src.calls == 0 {
			t.Error("the mirror source was never consulted")
		}
		// The pod asked for the node-relative reference, so that is the name the
		// node must now hold the image under — a later IfNotPresent serve looks
		// it up by that name, and the peer's spelling would not be found.
		policy := image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		if _, ok, err := rt.index.Lookup(context.Background(), podRef, policy); err != nil || !ok {
			t.Errorf("index lookup of the ORIGINAL reference %q = ok %v, err %v; want it recorded", podRef, ok, err)
		}
		peerRef := peerHost + "/team/app:v1"
		if _, ok, err := rt.index.Lookup(context.Background(), peerRef, policy); err == nil && ok {
			t.Errorf("index recorded the MIRROR reference %q; the peer must never become the image's identity", peerRef)
		}
	})

	t.Run("negative control: with no peers wired, the same pull fails", func(t *testing.T) {
		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		p := &pod{box: hostBinBox(rt, "pod-nomirror"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		c := &runtimev1.Container{Name: "app", Image: podRef, Command: []string{"/app"}}
		if _, err := rt.resolveBinary(context.Background(), p, t.TempDir(), c); err == nil {
			t.Fatal("resolveBinary succeeded with the image on no registry this node was told about")
		}
	})
}
