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
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestDepsLocalRegistryHostReachesThePuller is the wiring gate for
// Deps.LocalRegistryHost, driven through the puller runtime.New builds when
// Deps.Puller is absent — the DAEMON's own wiring, against an in-process
// registry on loopback.
//
// It is the one row that fails if the seam is threaded to nothing: every
// unit-level row in pkg/image fakes the fetcher, so all of them stay green
// against a runtime that never passes image.WithLocalRegistry at all. The pod
// asks for a BARE name that exists only on this node's registry; if the option
// did not reach the puller the reference would normalise to Docker Hub and the
// resolve would fail.
func TestDepsLocalRegistryHostReachesThePuller(t *testing.T) {
	t.Run("a bare name resolves against the node's own registry", func(t *testing.T) {
		nodeRegistry := testRegistryHost(t)
		pushPlatformImage(t, nodeRegistry, "app", "darwin", "arm64")

		rt, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{LocalRegistryHost: nodeRegistry}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		p := &pod{box: hostBinBox(rt, "pod-localreg"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		c := &runtimev1.Container{Name: "app", Image: "app:v1", Command: []string{"/app"}}
		if _, err := rt.resolveBinary(context.Background(), p, t.TempDir(), c); err != nil {
			t.Fatalf("resolveBinary of a bare name against the node registry: %v", err)
		}
		// The index records what the POD wrote, so a later IfNotPresent serve
		// finds it under that name and `image ls` shows the operator's spelling.
		policy := image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		if _, ok, err := rt.index.Lookup(context.Background(), "app:v1", policy); err != nil || !ok {
			t.Errorf("index lookup of the ORIGINAL reference \"app:v1\" = ok %v, err %v; want it recorded", ok, err)
		}
		rewritten := nodeRegistry + "/app:v1"
		if _, ok, err := rt.index.Lookup(context.Background(), rewritten, policy); err == nil && ok {
			t.Errorf("index recorded the rewritten spelling %q; the node registry is transport, not identity", rewritten)
		}
	})

	t.Run("a host this node cannot call its own fails startup", func(t *testing.T) {
		// Neither a loopback spelling nor an admitted cluster registry: accepting
		// it would let a node be configured to resolve every bare name against a
		// third-party registry.
		_, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{LocalRegistryHost: "registry.example:5000"}))
		if err == nil {
			t.Fatal("New accepted a local registry host that is not cluster-local")
		}
		if !strings.Contains(err.Error(), "local registry host") {
			t.Errorf("New error = %v, want it to name the local registry host", err)
		}
	})

	t.Run("an admitted cluster registry may be the node's own registry", func(t *testing.T) {
		if _, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{
			ClusterRegistries: []string{"registry.k3sm-system.svc.cluster.local:6450"},
			LocalRegistryHost: "registry.k3sm-system.svc.cluster.local:6450",
		})); err != nil {
			t.Fatalf("New: %v", err)
		}
	})

	t.Run("no host is the default and changes nothing", func(t *testing.T) {
		if _, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{})); err != nil {
			t.Fatalf("New with no local registry host: %v", err)
		}
	})
}
