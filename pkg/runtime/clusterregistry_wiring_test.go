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
	"strings"
	"testing"
)

// TestDepsClusterRegistriesReachThePuller is the wiring gate for
// Deps.ClusterRegistries: the list the embedder supplies must reach the puller
// runtime.New builds, and it must reach it with its plain-HTTP fetcher.
//
// It is asserted through CONSTRUCTION rather than through a live pull, and
// deliberately so. Every httptest registry binds 127.0.0.1, which is already
// cluster-local by the unconditional loopback gate — so a pull-based row would
// pass identically against a runtime that never passes image.WithClusterRegistries
// at all, which is exactly the mis-wiring this row exists to catch. A malformed
// authority is refused only INSIDE image.NewPuller, so a refusal here is proof
// the list was threaded through; and image.NewPuller refuses a set with no
// fetcher, so acceptance of a well-formed set is proof the fetcher went with it.
func TestDepsClusterRegistriesReachThePuller(t *testing.T) {
	t.Run("a malformed authority fails daemon startup", func(t *testing.T) {
		// "registry" carries neither a '.' nor a ':', so go-containerregistry
		// reads it as a repository element and it could never match a parsed
		// reference. A node that accepted it would believe it brokers a spelling
		// it silently never sees.
		_, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{ClusterRegistries: []string{"registry"}}))
		if err == nil {
			t.Fatal("New accepted a malformed cluster-registry authority; the list is not reaching image.NewPuller")
		}
		if !strings.Contains(err.Error(), "cluster registry") {
			t.Errorf("New error = %v, want it to name the cluster registry that was refused", err)
		}
	})

	t.Run("a well-formed set starts, so its fetcher went with it", func(t *testing.T) {
		if _, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{
			ClusterRegistries: []string{"registry.k3sm-system.svc.cluster.local:6450", "10.43.0.7:6450"},
		})); err != nil {
			t.Fatalf("New with a well-formed cluster-registry set: %v", err)
		}
	})

	t.Run("no set is the default and changes nothing", func(t *testing.T) {
		if _, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{})); err != nil {
			t.Fatalf("New with no cluster-registry set: %v", err)
		}
	})

	t.Run("a caller-supplied puller keeps its own pull decisions", func(t *testing.T) {
		// Deps.Puller documents that the mirror and cluster-registry seams are
		// ignored when the caller brings a puller — so even a malformed set must
		// not fail startup, because no puller is built from it.
		if _, err := New(Config{Root: t.TempDir()}, testDeps(t, Deps{
			Puller:            &fakePuller{},
			ClusterRegistries: []string{"registry"},
		})); err != nil {
			t.Fatalf("New with a caller-supplied puller: %v", err)
		}
	})
}
