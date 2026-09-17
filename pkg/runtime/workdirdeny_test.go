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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// TestEveryDaemonPrivateSubdirIsDenied is the cross-package half of the
// work-dir deny-set contract, and it lives here because pkg/runtime is the only
// package that imports all three owners of the names: pkg/sandbox (which renders
// the deny), pkg/image (which owns five of the directories) and
// pkg/guestartifacts (which owns one).
//
// pkg/sandbox cannot import the other two — pkg/guestartifacts imports IT, so
// that edge is a cycle, and the SBPL generator is deliberately a leaf — so the
// six names are MIRRORED as sandbox consts. A mirror is a second spelling, and a
// second spelling is exactly the drift the exported consts exist to prevent: a
// renamed directory with a stale mirror leaves the profile denying an empty
// sibling while the real store stays writable, with every test in both packages
// still green. This is the test that is not.
func TestEveryDaemonPrivateSubdirIsDenied(t *testing.T) {
	// (1) Each mirror still equals the const it mirrors. Written as explicit
	// pairs rather than derived from anything: a derivation would compare a
	// value to itself.
	t.Run("the mirrored names still equal the originals", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			mirror, source string
		}{
			{"image.IndexSubdir", sandbox.ImageIndexSubdir, image.IndexSubdir},
			{"image.OperatorSubdir", sandbox.ImageOperatorSubdir, image.OperatorSubdir},
			{"image.UnpackedSubdir", sandbox.ImageUnpackedSubdir, image.UnpackedSubdir},
			{"image.SnapshotsSubdir", sandbox.ImageSnapshotsSubdir, image.SnapshotsSubdir},
			{"image.IngestSubdir", sandbox.ImageIngestSubdir, image.IngestSubdir},
			{"guestartifacts.GuestArtifactsSubdir", sandbox.GuestArtifactsSubdir, guestartifacts.GuestArtifactsSubdir},
		} {
			if tc.mirror != tc.source {
				t.Errorf("sandbox mirror of %s = %q, want %q — the SBPL deny names a directory the owning package no longer uses", tc.name, tc.mirror, tc.source)
			}
		}
	})

	// (2) Nothing daemon-private is missing from the deny lists.
	//
	// everyDaemonPrivateSubdir is a MAINTAINED list, on purpose. Go offers no way
	// to enumerate a package's exported consts at run time, and a list derived
	// from the deny lists themselves could never detect an omission. So: adding a
	// *Subdir const to pkg/sandbox, pkg/image or pkg/guestartifacts means adding
	// it here AND to sandbox.ReapStoreSubdirs/DaemonTreeSubdirs. If it genuinely
	// must stay reachable by pods, it goes in the exemption list below with the
	// reason, which is a visible decision rather than a silent omission.
	t.Run("every daemon-private subdir is in a deny list", func(t *testing.T) {
		everyDaemonPrivateSubdir := []string{
			// pkg/sandbox's own.
			sandbox.PodReapSubdir,
			sandbox.VMReapSubdir,
			sandbox.ServerSubdir,
			sandbox.AgentSubdir,
			sandbox.RunSubdir,
			sandbox.BlobsSubdir,
			sandbox.ProfileSubdir,
			// pkg/image's, named from the OWNING package so this half of the
			// test fails on a rename even if the mirror check above were
			// deleted.
			image.IndexSubdir,
			image.OperatorSubdir,
			image.UnpackedSubdir,
			image.SnapshotsSubdir,
			image.IngestSubdir,
			// pkg/guestartifacts'.
			guestartifacts.GuestArtifactsSubdir,
		}

		denied := map[string]bool{}
		for _, sub := range append(sandbox.ReapStoreSubdirs(), sandbox.DaemonTreeSubdirs()...) {
			if denied[sub] {
				t.Errorf("%q appears twice in the deny lists — it would render two identical (deny ...) lines", sub)
			}
			denied[sub] = true
		}
		for _, sub := range everyDaemonPrivateSubdir {
			if !denied[sub] {
				t.Errorf("%q is a daemon-private work-dir subdir but is in neither ReapStoreSubdirs nor DaemonTreeSubdirs — a pod can read and write it", sub)
			}
		}
		// The converse: a name in a deny list that no package owns is a deny for
		// a directory nothing writes, which reads as protection and is not.
		want := map[string]bool{}
		for _, sub := range everyDaemonPrivateSubdir {
			want[sub] = true
		}
		for sub := range denied {
			if !want[sub] {
				t.Errorf("%q is denied but is not in this test's list of daemon-private subdirs — either add it here or drop the deny", sub)
			}
		}
	})

	// (3) The one documented exemption, stated so it is a decision rather than a
	// gap. <Root>/storage is the parent of every pod's PVC dir (runtime.New
	// derives the PV class base path from it) and the protected denies are
	// emitted AFTER the PV allows, so denying it would clobber every legitimate
	// write grant on the node. The cost is explicit in resolvePosture: a
	// caller-supplied extra path at <Root>/storage stays reachable.
	t.Run("storage is the one exemption", func(t *testing.T) {
		const storage = "storage"
		for _, sub := range append(sandbox.ReapStoreSubdirs(), sandbox.DaemonTreeSubdirs()...) {
			if sub == storage {
				t.Fatalf("%q is denied; it is the PV parent and the deny would clobber every PVC write grant", storage)
			}
		}
		root := t.TempDir()
		rt := newTestRuntimeCfg(t, Config{Root: root}, Deps{})
		if got, want := rt.binder.Class().BasePath, filepath.Join(root, storage); got != want {
			t.Errorf("PV class base path = %q, want %q — the exemption names a directory the binder no longer uses", got, want)
		}
	})

	// (4) The wiring pin. The deny-set is only worth anything if the work-dir it
	// is computed from is the same directory the daemon's stores actually live
	// under. runtime.New wires cfg.Root into the vm backend (WithStateRoot, so
	// <Root>/vmreap) and into the SBPL generator (Posture.WorkDir, in
	// createPod) in two separate statements; this asserts they have not
	// diverged, end to end, by reading the profile the daemon really emitted for
	// a pod.
	t.Run("the vm state root and the posture work-dir are one path", func(t *testing.T) {
		root := t.TempDir()
		capture := &profileCapturingBackend{available: true}
		d := testDeps(t, Deps{})
		d.Backend = capture
		// nil so New builds the daemon's REAL sandbox.NewVMBackend wiring — the
		// fake testDeps installs carries no state root at all, and that wiring is
		// this subtest's whole subject. New is called directly for the same
		// reason: newTestRuntimeCfg re-runs testDeps, which would put the fake
		// back.
		d.VMBackend = nil
		d.Puller = &fakePuller{}
		d.Unpacker = &fakeUnpacker{}
		d.HostRosetta = func(context.Context) sandbox.HostRosettaState { return sandbox.HostRosettaAbsent }
		d.GuestRosetta = func() sandbox.GuestRosettaState { return sandbox.GuestRosettaQueryFailed }
		rt, err := New(Config{Root: root, PodLogsDir: filepath.Join(root, "podlogs")}, d)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = rt.Close() })

		vmb, ok := rt.vmBackend.(*sandbox.VMBackend)
		if !ok {
			t.Fatalf("default vm backend is %T, want *sandbox.VMBackend", rt.vmBackend)
		}
		if got := vmb.StateRoot(); got != root {
			t.Fatalf("vm backend state root = %q, want the runtime root %q — its vmreap store would sit outside the tree the SBPL deny protects", got, root)
		}

		mustCreatePod(t, rt, hostBinBox(rt, "pod-denyset"))
		profile := capture.profile()
		if profile == "" {
			t.Fatal("the sandbox backend was never handed a profile; this subtest asserts nothing without one")
		}
		var missing []string
		for _, sub := range append(sandbox.ReapStoreSubdirs(), sandbox.DaemonTreeSubdirs()...) {
			if !strings.Contains(profile, `(subpath "`+filepath.Join(root, sub)+`")`) {
				missing = append(missing, sub)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("the profile the daemon emitted does not deny %v under its own root %q", missing, root)
		}
	})
}

// profileCapturingBackend is a sandbox.Backend that keeps the last profile it
// was handed, so a test can assert on the SBPL the daemon really generated for a
// pod rather than on a profile the test itself built from a Posture it filled in
// — which would assert only that the test can copy a field.
//
// It validates the profile exactly as fakeBackend does, so a generator change
// that produced a fail-open profile still fails here rather than being recorded.
type profileCapturingBackend struct {
	available bool
	mu        sync.Mutex
	last      string
}

func (b *profileCapturingBackend) Available() bool { return b.available }
func (b *profileCapturingBackend) Name() string    { return "profile-capturing" }

func (b *profileCapturingBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	b.mu.Lock()
	b.last = profile
	b.mu.Unlock()
	return fakeBackend{available: b.available}.WrapCommand(ctx, profile, argv, spec)
}

func (b *profileCapturingBackend) profile() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}
