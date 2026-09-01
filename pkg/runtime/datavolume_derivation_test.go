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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestNewRejectsUnusableRoot pins the two startup guards on Config.Root. Both
// exist to turn a NODE-WIDE outage that reports itself one pod at a time into a
// single startup error:
//
//   - relative (B140) — supervisor.ChownForFSGroup's strict-containment bound
//     admits nothing when either operand is relative, so fsGroup would fail for
//     every pod as a rootfs-setup fault.
//   - unclean (B142) — the root is passed through as sandbox.Posture.WorkDir,
//     which resolvePosture rejects unless it is already clean, so SBPL generation
//     would fail for every pod as a sandbox-setup fault; and the provider's
//     concatenated data_volume_path would stop matching the cache's Join-derived
//     one, so every box would additionally look invalid.
func TestNewRejectsUnusableRoot(t *testing.T) {
	for _, root := range []string{"relative/k3sm", "var/lib/k3sm", "/var/lib/k3sm/", "/var/lib//k3sm", "/var/lib/k3sm/../k3sm"} {
		t.Run("reject/"+root, func(t *testing.T) {
			if _, err := New(Config{Root: root}, testDeps(t, Deps{Puller: &fakePuller{}})); err == nil {
				t.Fatalf("New(Root=%q) succeeded; an unusable root must fail at startup, not per pod", root)
			}
		})
	}
	// positive CONTROL: an absolute, clean root still constructs (t.TempDir() is
	// both), or the guards above would refuse every daemon.
	t.Run("positive/absolute-and-clean", func(t *testing.T) {
		if rt := newTestRuntimeCfg(t, Config{Root: t.TempDir()}, Deps{}); rt == nil {
			t.Fatal("New returned no runtime for an absolute, clean root")
		}
	})
}

// TestDataVolumePathMustBeDerived is B142's primary gate: a
// sandbox_profile.data_volume_path that is not one of this pod's two derived
// spellings is refused at the CreatePod ingress, with the terminal reason.
//
// It is a separate gate from the sandbox-side bound, not a duplicate of it,
// because the two guards fail on different inputs and one test cannot witness
// both. The headline row here — <PodsRoot>/<other-ID>/rootfs — is a row
// sandbox.Generate ACCEPTS: it is properly under the pods root, which is all the
// generator can check without a pod id. Only the runtime knows which pod is
// asking. Conversely the ancestor rows ("/", the work-dir) are the sink's
// business. A single test over either layer alone would pass while the other
// half of the class stayed open, which is why both layers carry their own.
//
// The reason assertion is load-bearing and is not merely "an error came back":
// SANDBOX_SETUP is what the provider's retry logic reads as a transient host
// fault, so a guard that surfaced this as SANDBOX_SETUP would have the provider
// re-submit an unchanged, permanently-invalid box forever. A value the caller
// must change is terminal: INVALID_POD_BOX.
func TestDataVolumePathMustBeDerived(t *testing.T) {
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
	podsRoot := rt.cache.PodsRoot()
	const otherID = "pod-victim-b142"

	otherRootfs := rt.cache.PodRootfs(mustPodID(t, otherID))

	reject := []struct {
		name    string
		podID   string
		dataVol string
	}{{
		// the case layer 2 cannot catch: properly under the pods root, so the
		// SBPL bound accepts it, and it re-allows read+write over another pod's
		// materialized secrets and projected SA-token.
		name:    "cross-pod-into-another-pods-rootfs",
		podID:   "pod-cross",
		dataVol: otherRootfs,
	}, {
		name:    "cross-pod-into-another-pods-dir",
		podID:   "pod-cross-dir",
		dataVol: filepath.Join(podsRoot, otherID),
	}, {
		// Case aliasing: the default APFS volume is case-insensitive, so this
		// names the victim's directory while spelling a different id.
		name:    "uppercase-id-alias-on-case-insensitive-apfs",
		podID:   "pod-cross-case",
		dataVol: filepath.Join(podsRoot, strings.ToUpper(otherID), "rootfs"),
	}, {
		// The whole pods tree in one line — every sibling pod at once.
		name:    "the-pods-root-itself",
		podID:   "pod-podsroot",
		dataVol: podsRoot,
	}, {
		// Inside the daemon root but outside the pods tree (the CA keys + kine
		// datastore live here). The sink bound catches this one too; the point of
		// the row is that the ingress refuses it FIRST, with a terminal reason.
		name:    "the-control-plane-state-dir",
		podID:   "pod-server",
		dataVol: filepath.Join(rt.cfg.Root, "server"),
	}, {
		name:    "an-absolute-path-off-the-daemon-root",
		podID:   "pod-abs",
		dataVol: "/private/var/db",
	}, {
		// A deeper path inside the pod's own dir: strictly less privilege than
		// the derivation, but still refused — the rule is equality with one of
		// two spellings, not containment, so there is no third accepted shape to
		// reason about.
		name:    "a-subdir-of-the-pods-own-rootfs",
		podID:   "pod-deeper",
		dataVol: filepath.Join(podsRoot, "pod-deeper", "rootfs", "volumes"),
	}, {
		// The firmlink alias of the derived path: refused, fail-closed, for the
		// same reason rootfs_path refuses it (normalizing means resolving, and a
		// resolver that mis-parses fails OPEN).
		name:    "firmlink-alias-spelling-of-the-derivation",
		podID:   "pod-firm",
		dataVol: "/private" + rt.cache.PodRootfs(mustPodID(t, "pod-firm")),
	}, {
		name:    "empty",
		podID:   "pod-empty-dv",
		dataVol: "",
	}}

	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			box := hostBinBox(rt, tc.podID)
			box.SandboxProfile.DataVolumePath = tc.dataVol

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod transport: %v", err)
			}
			if resp.GetError() == nil {
				t.Fatalf("CreatePod(data_volume_path=%q) succeeded; an underived data volume must be refused", tc.dataVol)
			}
			// not SANDBOX_SETUP: that reads as a transient host fault to the
			// provider's retry logic, and this box can never become valid without
			// the caller changing it.
			if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Errorf("failure reason = %v, want INVALID_POD_BOX (SANDBOX_SETUP would be retried forever)", got)
			}
			// Directly too, so a refactor that stops routing through the seam
			// still fails here.
			if p, err := rt.dataVolumePath(box); !errors.Is(err, errUnderivedDataVolume) {
				t.Errorf("dataVolumePath(%q) = (%q, %v), want an errUnderivedDataVolume error and no path", tc.dataVol, p, err)
			}
		})
	}

	// The victim's tree was never created by any refused request. The guard runs
	// before sandbox.Generate, so nothing downstream ever saw the value — and
	// nothing on the create spine ever named the victim's dir either.
	if _, err := os.Stat(otherRootfs); !os.IsNotExist(err) {
		t.Errorf("stat %s = %v; a refused data volume must not have been created", otherRootfs, err)
	}

	// positive CONTROLS for both accepted spellings. Without them this gate
	// cannot distinguish "underived values refused" from "every pod on the node
	// refused" — and the PodDir row specifically pins the spelling the only
	// producer (the k3sm provider's podRoot(id)) actually sends, so a future
	// tightening to rootfs-only cannot land silently.
	positive := []struct {
		name  string
		podID string
		spell func(image.PodID) string
	}{
		{"the pod dir — what the k3sm provider sends", "pod-ok-poddir", rt.cache.PodDir},
		{"the rootfs under it — strictly narrower", "pod-ok-rootfs", rt.cache.PodRootfs},
	}
	for _, tc := range positive {
		t.Run("positive/"+tc.name, func(t *testing.T) {
			want := tc.spell(mustPodID(t, tc.podID))
			box := hostBinBox(rt, tc.podID)
			box.SandboxProfile.DataVolumePath = want

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod(data_volume_path=%q) failed: %v (reason %v)", want, resp.GetError(), resp.GetFailureReason())
			}
			if got, err := rt.dataVolumePath(box); err != nil || got != want {
				t.Fatalf("dataVolumePath = (%q, %v), want (%q, nil)", got, err, want)
			}
			// Whichever accepted spelling arrived, the profile re-allows the
			// narrower one — the rootfs. The accept set is a compatibility surface
			// (the producer sends the pod dir); the EMITTED value is the privilege
			// surface, and nothing a Seatbelt pod needs lives above <podDir>/rootfs.
			// Asserting the emitted tree rather than the accepted one is what keeps
			// a later widening of the accept set from silently widening the grant.
			rootfs := rt.cache.PodRootfs(mustPodID(t, tc.podID))
			rt.mu.Lock()
			p := rt.pods[tc.podID]
			rt.mu.Unlock()
			if p == nil {
				t.Fatalf("pod %s not registered after a successful create", tc.podID)
			}
			if !strings.Contains(p.profile, "(allow file-read* file-write*\n  (subpath \""+rootfs+"\")") {
				t.Fatalf("the profile does not re-allow the narrowed rootfs %q (accepted %q):\n%s", rootfs, want, p.profile)
			}
			// And it must not re-allow the pod dir, which is one level wider.
			if podDir := rt.cache.PodDir(mustPodID(t, tc.podID)); strings.Contains(p.profile, "(subpath \""+podDir+"\")") {
				t.Errorf("the profile re-allows the pod dir %q; the emitted grant must be the rootfs only", podDir)
			}
		})
	}
}
