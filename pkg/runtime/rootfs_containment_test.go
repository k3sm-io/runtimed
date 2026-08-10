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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// victimPodID is the pod whose materialized data volume the cross-pod and
// case-alias cases aim at. It is a legal (lowercase) id, so the only thing that
// can protect it is the rootfs_path rule itself.
const victimPodID = "pod-victim"

// permTree lists every path under root with its type, permission bits, setgid
// bit and owning gid — the shape tree() has, plus exactly the attributes
// ChownForFSGroup mutates. tree() alone cannot see an fsGroup escalation: it
// creates no files, it only re-modes and re-groups the ones already there.
func permTree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		gid := -1
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			gid = int(st.Gid)
		}
		out = append(out, rel+"|"+info.Mode().String()+"|gid="+strconv.Itoa(gid))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

// TestRootfsPathRejectsUncontained is B140's gate: a PodBox rootfs_path that is
// not BYTE-EQUAL to the runtime's derived pod data volume is refused, and the
// refusal happens before ANY of the root daemon's write-side sinks run.
//
// Why the assertions are shaped this way — two traps this gate is built to
// avoid, both of which would leave it green against unguarded code:
//
//   - An error-only assertion is VACUOUS. Before the guard, a hostile
//     rootfs_path aimed at a tree the test process cannot chown already made
//     createPod return FAILURE_REASON_ROOTFS_SETUP (ChownForFSGroup's Lchown to
//     a foreign gid returns EPERM for a non-root process). So the table asserts
//     the SINK SIDE EFFECTS — the victim tree's existence, mode, setgid and gid
//     — plus the TYPED reason INVALID_POD_BOX, explicitly NOT ROOTFS_SETUP. It
//     also chowns to the test process's OWN gid, so on unguarded code the sinks
//     SUCCEED rather than failing with EPERM: the escape is then unmistakable.
//   - A test that only called validatePodBox would exercise no sink at all. Every
//     hostile row goes through the real CreatePod spine (MkdirAll → Materialize →
//     ChownForFSGroup), AND calls r.rootfsPath directly, because Exec,
//     RestartContainer and createVMPod reach it without passing CreatePod.
//
// The /private/var vs /var firmlink question is settled here by construction and
// deliberately not normalized: byte-equality refuses an alias spelling of the
// derived path. That is fail-CLOSED — a rejected alias costs a caller nothing
// (no producer sets the field), whereas resolving aliases means resolving paths,
// and a resolver that mis-parses fails OPEN.
func TestRootfsPathRejectsUncontained(t *testing.T) {
	gid := os.Getgid()
	if gid <= 0 {
		t.Skip("test process gid <= 0 (running as root?); the fsGroup sink asserts a >0 gid")
	}

	// Same TempDir topology as TestCreatePodRejectsTraversingPodID: ONE shared
	// root for Config.Root and the image cache (otherwise the pods-root-bounded
	// guards are unsatisfiable and their sinks unreachable), nested inside an
	// observable parent so an escape ABOVE the root is visible.
	outside := t.TempDir()
	root := filepath.Join(outside, "a", "b", "k3sm")
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	// Siblings of the pods tree inside the daemon root — the control-plane state
	// dir is the case a bare root-prefix check admits.
	mustMkdirMode(t, filepath.Join(root, "server", "db"), 0o700)
	mustWrite(t, filepath.Join(root, "server", "k3sm.kubeconfig"), "sentinel")
	// A sibling of the ROOT whose name merely starts with it.
	mustMkdirMode(t, filepath.Join(outside, "a", "b", "k3sm-evil"), 0o700)

	rt := newTestRuntimeCfg(t, Config{Root: root}, testDeps(t, Deps{Cache: cache}))
	podsRoot := cache.PodsRoot()

	// The victim pod's materialized data volume (secrets + projected SA-token
	// live here in production). Pre-created at 0o700 so the fsGroup pass has
	// something observable to widen.
	victimID, err := image.ParsePodID(victimPodID)
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	victimRootfs := cache.PodRootfs(victimID)
	mustMkdirMode(t, filepath.Join(victimRootfs, "var", "run", "secrets"), 0o700)
	mustWrite(t, filepath.Join(victimRootfs, "var", "run", "secrets", "token"), "VICTIM-SA-TOKEN")

	// The attacker's own data volume, with a symlink planted inside it pointing
	// at the daemon root. A pod's own rootfs is writable at BOTH the POSIX and
	// the SBPL layer (it is re-allowed after the protected denies), so planting
	// this link is within a confined pod's reach — which is precisely why a
	// lexical containment check would not be enough.
	const symlinkPodID = "pod-symlink"
	symlinkID, err := image.ParsePodID(symlinkPodID)
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	mustMkdirMode(t, cache.PodRootfs(symlinkID), 0o700)
	linkPath := filepath.Join(cache.PodRootfs(symlinkID), "link")
	if err := os.Symlink(root, linkPath); err != nil {
		t.Fatalf("symlink %s -> %s: %v", linkPath, root, err)
	}

	before := permTree(t, outside)

	cases := []struct {
		name string
		// podID is the ATTACKER's pod id (a legal one — the id rule is B136's
		// gate, not this one).
		podID string
		// rootfs is the hostile box.rootfs_path.
		rootfs string
		// absent, when non-empty, must not exist on disk after the call.
		absent string
	}{{
		name:   "absolute-escape-outside-the-daemon-root",
		podID:  "pod-esc-abs",
		rootfs: filepath.Join(outside, "a", "b", "k3sm-evil", "loot"),
		absent: filepath.Join(outside, "a", "b", "k3sm-evil", "loot"),
	}, {
		// Inside the daemon root but OUTSIDE the pods tree: the exact case a
		// bare root-prefix check admits, and it names the control-plane state.
		name:   "inside-the-root-outside-the-pods-tree",
		podID:  "pod-esc-server",
		rootfs: filepath.Join(root, "server"),
	}, {
		// Passes any "strictly under the pods root" test, and removePodDir —
		// which derives from the ATTACKER's id — would never clean it up.
		name:   "cross-pod-into-another-pods-rootfs",
		podID:  "pod-esc-cross",
		rootfs: victimRootfs,
	}, {
		// The default APFS volume is case-insensitive, so this NAMES the victim's
		// directory while spelling a different id.
		name:   "uppercase-id-alias-on-case-insensitive-apfs",
		podID:  "pod-esc-case",
		rootfs: filepath.Join(podsRoot, strings.ToUpper(victimPodID), "rootfs"),
	}, {
		// Lexically strictly under <PodsRoot>/<own-id>/rootfs, but "link" is a
		// symlink to the daemon root, so MkdirAll/Materialize/the fsGroup walk
		// land on <root>/server.
		name:   "symlink-hop-out-of-the-pods-own-rootfs",
		podID:  symlinkPodID,
		rootfs: filepath.Join(cache.PodRootfs(symlinkID), "link", "server"),
	}, {
		name:   "relative-path",
		podID:  "pod-esc-rel",
		rootfs: "pods/pod-esc-rel/rootfs",
		absent: filepath.Join(outside, "pods"),
	}, {
		// An UNCLEANED traversal. filepath.Join would Clean this to <root>/server
		// and duplicate the row above; the raw string is a distinct input class,
		// because byte-equality never normalizes what it is handed.
		name:   "dot-dot-traversal-uncleaned",
		podID:  "pod-esc-dots",
		rootfs: podsRoot + "/pod-esc-dots/rootfs/../../../server",
	}, {
		// The firmlink alias of the derived path: refused, fail-closed.
		name:   "firmlink-alias-spelling-of-the-derived-path",
		podID:  "pod-esc-firmlink",
		rootfs: "/private" + cache.PodRootfs(mustPodID(t, "pod-esc-firmlink")),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			box := hostBinBox(tc.podID)
			box.RootfsPath = tc.rootfs
			box.PodSecurityContext = &runtimev1.PodSecurityContext{FsGroup: int64(gid)}

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod transport: %v", err)
			}
			if resp.GetError() == nil {
				t.Fatalf("CreatePod(rootfs_path=%q) succeeded; an uncontained rootfs_path must be refused", tc.rootfs)
			}
			// The TYPED reason matters: ROOTFS_SETUP is what unguarded code
			// already returns when a sink fails late (EPERM on a foreign gid), so
			// accepting it would make this gate vacuous.
			if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Errorf("failure reason = %v, want INVALID_POD_BOX (a ROOTFS_SETUP here means a sink ran and merely failed)", got)
			}

			// Directly, too: Exec, RestartContainer and createVMPod reach
			// rootfsPath without passing through CreatePod.
			if p, err := rt.rootfsPath(box); !errors.Is(err, errUncontainedRootfs) {
				t.Errorf("rootfsPath(%q) = (%q, %v), want an errUncontainedRootfs error and no path", tc.rootfs, p, err)
			}

			if tc.absent != "" {
				if _, err := os.Stat(tc.absent); !os.IsNotExist(err) {
					t.Errorf("%s exists after a refused create (err=%v); MkdirAll must never have run", tc.absent, err)
				}
			}
		})
	}

	// The victim's data volume was never created-into, re-moded, setgid'd or
	// re-grouped; neither was the control-plane state dir, nor anything else
	// under the observable parent.
	if got := permTree(t, outside); !slices.Equal(before, got) {
		t.Errorf("an uncontained rootfs_path mutated the filesystem\nbefore: %v\ndiff:   %v", before, diffTrees(before, got))
	}

	// POSITIVE CONTROLS. Without these the table cannot distinguish "the guard
	// works" from "pod creation is now broken", which would break every pod on
	// the node.
	t.Run("positive/rootfs_path-empty", func(t *testing.T) {
		assertCreatesDerivedRootfs(t, rt, cache, "pod-ok-empty", "")
	})
	t.Run("positive/rootfs_path-equals-the-derivation", func(t *testing.T) {
		id := mustPodID(t, "pod-ok-derived")
		assertCreatesDerivedRootfs(t, rt, cache, "pod-ok-derived", cache.PodRootfs(id))
	})
}

// assertCreatesDerivedRootfs drives a real CreatePod and asserts it succeeded
// and materialized <PodsRoot>/<podID>/rootfs — the guard's accept branch.
func assertCreatesDerivedRootfs(t *testing.T, rt *Runtime, cache *image.Cache, podID, rootfsPath string) {
	t.Helper()
	box := hostBinBox(podID)
	box.RootfsPath = rootfsPath

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod(rootfs_path=%q) failed: %v (reason %v)", rootfsPath, resp.GetError(), resp.GetFailureReason())
	}
	want := cache.PodRootfs(mustPodID(t, podID))
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Fatalf("stat %s = (%v, %v), want the derived pod rootfs to exist", want, fi, err)
	}
	if got, err := rt.rootfsPath(box); err != nil || got != want {
		t.Fatalf("rootfsPath = (%q, %v), want (%q, nil)", got, err, want)
	}
}

func mustPodID(t *testing.T, s string) image.PodID {
	t.Helper()
	id, err := image.ParsePodID(s)
	if err != nil {
		t.Fatalf("ParsePodID(%q): %v", s, err)
	}
	return id
}

func mustMkdirMode(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, mode); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	// MkdirAll applies umask; force the exact mode so the fsGroup widening is
	// observable (0o700 -> 0o770|setgid).
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod %s: %v", p, err)
	}
}

// diffTrees returns the entries that differ between two permTree snapshots, so a
// failure names the escape instead of dumping the whole filesystem twice.
func diffTrees(before, after []string) []string {
	var out []string
	for _, a := range after {
		if !slices.Contains(before, a) {
			out = append(out, "+"+a)
		}
	}
	for _, b := range before {
		if !slices.Contains(after, b) {
			out = append(out, "-"+b)
		}
	}
	return out
}
