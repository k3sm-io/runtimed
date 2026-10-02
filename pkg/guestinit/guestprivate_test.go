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

package guestinit

import (
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// ---------------------------------------------------------------------------
// An independent mount-table simulator.
//
// It interprets MountSteps the way the Linux kernel would apply them and knows
// nothing about which mounts a container "should" see: it reads only the plan's
// data types (MountStep, MountOption, BootPlan) and walks paths with its own
// resolver. It never calls containerVisibleMounts, ContainerPodMounts or any
// other planner helper, so a verdict it reaches is evidence about the plan, not
// a restatement of the planner's own rule.
//
// Modelled: fresh mounts (a virtiofs share is its fixture tree, an overlay
// presents its lower layer, anything else is an empty filesystem), bind and
// rbind (which copies the visible submounts beneath its source), remounts
// (flags only, so no reachability change), and OptionDetach (removes the mount
// at the target and everything mounted beneath it). Stacking is modelled: a
// mount made later at a path or an ancestor of it hides an earlier one.
// Not modelled: propagation, permissions, symlinks. The MS_PRIVATE/MNT_DETACH
// argument shape of a detach is covered by LinuxDetach's unit test instead.
// ---------------------------------------------------------------------------

// simFS is one filesystem instance: an id and the files it holds, by path
// relative to its own root.
type simFS struct {
	id    string
	files []string
}

// simMount is one entry in the mount table: fs's subtree sub, attached at target.
type simMount struct {
	target string
	fs     *simFS
	sub    string
}

// mountTable is the guest's mount table, in mount order.
type mountTable struct {
	mounts   []simMount
	fixtures map[string]*simFS
	anon     int
}

func newMountTable(fixtures map[string]*simFS) *mountTable {
	mt := &mountTable{fixtures: fixtures}
	mt.mounts = append(mt.mounts, simMount{target: "/", fs: &simFS{id: "guest-rootfs"}})
	return mt
}

// under reports whether p is target or a path beneath it.
func under(p, target string) bool {
	if target == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == target || strings.HasPrefix(p, target+"/")
}

// visible reports whether the mount at index i is still reachable at all: no
// LATER mount was made at its target or at an ancestor of it.
func (mt *mountTable) visible(i int) bool {
	for j := i + 1; j < len(mt.mounts); j++ {
		if under(mt.mounts[i].target, mt.mounts[j].target) {
			return false
		}
	}
	return true
}

// resolve returns the index of the mount serving p and p's path inside it.
func (mt *mountTable) resolve(p string) (int, string) {
	best := -1
	for i, m := range mt.mounts {
		if !under(p, m.target) || !mt.visible(i) {
			continue
		}
		if best < 0 || len(m.target) > len(mt.mounts[best].target) {
			best = i
		}
	}
	m := mt.mounts[best]
	rel := strings.TrimPrefix(strings.TrimPrefix(p, m.target), "/")
	return best, path.Join(m.sub, rel)
}

func (mt *mountTable) newFS(kind string) *simFS {
	mt.anon++
	return &simFS{id: fmt.Sprintf("%s#%d", kind, mt.anon)}
}

// apply interprets one MountStep.
func (mt *mountTable) apply(s MountStep) error {
	has := func(o MountOption) bool {
		for _, x := range s.Options {
			if x == o {
				return true
			}
		}
		return false
	}
	switch {
	case has(OptionDetach):
		return mt.detach(s.Target)
	case has(OptionRemount):
		return nil
	case has(OptionRBind):
		mt.bind(s.Source, s.Target, true)
		return nil
	case has(OptionBind):
		mt.bind(s.Source, s.Target, false)
		return nil
	}
	var fs *simFS
	switch s.FSType {
	case "virtiofs":
		fs = mt.fixtures[s.Source]
		if fs == nil {
			fs = mt.newFS("virtiofs:" + s.Source)
		}
	case "overlay":
		lower := ""
		for _, kv := range strings.Split(s.Data, ",") {
			if v, ok := strings.CutPrefix(kv, "lowerdir="); ok {
				lower = v
			}
		}
		i, rel := mt.resolve(lower)
		mt.mounts = append(mt.mounts, simMount{target: s.Target, fs: mt.mounts[i].fs, sub: rel})
		return nil
	case "":
		return fmt.Errorf("step at %s has no fs type and no bind option", s.Target)
	default:
		fs = mt.newFS(s.FSType)
	}
	mt.mounts = append(mt.mounts, simMount{target: s.Target, fs: fs})
	return nil
}

// bind attaches what source resolves to at target; recursive also copies every
// visible mount beneath source.
func (mt *mountTable) bind(source, target string, recursive bool) {
	i, rel := mt.resolve(source)
	var copies []simMount
	if recursive {
		for j, m := range mt.mounts {
			if m.target != source && under(m.target, source) && mt.visible(j) {
				copies = append(copies, simMount{
					target: path.Join(target, strings.TrimPrefix(m.target, source)),
					fs:     m.fs, sub: m.sub,
				})
			}
		}
	}
	mt.mounts = append(mt.mounts, simMount{target: target, fs: mt.mounts[i].fs, sub: rel})
	mt.mounts = append(mt.mounts, copies...)
}

// detach removes the top mount at target and every mount made beneath it after
// it, as umount2(MNT_DETACH) takes the whole subtree.
func (mt *mountTable) detach(target string) error {
	top := -1
	for i, m := range mt.mounts {
		if m.target == target && mt.visible(i) {
			top = i
		}
	}
	if top < 0 {
		return fmt.Errorf("detach %s: nothing is mounted there", target)
	}
	var kept []simMount
	for i, m := range mt.mounts {
		if i == top || (i > top && m.target != target && under(m.target, target)) {
			continue
		}
		kept = append(kept, m)
	}
	mt.mounts = kept
	return nil
}

// view returns every file reachable under root, keyed by the path a process
// chrooted at root would use, valued "<fs id>:<file>". root "/" is the guest's
// own view (what /proc/1/root reaches).
func (mt *mountTable) view(root string) map[string]string {
	out := map[string]string{}
	for i, m := range mt.mounts {
		for _, f := range m.fs.files {
			if m.sub != "" && !under("/"+f, "/"+m.sub) {
				continue
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(f, m.sub), "/")
			p := path.Join(m.target, rel)
			if !under(p, root) {
				continue
			}
			if j, got := mt.resolve(p); j != i || got != f {
				continue // shadowed
			}
			cp := "/" + strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
			out[cp] = m.fs.id + ":" + f
		}
	}
	return out
}

// reaches reports whether file (fs id + path) is reachable in v, and where.
func reaches(v map[string]string, file string) (string, bool) {
	for p, f := range v {
		if f == file {
			return p, true
		}
	}
	return "", false
}

// simEffects drives the simulator through RunStart, so the passes are applied in
// the order the real sequencer orders them.
type simEffects struct {
	mt     *mountTable
	calls  []string
	starts map[string]map[string]string // container -> guest-root view at its start
	views  map[string]map[string]string // container -> its own view at its start
	roots  map[string]string
}

func (e *simEffects) Compose(cp *ContainerPlan) error {
	e.calls = append(e.calls, "compose:"+cp.Name)
	e.roots[cp.Name] = cp.Root
	for _, s := range cp.Mounts {
		if err := e.mt.apply(s); err != nil {
			return err
		}
	}
	return nil
}

func (e *simEffects) Detach(step MountStep) error {
	e.calls = append(e.calls, "detach:"+step.Target)
	return e.mt.apply(step)
}

func (e *simEffects) Start(cp ContainerPlan) error {
	e.calls = append(e.calls, "start:"+cp.Name)
	e.starts[cp.Name] = e.mt.view("/")
	e.views[cp.Name] = e.mt.view(cp.Root)
	return nil
}

// simulate boots plan through the simulator: the pod mounts in the guest root,
// then RunStart's three passes.
func simulate(t *testing.T, plan *BootPlan, fixtures map[string]*simFS) *simEffects {
	t.Helper()
	mt := newMountTable(fixtures)
	for _, s := range plan.PodMounts {
		if err := mt.apply(s); err != nil {
			t.Fatalf("pod mount: %v", err)
		}
	}
	fx := &simEffects{mt: mt, starts: map[string]map[string]string{},
		views: map[string]map[string]string{}, roots: map[string]string{}}
	if err := RunStart(plan, fx); err != nil {
		t.Fatalf("RunStart: %v", err)
	}
	return fx
}

// --- the fixture ----------------------------------------------------------

const (
	stagingRoot = GuestRoot + "/shares/k3sm.proj"
	fileA       = "k3sm.proj:vol-a/data"
	fileB       = "k3sm.proj:vol-b/secret"
)

func shareFixtures() map[string]*simFS {
	return map[string]*simFS{
		"k3sm.proj":   {id: "k3sm.proj", files: []string{"vol-a/data", "vol-b/secret"}},
		"k3sm.rootfs": {id: "k3sm.rootfs", files: []string{"bin/sh"}},
	}
}

// unmountedVolumeSpec is the shape the host composer emits for a pooled
// projected share: a read-only staging mount of the whole share, and a bind of
// volume A out of it. Container x mounts A; nobody mounts B. withY adds a
// container y that mounts B (the documented ceiling fixture).
func unmountedVolumeSpec(private, withY bool, xUID int64) *guestv1.GuestSpec {
	c := func(name string, uid int64) *guestv1.GuestContainer {
		return &guestv1.GuestContainer{Name: name, RootfsTag: "k3sm.rootfs", Command: []string{"/bin/sh"}, Uid: uid, Gid: uid}
	}
	spec := &guestv1.GuestSpec{
		Hostname: "p", AgentPort: 1024,
		Containers: []*guestv1.GuestContainer{c("x", xUID)},
		Mounts: []*guestv1.GuestMount{
			{
				TagOrSource: "k3sm.proj", Target: stagingRoot,
				Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS, ReadOnly: true, GuestPrivate: private,
			},
			{
				TagOrSource: stagingRoot + "/vol-a", Target: "/etc/config-a",
				Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND, ReadOnly: true,
			},
		},
	}
	if withY {
		spec.Containers = append(spec.Containers, c("y", 1000))
		spec.Mounts = append(spec.Mounts, &guestv1.GuestMount{
			TagOrSource: stagingRoot + "/vol-b", Target: "/etc/secret-b",
			Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND, ReadOnly: true,
		})
	}
	return spec
}

func mustPlan(t *testing.T, spec *guestv1.GuestSpec) *BootPlan {
	t.Helper()
	plan, err := Plan(spec, Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return plan
}

// TestContainerCannotReadUnmountedVolume is the guest_private gate: a volume
// that lives in a pooled share and that NO container mounts is unreachable from
// every container, through the staging path and through the guest root
// (/proc/1/root), and the plan that makes that true is the same whatever uid
// the container runs as.
//
// The verdicts come from an independent mount-table simulator driven through
// RunStart (see the simulator's header), and two in-test mutants show the
// simulator SEES each of the fix's two mechanisms fail: M1 removes the
// guest_private bit (the pre-fix composer output), M2 keeps it but drops the
// detach pass. The ceiling fixture pins the documented width of the fix: a
// volume a SIBLING container mounts is still visible in every container at the
// sibling's mount path, and the test says so rather than hiding it.
func TestContainerCannotReadUnmountedVolume(t *testing.T) {
	t.Run("simulator self-test", func(t *testing.T) {
		fix := map[string]*simFS{"t": {id: "t", files: []string{"A/f", "B/g"}}}

		mt := newMountTable(fix)
		for _, s := range []MountStep{
			{Source: "t", Target: "/s", FSType: "virtiofs"},
			{Source: "/s/A", Target: "/t", Options: []MountOption{OptionBind}},
			{Source: "/t", Target: "/r/t", Options: []MountOption{OptionRBind}},
			{Source: "/s", Target: "/r/s", Options: []MountOption{OptionRBind}},
			{Target: "/s", Options: []MountOption{OptionDetach}},
		} {
			if err := mt.apply(s); err != nil {
				t.Fatal(err)
			}
		}
		got := mt.view("/")
		want := map[string]string{"/t/f": "t:A/f", "/r/t/f": "t:A/f", "/r/s/A/f": "t:A/f", "/r/s/B/g": "t:B/g"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("bind-then-detach view = %v, want %v (binds survive a detach of their source)", got, want)
		}
		if v := mt.view("/r"); !reflect.DeepEqual(v, map[string]string{"/t/f": "t:A/f", "/s/A/f": "t:A/f", "/s/B/g": "t:B/g"}) {
			t.Errorf("chroot view at /r = %v", v)
		}

		// Detach FIRST, then bind out of the detached path: the source now
		// resolves to the empty guest root, so nothing is reachable.
		mt = newMountTable(fix)
		for _, s := range []MountStep{
			{Source: "t", Target: "/s", FSType: "virtiofs"},
			{Target: "/s", Options: []MountOption{OptionDetach}},
			{Source: "/s/A", Target: "/t", Options: []MountOption{OptionBind}},
		} {
			if err := mt.apply(s); err != nil {
				t.Fatal(err)
			}
		}
		if v := mt.view("/"); len(v) != 0 {
			t.Errorf("detach-then-bind view = %v, want empty", v)
		}

		// Stacking: a later mount at the same path hides the earlier one.
		mt = newMountTable(fix)
		_ = mt.apply(MountStep{Source: "t", Target: "/s", FSType: "virtiofs"})
		_ = mt.apply(MountStep{Source: "tmpfs", Target: "/s", FSType: "tmpfs"})
		if v := mt.view("/"); len(v) != 0 {
			t.Errorf("shadowed view = %v, want empty", v)
		}
	})

	plan := mustPlan(t, unmountedVolumeSpec(true, false, 1000))
	fx := simulate(t, plan, shareFixtures())
	rootX := ContainerRootDir("x")

	t.Run("leg 1: x's view reaches A and not B, and x's plan never names staging", func(t *testing.T) {
		for _, s := range plan.Containers[0].Mounts {
			target := strings.TrimPrefix(s.Target, rootX)
			for _, p := range []string{s.Target, target, s.Source} {
				if p != "" && under(p, stagingRoot) {
					t.Errorf("x's plan step %+v touches the staging root", s)
				}
			}
		}
		view := fx.views["x"]
		if p, ok := reaches(view, fileB); ok {
			t.Errorf("x reaches B at %s", p)
		}
		if p, ok := reaches(view, fileA); !ok || p != "/etc/config-a/data" {
			t.Errorf("x reaches A at %q (%v), want /etc/config-a/data", p, ok)
		}
	})

	t.Run("leg 2: the detach covers every guest-private target, after all composition, before the first start", func(t *testing.T) {
		if len(plan.Detach) != 1 || plan.Detach[0].Target != stagingRoot ||
			!reflect.DeepEqual(plan.Detach[0].Options, []MountOption{OptionDetach}) {
			t.Fatalf("Detach = %+v, want exactly the staging root", plan.Detach)
		}
		want := []string{"compose:x", "detach:" + stagingRoot, "start:x"}
		if !reflect.DeepEqual(fx.calls, want) {
			t.Fatalf("pass order = %v, want %v", fx.calls, want)
		}

		// With more than one container the order holds across all of them.
		multi := mustPlan(t, unmountedVolumeSpec(true, true, 1000))
		multi.Containers[0].WaitForExit = true // an init-like waited step must not change the order
		mfx := simulate(t, multi, shareFixtures())
		wantMulti := []string{"compose:x", "compose:y", "detach:" + stagingRoot, "start:x", "start:y"}
		if !reflect.DeepEqual(mfx.calls, wantMulti) {
			t.Fatalf("pass order = %v, want %v", mfx.calls, wantMulti)
		}
	})

	t.Run("leg 3: B is unreachable from the guest root, and the plan is uid-invariant", func(t *testing.T) {
		if p, ok := reaches(fx.starts["x"], fileB); ok {
			t.Errorf("B reachable in the guest-root view (/proc/1/root) at %s when x starts", p)
		}
		if _, ok := reaches(fx.starts["x"], fileA); !ok {
			t.Error("A is not reachable from the guest root at all; the simulator is not seeing the binds")
		}
		// guest/v1 has no privilege field; the strongest identity a container
		// can carry is uid 0. The MOUNT plan must not depend on it.
		rootPlan := mustPlan(t, unmountedVolumeSpec(true, false, 0))
		if rootPlan.Containers[0].Ident.UID != 0 || plan.Containers[0].Ident.UID != 1000 {
			t.Fatal("fixture did not vary the uid")
		}
		strip := func(p *BootPlan) BootPlan {
			c := *p
			c.Containers = append([]ContainerPlan{}, p.Containers...)
			for i := range c.Containers {
				c.Containers[i].Ident = Ident{}
			}
			return c
		}
		if a, b := strip(plan), strip(rootPlan); !reflect.DeepEqual(a, b) {
			t.Error("the plan for x at uid 0 differs from x at uid 1000 beyond its identity")
		}
	})

	t.Run("leg 4 M1: without guest_private the simulator reports B in x's view", func(t *testing.T) {
		m1 := mustPlan(t, unmountedVolumeSpec(false, false, 1000))
		mfx := simulate(t, m1, shareFixtures())
		p, ok := reaches(mfx.views["x"], fileB)
		if !ok {
			t.Fatal("mutant M1 (guest_private=false) shows no leak; the simulator cannot see the re-exposure")
		}
		t.Logf("M1 leak observed: x reads B at %s", p)
	})

	t.Run("leg 4 M2: without the detach the simulator reports B in the guest-root view", func(t *testing.T) {
		m2 := mustPlan(t, unmountedVolumeSpec(true, false, 1000))
		m2.Detach = nil
		mfx := simulate(t, m2, shareFixtures())
		p, ok := reaches(mfx.starts["x"], fileB)
		if !ok {
			t.Fatal("mutant M2 (no detach) shows no leak; the simulator cannot see the staging mount")
		}
		if _, inX := reaches(mfx.views["x"], fileB); inX {
			t.Error("M2 leaked B into x's own view; only the guest-root route should be open")
		}
		t.Logf("M2 leak observed: the guest root reads B at %s", p)
	})

	t.Run("leg 5 ceiling: a volume a sibling mounts is visible in x at the sibling's path", func(t *testing.T) {
		ceil := mustPlan(t, unmountedVolumeSpec(true, true, 1000))
		cfx := simulate(t, ceil, shareFixtures())
		p, ok := reaches(cfx.views["x"], fileB)
		if !ok || p != "/etc/secret-b/secret" {
			t.Fatalf("x reaches B at %q (%v); the documented pod-level-mount ceiling says it does, at y's path /etc/secret-b", p, ok)
		}
		// The staging path itself stays closed even here.
		var paths []string
		for q := range cfx.views["x"] {
			paths = append(paths, q)
		}
		sort.Strings(paths)
		for _, q := range paths {
			if under(q, stagingRoot) {
				t.Errorf("x reaches %s under the staging root", q)
			}
		}
	})
}
