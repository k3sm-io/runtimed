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

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/guestinit"
)

// TestStageOwnershipSidecarsLandsBesideTheGuestSpec pins the host half of the
// ownership handoff: the materialized tree's sidecar is copied into the k3sm.spec
// share root, beside guest-spec.json, under the name the guest plan derives from
// the container's rootfs tag — and nothing is staged for a tag that has none.
func TestStageOwnershipSidecarsLandsBesideTheGuestSpec(t *testing.T) {
	t.Parallel()
	podDir := t.TempDir()
	specRoot := filepath.Join(podDir, guestinit.SpecShareTag)
	if err := os.MkdirAll(specRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	gs, err := buildGuestSpec(guestSpecFixture())
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	if _, err := writeGuestSpec(podDir, gs); err != nil {
		t.Fatalf("writeGuestSpec: %v", err)
	}
	treeSidecar := filepath.Join(t.TempDir(), "ownership.jsonl")
	const body = `{"path":"tmp","type":"dir","uid":0,"gid":0,"mode":1023}` + "\n"
	if err := os.WriteFile(treeSidecar, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// A stale sidecar for a tag that no longer has one must not survive.
	stale := filepath.Join(specRoot, guestinit.OwnershipSidecarName("k3sm.rootfs.other"))
	if err := os.WriteFile(stale, []byte("old\n"), 0o444); err != nil {
		t.Fatal(err)
	}

	containers := []VMContainer{
		{Name: "a", RootfsTag: "k3sm.rootfs", OwnershipPath: treeSidecar},
		{Name: "b", RootfsTag: "k3sm.rootfs"}, // shares the tree; materialized none
		{Name: "c", RootfsTag: "k3sm.rootfs.other"},
	}
	if err := stageOwnershipSidecars(podDir, containers); err != nil {
		t.Fatalf("stageOwnershipSidecars: %v", err)
	}

	staged := filepath.Join(specRoot, guestinit.OwnershipSidecarName("k3sm.rootfs"))
	if filepath.Dir(staged) != filepath.Dir(filepath.Join(specRoot, VMGuestSpecFileName)) {
		t.Fatalf("sidecar %s is not beside the guest spec", staged)
	}
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("the sidecar was not staged beside guest-spec.json: %v", err)
	}
	if string(got) != body {
		t.Errorf("staged sidecar = %q, want the tree's bytes %q", got, body)
	}
	if fi, err := os.Stat(staged); err != nil || fi.Mode().Perm() != 0o444 {
		t.Errorf("staged sidecar mode = %v (err %v), want 0444", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale sidecar for a tag with none survived: %v", err)
	}
	entries, err := os.ReadDir(specRoot)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{VMGuestSpecFileName, guestinit.OwnershipSidecarName("k3sm.rootfs")}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Errorf("spec share holds %v, want exactly %v (no temp files, nothing in the rootfs share)", names, want)
	}

	t.Run("a restage over an existing sidecar replaces it", func(t *testing.T) {
		if err := stageOwnershipSidecars(podDir, containers); err != nil {
			t.Fatalf("second stage: %v", err)
		}
	})

	t.Run("a tag that cannot be a filename is refused", func(t *testing.T) {
		err := stageOwnershipSidecars(podDir, []VMContainer{{Name: "x", RootfsTag: "../x", OwnershipPath: treeSidecar}})
		if !errors.Is(err, ErrInvalidGuestSpec) {
			t.Errorf("err = %v, want ErrInvalidGuestSpec", err)
		}
	})
}

// TestCreateVMStagesTheOwnershipSidecarBeforeTheSpawn drives the real CreateVM:
// a container carrying its tree's sidecar path boots with that sidecar already
// committed in the k3sm.spec share at the instant the helper is spawned — the
// window in which no guest holds the share.
func TestCreateVMStagesTheOwnershipSidecarBeforeTheSpawn(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	fixture := guestSpecFixture()
	spec.Network, spec.Containers, spec.Volumes = fixture.Network, fixture.Containers, fixture.Volumes
	treeSidecar := filepath.Join(t.TempDir(), "ownership.jsonl")
	if err := os.WriteFile(treeSidecar, []byte(`{"path":"etc","type":"dir","uid":0,"gid":0,"mode":493}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec.Containers[1].OwnershipPath = treeSidecar // postgres, tag k3sm.rootfs.postgres

	staged := filepath.Join(spec.PodDir, guestinit.SpecShareTag, guestinit.OwnershipSidecarName("k3sm.rootfs.postgres"))
	watcher := &specWatchingSpawner{path: staged, next: &fakeSpawner{}}
	b, _, _, _ := labBackend(t, root, func(context.Context, string) error { return nil },
		WithVMProcessSeams(watcher, nil, nil, nil, nil, nil))
	if err := b.CreateVM(context.Background(), spec); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if !watcher.spawned {
		t.Fatal("no helper was spawned; the ordering assertion would be vacuous")
	}
	if watcher.seen == nil {
		t.Fatal("the ownership sidecar was not staged in the spec share before the helper was spawned")
	}
	if _, err := os.Stat(filepath.Join(spec.PodDir, guestinit.SpecShareTag, guestinit.OwnershipSidecarName("k3sm.rootfs.init-db"))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a sidecar was staged for init-db, whose container carries none (stat err %v)", err)
	}
}

// TestStageOwnershipSidecarsRefusesPlantedSymlinks pins copySealed's no-follow
// claim: a symlink pre-planted at the fixed temp name makes the write fail
// rather than land in the link's target, and one planted at the final name is
// REPLACED by the rename rather than written through.
func TestStageOwnershipSidecarsRefusesPlantedSymlinks(t *testing.T) {
	t.Parallel()
	const body = `{"path":"tmp","type":"dir","uid":0,"gid":0,"mode":1023}` + "\n"
	setup := func(t *testing.T) (podDir, dst, victim string, containers []VMContainer) {
		t.Helper()
		podDir = t.TempDir()
		specRoot := filepath.Join(podDir, guestinit.SpecShareTag)
		if err := os.MkdirAll(specRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(t.TempDir(), "ownership.jsonl")
		if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		victim = filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
			t.Fatal(err)
		}
		dst = filepath.Join(specRoot, guestinit.OwnershipSidecarName("k3sm.rootfs"))
		return podDir, dst, victim, []VMContainer{{Name: "a", RootfsTag: "k3sm.rootfs", OwnershipPath: src}}
	}
	assertVictim := func(t *testing.T, victim string) {
		t.Helper()
		if got, err := os.ReadFile(victim); err != nil || string(got) != "untouched" {
			t.Errorf("the link target was written through: %q (err %v)", got, err)
		}
	}

	t.Run("a symlink at the temp name is refused, not followed", func(t *testing.T) {
		podDir, dst, victim, containers := setup(t)
		if err := os.Symlink(victim, dst+".tmp"); err != nil {
			t.Fatal(err)
		}
		if err := stageOwnershipSidecars(podDir, containers); err == nil {
			t.Error("staging succeeded through a planted temp-name symlink; want a refusal")
		}
		assertVictim(t, victim)
		if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a sidecar was committed despite the refusal (lstat err %v)", err)
		}
	})

	t.Run("a symlink at the final name is replaced by the real file", func(t *testing.T) {
		podDir, dst, victim, containers := setup(t)
		if err := os.Symlink(victim, dst); err != nil {
			t.Fatal(err)
		}
		if err := stageOwnershipSidecars(podDir, containers); err != nil {
			t.Fatalf("stageOwnershipSidecars: %v", err)
		}
		assertVictim(t, victim)
		fi, err := os.Lstat(dst)
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("final name is %v (err %v), want a regular file replacing the link", fi.Mode(), err)
		}
		if got, _ := os.ReadFile(dst); string(got) != body {
			t.Errorf("staged sidecar = %q, want %q", got, body)
		}
	})
}
