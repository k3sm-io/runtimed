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
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The pair python:3.13-bookworm carries, in the shape it carries it: a regular
// file and a symlink to it, in names that differ only by case. The second pair
// is two regular files, so a merge shows up in their bytes.
const (
	casePathManUpper    = "usr/share/man/man7/PAM.7.gz"
	casePathManLower    = "usr/share/man/man7/pam.7.gz"
	casePathConfigUpper = "etc/Config"
	casePathConfigLower = "etc/config"
)

// caseOnlyImageHeaders is the layer holding both pairs.
func caseOnlyImageHeaders() []caseEntry {
	return []caseEntry{
		{hdr: tar.Header{Name: casePathManUpper, Typeflag: tar.TypeReg, Mode: 0o644}, data: "PAM page"},
		{hdr: tar.Header{Name: casePathManLower, Typeflag: tar.TypeSymlink, Mode: 0o777, Linkname: "PAM.7.gz"}},
		{hdr: tar.Header{Name: casePathConfigUpper, Typeflag: tar.TypeReg, Mode: 0o644}, data: "upper"},
		{hdr: tar.Header{Name: casePathConfigLower, Typeflag: tar.TypeReg, Mode: 0o600}, data: "lower"},
	}
}

// caseEntry is one tar entry of a fixture layer.
type caseEntry struct {
	hdr  tar.Header
	data string
}

// pushCaseImage publishes a linux/arm64 image of one layer holding entries.
func pushCaseImage(t *testing.T, host, repo string, entries []caseEntry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		hdr.Size = int64(len(e.data))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("write header %s: %v", hdr.Name, err)
		}
		if _, err := tw.Write([]byte(e.data)); err != nil {
			t.Fatalf("write body %s: %v", hdr.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var img ggcrv1.Image
	if img, err = mutate.AppendLayers(empty.Image, layer); err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "arm64"
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push %s: %v", ref, err)
	}
	return ref.String()
}

// countingCloner counts the clones a materialize attempted, so a refusal can be
// shown to have stopped ahead of the first one.
type countingCloner struct {
	n atomic.Int64
}

func (c *countingCloner) Clone(src, dst string) (bool, error) {
	c.n.Add(1)
	return image.ByteCopier{}.Clone(src, dst)
}

// caseRig is a runtime with the real puller and the real unpacker over one
// cache, and a vm backend that boots nothing.
type caseRig struct {
	rt     *Runtime
	vmb    *fakeVMBackend
	cache  *image.Cache
	cloner *countingCloner
}

// newCaseRig builds a caseRig. A nil probe leaves the real measurement in place.
func newCaseRig(t *testing.T, probe image.CaseProbe) *caseRig {
	t.Helper()
	root := t.TempDir()
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	cloner := &countingCloner{}
	opts := []image.UnpackerOption{image.WithCloner(cloner)}
	if probe != nil {
		opts = append(opts, image.WithCaseProbe(probe))
	}
	unpacker, err := image.NewUnpacker(cache, opts...)
	if err != nil {
		t.Fatal(err)
	}
	index, err := image.NewFileIndex(cache)
	if err != nil {
		t.Fatal(err)
	}
	puller, err := image.NewPuller(cache, image.RemoteFetch, index)
	if err != nil {
		t.Fatal(err)
	}
	vmb := &fakeVMBackend{available: true, bootOK: true}
	cfg, deps := vmPodConfig(t, Deps{VMBackend: vmb, Puller: puller, Unpacker: unpacker})
	cfg.Root, deps.Cache = root, cache
	return &caseRig{rt: newTestRuntimeCfg(t, cfg, deps), vmb: vmb, cache: cache, cloner: cloner}
}

// create drives the real CreatePod for a one-container vm pod running ref.
func (r *caseRig) create(t *testing.T, ref string) *runtimev1.CreatePodResponse {
	t.Helper()
	box := vmBoxWith(r.rt, "pod-case", nil, []*runtimev1.Container{
		{Name: "probe", Image: ref, Command: []string{"/bin/sh"}},
	})
	resp, err := r.rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	return resp
}

// podRootfs is the materialized rootfs of the pod create made.
func (r *caseRig) podRootfs(t *testing.T) string {
	t.Helper()
	return filepath.Join(mustPodDir(t, r.rt, "pod-case"), "rootfs")
}

// snapshots lists the committed snapshot directories.
func (r *caseRig) snapshots(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(r.cache.SnapshotsRoot(), "sha256", "*"))
	if err != nil {
		t.Fatal(err)
	}
	var committed []string
	for _, d := range dirs {
		if !strings.HasPrefix(filepath.Base(d), ".") {
			committed = append(committed, d)
		}
	}
	return committed
}

// ownershipPaths reads the one committed snapshot's ownership sidecar, the
// record the guest restores the tree from.
func (r *caseRig) ownershipPaths(t *testing.T) map[string]bool {
	t.Helper()
	snaps := r.snapshots(t)
	if len(snaps) != 1 {
		t.Fatalf("committed snapshots = %v, want exactly one", snaps)
	}
	entries, err := image.ReadOwnershipSidecar(filepath.Join(snaps[0], "ownership.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]bool, len(entries))
	for _, e := range entries {
		paths[e.Path] = true
	}
	return paths
}

// assertRefusal checks a refusal is ROOTFS_SETUP and names
// every fragment in want, and that the guest was never asked for.
func (r *caseRig) assertRefusal(t *testing.T, resp *runtimev1.CreatePodResponse, want ...string) {
	t.Helper()
	msg := resp.GetError().GetMessage()
	if resp.GetError() == nil {
		t.Fatal("CreatePod succeeded; a pair the destination would merge must be refused")
	}
	if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP {
		t.Errorf("failure reason = %v, want ROOTFS_SETUP", got)
	}
	for _, s := range want {
		if !strings.Contains(msg, s) {
			t.Errorf("refusal does not name %q:\n%s", s, msg)
		}
	}
	if n, _ := r.vmb.created(); n != 0 {
		t.Errorf("CreateVM called %d times after a refusal", n)
	}
}

// assertBothOnDisk proves tree holds both pairs as separate nodes, which only a
// genuinely case-sensitive directory can.
func assertBothOnDisk(t *testing.T, tree string) {
	t.Helper()
	for p, want := range map[string]string{casePathManUpper: "PAM page", casePathConfigUpper: "upper", casePathConfigLower: "lower"} {
		got, err := os.ReadFile(filepath.Join(tree, p))
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q: the pair merged", p, got, want)
		}
	}
	if target, err := os.Readlink(filepath.Join(tree, casePathManLower)); err != nil || target != "PAM.7.gz" {
		t.Errorf("readlink %s = %q, %v, want PAM.7.gz", casePathManLower, target, err)
	}
}

// tempIsCaseSensitive measures this host's t.TempDir with one name and its other
// spelling.
func tempIsCaseSensitive(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "witness"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := os.Lstat(filepath.Join(dir, "WITNESS"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err != nil
}

// TestVMImageWithCaseOnlyPathsMaterializes is the gate for a Linux image that
// holds two names differing only by case, from CreatePod down through the real
// puller and unpacker: the store's measured case sensitivity decides, a
// case-sensitive store holds both names, and a case-insensitive one refuses and
// says what to do.
//
// The measured rows inject the measurement, because a stock host's temp directory
// is case-insensitive and a case-sensitive volume needs a mount. The real rows
// run the real measurement and skip by name when the temp directory is the other
// kind; point TMPDIR at a case-sensitive volume to run the first.
func TestVMImageWithCaseOnlyPathsMaterializes(t *testing.T) {
	host := testRegistryHost(t)
	pairRef := pushCaseImage(t, host, "case-pair", caseOnlyImageHeaders())
	const remedy = "sudo k3sm install --data-volume"

	sensitive := func(*os.Root) (bool, error) { return true, nil }
	insensitive := func(*os.Root) (bool, error) { return false, nil }

	t.Run("a store measured case-sensitive materializes both paths", func(t *testing.T) {
		rig := newCaseRig(t, sensitive)
		resp := rig.create(t, pairRef)
		if resp.GetError() != nil {
			t.Fatalf("CreatePod refused: %v (%v)", resp.GetError(), resp.GetFailureReason())
		}
		if n, _ := rig.vmb.created(); n != 1 {
			t.Errorf("CreateVM called %d times, want 1", n)
		}
		paths := rig.ownershipPaths(t)
		for _, p := range []string{casePathManUpper, casePathManLower, casePathConfigUpper, casePathConfigLower} {
			if !paths[p] {
				t.Errorf("the ownership sidecar has no entry for %s", p)
			}
		}
		if rig.cloner.n.Load() == 0 {
			t.Error("the tree was never cloned into the pod")
		}
	})

	t.Run("a store measured case-insensitive refuses and names the pair and the fix", func(t *testing.T) {
		rig := newCaseRig(t, insensitive)
		rig.assertRefusal(t, rig.create(t, pairRef), casePathManUpper, casePathManLower, remedy)
		if snaps := rig.snapshots(t); len(snaps) != 0 {
			t.Errorf("a refused unpack committed %v", snaps)
		}
	})

	t.Run("a store that cannot be measured refuses and says so", func(t *testing.T) {
		rig := newCaseRig(t, func(*os.Root) (bool, error) { return false, errors.New("probe boom") })
		rig.assertRefusal(t, rig.create(t, pairRef), casePathManUpper, casePathManLower, remedy, "probe boom")
	})

	t.Run("a pair-free image is not refused on a case-insensitive store", func(t *testing.T) {
		rig := newCaseRig(t, insensitive)
		ref := pushCaseImage(t, host, "pair-free", []caseEntry{
			{hdr: tar.Header{Name: casePathManUpper, Typeflag: tar.TypeReg, Mode: 0o644}, data: "PAM page"},
		})
		if resp := rig.create(t, ref); resp.GetError() != nil {
			t.Fatalf("CreatePod refused a pair-free image: %v", resp.GetError())
		}
	})

	t.Run("real measurement on a case-sensitive temp volume keeps both paths", func(t *testing.T) {
		if !tempIsCaseSensitive(t) {
			t.Skip("needs a case-sensitive temp directory (TMPDIR on a case-sensitive volume); this one merges case")
		}
		rig := newCaseRig(t, nil)
		resp := rig.create(t, pairRef)
		if resp.GetError() != nil {
			t.Fatalf("CreatePod refused: %v", resp.GetError())
		}
		snaps := rig.snapshots(t)
		if len(snaps) != 1 {
			t.Fatalf("committed snapshots = %v, want one", snaps)
		}
		assertBothOnDisk(t, filepath.Join(snaps[0], image.TreeRootfsName))
		assertBothOnDisk(t, rig.podRootfs(t))
	})

	t.Run("real measurement on a case-insensitive temp volume refuses", func(t *testing.T) {
		if tempIsCaseSensitive(t) {
			t.Skip("needs a case-insensitive temp directory; this one keeps case apart")
		}
		rig := newCaseRig(t, nil)
		rig.assertRefusal(t, rig.create(t, pairRef), casePathManUpper, casePathManLower, remedy)
	})
}
