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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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

// linkEscapeEntries is the image tree both subtests materialize: a file under a
// directory the pod can replace with a link, and the binary the command names.
func linkEscapeEntries() []caseEntry {
	return []caseEntry{
		{hdr: tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "etc/hostname", Typeflag: tar.TypeReg, Mode: 0o644}, data: "h"},
		{hdr: tar.Header{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "bin/app", Typeflag: tar.TypeReg, Mode: 0o755}, data: "x"},
	}
}

// pushOSImage is pushCaseImage with the config's os as a parameter: the native
// spine admits only a darwin image, so the linux/arm64 fixture never reaches
// the materialize this test is about.
func pushOSImage(t *testing.T, host, repo, osName string, entries []caseEntry) string {
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
	cf.OS, cf.Architecture = osName, "arm64"
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

// newNativeLinkRig is newCaseRig for the native spine: the real cache, puller
// and unpacker (a fake tree cannot follow a link), a fake spawner, and the
// restart seams of TestRestartContainerReExecs so a kill releases the waiter.
func newNativeLinkRig(t *testing.T) *Runtime {
	t.Helper()
	root := t.TempDir()
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	unpacker, err := image.NewUnpacker(cache, image.WithCloner(&countingCloner{}))
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
	w := newBlockingWaiter()
	rt := newTestRuntimeCfg(t, Config{Root: root}, Deps{
		Puller: puller, Unpacker: unpacker, Spawner: &fakeSpawner{}, Waiter: w, Cache: cache,
	})
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal
	return rt
}

// plantEtcLink does what a pod can do to its own rootfs: replace etc with a
// link to a directory outside it. It returns the victim and its snapshot.
func plantEtcLink(t *testing.T, rootfs string) (string, map[string]string) {
	t.Helper()
	victim := t.TempDir()
	if err := os.WriteFile(filepath.Join(victim, "keep"), []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(rootfs, "etc")
	if err := os.RemoveAll(etc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, etc); err != nil {
		t.Fatal(err)
	}
	return victim, snapshotDir(t, victim)
}

// snapshotDir maps every path under dir to its mode and bytes.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		val := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			val += ":" + string(b)
		}
		out[rel] = val
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

// assertVictimUntouched fails if the victim gained, lost or changed anything.
func assertVictimUntouched(t *testing.T, victim string, before map[string]string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(victim, "hostname")); err == nil {
		t.Errorf("the materialize wrote hostname through the rootfs link into %s", victim)
	}
	after := snapshotDir(t, victim)
	if len(after) != len(before) {
		t.Errorf("victim changed: before %v, after %v", sortedKeys(before), sortedKeys(after))
		return
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("victim entry %q changed: %q -> %q", k, v, after[k])
		}
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestRestartContainerRefusesRootfsSymlinkEscape pins that re-materializing the
// image tree into a pod's rootfs never follows a link the pod put at one of the
// rootfs's directory components: the daemon writes as itself, so following it
// writes the tree's files wherever the pod pointed. The verb must report the
// failure instead, and leave the link's target byte-identical.
func TestRestartContainerRefusesRootfsSymlinkEscape(t *testing.T) {
	host := testRegistryHost(t)

	t.Run("restart", func(t *testing.T) {
		rt := newNativeLinkRig(t)
		ref := pushOSImage(t, host, "esc/restart", "darwin", linkEscapeEntries())
		const podID = "pod-esc"
		mustCreatePod(t, rt, pullBox(rt, podID,
			&runtimev1.Container{Name: "main", Image: ref, Command: []string{"/bin/app"}}))
		rootfs := derivedRootfs(t, rt, podID)
		if _, err := os.Stat(filepath.Join(rootfs, "etc", "hostname")); err != nil {
			t.Fatalf("setup: the create did not materialize etc/hostname: %v", err)
		}
		before := statusNamed(t, rt, podID, "main").GetRestartCount()
		victim, snap := plantEtcLink(t, rootfs)

		resp, err := rt.RestartContainer(context.Background(),
			&runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if resp.GetError() == nil {
			t.Errorf("RestartContainer reported success through a rootfs link (status %v)", resp.GetStatus().GetState())
		}
		if got := statusNamed(t, rt, podID, "main").GetRestartCount(); got != before {
			t.Errorf("restart_count = %d, want %d (unchanged by a refused restart)", got, before)
		}
		assertVictimUntouched(t, victim, snap)
	})

	t.Run("start", func(t *testing.T) {
		rt := newNativeLinkRig(t)
		good := pushOSImage(t, host, "esc/good", "darwin", linkEscapeEntries())
		// Not pushed yet: the create leaves this container waiting on the pull,
		// so StartContainer is the verb that later materializes it.
		late := host + "/esc/late:v1"
		const podID = "pod-esc-start"
		mustCreatePod(t, rt, pullBox(rt, podID,
			&runtimev1.Container{Name: "good", Image: good, Command: []string{"/bin/app"}},
			&runtimev1.Container{Name: "late", Image: late, Command: []string{"/bin/app"}}))
		if st := statusNamed(t, rt, podID, "late").GetState(); st.GetWaiting() == nil {
			t.Fatalf("setup: late container should be waiting, got %v", st)
		}
		rootfs := derivedRootfs(t, rt, podID)
		if _, err := os.Stat(filepath.Join(rootfs, "etc", "hostname")); err != nil {
			t.Fatalf("setup: the create did not materialize etc/hostname: %v", err)
		}
		pushOSImage(t, host, "esc/late", "darwin", linkEscapeEntries())
		victim, snap := plantEtcLink(t, rootfs)

		resp, err := rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: podID, Container: "late"})
		if err != nil {
			t.Fatalf("StartContainer: %v", err)
		}
		if resp.GetError() == nil {
			t.Errorf("StartContainer reported success through a rootfs link (status %v)", resp.GetStatus().GetState())
		}
		assertVictimUntouched(t, victim, snap)
	})
}
