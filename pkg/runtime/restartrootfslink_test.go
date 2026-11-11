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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

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

// linkRig is the native-spine runtime plus the two fakes the assertions read:
// the spawner (how many spawns happened) and the waiter (how many WaitExit
// calls are still blocked).
type linkRig struct {
	rt     *Runtime
	spawn  *fakeSpawner
	waiter *trackingWaiter
}

// spawns is how many processes the fake spawner has started so far.
func (lr linkRig) spawns() int {
	lr.spawn.mu.Lock()
	defer lr.spawn.mu.Unlock()
	return len(lr.spawn.specs)
}

// trackingWaiter is blockingWaiter with a count of the WaitExit calls still
// blocked, so a cleanup can show that no reaper outlives the rig.
type trackingWaiter struct {
	*blockingWaiter
	inFlight atomic.Int64
}

func (w *trackingWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	w.inFlight.Add(1)
	defer w.inFlight.Add(-1)
	return w.blockingWaiter.WaitExit(ctx, pid)
}

// releaseAll ends every wait not yet released, as the processes' exits would.
// It runs only at cleanup, when no verb can race it into a double release.
func (w *trackingWaiter) releaseAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ch := range w.released {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

// newNativeLinkRig is newCaseRig for the native spine: the real cache, puller
// and unpacker (a fake tree cannot follow a link), a fake spawner, and the
// restart seams of TestRestartContainerReExecs so a kill releases the waiter.
//
// Its cleanup releases every wait still blocked and closes the runtime
// (idempotent; newTestRuntimeCfg's own Close then finds it done), then fails
// the test if any WaitExit is still blocked: the blocking waiter's goroutines
// must end with the test, not leak into the next. The release is needed, not
// tidy: Close's supervision cancel does not reach the reaper of a replacement
// a successful RestartContainer spawned, so without it that wait outlives the
// test and Close spends its whole deadline on it.
func newNativeLinkRig(t *testing.T) linkRig {
	t.Helper()
	root := t.TempDir()
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	unpacker, err := image.NewUnpacker(cache, image.WithCloner((&countingCloner{}).cloner()))
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
	w := &trackingWaiter{blockingWaiter: newBlockingWaiter()}
	sp := &fakeSpawner{}
	rt := newTestRuntimeCfg(t, Config{Root: root}, Deps{
		Puller: puller, Unpacker: unpacker, Spawner: sp, Waiter: w, Cache: cache,
	})
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal
	t.Cleanup(func() {
		w.releaseAll()
		if err := rt.Close(); err != nil {
			t.Errorf("close runtime: %v", err)
		}
		if n := w.inFlight.Load(); n != 0 {
			t.Errorf("%d WaitExit call(s) still blocked after the runtime closed", n)
		}
	})
	return linkRig{rt: rt, spawn: sp, waiter: w}
}

// assertRefusedByLink fails unless the verb's response names the
// destination-link refusal: the typed reason the image-resolve path returns for
// a materialize failure, and the sentinel's own text in the message. Any other
// failure (a spawn error, a pull error) carries a different reason or message.
func assertRefusedByLink(t *testing.T, verb string, st *rpcstatus.Status, reason runtimev1.FailureReason) {
	t.Helper()
	if st == nil {
		t.Fatalf("%s reported success through a rootfs link", verb)
	}
	if reason != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
		t.Errorf("%s failure_reason = %v, want %v (a materialize refusal)",
			verb, reason, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL)
	}
	if want := image.ErrDestinationLink.Error(); !strings.Contains(st.GetMessage(), want) {
		t.Errorf("%s error message = %q, want it to carry %q", verb, st.GetMessage(), want)
	}
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
// destination-link refusal as its cause, spawn nothing, and leave the link's
// target byte-identical. A link that stays inside the rootfs is not refused,
// so the refusal is not a blanket failure of any rootfs holding a link.
func TestRestartContainerRefusesRootfsSymlinkEscape(t *testing.T) {
	host := testRegistryHost(t)

	t.Run("restart", func(t *testing.T) {
		lr := newNativeLinkRig(t)
		rt := lr.rt
		ref := pushOSImage(t, host, "esc/restart", "darwin", linkEscapeEntries())
		const podID = "pod-esc"
		mustCreatePod(t, rt, pullBox(rt, podID,
			&runtimev1.Container{Name: "main", Image: ref, Command: []string{"/bin/app"}}))
		rootfs := derivedRootfs(t, rt, podID)
		if _, err := os.Stat(filepath.Join(rootfs, "etc", "hostname")); err != nil {
			t.Fatalf("setup: the create did not materialize etc/hostname: %v", err)
		}
		before := statusNamed(t, rt, podID, "main").GetRestartCount()
		spawnsBefore := lr.spawns()
		victim, snap := plantEtcLink(t, rootfs)

		resp, err := rt.RestartContainer(context.Background(),
			&runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		assertRefusedByLink(t, "RestartContainer", resp.GetError(), resp.GetFailureReason())
		if got := lr.spawns(); got != spawnsBefore {
			t.Errorf("spawns = %d after the refused restart, want %d (no spawn through the link)", got, spawnsBefore)
		}
		if got := statusNamed(t, rt, podID, "main").GetRestartCount(); got != before {
			t.Errorf("restart_count = %d, want %d (unchanged by a refused restart)", got, before)
		}
		assertVictimUntouched(t, victim, snap)
	})

	t.Run("start", func(t *testing.T) {
		lr := newNativeLinkRig(t)
		rt := lr.rt
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
		spawnsBefore := lr.spawns()
		victim, snap := plantEtcLink(t, rootfs)

		resp, err := rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: podID, Container: "late"})
		if err != nil {
			t.Fatalf("StartContainer: %v", err)
		}
		assertRefusedByLink(t, "StartContainer", resp.GetError(), resp.GetFailureReason())
		if got := lr.spawns(); got != spawnsBefore {
			t.Errorf("spawns = %d after the refused start, want %d (no spawn through the link)", got, spawnsBefore)
		}
		assertVictimUntouched(t, victim, snap)
	})

	t.Run("in_root_link_still_restarts", func(t *testing.T) {
		lr := newNativeLinkRig(t)
		rt := lr.rt
		ref := pushOSImage(t, host, "esc/inroot", "darwin", linkEscapeEntries())
		const podID = "pod-esc-inroot"
		mustCreatePod(t, rt, pullBox(rt, podID,
			&runtimev1.Container{Name: "main", Image: ref, Command: []string{"/bin/app"}}))
		rootfs := derivedRootfs(t, rt, podID)
		if _, err := os.Stat(filepath.Join(rootfs, "etc", "hostname")); err != nil {
			t.Fatalf("setup: the create did not materialize etc/hostname: %v", err)
		}
		before := statusNamed(t, rt, podID, "main").GetRestartCount()
		spawnsBefore := lr.spawns()
		// A relative link to a sibling inside the rootfs: etc -> etc.real.
		etc := filepath.Join(rootfs, "etc")
		if err := os.Rename(etc, filepath.Join(rootfs, "etc.real")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("etc.real", etc); err != nil {
			t.Fatal(err)
		}

		resp, err := rt.RestartContainer(context.Background(),
			&runtimev1.RestartContainerRequest{PodId: podID, Container: "main"})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if e := resp.GetError(); e != nil {
			t.Fatalf("RestartContainer through an in-root link failed: %v (reason %v)", e, resp.GetFailureReason())
		}
		if got := statusNamed(t, rt, podID, "main").GetRestartCount(); got != before+1 {
			t.Errorf("restart_count = %d, want %d", got, before+1)
		}
		if got := lr.spawns(); got != spawnsBefore+1 {
			t.Errorf("spawns = %d, want %d (one re-spawn)", got, spawnsBefore+1)
		}
		if fi, err := os.Lstat(etc); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("etc is no longer the in-root link after the restart (lstat %v, err %v)", fi, err)
		}
		if _, err := os.Stat(filepath.Join(rootfs, "etc.real", "hostname")); err != nil {
			t.Errorf("etc.real/hostname missing after the restart: %v", err)
		}
	})
}
