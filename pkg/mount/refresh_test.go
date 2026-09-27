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

package mount

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// refreshResolver is a mutable, call-counting Resolver: a test changes the data
// between Materialize and Refresh and asserts which fetches happened.
type refreshResolver struct {
	mu     sync.Mutex
	cms    map[string]SourceData
	cmErr  map[string]error
	tokenN int
	calls  map[string]int
}

func newRefreshResolver() *refreshResolver {
	return &refreshResolver{cms: map[string]SourceData{}, cmErr: map[string]error{}, calls: map[string]int{}}
}

func (f *refreshResolver) set(name string, immutable bool, kv ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := map[string][]byte{}
	for i := 0; i+1 < len(kv); i += 2 {
		d[kv[i]] = []byte(kv[i+1])
	}
	f.cms[name] = SourceData{Data: d, Immutable: immutable}
}

func (f *refreshResolver) fail(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmErr[name] = err
}

func (f *refreshResolver) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

func (f *refreshResolver) ConfigMap(_ context.Context, _, name string) (SourceData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["cm/"+name]++
	if err := f.cmErr[name]; err != nil {
		return SourceData{}, err
	}
	d, ok := f.cms[name]
	if !ok {
		return SourceData{}, fmt.Errorf("configMap %q: %w", name, os.ErrNotExist)
	}
	return d, nil
}

func (f *refreshResolver) Secret(_ context.Context, _, name string) (SourceData, error) {
	return SourceData{}, fmt.Errorf("secret %q: %w", name, os.ErrNotExist)
}

func (f *refreshResolver) ServiceAccountToken(_ context.Context, _, _ string, _ int64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["token"]++
	f.tokenN++
	return fmt.Sprintf("TOKEN-%d", f.tokenN), nil
}

// mountBox builds a one-container PodBox with the given volumes and mounts.
func mountBox(vols []*runtimev1.Volume, mounts ...*runtimev1.VolumeMount) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:      "pod-1",
		Namespace:  "default",
		Name:       "demo",
		Volumes:    vols,
		Containers: []*runtimev1.Container{{Name: "main", VolumeMounts: mounts}},
	}
}

func cmVolume(name, cm string) *runtimev1.Volume {
	return &runtimev1.Volume{Name: name, ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: cm}}
}

// liveGen returns the generation dir ..data names under dir.
func liveGen(t *testing.T, dir string) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(dir, dataLink))
	if err != nil {
		t.Fatalf("readlink %s/..data: %v", dir, err)
	}
	return target
}

// generations lists the generation dirs present under dir.
func generations(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && isGenerationName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

func readString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// layoutShape describes a mount dir with the generation name normalized, so a
// create-time and a refresh-time layout of the same data compare equal.
func layoutShape(t *testing.T, dir string) map[string]string {
	t.Helper()
	gen := liveGen(t, dir)
	shape := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case name == gen:
			name = "<gen>"
			snap, err := snapshotTree(filepath.Join(dir, gen))
			if err != nil {
				t.Fatal(err)
			}
			for rel, te := range snap {
				shape["<gen>/"+rel] = fmt.Sprintf("%v %q", te.mode, te.data)
			}
		case e.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if target == gen {
				target = "<gen>"
			}
			shape[name] = "-> " + target
		default:
			shape[name] = e.Type().String()
		}
	}
	return shape
}

// countFlips swaps the rename seam for the test: it counts renames onto a
// ..data link and, at each one, asserts the generation the fresh link names is
// already complete (want: key -> content).
func countFlips(t *testing.T, want map[string]string) *int {
	t.Helper()
	n := 0
	orig := rename
	rename = func(oldpath, newpath string) error {
		if filepath.Base(newpath) == dataLink {
			n++
			target, err := os.Readlink(oldpath)
			if err != nil {
				t.Errorf("flip source %s is not a symlink: %v", oldpath, err)
			}
			gen := filepath.Join(filepath.Dir(newpath), target)
			for k, v := range want {
				if got, err := os.ReadFile(filepath.Join(gen, k)); err != nil || string(got) != v {
					t.Errorf("at the flip, %s/%s = %q (%v), want %q: the new tree must be complete before it goes live", target, k, got, err, v)
				}
			}
		}
		return orig(oldpath, newpath)
	}
	t.Cleanup(func() { rename = orig })
	return &n
}

// TestRefreshSwapsGenerationsAtomically is the pkg/mount gate for the
// projected-volume refresh: generation-backed mounts use the kubelet atomic
// writer layout at create and at refresh alike, a refresh flips ..data with one
// rename after the new tree is complete, a failed fetch leaves the live
// generation alone, and immutable sources, subPath mounts, and SA tokens with
// lifetime to spare are not re-resolved.
func TestRefreshSwapsGenerationsAtomically(t *testing.T) {
	ctx := context.Background()

	t.Run("configmap-change-flips-once-and-old-readers-keep-old", func(t *testing.T) {
		root := t.TempDir()
		r := newRefreshResolver()
		r.set("app", false, "a", "1", "b", "2")
		box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "app")},
			&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg"})
		layout, err := Materialize(ctx, box, root, "", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		dir := filepath.Join(root, "etc/cfg")
		oldGen := liveGen(t, dir)

		held, err := os.Open(filepath.Join(dir, "a"))
		if err != nil {
			t.Fatalf("open old a: %v", err)
		}
		defer func() { _ = held.Close() }()

		r.set("app", false, "a", "10", "b", "2")
		flips := countFlips(t, map[string]string{"a": "10", "b": "2"})
		res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if *flips != 1 {
			t.Errorf("..data flips = %d, want exactly 1 rename", *flips)
		}
		if got := res.Volumes; len(got) != 1 || got[0].Outcome != RefreshUpdated {
			t.Fatalf("outcomes = %+v, want one Updated", got)
		}
		buf := make([]byte, 16)
		n, err := held.Read(buf)
		if err != nil || string(buf[:n]) != "1" {
			t.Errorf("reader holding the old file read %q (%v), want the old content %q", buf[:n], err, "1")
		}
		if got := readString(t, filepath.Join(dir, "a")); got != "10" {
			t.Errorf("a after refresh = %q, want 10", got)
		}
		if newGen := liveGen(t, dir); newGen == oldGen {
			t.Errorf("..data still names %s after a change", oldGen)
		}
		if gens := generations(t, dir); len(gens) != 1 {
			t.Errorf("generations after refresh = %v, want only the live one (the old one removed)", gens)
		}

		// An unchanged refresh flips nothing.
		res, err = Refresh(ctx, root, box, r, RefreshOptions{State: res.State})
		if err != nil || res.Volumes[0].Outcome != RefreshUnchanged || *flips != 1 {
			t.Errorf("unchanged refresh: outcome %+v err %v flips %d, want Unchanged with no flip", res.Volumes, err, *flips)
		}
	})

	t.Run("second-key-fetch-fails-keeps-old-generation", func(t *testing.T) {
		root := t.TempDir()
		r := newRefreshResolver()
		r.set("one", false, "k1", "v1")
		r.set("two", false, "k2", "v2")
		r.set("other", false, "o", "x")
		proj := &runtimev1.Volume{Name: "proj", Projected: &runtimev1.ProjectedVolumeSource{
			Sources: []*runtimev1.VolumeProjection{
				{ConfigMap: &runtimev1.ConfigMapProjection{Name: "one"}},
				{ConfigMap: &runtimev1.ConfigMapProjection{Name: "two"}},
			},
		}}
		box := mountBox([]*runtimev1.Volume{proj, cmVolume("other", "other")},
			&runtimev1.VolumeMount{Name: "proj", MountPath: "/etc/proj"},
			&runtimev1.VolumeMount{Name: "other", MountPath: "/etc/other"})
		layout, err := Materialize(ctx, box, root, "", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		dir := filepath.Join(root, "etc/proj")
		oldGen := liveGen(t, dir)

		r.set("one", false, "k1", "CHANGED")
		r.fail("two", errors.New("apiserver unavailable"))
		r.set("other", false, "o", "y")
		flips := countFlips(t, nil)
		res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
		if err == nil || !strings.Contains(err.Error(), "proj") {
			t.Fatalf("Refresh err = %v, want an error naming volume proj", err)
		}
		if got := liveGen(t, dir); got != oldGen {
			t.Errorf("..data = %s, want the old generation %s kept", got, oldGen)
		}
		if got := readString(t, filepath.Join(dir, "k1")); got != "v1" {
			t.Errorf("k1 = %q, want the old v1", got)
		}
		if gens := generations(t, dir); len(gens) != 1 {
			t.Errorf("generations = %v, want only the old one (the failed render discarded)", gens)
		}
		// The failure did not stop the other volume.
		if got := readString(t, filepath.Join(root, "etc/other/o")); got != "y" {
			t.Errorf("other/o = %q, want y (a failure elsewhere must not stop this volume)", got)
		}
		if *flips != 1 {
			t.Errorf("flips = %d, want 1 (the healthy volume only)", *flips)
		}
		byName := map[string]RefreshOutcome{}
		for _, v := range res.Volumes {
			byName[v.Name] = v.Outcome
		}
		if byName["proj"] != RefreshFailed || byName["other"] != RefreshUpdated {
			t.Errorf("outcomes = %v, want proj Failed, other Updated", byName)
		}
	})

	t.Run("immutable-source-not-refetched", func(t *testing.T) {
		root := t.TempDir()
		r := newRefreshResolver()
		r.set("frozen", true, "a", "1")
		box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "frozen")},
			&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg"})
		layout, err := Materialize(ctx, box, root, "", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		before := r.count("cm/frozen")
		res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if after := r.count("cm/frozen"); after != before {
			t.Errorf("immutable ConfigMap fetched %d more times, want 0", after-before)
		}
		if res.Volumes[0].Outcome != RefreshSkipped {
			t.Errorf("outcome = %+v, want Skipped", res.Volumes[0])
		}
	})

	t.Run("subpath-mount-untouched", func(t *testing.T) {
		root := t.TempDir()
		r := newRefreshResolver()
		r.set("app", false, "a", "1")
		box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "app")},
			&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/a.conf", SubPath: "a"})
		layout, err := Materialize(ctx, box, root, "", r)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		r.set("app", false, "a", "2")
		before := r.count("cm/app")
		res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if got := readString(t, filepath.Join(root, "etc/a.conf")); got != "1" {
			t.Errorf("subPath file = %q, want the create-time 1", got)
		}
		if r.count("cm/app") != before || res.Volumes[0].Outcome != RefreshSkipped {
			t.Errorf("subPath mount re-resolved (%d fetches) or not skipped (%+v)", r.count("cm/app")-before, res.Volumes[0])
		}
	})

	tokenBox := func() *runtimev1.PodBox {
		return mountBox([]*runtimev1.Volume{{Name: "tok", Projected: &runtimev1.ProjectedVolumeSource{
			Sources: []*runtimev1.VolumeProjection{
				{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: 3600}},
			},
		}}}, &runtimev1.VolumeMount{Name: "tok", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount"})
	}
	for _, tc := range []struct {
		name      string
		elapsed   time.Duration
		wantMint  bool
		wantToken string
	}{
		{name: "sa-token-under-20pct-reminted", elapsed: 50 * time.Minute, wantMint: true, wantToken: "TOKEN-2"},
		{name: "sa-token-over-20pct-kept", elapsed: 10 * time.Minute, wantMint: false, wantToken: "TOKEN-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			r := newRefreshResolver()
			box := tokenBox()
			layout, err := Materialize(ctx, box, root, "", r)
			if err != nil {
				t.Fatalf("Materialize: %v", err)
			}
			dir := filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount")
			iss, ok := layout.State.Tokens[filepath.Join(dir, "token")]
			if !ok {
				t.Fatalf("create did not record the token issue (state %+v)", layout.State)
			}
			now := func() time.Time { return iss.IssuedAt.Add(tc.elapsed) }
			res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State, Now: now})
			if err != nil {
				t.Fatalf("Refresh: %v", err)
			}
			if minted := r.count("token") == 2; minted != tc.wantMint {
				t.Errorf("re-minted = %v, want %v (token calls %d)", minted, tc.wantMint, r.count("token"))
			}
			if got := readString(t, filepath.Join(dir, "token")); got != tc.wantToken {
				t.Errorf("token = %q, want %q", got, tc.wantToken)
			}
			if tc.wantMint && !res.State.Tokens[filepath.Join(dir, "token")].IssuedAt.Equal(now()) {
				t.Errorf("re-minted token's issue time not recorded: %+v", res.State.Tokens)
			}
		})
	}

	t.Run("create-layout-equals-refresh-layout", func(t *testing.T) {
		mounts := &runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg"}
		items := []*runtimev1.KeyToPath{{Key: "a", Path: "a"}, {Key: "n", Path: "sub/n"}}
		vol := &runtimev1.Volume{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app", Items: items}}
		box := mountBox([]*runtimev1.Volume{vol}, mounts)

		created := t.TempDir()
		rc := newRefreshResolver()
		rc.set("app", false, "a", "final", "n", "nested")
		if _, err := Materialize(ctx, box, created, "", rc); err != nil {
			t.Fatalf("Materialize: %v", err)
		}

		refreshed := t.TempDir()
		rr := newRefreshResolver()
		rr.set("app", false, "a", "first", "n", "nested")
		layout, err := Materialize(ctx, box, refreshed, "", rr)
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		rr.set("app", false, "a", "final", "n", "nested")
		if _, err := Refresh(ctx, refreshed, box, rr, RefreshOptions{State: layout.State}); err != nil {
			t.Fatalf("Refresh: %v", err)
		}

		want := layoutShape(t, filepath.Join(created, "etc/cfg"))
		got := layoutShape(t, filepath.Join(refreshed, "etc/cfg"))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("refresh-time layout differs from create-time layout:\n got %v\nwant %v", got, want)
		}
		if want["..data"] != "-> <gen>" || want["a"] != "-> ..data/a" || want["sub"] != "-> ..data/sub" {
			t.Errorf("create-time layout is not the atomic-writer layout: %v", want)
		}
	})
}

// TestWriteGenerationRefusesUnsafeGenerations drives writeGeneration's fill seam
// to plant each shape verifyGeneration must refuse, and asserts the refusal
// happens before any flip: no rename onto ..data, the old generation still live
// and still on disk, and the bad generation discarded.
func TestWriteGenerationRefusesUnsafeGenerations(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("host"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		plant   func(t *testing.T, gen string)
		wantErr string
	}{
		{
			name: "symlink-entry",
			plant: func(t *testing.T, gen string) {
				if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(gen, "k")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "neither a regular file nor a directory",
		},
		{
			name: "dotdot-prefixed-top-level-key",
			plant: func(t *testing.T, gen string) {
				if err := os.WriteFile(filepath.Join(gen, "..data2"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: `reserved ".." prefix`,
		},
		{
			name: "generation-resolving-outside-the-mount-dir",
			plant: func(t *testing.T, gen string) {
				if err := os.RemoveAll(gen); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, gen); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "resolves outside mount dir",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := writeGeneration(dir, func(gen, _ string) error {
				return os.WriteFile(filepath.Join(gen, "k"), []byte("old"), 0o644)
			}); err != nil {
				t.Fatalf("seed generation: %v", err)
			}
			oldGen := liveGen(t, dir)

			flips := countFlips(t, nil)
			flipped, err := writeGeneration(dir, func(gen, _ string) error {
				tc.plant(t, gen)
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want a refusal containing %q", err, tc.wantErr)
			}
			if flipped || *flips != 0 {
				t.Errorf("flipped = %v, flips = %d: the refusal must come before any flip", flipped, *flips)
			}
			if got := liveGen(t, dir); got != oldGen {
				t.Errorf("..data = %s, want the old generation %s", got, oldGen)
			}
			if got := readString(t, filepath.Join(dir, "k")); got != "old" {
				t.Errorf("k = %q, want old", got)
			}
			if gens := generations(t, dir); len(gens) != 1 || gens[0] != oldGen {
				t.Errorf("generations = %v, want only %s (the refused one discarded)", gens, oldGen)
			}
			if got := readString(t, filepath.Join(outside, "secret")); got != "host" {
				t.Errorf("host file touched: %q", got)
			}
		})
	}
}

// TestRefreshHousekeepingFailureAfterFlipIsAWarning forces the key-link step
// (after a successful ..data flip) to fail and asserts the outcome is
// RefreshUpdatedWithWarnings naming that error — the new generation is live —
// not RefreshFailed, which means the live generation was left alone.
func TestRefreshHousekeepingFailureAfterFlipIsAWarning(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	r := newRefreshResolver()
	r.set("app", false, "a", "1")
	box := mountBox([]*runtimev1.Volume{cmVolume("cfg", "app")},
		&runtimev1.VolumeMount{Name: "cfg", MountPath: "/etc/cfg"})
	layout, err := Materialize(ctx, box, root, "", r)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	dir := filepath.Join(root, "etc/cfg")
	oldGen := liveGen(t, dir)

	// A new key needs a new top-level link; make exactly that rename fail.
	r.set("app", false, "a", "2", "b", "new")
	orig := rename
	rename = func(oldpath, newpath string) error {
		if filepath.Base(newpath) == "b" {
			return errors.New("injected link failure")
		}
		return orig(oldpath, newpath)
	}
	t.Cleanup(func() { rename = orig })

	res, err := Refresh(ctx, root, box, r, RefreshOptions{State: layout.State})
	if err == nil || !strings.Contains(err.Error(), "injected link failure") || !strings.Contains(err.Error(), "cfg") {
		t.Fatalf("err = %v, want the housekeeping error naming volume cfg", err)
	}
	v := res.Volumes[0]
	if v.Outcome != RefreshUpdatedWithWarnings || v.Err == nil || !strings.Contains(v.Err.Error(), "injected link failure") {
		t.Errorf("outcome = %+v, want UpdatedWithWarnings carrying the link error", v)
	}
	if got := liveGen(t, dir); got == oldGen {
		t.Errorf("..data still names the old generation; the flip should have happened")
	}
	if got := readString(t, filepath.Join(dir, "..data/b")); got != "new" {
		t.Errorf("..data/b = %q, want new (the new generation is live)", got)
	}
	if got := readString(t, filepath.Join(dir, "a")); got != "2" {
		t.Errorf("a = %q, want 2", got)
	}
}
