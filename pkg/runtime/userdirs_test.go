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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errUserDirsOffInTests is the default DarwinUserDirs answer in unit tests
// (testDeps): the real probe names this user's shared /var/folders trees.
var errUserDirsOffInTests = errors.New("per-pod darwin user dirs are off in unit tests")

// fakeUserDirs returns a DarwinUserDirs seam over two temp trees laid out as
// dirhelper lays them out (…/T and …/C), plus their resolved paths.
func fakeUserDirs(t *testing.T) (func() (string, string, error), string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	temp, cache := filepath.Join(root, "T"), filepath.Join(root, "C")
	for _, d := range []string{temp, cache} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return func() (string, string, error) { return temp, cache, nil }, temp, cache
}

func lastSpec(t *testing.T, sp *fakeSpawner) []string {
	t.Helper()
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if len(sp.specs) == 0 {
		t.Fatal("nothing was spawned")
	}
	return sp.specs[len(sp.specs)-1].Env
}

func TestPodUserDirs(t *testing.T) {
	newRT := func(t *testing.T) (*Runtime, *fakeSpawner, string, string) {
		probe, temp, cache := fakeUserDirs(t)
		sp := &fakeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter(), DarwinUserDirs: probe})
		return rt, sp, temp, cache
	}

	t.Run("links into the data volume, suffix injected", func(t *testing.T) {
		rt, sp, temp, cache := newRT(t)
		const podID = "pod-ud"
		mustCreatePod(t, rt, hostBinBox(rt, podID))

		sfx := sandbox.UserDirSuffixPrefix + podID
		if got := mustEnvValue(t, lastSpec(t, sp), userDirSuffixEnv); got != sfx {
			t.Errorf("%s = %q, want %q", userDirSuffixEnv, got, sfx)
		}
		wantTemp, wantCache := podUserDirTargets(derivedRootfs(t, rt, podID))
		for _, l := range [][2]string{{filepath.Join(temp, sfx), wantTemp}, {filepath.Join(cache, sfx), wantCache}} {
			got, err := os.Readlink(l[0])
			if err != nil || got != l[1] {
				t.Errorf("link %s -> %q (%v), want -> %q", l[0], got, err, l[1])
			}
			fi, err := os.Stat(l[1])
			if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
				t.Errorf("target %s: %v %v, want a 0700 dir", l[1], fi, err)
			}
		}
	})

	t.Run("the profile grants exactly the pod's two links", func(t *testing.T) {
		rt, _, temp, cache := newRT(t)
		const podID = "pod-ud-prof"
		box := hostBinBox(rt, podID)
		mustCreatePod(t, rt, box)
		prof, err := rt.compileProfile(box, derivedRootfs(t, rt, podID), "", nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		sfx := sandbox.UserDirSuffixPrefix + podID
		for _, l := range []string{filepath.Join(temp, sfx), filepath.Join(cache, sfx)} {
			if !containsLine(prof, `  (literal "`+l+`")`) {
				t.Errorf("profile lacks the metadata literal for %s:\n%s", l, prof)
			}
		}
	})

	t.Run("a spec value is dropped", func(t *testing.T) {
		rt, sp, _, _ := newRT(t)
		const podID = "pod-ud-spec"
		box := hostBinBox(rt, podID)
		box.GetContainers()[0].Env = []*runtimev1.EnvVar{{Name: userDirSuffixEnv, Value: "k3sm.someone-else"}}
		mustCreatePod(t, rt, box)
		env := lastSpec(t, sp)
		if got := mustEnvValue(t, env, userDirSuffixEnv); got != sandbox.UserDirSuffixPrefix+podID {
			t.Errorf("%s = %q, want the runtime's own value", userDirSuffixEnv, got)
		}
		if n := countName(env, userDirSuffixEnv); n != 1 {
			t.Errorf("%s appears %d times, want 1", userDirSuffixEnv, n)
		}
	})

	t.Run("no link, no suffix", func(t *testing.T) {
		rt, _, temp, _ := newRT(t)
		const podID = "pod-ud-gone"
		box := hostBinBox(rt, podID)
		mustCreatePod(t, rt, box)
		if err := os.Remove(filepath.Join(temp, sandbox.UserDirSuffixPrefix+podID)); err != nil {
			t.Fatal(err)
		}
		env, err := rt.containerEnv(box, box.GetContainers()[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := envValue(env, userDirSuffixEnv); ok {
			t.Errorf("suffix injected with a link missing; dirhelper would make an undeletable dir: %v", env)
		}
		// The next spawn's ensure puts it back.
		rt.ensurePodUserDirLinks(box)
		if _, ok := rt.podUserDirLinksReady(box); !ok {
			t.Error("ensure did not restore the missing link")
		}
	})

	t.Run("an occupied link path is never replaced, and gets no suffix", func(t *testing.T) {
		rt, _, temp, _ := newRT(t)
		const podID = "pod-ud-occupied"
		link := filepath.Join(temp, sandbox.UserDirSuffixPrefix+podID)
		if err := os.Mkdir(link, 0o700); err != nil {
			t.Fatal(err)
		}
		box := hostBinBox(rt, podID)
		mustCreatePod(t, rt, box)
		if fi, err := os.Lstat(link); err != nil || !fi.IsDir() {
			t.Fatalf("the occupying directory was touched: %v %v", fi, err)
		}
		env, err := rt.containerEnv(box, box.GetContainers()[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := envValue(env, userDirSuffixEnv); ok {
			t.Error("suffix injected over an occupied link path")
		}
	})

	t.Run("a link to anything else is replaced", func(t *testing.T) {
		rt, _, temp, _ := newRT(t)
		const podID = "pod-ud-stale"
		link := filepath.Join(temp, sandbox.UserDirSuffixPrefix+podID)
		if err := os.Symlink("/nowhere", link); err != nil {
			t.Fatal(err)
		}
		box := hostBinBox(rt, podID)
		mustCreatePod(t, rt, box)
		want, _ := podUserDirTargets(derivedRootfs(t, rt, podID))
		if got, _ := os.Readlink(link); got != want {
			t.Errorf("stale link -> %q, want -> %q", got, want)
		}
	})

	t.Run("a container that runs as another uid gets no suffix", func(t *testing.T) {
		rt, _, _, _ := newRT(t)
		const podID = "pod-ud-uid"
		box := hostBinBox(rt, podID)
		mustCreatePod(t, rt, box)
		c := box.GetContainers()[0]
		c.SecurityContext = &runtimev1.SecurityContext{RunAsUser: int64(rt.userDirs.uid + 4242)}
		env, err := rt.containerEnv(box, c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := envValue(env, userDirSuffixEnv); ok {
			t.Error("suffix injected for a container whose uid has no links")
		}
	})

	t.Run("removing the pod dir removes the links", func(t *testing.T) {
		rt, _, temp, cache := newRT(t)
		const podID = "pod-ud-rm"
		mustCreatePod(t, rt, hostBinBox(rt, podID))
		if err := rt.removePodDir(podID); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{temp, cache} {
			if _, err := os.Lstat(filepath.Join(d, sandbox.UserDirSuffixPrefix+podID)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("link in %s survived the pod dir: %v", d, err)
			}
		}
	})

	t.Run("the startup sweep removes dangling links only", func(t *testing.T) {
		probe, temp, _ := fakeUserDirs(t)
		live := t.TempDir()
		mk := func(name, target string) string {
			p := filepath.Join(temp, name)
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			return p
		}
		dangling := mk(sandbox.UserDirSuffixPrefix+"dead", filepath.Join(live, "gone"))
		alive := mk(sandbox.UserDirSuffixPrefix+"alive", live)
		foreign := mk("not-ours", filepath.Join(live, "gone"))
		newTestRuntime(t, Deps{DarwinUserDirs: probe})
		if _, err := os.Lstat(dangling); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("dangling k3sm link survived: %v", err)
		}
		for _, p := range []string{alive, foreign} {
			if _, err := os.Lstat(p); err != nil {
				t.Errorf("%s was swept: %v", p, err)
			}
		}
	})

	t.Run("off: no suffix, no links, no grant", func(t *testing.T) {
		sp := &fakeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-ud-off"
		box := hostBinBox(rt, podID)
		mustCreatePod(t, rt, box)
		if _, ok := envValue(lastSpec(t, sp), userDirSuffixEnv); ok {
			t.Error("suffix injected with the feature off")
		}
		temp, _ := podUserDirTargets(derivedRootfs(t, rt, podID))
		if _, err := os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("targets made with the feature off: %v", err)
		}
	})
}

func containsLine(s, line string) bool {
	return slices.Contains(strings.Split(s, "\n"), line)
}

// TestWithoutEnvName pins the exec fallback's strip: every entry for the name
// goes, a longer name that shares its prefix stays, and the stored env is not
// modified.
func TestWithoutEnvName(t *testing.T) {
	t.Parallel()
	env := []string{"PATH=/usr/bin", userDirSuffixEnv + "=k3sm.p1", userDirSuffixEnv + "X=keep", userDirSuffixEnv + "=k3sm.p2"}
	orig := append([]string(nil), env...)
	got := withoutEnvName(env, userDirSuffixEnv)
	want := []string{"PATH=/usr/bin", userDirSuffixEnv + "X=keep"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("withoutEnvName = %q, want %q", got, want)
	}
	if strings.Join(env, "\n") != strings.Join(orig, "\n") {
		t.Errorf("withoutEnvName modified its input: %q", env)
	}
}
