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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

var updateXcodeEnvGolden = flag.Bool("update-xcode-env", false, "rewrite testdata/xcode-pod-env.golden")

// stubUserName states the host fact the USER/LOGNAME default reads.
func stubUserName(t *testing.T, name string) {
	t.Helper()
	old := lookupUserName
	lookupUserName = func(int) (string, error) { return name, nil }
	t.Cleanup(func() { lookupUserName = old })
}

// xcodePodLaunchEnv creates an Xcode-granted host-binary pod, with mutate
// applied to its box, and returns the env the spawner was handed and the
// pod's data volume.
func xcodePodLaunchEnv(t *testing.T, podID string, mutate func(*runtimev1.PodBox)) ([]string, string) {
	t.Helper()
	sp := &mcProbeSpawner{}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	box := hostBinBox(rt, podID)
	box.GetSandboxProfile().XcodeToolchainDir = testDevDir
	if mutate != nil {
		mutate(box)
	}
	mustCreatePod(t, rt, box)
	spec, _, _ := sp.last()
	return spec.Env, box.GetSandboxProfile().GetDataVolumePath()
}

// TestXcodePodEnvGolden pins the whole launch environment of an Xcode pod, the
// pod mutation a workload sees, byte for byte (with the data volume written as
// $DATA). A golden rather than per-variable assertions so an ADDED variable is
// as red as a changed one. Regenerate with -update-xcode-env.
func TestXcodePodEnvGolden(t *testing.T) {
	stubUserName(t, "_k3sm")
	env, dataVol := xcodePodLaunchEnv(t, "pod-xenv", nil)
	got := strings.ReplaceAll(strings.Join(env, "\n")+"\n", dataVol, "$DATA")
	golden := filepath.Join("testdata", "xcode-pod-env.golden")
	if *updateXcodeEnvGolden {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("Xcode pod launch env differs from %s.\n--- got ---\n%s--- want ---\n%s", golden, got, want)
	}
}

// TestXcodePodEnvDefaults asserts the meaning the golden only records: each
// default names the pod's own home or the granted toolchain, and each appears
// exactly once.
func TestXcodePodEnvDefaults(t *testing.T) {
	stubUserName(t, "_k3sm")
	env, dataVol := xcodePodLaunchEnv(t, "pod-xdef", nil)
	home := filepath.Join(dataVol, podHomeName)
	for name, want := range map[string]string{
		homeEnv:        home,
		cfFixedHomeEnv: home,
		userEnv:        "_k3sm",
		logNameEnv:     "_k3sm",
		pathEnv:        testDevDir + "/usr/bin:" + testDevDir + "/Toolchains/XcodeDefault.xctoolchain/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin",
	} {
		if got := mustEnvValue(t, env, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
		if n := countName(env, name); n != 1 {
			t.Errorf("%s appears %d times, want 1", name, n)
		}
	}
}

// TestXcodePodEnvSpecWins: a name the spec sets is kept, once, and
// CFFIXED_USER_HOME follows the spec's HOME, since that is the home the
// workload chose and Xcode must see the same one.
func TestXcodePodEnvSpecWins(t *testing.T) {
	stubUserName(t, "_k3sm")
	env, _ := xcodePodLaunchEnv(t, "pod-xspec", func(b *runtimev1.PodBox) {
		b.GetContainers()[0].Env = []*runtimev1.EnvVar{
			{Name: homeEnv, Value: "/spec/home"},
			{Name: pathEnv, Value: "/spec/bin"},
			{Name: userEnv, Value: "builder"},
		}
	})
	for name, want := range map[string]string{
		homeEnv:        "/spec/home",
		cfFixedHomeEnv: "/spec/home",
		pathEnv:        "/spec/bin",
		userEnv:        "builder",
		logNameEnv:     "_k3sm",
	} {
		if got := mustEnvValue(t, env, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
		if n := countName(env, name); n != 1 {
			t.Errorf("%s appears %d times, want 1", name, n)
		}
	}
}

// TestNonXcodePodGetsNoXcodeDefaults is the negative half: a pod without the
// grant gets no home, no Xcode variables and no home directory.
func TestNonXcodePodGetsNoXcodeDefaults(t *testing.T) {
	stubUserName(t, "_k3sm")
	sp := &mcProbeSpawner{}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
	box := hostBinBox(rt, "pod-xnone")
	mustCreatePod(t, rt, box)
	spec, _, _ := sp.last()
	for _, name := range []string{homeEnv, cfFixedHomeEnv, userEnv, logNameEnv, pathEnv} {
		if v, has := envValue(spec.Env, name); has {
			t.Errorf("%s=%q is in the launch env of a pod with no xcode_toolchain_dir", name, v)
		}
	}
	if _, err := os.Stat(podHomeDir(box.GetSandboxProfile().GetDataVolumePath())); !os.IsNotExist(err) {
		t.Errorf("a pod with no grant has a home dir (stat err %v)", err)
	}
}

// TestProvisionPodHome: the home is 0700, carries the git configuration that
// lets a pod clone a host-shared repository, and a second provision (a
// re-attach) keeps a configuration the workload changed.
func TestProvisionPodHome(t *testing.T) {
	dataVol := t.TempDir()
	if err := provisionPodHome(dataVol); err != nil {
		t.Fatalf("provisionPodHome: %v", err)
	}
	fi, err := os.Stat(podHomeDir(dataVol))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("home mode = %v, want 0700", fi.Mode().Perm())
	}
	cfg := filepath.Join(podHomeDir(dataVol), podGitConfigName)
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "[safe]\n\tdirectory = *\n") {
		t.Errorf("git config lacks safe.directory=*:\n%s", b)
	}
	if err := os.WriteFile(cfg, []byte("[user]\n\tname = w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provisionPodHome(dataVol); err != nil {
		t.Fatalf("second provisionPodHome: %v", err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "[user]\n\tname = w\n" {
		t.Errorf("a re-provision rewrote the workload's git config: %q", b)
	}
}
