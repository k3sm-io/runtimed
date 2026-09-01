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

package guestagent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCgroupRoot builds a temp dir shaped like a cgroup2 hierarchy root: the two
// interface files a parent carries, with `available` as its delegatable set.
//
// It stands in for cgroupfs, and only for cgroupfs. Everything under test — the
// name validation, the availability intersection, the one-write-per-controller
// rule, the leaf path, the procs write — is the same code the guest runs; what a
// darwin host cannot supply is a kernel that synthesizes memory.current when a
// directory is created, so the test writes those files where the kernel would.
func fakeCgroupRoot(t *testing.T, available ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ControllersFile), []byte(strings.Join(available, " ")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, SubtreeControlFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestCgroup2LeafProvisioning is the gate on `kubectl top` reporting nothing for
// a vm pod: /stats/summary answered {"node":{…},"pods":null} because guest init
// created no per-container cgroup2 leaf, so cgroupSampler found no cpu.stat and
// the Stats verb omitted every container.
func TestCgroup2LeafProvisioning(t *testing.T) {
	t.Run("controllers-are-delegated-one-write-at-a-time", func(t *testing.T) {
		root := fakeCgroupRoot(t, "cpu", "memory", "io", "pids")
		enabled, err := EnableSubtreeControllers(root, StatsControllers)
		if err != nil {
			t.Fatalf("EnableSubtreeControllers: %v", err)
		}
		if len(enabled) != 2 || enabled[0] != "cpu" || enabled[1] != "memory" {
			t.Errorf("enabled = %v, want [cpu memory]", enabled)
		}
		// Each controller is its own write(2): the kernel parses a cgroup2
		// interface write per call, and it rejects the WHOLE write if any token is
		// unacceptable.
		got := readFile(t, filepath.Join(root, SubtreeControlFile))
		if got != "+memory" {
			t.Errorf("last subtree_control write = %q, want the final single-controller write %q", got, "+memory")
		}
	})

	t.Run("a-missing-controller-does-not-cost-the-others", func(t *testing.T) {
		// The reason for one write per controller: on a kernel built without
		// CONFIG_CGROUP_SCHED a combined "+cpu +memory" loses memory too — and
		// memory is the controller that carries the OOM truth.
		root := fakeCgroupRoot(t, "memory", "pids")
		enabled, err := EnableSubtreeControllers(root, StatsControllers)
		if err == nil {
			t.Error("a missing controller must be reported, not swallowed")
		}
		if len(enabled) != 1 || enabled[0] != "memory" {
			t.Errorf("enabled = %v, want [memory] to survive cpu's absence", enabled)
		}
		if got := readFile(t, filepath.Join(root, SubtreeControlFile)); got != "+memory" {
			t.Errorf("subtree_control = %q, want %q", got, "+memory")
		}
	})

	t.Run("a-leaf-is-created-per-container-with-the-samplers-files-and-the-pid", func(t *testing.T) {
		root := fakeCgroupRoot(t, "cpu", "memory")
		if _, err := EnableSubtreeControllers(root, StatsControllers); err != nil {
			t.Fatalf("EnableSubtreeControllers: %v", err)
		}

		for _, container := range []string{"init-db", "postgres"} {
			leaf, err := CreateLeaf(root, container)
			if err != nil {
				t.Fatalf("CreateLeaf(%s): %v", container, err)
			}
			// The path contract cgroupSampler depends on: <root>/<container>.
			if want := filepath.Join(root, container); leaf != want {
				t.Errorf("leaf = %q, want %q", leaf, want)
			}
			if fi, serr := os.Stat(leaf); serr != nil || !fi.IsDir() {
				t.Fatalf("leaf %s is not a directory: %v", leaf, serr)
			}
			// The kernel synthesizes these on mkdir; a darwin temp dir does not,
			// so they are written here exactly where cgroupSampler reads them.
			write := map[string]string{
				"cpu.stat":       "usage_usec 1234\nuser_usec 900\nsystem_usec 334\n",
				"memory.current": "20480\n",
				"memory.stat":    "anon 8192\ninactive_file 4096\n",
				ProcsFile:        "",
			}
			for name, content := range write {
				if err := os.WriteFile(filepath.Join(leaf, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range SampleFiles {
				if _, serr := os.Stat(filepath.Join(leaf, name)); serr != nil {
					t.Errorf("leaf %s has no %s; cgroupSampler omits the container without it", leaf, name)
				}
			}

			const pid = 93
			if err := JoinLeaf(leaf, pid); err != nil {
				t.Fatalf("JoinLeaf: %v", err)
			}
			if got := strings.TrimSpace(readFile(t, filepath.Join(leaf, ProcsFile))); got != "93" {
				t.Errorf("%s = %q, want the container's pid %d", ProcsFile, got, pid)
			}

			// And the sampler's own parsers read what the leaf now holds, so the
			// files are not merely present but usable.
			usage, err := CPUUsageUsec(write["cpu.stat"])
			if err != nil || usage != 1234 {
				t.Errorf("CPUUsageUsec = %d, %v; want 1234", usage, err)
			}
			ws, err := WorkingSet(write["memory.current"], write["memory.stat"])
			if err != nil || ws != 20480-4096 {
				t.Errorf("WorkingSet = %d, %v; want %d", ws, err, 20480-4096)
			}
		}

		// Two containers, two leaves: a per-pod leaf would make `kubectl top`
		// report one row for the pod's whole cgroup rather than one per container.
		for _, container := range []string{"init-db", "postgres"} {
			if _, err := os.Stat(filepath.Join(root, container)); err != nil {
				t.Errorf("leaf for %s is missing: %v", container, err)
			}
		}
	})

	t.Run("a-leaf-name-that-is-not-one-path-component-is-refused", func(t *testing.T) {
		root := fakeCgroupRoot(t, "cpu", "memory")
		for _, name := range []string{"", ".", "..", "../escape", "a/b", `a\b`, "./x"} {
			if _, err := LeafPath(root, name); !errors.Is(err, ErrInvalidCgroupName) {
				t.Errorf("LeafPath(%q) err = %v, want ErrInvalidCgroupName", name, err)
			}
			if _, err := CreateLeaf(root, name); err == nil {
				t.Errorf("CreateLeaf(%q) was allowed; a leaf is a directory this guest writes pids into", name)
			}
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape")); err == nil {
			t.Error("a traversing leaf name created a directory outside the hierarchy root")
		}
	})

	t.Run("creating-an-existing-leaf-is-idempotent", func(t *testing.T) {
		root := fakeCgroupRoot(t, "cpu", "memory")
		first, err := CreateLeaf(root, "app")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(first, "marker"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		second, err := CreateLeaf(root, "app")
		if err != nil {
			t.Fatalf("re-creating a leaf must not fail: %v", err)
		}
		if second != first {
			t.Errorf("leaf = %q, want the same %q", second, first)
		}
		if _, err := os.Stat(filepath.Join(first, "marker")); err != nil {
			t.Errorf("re-creating a leaf disturbed it: %v", err)
		}
	})

	t.Run("joining-with-a-nonsense-pid-is-refused", func(t *testing.T) {
		root := fakeCgroupRoot(t, "cpu", "memory")
		leaf, err := CreateLeaf(root, "app")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(leaf, ProcsFile), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, pid := range []int{0, -1} {
			if err := JoinLeaf(leaf, pid); err == nil {
				t.Errorf("JoinLeaf(%d) was allowed; a pid of %d addresses the caller's own process group", pid, pid)
			}
		}
	})
}
