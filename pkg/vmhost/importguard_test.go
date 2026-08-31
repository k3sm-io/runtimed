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

package vmhost_test

import (
	"os/exec"
	"strings"
	"testing"
)

// vzModulePrefix is the import path of the Virtualization binding. Matching on
// the module prefix rather than the exact package catches a future
// github.com/Code-Hex/vz/v4 or a subpackage, which an exact-string check would
// wave through.
const vzModulePrefix = "github.com/Code-Hex/vz"

// TestVZIsNotReachableFromTheDaemon asserts the import boundary the entitlement
// split rests on: github.com/Code-Hex/vz must be reachable ONLY from pkg/vmhost
// and cmd/k3sm-vmhost, never from any package the k3sm daemon links.
//
// THE SPLIT IS ONLY REAL IF THIS HOLDS. k3sm-vmhost is the one binary carrying
// com.apple.security.virtualization precisely so that the daemon — which parses
// tenant images, serves a gRPC socket and talks to the provider — holds no
// virtualization authority. An import that dragged the Virtualization-linking
// module into pkg/runtime or pkg/sandbox would put the framework inside the
// daemon's address space, and the separation would survive only as a claim in a
// doc comment.
//
// It runs here rather than in a shell script so it FIRES IN THE PR THAT ADDS THE
// BAD IMPORT — under `go test ./...`, on the author's machine, before review —
// rather than one repo downstream when someone notices the daemon linking
// Virtualization.
//
// It shells out to `go list -deps`, which is the same question a linker asks and
// the only answer that accounts for transitive imports. Hermetic: no network (the
// module graph is already resolved), no VM, no entitlement.
func TestVZIsNotReachableFromTheDaemon(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}

	// Every package the daemon links, named explicitly. A wildcard would silently
	// start covering less the day a package moved.
	daemonPkgs := []string{
		"k3sm.io/runtimed/pkg/runtime",
		"k3sm.io/runtimed/pkg/sandbox",
		"k3sm.io/runtimed/pkg/image",
		"k3sm.io/runtimed/pkg/mount",
		"k3sm.io/runtimed/pkg/supervisor",
		"k3sm.io/runtimed/pkg/guestagent",
		"k3sm.io/runtimed/pkg/volume",
		"k3sm.io/runtimed/cmd/k3sm-runtimed",
	}
	for _, pkg := range daemonPkgs {
		t.Run(pkg, func(t *testing.T) {
			for _, dep := range deps(t, pkg) {
				if strings.HasPrefix(dep, vzModulePrefix) {
					t.Fatalf("%s reaches %s — the k3sm daemon would link Virtualization.framework, "+
						"which is exactly what the separate, singly-entitled k3sm-vmhost helper exists to prevent. "+
						"Move the code behind pkg/vmhost's one-way MachineConfig translation.", pkg, dep)
				}
			}
		})
	}

	// The converse, so a passing suite cannot mean "vz was removed entirely":
	// the two packages that ARE allowed to reach it must still do so.
	t.Run("the-helper-still-reaches-it", func(t *testing.T) {
		found := false
		for _, dep := range deps(t, "k3sm.io/runtimed/pkg/vmhost") {
			if strings.HasPrefix(dep, vzModulePrefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pkg/vmhost does not reach %s; either the machine builder was removed or this test is now vacuous "+
				"(note: it is only reachable on the darwin+cgo lane, where this test is meant to run)", vzModulePrefix)
		}
	})
}

// deps returns the transitive import list of pkg, for the CURRENT build lane —
// which is what makes the assertion meaningful: the vz import sits behind
// `darwin && cgo`, so the lane that could pull it in is the lane that must be
// checked.
func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}
