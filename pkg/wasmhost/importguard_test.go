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

package wasmhost_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The wasmtime targets the daemon must never link: the upstream Go binding, the
// pinned fork, and this repo's cgo engine package (and anything under it).
// Module prefixes rather than exact packages, so a /v50 or a subpackage cannot
// slip past.
var wasmtimeModulePrefixes = []string{
	"github.com/bytecodealliance/wasmtime-go",
	"github.com/k3sm-io/wasmtime-go",
}

const wasmtimeEnginePkg = "k3sm.io/runtimed/pkg/wasmhost/wasmtime"

// helperPkg is the one binary allowed to link the engine. It does not exist
// until B497.
const helperPkg = "k3sm.io/runtimed/cmd/k3sm-wasmhost"

// daemonPkgs is every package the daemon links, named explicitly: the
// pkg/vmhost guard's list, the exec shim that launches the helper, this
// package (the daemon's start path imports it for the spec builder), and the
// test-support fake other packages' tests link. A
// wildcard would silently start covering less the day a package moved.
var daemonPkgs = []string{
	"k3sm.io/runtimed/cmd/k3sm-runtimed",
	"k3sm.io/runtimed/cmd/k3sm-execshim",
	"k3sm.io/runtimed/pkg/runtime",
	"k3sm.io/runtimed/pkg/sandbox",
	"k3sm.io/runtimed/pkg/image",
	"k3sm.io/runtimed/pkg/mount",
	"k3sm.io/runtimed/pkg/supervisor",
	"k3sm.io/runtimed/pkg/guestagent",
	"k3sm.io/runtimed/pkg/volume",
	"k3sm.io/runtimed/pkg/wasmhost",
	"k3sm.io/runtimed/pkg/wasmhost/wasmhosttest",
}

// guardEnv pins the build lane the guard asks about. The engine sits behind
// darwin+cgo, so that is the lane that could pull it in and the lane that must
// be checked; inheriting CGO_ENABLED, GOOS or GOARCH from whoever runs the test
// would let a CGO_ENABLED=0 run pass vacuously.
func guardEnv(cgo string) []string {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "CGO_ENABLED=") || strings.HasPrefix(kv, "GOOS=") || strings.HasPrefix(kv, "GOARCH=")
	})
	return append(env, "CGO_ENABLED="+cgo, "GOOS=darwin", "GOARCH=arm64")
}

func goList(t *testing.T, cgo string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Env = guardEnv(cgo)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list %s (CGO_ENABLED=%s): %v\n%s", strings.Join(args, " "), cgo, err, ee.Stderr)
		}
		t.Fatalf("go list %s (CGO_ENABLED=%s): %v", strings.Join(args, " "), cgo, err)
	}
	return strings.Fields(string(out))
}

// isWasmtime reports whether dep is one of the forbidden wasmtime targets.
func isWasmtime(dep string) bool {
	for _, p := range wasmtimeModulePrefixes {
		if dep == p || strings.HasPrefix(dep, p+"/") {
			return true
		}
	}
	return dep == wasmtimeEnginePkg || strings.HasPrefix(dep, wasmtimeEnginePkg+"/")
}

// converseMode is what the converse leg asserts.
type converseMode int

const (
	// converseResolves: the helper does not exist yet, so the converse proves
	// only that the guard's package list resolves, then skips naming B497.
	converseResolves converseMode = iota
	// converseHelperReaches: the helper exists and MUST reach the engine.
	converseHelperReaches
)

// selectConverse picks the converse by whether the helper's directory exists.
// A directory that exists but does not build fails go list, which fails the
// test: an existing helper is never skipped.
func selectConverse(helperDirExists bool) converseMode {
	if helperDirExists {
		return converseHelperReaches
	}
	return converseResolves
}

// checkHelperReaches returns nil iff deps reach a wasmtime target.
func checkHelperReaches(deps []string) error {
	if slices.ContainsFunc(deps, isWasmtime) {
		return nil
	}
	return fmt.Errorf("%s reaches no wasmtime target (%v or %s); either the engine was removed or this guard is vacuous",
		helperPkg, wasmtimeModulePrefixes, wasmtimeEnginePkg)
}

// checkResolves returns nil iff deps is the non-empty dependency list of pkg
// (go list -deps lists the package itself last).
func checkResolves(pkg string, deps []string) error {
	if len(deps) == 0 {
		return fmt.Errorf("%s: empty dependency list", pkg)
	}
	if !slices.Contains(deps, pkg) {
		return fmt.Errorf("%s: not in its own dependency list; the package was not found", pkg)
	}
	return nil
}

// TestWasmtimeIsNotReachableFromTheDaemon asserts the import boundary the
// helper split rests on: the wasmtime engine (the Go binding, the pinned fork,
// and the cgo engine package) must be reachable only from cmd/k3sm-wasmhost,
// never from a package the runtime daemon links.
//
// The split is what keeps a JIT and its C runtime out of the root daemon's
// address space: the daemon parses tenant images and serves the runtime socket,
// and the engine compiles attacker-chosen bytes to native code. If an import
// dragged the engine into pkg/runtime, the separation would survive only as a
// claim in a doc comment. It runs under go test so it fires in the change that
// adds the bad import, the pkg/vmhost idiom.
//
// It asks `go list -deps`, the linker's own question, with the build lane
// pinned to darwin/arm64 with cgo on. Hermetic: no network (the module graph is
// already resolved).
func TestWasmtimeIsNotReachableFromTheDaemon(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	for _, pkg := range daemonPkgs {
		t.Run(pkg, func(t *testing.T) {
			deps := goList(t, "1", "-deps", pkg)
			for _, dep := range deps {
				if isWasmtime(dep) {
					t.Fatalf("%s reaches %s: the runtime daemon would link the wasmtime engine, which only "+
						"the separate k3sm-wasmhost helper may link. Keep the daemon on pkg/wasmhost's spec builder.", pkg, dep)
				}
			}
		})
	}

	// The converse, so a passing suite cannot mean "the guard checks nothing".
	// It computes its own deps, so `-run .../converse` alone is meaningful.
	t.Run("converse", func(t *testing.T) {
		_, statErr := os.Stat(filepath.Join("..", "..", "cmd", "k3sm-wasmhost"))
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("stat the helper directory: %v", statErr)
		}
		switch selectConverse(statErr == nil) {
		case converseHelperReaches:
			if err := checkHelperReaches(goList(t, "1", "-deps", helperPkg)); err != nil {
				t.Fatal(err)
			}
		case converseResolves:
			for _, pkg := range daemonPkgs {
				if err := checkResolves(pkg, goList(t, "1", "-deps", pkg)); err != nil {
					t.Fatal(err)
				}
			}
			t.Skipf("%s does not exist yet (B497 adds it); the guard's %d packages resolve, "+
				"and the converse becomes a hard requirement the moment the helper exists", helperPkg, len(daemonPkgs))
		}
	})
}

// TestImportGuardConverseSelection pins the converse's branch choice and both
// of its checks, so the B497 branch is tested before the helper exists.
func TestImportGuardConverseSelection(t *testing.T) {
	if selectConverse(true) != converseHelperReaches {
		t.Error("an existing helper must make the converse a hard requirement")
	}
	if selectConverse(false) != converseResolves {
		t.Error("an absent helper must select the resolve-and-skip converse")
	}

	reaching := [][]string{
		{"fmt", "github.com/bytecodealliance/wasmtime-go/v49", helperPkg},
		{"github.com/k3sm-io/wasmtime-go/v49", helperPkg},
		{wasmtimeEnginePkg, helperPkg},
		{wasmtimeEnginePkg + "/internal", helperPkg},
	}
	for _, deps := range reaching {
		if err := checkHelperReaches(deps); err != nil {
			t.Errorf("checkHelperReaches(%v) = %v, want nil", deps, err)
		}
	}
	notReaching := [][]string{
		nil,
		{"fmt", helperPkg},
		{"k3sm.io/runtimed/pkg/wasmhost", helperPkg},
		{"k3sm.io/runtimed/pkg/wasmhost/wasmtimefake"},
		{"github.com/bytecodealliance/wasmtime-gofake"},
	}
	for _, deps := range notReaching {
		if err := checkHelperReaches(deps); err == nil {
			t.Errorf("checkHelperReaches(%v) = nil, want an error", deps)
		}
	}

	if err := checkResolves("p", []string{"fmt", "p"}); err != nil {
		t.Errorf("checkResolves on a resolved list = %v", err)
	}
	if err := checkResolves("p", nil); err == nil {
		t.Error("checkResolves accepted an empty list")
	}
	if err := checkResolves("p", []string{"fmt"}); err == nil {
		t.Error("checkResolves accepted a list without the package")
	}
}

// TestTheSeamIsPureGo asserts pkg/wasmhost and everything it imports build
// without cgo: it lists at CGO_ENABLED=0, and at CGO_ENABLED=1 none of its
// dependencies carries a cgo file or pulls runtime/cgo. The daemon and every
// unit test link this package; cgo here would undo the engine split.
func TestTheSeamIsPureGo(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	const self = "k3sm.io/runtimed/pkg/wasmhost"
	if err := checkResolves(self, goList(t, "0", "-deps", self)); err != nil {
		t.Fatalf("CGO_ENABLED=0: %v", err)
	}
	lines := goList(t, "1", "-deps", "-f", "{{.ImportPath}}:{{len .CgoFiles}}", self)
	for _, l := range lines {
		pkg, n, _ := strings.Cut(l, ":")
		if pkg == "runtime/cgo" || n != "0" {
			t.Errorf("%s depends on %s (%s cgo files); the seam must stay pure Go", self, pkg, n)
		}
	}
}
