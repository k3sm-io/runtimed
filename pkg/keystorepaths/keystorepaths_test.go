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

package keystorepaths_test

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/keystorepaths"
)

const pkg = "k3sm.io/runtimed/pkg/keystorepaths"

// TestLeafImportsOnlyTheStandardLibrary pins the package as a leaf a caller can
// import without the sandbox's cgo or any module: every package in its
// dependency graph, itself aside, is standard library, and none of the graph
// (itself included) has a cgo file. It asks the darwin cgo lane, the one the
// daemon builds in, so a CGO_ENABLED=0 run cannot pass vacuously.
func TestLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "CGO_ENABLED=") || strings.HasPrefix(kv, "GOOS=") || strings.HasPrefix(kv, "GOARCH=")
	})
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{.Standard}} {{len .CgoFiles}}", pkg)
	cmd.Env = append(env, "CGO_ENABLED=1", "GOOS=darwin", "GOARCH=arm64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	seen := false
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			t.Fatalf("unexpected go list line %q", line)
		}
		path, std, cgo := f[0], f[1] == "true", f[2] != "0"
		if path == pkg {
			seen = true
		} else if !std {
			t.Errorf("%s imports the non-standard package %s", pkg, path)
		}
		if cgo && !std {
			t.Errorf("%s has cgo files", path)
		}
		if path == "runtime/cgo" {
			t.Errorf("%s pulls in runtime/cgo", pkg)
		}
	}
	if !seen {
		t.Fatalf("go list did not report %s itself:\n%s", pkg, out)
	}
}

// TestNames pins the spellings both ends share.
func TestNames(t *testing.T) {
	if keystorepaths.DataRootPrefix != "keystore-" || keystorepaths.RunDir != "keystore-run" || keystorepaths.SockDir != "keystore-sock" {
		t.Errorf("names = %q %q %q", keystorepaths.DataRootPrefix, keystorepaths.RunDir, keystorepaths.SockDir)
	}
	if got, want := keystorepaths.SocketPath("/var/lib/k3sm"), "/var/lib/k3sm/keystore-sock/keys.sock"; got != want {
		t.Errorf("SocketPath = %q, want %q", got, want)
	}
}
