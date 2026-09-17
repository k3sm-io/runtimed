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

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLinuxLaneBuilds asserts the off-platform stub (main_other.go) keeps this
// command buildable on a lane with no darwin+cgo, shelling out to go the way
// pkg/vmhost/importguard_test.go does for its import guard. Without the
// stub the shim only compiles behind //go:build darwin && cgo, and a linux
// CI/lane build of ./... would fail on this package.
func TestLinuxLaneBuilds(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}

	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "execshim")
			cmd := exec.Command("go", "build", "-o", out, "./")
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("GOOS=linux GOARCH=%s CGO_ENABLED=0 go build ./: %v\n%s", arch, err, out)
			}
		})
	}
}
