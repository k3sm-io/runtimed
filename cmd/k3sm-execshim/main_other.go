//go:build !(darwin && cgo)

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

// Command k3sm-execshim is the ad-hoc-signed Seatbelt exec-shim. This is the
// off-PLATFORM stub: libsandbox confinement exists only on darwin and is
// reachable only through cgo, so on every other build lane the shim refuses to
// run rather than failing to compile.
//
// The stub is what keeps `go build ./...` and `go vet ./...` meaningful on a
// CGO_ENABLED=0 lane and on Linux CI. Without it this command would simply have
// no files there, and "the package still compiles" would silently stop being a
// fact anything checked.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"k3sm-execshim: this build cannot confine a process — "+
			"Seatbelt confinement needs darwin with cgo (CGO_ENABLED=1)")
	os.Exit(1)
}
