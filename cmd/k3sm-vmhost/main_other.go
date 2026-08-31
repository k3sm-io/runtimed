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

// Command k3sm-vmhost is the per-pod VM host helper. This is the OFF-PLATFORM
// stub: Virtualization.framework exists only on darwin and is reachable only
// through cgo, so on every other build lane the helper refuses to run rather than
// failing to compile.
//
// The stub is what keeps `go build ./...` and `go vet ./...` meaningful on a
// CGO_ENABLED=0 lane and on Linux CI. Without it this command would simply have no
// files there, and "the package still compiles" would silently stop being a fact
// anything checked.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"k3sm-vmhost: this build cannot create virtual machines — "+
			"Virtualization.framework needs darwin with cgo (CGO_ENABLED=1)")
	os.Exit(1)
}
