//go:build !linux

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

// Command k3sm-guest-init is PID 1 of a k3sm vm-backend pod's micro-VM. It
// runs only inside that guest, so on every other platform this file is all
// there is: the package must still build and vet as part of `go build ./...`
// on the darwin host that cross-compiles it.
//
// The real binary is main_linux.go; the plan producers it walks are in
// k3sm.io/runtimed/pkg/guestinit and are unit-tested on this platform.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr,
		"k3sm-guest-init is the PID 1 of a Linux micro-VM guest and cannot run on %s/%s\n",
		runtime.GOOS, runtime.GOARCH)
	os.Exit(1)
}
