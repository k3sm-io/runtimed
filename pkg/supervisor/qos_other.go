//go:build !darwin

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

package supervisor

// Compile-parity mirrors of the darwin PRIO_DARWIN_* selectors (qos_darwin.go is
// the documented source of truth, pinned from the public MacOSX SDK
// <sys/resource.h>). They exist only so the OS-portable RunLaunchSequence
// compiles off-darwin (this package cross-compiles for tooling); the Setpriority
// step is only ever EXECUTED inside the darwin exec-shim.
const (
	prioDarwinProcess = 4
	prioDarwinBG      = 0x1000
)
