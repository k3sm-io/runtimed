//go:build darwin

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

package sandbox

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// darwinMajorVersion returns the host's macOS major version (e.g. 26 for
// "26.5.1") from the kern.osproductversion sysctl. It is the OS gate for
// version-sensitive backends.
func darwinMajorVersion() (int, error) {
	v, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return 0, fmt.Errorf("read kern.osproductversion: %w", err)
	}
	major, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(strings.TrimSpace(major))
	if err != nil {
		return 0, fmt.Errorf("parse macOS version %q: %w", v, err)
	}
	return n, nil
}
