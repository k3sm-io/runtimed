//go:build darwin

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
