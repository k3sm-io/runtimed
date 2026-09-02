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

package guestinit

import (
	"errors"
	"os"
)

// ErrNoPTY reports that this build cannot allocate a pseudoterminal.
//
// It exists so the package builds and its pure half tests on darwin, where the
// repo's CI actually runs. The guest is linux/arm64 and always takes the real
// implementation in pty_linux.go; anything reaching these stubs is a build that
// was never going to be PID 1 of a micro-VM.
var ErrNoPTY = errors.New("guestinit: pseudoterminal allocation is only implemented on linux")

// OpenPTY fails closed on a non-linux build. See the linux implementation.
func OpenPTY(_, _ string) (master, slave *os.File, err error) { return nil, nil, ErrNoPTY }

// SetWinsize fails closed on a non-linux build. See the linux implementation.
func SetWinsize(*os.File, WinSize) error { return ErrNoPTY }

// ChownTTY fails closed on a non-linux build. See the linux implementation.
func ChownTTY(*os.File, int, int) error { return ErrNoPTY }
