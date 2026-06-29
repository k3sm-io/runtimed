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

package runtime

import (
	"errors"
	"os"
)

// errPTYUnsupported reports that a tty exec (pty allocation) is darwin-only. The
// runtime targets macOS; this stub lets the package build and run its non-tty
// exec tests on linux CI. A tty exec off darwin fails closed with this error.
var errPTYUnsupported = errors.New("runtime: tty exec (pty) requires darwin")

func openPTY() (*os.File, *os.File, error) { return nil, nil, errPTYUnsupported }

func setWinsize(*os.File, uint16, uint16) error { return errPTYUnsupported }
