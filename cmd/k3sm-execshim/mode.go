//go:build darwin && cgo

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

import "k3sm.io/runtimed/pkg/supervisor"

// parseMode splits argv (without the program name) into the mode token and the
// rest. ok is false for a missing or unknown token — including every argv of the
// pre-mode shape, whose first token is a uid — so such an argv fails closed with
// a usage error rather than being read under the wrong layout.
func parseMode(argv []string) (mode string, rest []string, ok bool) {
	if len(argv) == 0 {
		return "", nil, false
	}
	switch argv[0] {
	case supervisor.ShimModeLaunch, supervisor.ShimModeServe, supervisor.ShimModeExec:
		return argv[0], argv[1:], true
	}
	return "", nil, false
}
