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

package supervisor

// Darwin setpriority(2) selectors for the launch sequence's background-QoS step.
//
// golang.org/x/sys/unix exports Setpriority but not the darwin-specific
// PRIO_DARWIN_* selectors, so their values are pinned here verbatim from the
// PUBLIC MacOSX SDK header <sys/resource.h>:
//
//	#define PRIO_DARWIN_PROCESS 4        /* Second argument is a PID */
//	#define PRIO_DARWIN_BG      0x1000   /* background throttle mode */
//
// This is public, documented API — not libsandbox/memorystatus-style private SPI
// — so it deliberately gets NO internal/spicanary symbol-canary. Note the darwin
// background band is a COUPLED policy: it throttles CPU scheduling, moves I/O to
// the throttled tier, and marks network traffic background class together (see
// docs/resources.md for the honesty notes and the cooperative, non-enforcing
// nature of the band).
const (
	// prioDarwinProcess is PRIO_DARWIN_PROCESS: the setpriority(2) "which"
	// selector targeting a process by pid ("who"; 0 = the calling process).
	prioDarwinProcess = 4
	// prioDarwinBG is PRIO_DARWIN_BG: the "prio" value placing the target in the
	// darwin background band. The only supported reversal is prio 0 — which the
	// launch sequence deliberately never issues (downward-only policy).
	prioDarwinBG = 0x1000
)
