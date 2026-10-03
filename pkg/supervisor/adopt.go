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

import (
	"context"
	"errors"
	"fmt"
)

// ErrExitUnknown reports that a process's exit was observed but its status could
// not be collected, because the process is not a child of this daemon (see
// AdoptedExitWaiter). It is returned INSTEAD of an exit code: a caller must not
// read the accompanying code and signal, which are zero only because an int has
// to hold something.
var ErrExitUnknown = errors.New("supervisor: exit status unknown: the process is not a child of this daemon")

// AdoptProcess returns a running Process for pid, a live process this daemon did
// not spawn (a pod process a previous daemon incarnation started), and starts its
// exit watch under ctx through waiter — which, for a process that is not a
// child, must be an AdoptedExitWaiter so the exit is reported as ErrExitUnknown
// rather than as a fabricated status.
//
// The process's output went to pipes that died with the old daemon, so there
// is nothing to drain and LogsDrained is closed from the start. (A container
// whose output must survive the daemon runs beside a resident shim, and is
// re-attached through AdoptShim instead.)
//
// Done, Wait, PID and State behave as for a spawned Process, which is what lets
// a graceful stop, the memory sampler and the status path treat the two alike.
//
// pid must be > 1: pid 1 is launchd and a pid <= 0 is a wait/kill wildcard, and
// an adopted pid is later signalled as a process GROUP.
func AdoptProcess(ctx context.Context, waiter ExitWaiter, pid int) (*Process, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("supervisor: refusing to adopt pid %d (must be > 1)", pid)
	}
	if waiter == nil {
		return nil, errors.New("supervisor: adopt needs an exit waiter")
	}
	p := &Process{
		waiter:  waiter,
		state:   StateRunning,
		pid:     pid,
		done:    make(chan struct{}),
		drained: make(chan struct{}),
	}
	p.closeDrained()
	go p.reap(ctx, pid)
	return p, nil
}
