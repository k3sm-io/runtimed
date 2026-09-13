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

package supervisor

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/crilog"
)

// unixSIGKILLForCleanup returns SIGKILL as the os.Signal type SignalGroup wants.
func unixSIGKILLForCleanup() os.Signal { return unix.SIGKILL }

// TestPumpStopsStreamOnSinkError is the write-failure-policy gate, against a
// REAL child: when the log sink refuses a chunk (a full or broken disk), the
// pump stops consuming that stream and closes its read end, so the container's
// next write(2) takes EPIPE/SIGPIPE and it dies. The failure that must never
// happen is the other one — a pump that stops reading without closing, leaving
// the pod blocked forever on a full 64 KiB pipe with nothing saying why.
//
// The spawner restores default signal dispositions (SETSIGDEF), so the shell
// takes SIGPIPE rather than inheriting an ignore, which is why the child is
// expected to die by signal 13 rather than merely to exit non-zero.
func TestPumpStopsStreamOnSinkError(t *testing.T) {
	refused := errors.New("no space left on device")
	var once sync.Once
	failed := make(chan struct{})
	sink := func(_ crilog.Stream, _ []byte, _ bool) error {
		once.Do(func() { close(failed) })
		return refused
	}

	spec := SpawnSpec{
		Path: "/bin/sh",
		// An endless writer: without the close-on-failure it would fill the
		// pipe and block forever, and this test would time out.
		Argv: []string{"/bin/sh", "-c", "while :; do echo chatter; done"},
		Env:  os.Environ(),
	}
	p := NewProcess(PosixSpawner{}, KqueueReaper{}, spec, sink)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = SignalGroup(p.PID(), unixSIGKILLForCleanup()) })

	select {
	case <-failed:
	case <-time.After(15 * time.Second):
		t.Fatal("the sink was never called")
	}

	code, sig, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("the child never exited after its log sink failed — the read end was not closed, "+
			"so it is blocked on a pipe nobody drains: %v", err)
	}
	if sig != int(unix.SIGPIPE) && code == 0 {
		t.Errorf("child exited (code=%d sig=%d), want death by SIGPIPE (%d) or a non-zero exit",
			code, sig, unix.SIGPIPE)
	}

	select {
	case <-p.LogsDrained():
	case <-time.After(15 * time.Second):
		t.Fatal("LogsDrained never closed after the pumps stopped")
	}
}
