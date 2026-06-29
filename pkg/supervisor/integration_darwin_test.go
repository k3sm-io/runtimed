//go:build integration && darwin

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
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// unixSIGKILL returns SIGKILL as the os.Signal type SignalGroup expects.
func unixSIGKILL() os.Signal { return unix.SIGKILL }

// TestIntegrationSpawnReapRealProcess drives the production PosixSpawner +
// KqueueReaper against a real child: it spawns /bin/sh that writes a line and
// exits non-zero, then asserts the kqueue reaper (the sole reaper) collects the
// exact exit code and the combined-log pipe captured the output. This is the live
// half of the M1.2-d3 supervisor lifecycle.
func TestIntegrationSpawnReapRealProcess(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	sink := func(b []byte) { mu.Lock(); lines = append(lines, string(b)); mu.Unlock() }

	spec := SpawnSpec{
		Path: "/bin/sh",
		Argv: []string{"/bin/sh", "-c", "echo combined-output; exit 5"},
		Env:  os.Environ(),
	}
	p := NewProcess(PosixSpawner{}, KqueueReaper{}, spec, sink)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if p.PID() <= 0 {
		t.Fatalf("bad pid %d", p.PID())
	}
	code, sig, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 5 || sig != 0 {
		t.Errorf("exit (code=%d sig=%d), want (5,0)", code, sig)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range lines {
		if l == "combined-output" {
			found = true
		}
	}
	if !found {
		t.Errorf("combined-log pipe did not capture output: %v", lines)
	}
}

// TestIntegrationSignalGroupKills spawns a long-lived child in its own process
// group and verifies SignalGroup(SIGKILL) tears it down (the DeletePod path).
func TestIntegrationSignalGroupKills(t *testing.T) {
	spec := SpawnSpec{
		Path: "/bin/sh",
		Argv: []string{"/bin/sh", "-c", "sleep 60"},
		Env:  os.Environ(),
	}
	p := NewProcess(PosixSpawner{}, KqueueReaper{}, spec, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Kill the pod's process group (pid == pgid for a SETSID leader).
	if err := SignalGroup(p.PID(), unixSIGKILL()); err != nil {
		t.Fatalf("SignalGroup: %v", err)
	}
	code, sig, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// Killed by SIGKILL → signal 9, code 128+9.
	if sig != 9 || code != 137 {
		t.Errorf("after SIGKILL got (code=%d sig=%d), want (137,9)", code, sig)
	}
}
