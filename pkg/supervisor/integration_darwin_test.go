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

// neverLivePgid is a pid/pgid that is effectively never live (the same pattern
// rusage_darwin_test.go uses for a dead pid): kern.proc.pgrp reports an empty
// group and kill(-pgid) reports ESRCH.
const neverLivePgid = 0x7FFFFFFE

// TestIntegrationProcGroupMembersEmptyGroupDrops pins the reap's drop contract:
// an inspectable-but-empty (dead) process group returns an EMPTY slice with
// ok=true — NOT an error. The startup reap reads ok=true + empty as "the group
// is gone, drop the record", whereas ok=false would keep the record forever. A
// never-live pgid must therefore report (empty, true), never (nil, false).
func TestIntegrationProcGroupMembersEmptyGroupDrops(t *testing.T) {
	members, ok := ProcGroupMembers(neverLivePgid)
	if !ok {
		t.Fatalf("ProcGroupMembers(dead pgid) ok=false; want ok=true so the reap DROPS the record (ok=false keeps it forever)")
	}
	if len(members) != 0 {
		t.Fatalf("ProcGroupMembers(dead pgid) = %v, want empty slice", members)
	}
}

// TestIntegrationProcStartDerivationIdentity closes the "both paths read the
// same field" gap the fake-group unit tests hard-code away: it spawns one real
// child in its own process group (POSIX_SPAWN_SETSID → pid == pgid) and asserts
// ProcStartTimeNano(pid) EQUALS the ProcGroupMembers(pgid) member whose Pid==pid.
// The reap's exact-equality kill decision depends on both derivations being
// bit-identical; a silent divergence would fail OPEN (the reaper stops killing
// its own orphans), so this must be an exact match, not an approximate one.
func TestIntegrationProcStartDerivationIdentity(t *testing.T) {
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
	// Tear the group down at the end regardless of assertions.
	defer func() {
		_ = SignalGroup(p.PID(), unixSIGKILL())
		_, _, _ = p.Wait(ctx)
	}()

	pid := p.PID()
	// The SETSID leader's pid is its pgid.
	leaderStart, ok := ProcStartTimeNano(pid)
	if !ok {
		t.Fatalf("ProcStartTimeNano(%d) ok=false for a live leader", pid)
	}
	members, ok := ProcGroupMembers(pid)
	if !ok {
		t.Fatalf("ProcGroupMembers(%d) ok=false for a live group", pid)
	}
	var found bool
	for _, m := range members {
		if m.Pid == pid {
			found = true
			if m.StartUnixNano != leaderStart {
				t.Errorf("derivation divergence: ProcGroupMembers leader start=%d, ProcStartTimeNano=%d — the reap's exact-equality kill needs these bit-identical",
					m.StartUnixNano, leaderStart)
			}
		}
	}
	if !found {
		t.Fatalf("ProcGroupMembers(%d) did not include the leader pid; members=%v", pid, members)
	}
}

// TestIntegrationSignalGroupESRCHIsNil pins the mapping the startup reap leans on
// (podreap.go): SignalGroup of an already-gone / never-live group maps the
// kernel's ESRCH to a nil error, so a reap of a group that vanished between the
// probe and the signal is a no-op, not a spurious failure that would keep the
// record and re-alert forever.
func TestIntegrationSignalGroupESRCHIsNil(t *testing.T) {
	if err := SignalGroup(neverLivePgid, unixSIGKILL()); err != nil {
		t.Fatalf("SignalGroup(never-live pgid) = %v, want nil (ESRCH maps to nil)", err)
	}
}
