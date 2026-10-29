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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The readiness wait under host load, with the bounds scaled 100x down
// (1 s -> 10 ms) so the state machine runs in well under a second per case.
const (
	scaledIdle    = 300 * time.Millisecond  // stands for vmBootIdleDeadline (30 s)
	scaledCeiling = 1200 * time.Millisecond // stands for vmBootCeiling (120 s)
	scaledHealthy = 350 * time.Millisecond  // stands for a guest that answers at 35 s
)

// retryBackend is labBackend with scaled boot bounds and a signal seam that
// makes the killed helper's exit observable at once, as the kernel would, so a
// failed attempt's teardown does not wait out the exit-observation grace.
func retryBackend(t *testing.T, root string, health GuestHealthFunc) (*VMBackend, *fakeSpawner, *signalRecorder) {
	t.Helper()
	b, sp, w, sig := labBackend(t, root, health)
	b.bootTiming = vmBootTiming{idle: scaledIdle, ceiling: scaledCeiling}
	b.signal = func(pgid int, s os.Signal) error {
		_ = sig.send(pgid, s)
		w.release(pgid)
		return nil
	}
	return b, sp, sig
}

// writeConsole keeps appending to the pod's console every interval until stop
// closes, standing in for a guest kernel and guest-init that are still working.
func writeConsole(t *testing.T, path string, every time.Duration, stop <-chan struct{}) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err == nil {
				_, _ = fmt.Fprintf(f, "guest-init: still applying ownership (%d)\n", i)
				_ = f.Close()
			}
			select {
			case <-stop:
				return
			case <-time.After(every):
			}
		}
	}()
	return &wg
}

func spawnCount(sp *fakeSpawner) int {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return len(sp.specs)
}

func retainedConsoles(t *testing.T, root string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(root, VMBootFailureSubdir, "*"+vmBootConsoleSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCreateVMWaitsForAWorkingGuestPastTheIdleWindow is the load case from
// the field: a guest that is still printing (the ownership step of a large
// image on a busy host) and answers 35 s after its spawn. A fixed 30 s
// deadline killed it; the idle window, restarted by console output, waits.
func TestCreateVMWaitsForAWorkingGuestPastTheIdleWindow(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	var once sync.Once
	var first time.Time
	health := func(context.Context, string) error {
		once.Do(func() { first = time.Now() })
		if time.Since(first) < scaledHealthy {
			return errors.New("error reading server preface: EOF")
		}
		return nil
	}
	b, sp, _ := retryBackend(t, root, health)
	stop := make(chan struct{})
	wg := writeConsole(t, filepath.Join(spec.PodDir, VMConsoleLogName), 50*time.Millisecond, stop)
	defer func() { close(stop); wg.Wait() }()

	if err := b.CreateVM(context.Background(), spec); err != nil {
		t.Fatalf("CreateVM = %v; a guest whose console is still active must not be failed at the idle window", err)
	}
	if n := spawnCount(sp); n != 1 {
		t.Errorf("spawned %d helpers, want 1: a guest that became ready needed no retry", n)
	}
	if got := retainedConsoles(t, root); len(got) != 0 {
		t.Errorf("a successful boot kept consoles: %v", got)
	}
	_ = b.StopVM(context.Background(), spec.PodID, 0)
}

// TestCreateVMRetriesANeverReadyGuestOnceAndKeepsTheEvidence: a guest that
// printed and then went silent without answering is booted twice, both
// helpers are killed, and the failure names the attempts, carries the
// sanitised console tail and points at a retained copy that outlives the pod.
func TestCreateVMRetriesANeverReadyGuestOnceAndKeepsTheEvidence(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	health := func(context.Context, string) error { return errors.New("error reading server preface: EOF") }
	b, sp, sig := retryBackend(t, root, health)

	var console strings.Builder
	for i := range 40 {
		fmt.Fprintf(&console, "[ %d.000] boot line %d\n", i, i)
	}
	console.WriteString("\x1b[31mguest-init: mount /data\x1b[0m\x07 stalled\r\n")
	if err := os.WriteFile(filepath.Join(spec.PodDir, VMConsoleLogName), []byte(console.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	err := b.CreateVM(context.Background(), spec)
	var bootErr *VMBootError
	if !errors.As(err, &bootErr) || bootErr.Cause != VMBootAgentNeverReady {
		t.Fatalf("CreateVM err = %v, want an agent-never-ready *VMBootError", err)
	}
	if n := spawnCount(sp); n != vmBootAttempts {
		t.Errorf("spawned %d helpers, want %d", n, vmBootAttempts)
	}
	if sig.count() < vmBootAttempts {
		t.Errorf("%d kills for %d failed attempts; every attempt's helper must be torn down", sig.count(), vmBootAttempts)
	}
	msg := err.Error()
	for _, want := range []string{"after 2 attempts", "guest-init: mount /data stalled", "boot line 39", "kept at " + bootErr.RetainedConsole, "no guest console output"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(bootErr.ConsoleTail, "boot line 19") {
		t.Errorf("console tail carries more than %d lines: %q", vmBootConsoleTailLines, bootErr.ConsoleTail)
	}
	if len(bootErr.ConsoleTail) > vmBootConsoleTailBytes || strings.ContainsAny(bootErr.ConsoleTail, "\x1b\x07\r\n") {
		t.Errorf("console tail is not bounded and sanitised: %q", bootErr.ConsoleTail)
	}
	// The retained copy survives the pod dir.
	if err := os.RemoveAll(spec.PodDir); err != nil {
		t.Fatal(err)
	}
	data, rerr := os.ReadFile(bootErr.RetainedConsole)
	if rerr != nil || !strings.Contains(string(data), "boot line 0") {
		t.Errorf("retained console %s unreadable or incomplete after the pod dir went: %v", bootErr.RetainedConsole, rerr)
	}
	if got := retainedConsoles(t, root); len(got) != vmBootAttempts {
		t.Errorf("kept %d consoles, want one per attempt (%d): %v", len(got), vmBootAttempts, got)
	}
	b.mu.Lock()
	live := len(b.live)
	b.mu.Unlock()
	if live != 0 {
		t.Errorf("%d helpers left registered after a failed boot", live)
	}
}

// TestCreateVMStopsAtTheCeilingWhileTheConsoleStaysBusy: console activity
// extends the wait only up to the ceiling, so a guest that prints forever
// still fails, twice, in bounded time.
func TestCreateVMStopsAtTheCeilingWhileTheConsoleStaysBusy(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	health := func(context.Context, string) error { return errors.New("no agent yet") }
	b, sp, _ := retryBackend(t, root, health)
	stop := make(chan struct{})
	wg := writeConsole(t, filepath.Join(spec.PodDir, VMConsoleLogName), 30*time.Millisecond, stop)
	defer func() { close(stop); wg.Wait() }()

	start := time.Now()
	err := b.CreateVM(context.Background(), spec)
	elapsed := time.Since(start)
	var bootErr *VMBootError
	if !errors.As(err, &bootErr) || bootErr.Cause != VMBootAgentNeverReady {
		t.Fatalf("CreateVM err = %v, want agent-never-ready", err)
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("error %q does not name the ceiling", err)
	}
	if n := spawnCount(sp); n != vmBootAttempts {
		t.Errorf("spawned %d helpers, want %d", n, vmBootAttempts)
	}
	if elapsed < vmBootAttempts*scaledCeiling || elapsed > vmBootAttempts*scaledCeiling+2*time.Second {
		t.Errorf("CreateVM took %s, want about %d x the %s ceiling", elapsed, vmBootAttempts, scaledCeiling)
	}
}

// TestCreateVMDoesNotRetryAHelperDeath: only agent-never-ready is retried. A
// helper that died is a fault a second boot would repeat; its console is
// still kept.
func TestCreateVMDoesNotRetryAHelperDeath(t *testing.T) {
	root := t.TempDir()
	spec := labSpec(t, root)
	health := func(context.Context, string) error { return errors.New("connection refused") }
	b, sp, w, _ := labBackend(t, root, health)
	b.bootTiming = vmBootTiming{idle: scaledIdle, ceiling: scaledCeiling}
	if err := os.WriteFile(filepath.Join(spec.PodDir, VMConsoleLogName), []byte("Kernel panic - not syncing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		for spawnCount(sp) == 0 {
			time.Sleep(time.Millisecond)
		}
		sp.mu.Lock()
		pid := sp.next
		sp.mu.Unlock()
		w.release(pid)
	}()

	err := b.CreateVM(context.Background(), spec)
	var bootErr *VMBootError
	if !errors.As(err, &bootErr) || bootErr.Cause != VMBootHelperDied {
		t.Fatalf("CreateVM err = %v, want helper-died", err)
	}
	if n := spawnCount(sp); n != 1 {
		t.Errorf("spawned %d helpers, want 1: a helper death is not retried", n)
	}
	if strings.Contains(err.Error(), "attempts") {
		t.Errorf("a single attempt is reported as several: %q", err)
	}
	if bootErr.RetainedConsole == "" || !strings.Contains(bootErr.ConsoleTail, "Kernel panic") {
		t.Errorf("a helper death's console was not kept: retained=%q tail=%q", bootErr.RetainedConsole, bootErr.ConsoleTail)
	}
}
