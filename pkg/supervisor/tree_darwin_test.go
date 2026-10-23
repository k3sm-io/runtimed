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
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// treeHelperEnv selects a helper role when this test binary is re-executed as
// one of the pod's children; treeDirEnv names the dir it writes its pid to.
const (
	treeHelperEnv = "K3SM_TREE_TEST_HELPER"
	treeDirEnv    = "K3SM_TREE_TEST_DIR"
)

// The helper roles run before any test does, in the re-executed binary.
func init() {
	role := os.Getenv(treeHelperEnv)
	if role == "" {
		return
	}
	dir := os.Getenv(treeDirEnv)
	writePid := func(name string) {
		_ = os.WriteFile(filepath.Join(dir, name+".pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
	switch role {
	case "setsid":
		// The escapee: a new session and group, out of reach of any group
		// signal and of the pod's session.
		if _, err := unix.Setsid(); err != nil {
			os.Exit(3)
		}
		writePid("escapee")
		time.Sleep(10 * time.Minute)
	case "doublefork":
		// The double-forker: starts the orphan, then exits before the stop,
		// so the orphan is reparented to launchd while the pod still runs.
		self, _ := os.Executable()
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), treeHelperEnv+"=orphan")
		if err := cmd.Start(); err != nil {
			os.Exit(3)
		}
		writePid("doublefork")
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(filepath.Join(dir, "orphan.pid")); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		os.Exit(0)
	case "orphan":
		// A new process group (same session), ignoring TERM.
		_ = unix.Setpgid(0, 0)
		signalIgnoreTerm()
		writePid("orphan")
		time.Sleep(10 * time.Minute)
	}
	os.Exit(0)
}

func signalIgnoreTerm() { signal.Ignore(unix.SIGTERM) }

// liveInstance reports whether pid is alive (not a zombie) with start time
// start, per the process table.
func liveInstance(t *testing.T, pid int, start int64) bool {
	t.Helper()
	entries, ok := ReadProcTable()
	if !ok {
		t.Fatal("read the process table")
	}
	for _, e := range entries {
		if e.Pid == pid {
			return e.StartUnixNano == start && !e.Zombie
		}
	}
	return false
}

func readPid(t *testing.T, dir, name string) (int, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".pid"))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid, err == nil
}

// TestContainerExitKillsTheRestOfTheGroup is the gate. A pod-shaped init
// (/bin/sh -c, its own session) forks a TERM-ignoring sleeper, a setsid
// escapee, and a double-forker whose parent exits before the stop. The stop
// sends SIGTERM to the init alone (the resident-shim shape), the init exits on
// it, and the exit path must then leave nothing of the tree alive: each
// member killed by exact instance, the straggler count logged, and a member
// whose pid now names another process (a recycled pid) never signalled.
func TestContainerExitKillsTheRestOfTheGroup(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := `trap 'exit 0' TERM
sh -c 'trap "" TERM; exec sleep 600' &
echo $! > "$` + treeDirEnv + `/sleeper.pid"
` + treeHelperEnv + `=setsid "$TREE_SELF" &
` + treeHelperEnv + `=doublefork "$TREE_SELF" &
wait`
	spec := SpawnSpec{
		Path: "/bin/sh",
		Argv: []string{"/bin/sh", "-c", script},
		Env:  append(os.Environ(), treeDirEnv+"="+dir, "TREE_SELF="+self),
	}
	proc := NewProcess(PosixSpawner{}, KqueueReaper{}, spec, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := proc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	initPid := proc.PID()

	// A bystander outside the tree, whose pid the recycled-pid fake reuses.
	bystander := exec.Command("/bin/sleep", "600")
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bystander.Process.Kill(); _ = bystander.Wait() })

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(b []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(b)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	var killMu sync.Mutex
	var killedPids []int
	var firstKill time.Time
	budget := 3 * time.Second
	proc.TrackTree(ctx, TreeConfig{
		Table: ReadProcTable,
		Kill: func(pid int, sig unix.Signal) error {
			killMu.Lock()
			killedPids = append(killedPids, pid)
			if firstKill.IsZero() {
				firstKill = time.Now()
			}
			killMu.Unlock()
			return KillPID(pid, sig)
		},
		KillGroup: SignalGroup,
		ProcStart: ProcStartTimeNano,
		Tick:      100 * time.Millisecond,
		Budget:    budget,
		Logger:    logger,
	})

	// Wait for every child, and for the double-forker to be gone.
	type inst struct {
		pid   int
		start int64
	}
	children := map[string]inst{}
	deadline := time.Now().Add(20 * time.Second)
	for len(children) < 3 || func() bool { d, ok := readPid(t, dir, "doublefork"); return !ok || liveProc(d) }() {
		if time.Now().After(deadline) {
			t.Fatalf("the pod's children did not come up: %v", children)
		}
		for _, name := range []string{"sleeper", "escapee", "orphan"} {
			if _, ok := children[name]; ok {
				continue
			}
			if pid, ok := readPid(t, dir, name); ok {
				if start, ok := ProcStartTimeNano(pid); ok {
					children[name] = inst{pid, start}
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		for _, c := range children {
			if s, ok := ProcStartTimeNano(c.pid); ok && s == c.start {
				_ = unix.Kill(c.pid, unix.SIGKILL)
			}
		}
	})
	// Let a tick see the reparented orphan, then plant the recycled-pid fake:
	// a member naming the bystander's pid with a start that is not its own.
	time.Sleep(300 * time.Millisecond)
	snapshot := proc.TreeMembers()
	inSnapshot := map[int]bool{}
	for _, m := range snapshot {
		inSnapshot[m.Pid] = true
	}
	for name, c := range children {
		if !inSnapshot[c.pid] {
			t.Fatalf("%s (pid %d) is not in the tree before the stop: %+v", name, c.pid, snapshot)
		}
	}
	byStart, _ := ProcStartTimeNano(bystander.Process.Pid)
	tr := proc.procTreeOf()
	tr.mu.Lock()
	tr.members[bystander.Process.Pid] = TreeMember{Pid: bystander.Process.Pid, StartUnixNano: byStart - 1, Pgid: tr.pgid, Sid: tr.sid}
	tr.mu.Unlock()

	// TERM to the init alone; KILL (only on a grace expiry) to the group.
	stopSig := proc.StopSignal(func(pgid int, sig os.Signal) error {
		if sig == unix.SIGTERM {
			return KillPID(pgid, unix.SIGTERM)
		}
		return SignalGroup(pgid, sig)
	})
	escalated, observed, err := GracefulStop(ctx, initPid, 10*time.Second, proc.Done(),
		unix.SIGTERM, unix.SIGKILL, stopSig, budget+time.Second)
	reported := time.Now()
	if err != nil || escalated || !observed {
		t.Fatalf("stop: escalated=%v observed=%v err=%v (the init exits on TERM)", escalated, observed, err)
	}

	// The exit path swept before the exit was reported: nothing may remain.
	for name, c := range children {
		if liveInstance(t, c.pid, c.start) {
			t.Errorf("%s (pid %d) survived its container's exit", name, c.pid)
		}
	}
	for _, m := range snapshot {
		if liveInstance(t, m.Pid, m.StartUnixNano) {
			t.Errorf("tree member %+v survived its container's exit", m)
		}
	}
	if s := proc.TreeSurvivors(); len(s) != 0 {
		t.Errorf("survivors reported: %+v", s)
	}
	killMu.Lock()
	for _, pid := range killedPids {
		if pid == bystander.Process.Pid {
			t.Errorf("the recycled-pid fake (pid %d) was signalled", pid)
		}
	}
	latency := reported.Sub(firstKill)
	killMu.Unlock()
	if !liveProc(bystander.Process.Pid) {
		t.Errorf("the bystander behind the recycled-pid fake was killed")
	}
	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	m := regexp.MustCompile(`killed=(\d+)`).FindStringSubmatch(logs)
	if m == nil {
		t.Fatalf("no straggler count logged:\n%s", logs)
	}
	if n, _ := strconv.Atoi(m[1]); n < 3 {
		t.Errorf("straggler count %d, want >= 3 (sleeper, escapee, orphan):\n%s", n, logs)
	}
	t.Logf("straggler kill: first SIGKILL to the exit reported (every member gone) in %s (bound %s)", latency, budget)
}

// liveProc reports whether pid names a live, non-zombie process.
func liveProc(pid int) bool {
	entries, ok := ReadProcTable()
	if !ok {
		return true
	}
	for _, e := range entries {
		if e.Pid == pid {
			return !e.Zombie
		}
	}
	return false
}

// writerFunc adapts a function to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
