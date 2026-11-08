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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Argv markers the liveGroups fake acts on: a spawn whose argv carries
// markFailSpawn fails; a group whose argv carries markExitNonZero exits 1 as it
// is spawned; and one carrying markExitHoldPipes exits 0 as it is spawned while
// its pipe write ends stay held, as a grandchild that inherited them would hold
// them, so its log pump never sees EOF.
const (
	markFailSpawn     = "--refused-create-fail-spawn"
	markExitNonZero   = "--refused-create-exit-1"
	markExitHoldPipes = "--refused-create-exit-hold-pipes"
)

// liveGroups is one fake process table behind the spawner, waiter, signal and
// group-inspection seams, so "is container 1's group still running" has a
// single answer: a group is live from its spawn until a SIGTERM or SIGKILL is
// delivered to it (markExitNonZero: it exits as it is spawned).
//
// A live group holds a dup of its stdout and stderr write ends, as a running
// child does, so its log pump stays blocked reading — and its log writer stays
// reachable and open — for exactly as long as the group lives. Without that
// the pump would see EOF at once and the writer would be closed by nothing but
// the garbage collector, which is not what a leaked container does.
//
// It records every signal per pgid, and which exited groups the runtime has
// inspected (procGroup): watchContainerExit inspects a group only after the
// process's Wait returned, so an inspected group's supervisor.Process is
// already Done.
type liveGroups struct {
	mu       sync.Mutex
	next     int
	exit     map[int]chan struct{}
	code     map[int]int
	live     map[int]bool
	pipes    map[int][]int
	held     []int
	signals  map[int][]os.Signal
	observed map[int]bool
	// changed is closed and replaced (under mu) whenever a group goes live,
	// exits or is observed gone, so a waiter blocks on it instead of sleeping.
	changed chan struct{}
}

func newLiveGroups(t *testing.T) *liveGroups {
	g := &liveGroups{
		exit: map[int]chan struct{}{}, code: map[int]int{}, live: map[int]bool{},
		pipes: map[int][]int{}, signals: map[int][]os.Signal{}, observed: map[int]bool{},
		changed: make(chan struct{}),
	}
	t.Cleanup(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, fd := range g.held {
			_ = unix.Close(fd)
		}
		g.held = nil
	})
	return g
}

// awaitExitedObserved blocks, within a bound, until every group that has
// exited has been inspected by its watcher, so a spawn failing after it is
// returned only once the earlier process is known to be Done.
func (g *liveGroups) awaitExitedObserved() {
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		g.mu.Lock()
		all := true
		for pid := range g.exit {
			if !g.live[pid] && !g.observed[pid] {
				all = false
			}
		}
		changed := g.changed
		g.mu.Unlock()
		if all {
			return
		}
		select {
		case <-changed:
		case <-timeout.C:
			return
		}
	}
}

func (g *liveGroups) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	if slices.Contains(spec.Argv, markFailSpawn) {
		g.awaitExitedObserved()
		return 0, errors.New("posix_spawn: no such file or directory")
	}
	if _, err := podEnvSpawn(spec); err != nil {
		return 0, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	pid := 3000 + g.next
	g.exit[pid] = make(chan struct{})
	g.live[pid] = true
	for _, fd := range []uintptr{spec.StdoutFD, spec.StderrFD} {
		if fd == 0 {
			continue
		}
		d, err := unix.Dup(int(fd))
		if err != nil {
			g.exitLocked(pid)
			return 0, err
		}
		g.pipes[pid] = append(g.pipes[pid], d)
	}
	if slices.Contains(spec.Argv, markExitNonZero) {
		g.code[pid] = 1
		g.exitLocked(pid)
	}
	if slices.Contains(spec.Argv, markExitHoldPipes) {
		g.held = append(g.held, g.pipes[pid]...)
		delete(g.pipes, pid)
		g.code[pid] = 0
		g.exitLocked(pid)
	}
	return pid, nil
}

func (g *liveGroups) notifyLocked() {
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *liveGroups) exitLocked(pid int) {
	if g.live[pid] {
		g.live[pid] = false
		g.notifyLocked()
		close(g.exit[pid])
		for _, fd := range g.pipes[pid] {
			_ = unix.Close(fd)
		}
		delete(g.pipes, pid)
	}
}

func (g *liveGroups) WaitExit(ctx context.Context, pid int) (int, int, error) {
	g.mu.Lock()
	ch, ok := g.exit[pid]
	code := g.code[pid]
	g.mu.Unlock()
	if !ok {
		return 0, 0, errors.New("wait for a pid the fake never spawned")
	}
	select {
	case <-ch:
		if code != 0 {
			return code, 0, nil
		}
		return 0, int(unix.SIGKILL), nil
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
}

func (g *liveGroups) signal(pgid int, sig os.Signal) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.signals[pgid] = append(g.signals[pgid], sig)
	if sig != termSignal && sig != killSignal {
		return nil
	}
	g.exitLocked(pgid)
	return nil
}

func (g *liveGroups) procGroup(pgid int) ([]supervisor.ProcMember, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.live[pgid] {
		return []supervisor.ProcMember{{Pid: pgid, StartUnixNano: 1}}, true
	}
	g.observed[pgid] = true
	g.notifyLocked()
	return nil, true
}

func (g *liveGroups) livePIDs() []int {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []int
	for pid, l := range g.live {
		if l {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

func (g *liveGroups) signalsTo(pgid int) []os.Signal {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]os.Signal(nil), g.signals[pgid]...)
}

func (g *liveGroups) spawned() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.next
}

// openLogFiles lists the files under dir that this test process still holds
// open, by matching every descriptor in /dev/fd against the files' inodes.
// TestOpenLogFilesSeesAHeldFile keeps it from passing vacuously.
func openLogFiles(t *testing.T, dir string) []string {
	t.Helper()
	type key struct {
		dev int32
		ino uint64
	}
	files := map[key]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type().IsRegular() {
			var st unix.Stat_t
			if err := unix.Stat(path, &st); err == nil {
				files[key{st.Dev, st.Ino}] = path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if len(files) == 0 {
		return nil
	}
	fds, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatalf("read /dev/fd: %v", err)
	}
	var open []string
	for _, e := range fds {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			continue
		}
		if p, ok := files[key{st.Dev, st.Ino}]; ok {
			open = append(open, p)
		}
	}
	return open
}

// TestOpenLogFilesSeesAHeldFile proves openLogFiles reports a file this process
// holds open and stops reporting it once closed, so the gate's log assertion
// below cannot pass by seeing nothing.
func TestOpenLogFilesSeesAHeldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c", "0.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := openLogFiles(t, dir); !slices.Equal(got, []string{path}) {
		_ = f.Close()
		t.Fatalf("held open: openLogFiles = %v, want [%s]", got, path)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := openLogFiles(t, dir); len(got) != 0 {
		t.Fatalf("after close: openLogFiles = %v, want none", got)
	}
}

// TestRefusedCreateLeavesNoLiveContainer pins the unwind of a refused
// CreatePod: a pod whose create fails after an earlier container was spawned is
// never registered, so nothing else will ever stop that container. When the
// refusal is returned, no group the create spawned may still run, the pod may
// hold no reap record, and no container log file may still be open. A retried
// create of the same pod must refuse the same way without stacking a copy.
func TestRefusedCreateLeavesNoLiveContainer(t *testing.T) {
	sidecar := func(name string) *runtimev1.Container {
		return &runtimev1.Container{
			Name:          name,
			Image:         "/bin/sleep",
			RestartPolicy: runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS,
		}
	}
	cases := []struct {
		name      string
		grace     int64
		inits     []*runtimev1.Container
		mains     []*runtimev1.Container
		attempts  int
		wantSpawn int   // groups each attempt spawns
		exited    []int // pgids that exit on their own and must never be signalled
	}{
		{
			name:  "second-main-spawn-fails",
			grace: 30,
			mains: []*runtimev1.Container{
				{Name: "c1", Image: "/bin/sleep"},
				{Name: "c2", Image: NativeImage, Command: []string{"/bin/sleep", markFailSpawn}},
			},
			attempts:  1,
			wantSpawn: 1,
		},
		{
			name:      "init-spawn-fails-after-sidecar",
			inits:     []*runtimev1.Container{sidecar("sc"), {Name: "init", Image: NativeImage, Command: []string{"/bin/sleep", markFailSpawn}}},
			mains:     []*runtimev1.Container{{Name: "main", Image: "/bin/sleep"}},
			attempts:  1,
			wantSpawn: 1,
		},
		{
			name:      "init-exits-nonzero-after-sidecar",
			grace:     30,
			inits:     []*runtimev1.Container{sidecar("sc"), {Name: "init", Image: NativeImage, Command: []string{"/bin/sleep", markExitNonZero}}},
			mains:     []*runtimev1.Container{{Name: "main", Image: "/bin/sleep"}},
			attempts:  1,
			wantSpawn: 2,
		},
		{
			// c1 runs to completion before c2's spawn fails, but its output pipe
			// is still held, so its terminated state is not yet written when the
			// unwind runs: only the process's own Done says it is gone.
			name:  "exited-main-is-never-signalled",
			grace: 30,
			mains: []*runtimev1.Container{
				{Name: "c1", Image: NativeImage, Command: []string{"/bin/sleep", markExitHoldPipes}},
				{Name: "c2", Image: NativeImage, Command: []string{"/bin/sleep", markFailSpawn}},
			},
			attempts:  1,
			wantSpawn: 1,
			exited:    []int{3001},
		},
		{
			name: "retry-after-refusal",
			mains: []*runtimev1.Container{
				{Name: "c1", Image: "/bin/sleep"},
				{Name: "c2", Image: NativeImage, Command: []string{"/bin/sleep", markFailSpawn}},
			},
			attempts:  2,
			wantSpawn: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLiveGroups(t)
			rt := newTestRuntime(t, Deps{Spawner: g, Waiter: g, SignalGroup: g.signal, ProcGroup: g.procGroup})
			const podID = "pod-refused-create"
			for attempt := 1; attempt <= tc.attempts; attempt++ {
				box := hostBinBox(rt, podID)
				box.TerminationGracePeriodSeconds = tc.grace
				box.InitContainers = tc.inits
				box.Containers = tc.mains
				resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
				if err != nil {
					t.Fatalf("attempt %d: CreatePod: %v", attempt, err)
				}
				if resp.GetError() == nil {
					t.Fatalf("attempt %d: CreatePod succeeded, want a refusal", attempt)
				}
				if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_SPAWN {
					t.Fatalf("attempt %d: failure reason = %v, want SPAWN", attempt, got)
				}
				if got, want := g.spawned(), attempt*tc.wantSpawn; got != want {
					t.Fatalf("attempt %d: %d groups spawned so far, want %d", attempt, got, want)
				}
				assertRefusedCreateUnwound(t, rt, g, podID, attempt)
				for _, pgid := range tc.exited {
					if sigs := g.signalsTo(pgid); len(sigs) > 0 {
						t.Errorf("attempt %d: pgid %d exited on its own before the refusal but was signalled %v", attempt, pgid, sigs)
					}
				}
			}
		})
	}
}

// assertRefusedCreateUnwound polls, within a bound, until the refused pod has
// no live group, no reap record and no open log file, and fails with whatever
// is still left when the bound runs out.
func assertRefusedCreateUnwound(t *testing.T, rt *Runtime, g *liveGroups, podID string, attempt int) {
	t.Helper()
	logDir := testPodLogDir(rt, podID)
	var (
		live    []int
		hasRec  bool
		recOK   bool
		openLog []string
	)
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		live = g.livePIDs()
		hasRec, recOK = rt.podHasReapRecord(podID)
		openLog = openLogFiles(t, logDir)
		if len(live) == 0 && !hasRec && recOK && len(openLog) == 0 {
			return
		}
		select {
		case <-tick.C:
			continue
		case <-timeout.C:
		}
		break
	}
	if len(live) > 0 {
		t.Errorf("attempt %d: process groups still live after the refusal: %v", attempt, live)
	}
	if hasRec || !recOK {
		t.Errorf("attempt %d: reap record left for the refused pod (has=%v, readable=%v)", attempt, hasRec, recOK)
	}
	if len(openLog) > 0 {
		t.Errorf("attempt %d: container log files still open: %v", attempt, openLog)
	}
}
