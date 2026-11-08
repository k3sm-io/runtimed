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
// is spawned; one carrying markExitZero exits 0 as it is spawned, as a
// completed Job container does; and one carrying markExitHoldPipes exits 0 as
// it is spawned while its pipe write ends stay held, as a grandchild that
// inherited them would hold them, so its log pump never sees EOF.
const (
	markFailSpawn     = "--refused-create-fail-spawn"
	markExitNonZero   = "--refused-create-exit-1"
	markExitZero      = "--refused-create-exit-0"
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
	sentAt   map[int][]time.Time
	observed map[int]bool
	// waitErr, when it holds an error for a pid, is what WaitExit returns for
	// that pid at once, while the group stays live: a wait that failed for a
	// reason other than its context, as an unreadable exit status does.
	waitErr map[int]error
	// deaf makes the table ignore every signal: a group then runs until the
	// test ends it (exitAll), so a stop that escalates is seen to escalate
	// rather than being cut short by an exit the first signal caused.
	deaf bool
	// onFailSpawn, when set, runs as a markFailSpawn spawn is refused: the
	// moment the create's refusal is decided.
	onFailSpawn func()
	// changed is closed and replaced (under mu) whenever a group goes live,
	// exits or is observed gone, so a waiter blocks on it instead of sleeping.
	changed chan struct{}
	// escapees maps an escaped child's pid to its parent's: procTable lists
	// it, in its own group and session, for as long as the test runs, and it
	// ignores every signal, so a tree sweep that adopted it reports it as a
	// survivor.
	escapees map[int]int
}

func newLiveGroups(t *testing.T) *liveGroups {
	g := &liveGroups{
		exit: map[int]chan struct{}{}, code: map[int]int{}, live: map[int]bool{},
		pipes: map[int][]int{}, signals: map[int][]os.Signal{}, sentAt: map[int][]time.Time{},
		observed: map[int]bool{}, waitErr: map[int]error{},
		changed: make(chan struct{}), escapees: map[int]int{},
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
		if g.onFailSpawn != nil {
			g.onFailSpawn()
		}
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
	if slices.Contains(spec.Argv, markExitZero) {
		g.code[pid] = 0
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
	werr := g.waitErr[pid]
	g.mu.Unlock()
	if !ok {
		return 0, 0, errors.New("wait for a pid the fake never spawned")
	}
	if werr != nil {
		return 0, 0, werr
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
	g.sentAt[pgid] = append(g.sentAt[pgid], time.Now())
	if g.deaf || (sig != termSignal && sig != killSignal) {
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

// signalTimes returns when each signal signalsTo reports was delivered.
func (g *liveGroups) signalTimes(pgid int) []time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]time.Time(nil), g.sentAt[pgid]...)
}

// exitAll ends every group still live, as the end of the test does.
func (g *liveGroups) exitAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for pid := range g.exit {
		g.exitLocked(pid)
	}
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

// TestRefusedCreateStopHonoursGraceAndEscalation pins the stop a refused
// CreatePod runs against groups that do not die when signalled, which is what
// separates a stop that escalates from one an exit happened to end. The table's
// groups ignore every signal (liveGroups.deaf), so each row's signals are the
// stop's own decisions:
//
//   - a main that ignores SIGTERM is sent SIGKILL once the pod's grace has run,
//     and not before;
//   - a request ctx cancelled at the refusal escalates to SIGKILL at once,
//     long before the grace would;
//   - a plain init container still running at the refusal is stopped with the
//     mains, as the kubelet's pod kill stops every running container: SIGTERM,
//     then SIGKILL once the pod's grace has run, and not before.
//
// There is no clock seam in this package, so the grace row runs on the
// shortest grace the API can express (one second) and the timings are read
// from when the fake received each signal.
func TestRefusedCreateStopHonoursGraceAndEscalation(t *testing.T) {
	cases := []struct {
		name string
		// grace is the pod's termination_grace_period_seconds.
		grace int64
		// cancelAtRefusal cancels the CreatePod ctx as the refusing spawn fails.
		cancelAtRefusal bool
		// plainInit runs the unwind directly on a pod whose one running
		// container is a plain init container: createPod drops a plain init
		// from p.containers once its wait returns, so no create refusal leaves
		// one there today, and the row pins what the stop would do if one did.
		plainInit bool
		// want is every signal container 1's group gets, in order.
		want []os.Signal
		// minGap and maxGap bound the time from the first signal to the second
		// (zero: unchecked).
		minGap, maxGap time.Duration
	}{
		{
			name:   "sigterm-ignoring-main-escalates-after-grace",
			grace:  1,
			want:   []os.Signal{termSignal, killSignal},
			minGap: time.Second,
		},
		{
			name:            "cancelled-ctx-escalates-at-once",
			grace:           30,
			cancelAtRefusal: true,
			want:            []os.Signal{termSignal, killSignal},
			maxGap:          10 * time.Second,
		},
		{
			name:      "plain-init-running-at-refusal-escalates-after-grace",
			grace:     1,
			plainInit: true,
			want:      []os.Signal{termSignal, killSignal},
			minGap:    time.Second,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLiveGroups(t)
			g.deaf = true
			rt := newTestRuntime(t, Deps{Spawner: g, Waiter: g, SignalGroup: g.signal, ProcGroup: g.procGroup})
			rt.drainGrace = 50 * time.Millisecond
			// Registered after the runtime, so it runs before rt.Close: the groups
			// end and their log pumps see EOF before supervision is torn down.
			t.Cleanup(g.exitAll)
			const (
				podID = "pod-refused-create-stop"
				c1    = 3001
			)
			box := hostBinBox(rt, podID)
			box.TerminationGracePeriodSeconds = tc.grace
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if tc.plainInit {
				box.Containers = []*runtimev1.Container{{Name: "init", Image: "/bin/sleep"}}
				resp, err := rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
				if err != nil || resp.GetError() != nil {
					t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
				}
				rt.mu.Lock()
				p := rt.pods[podID]
				delete(rt.pods, podID)
				rt.mu.Unlock()
				if p == nil {
					t.Fatal("created pod is not registered")
				}
				p.mu.Lock()
				for _, cp := range p.containers {
					// Re-declare the running container as a plain init: restart
					// policy unspecified, so it is init-declared but no sidecar.
					cp.initDeclared = true
				}
				p.mu.Unlock()
				rt.unwindRefusedCreate(ctx, p)
			} else {
				box.Containers = []*runtimev1.Container{
					{Name: "c1", Image: "/bin/sleep"},
					{Name: "c2", Image: NativeImage, Command: []string{"/bin/sleep", markFailSpawn}},
				}
				if tc.cancelAtRefusal {
					g.onFailSpawn = cancel
				}
				resp, err := rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
				if err != nil {
					t.Fatalf("CreatePod: %v", err)
				}
				if got := resp.GetFailureReason(); resp.GetError() == nil || got != runtimev1.FailureReason_FAILURE_REASON_SPAWN {
					t.Fatalf("CreatePod = reason %v, error %v; want a SPAWN refusal", got, resp.GetError())
				}
			}

			if got := g.spawned(); got != 1 {
				t.Fatalf("%d groups spawned, want 1", got)
			}
			sigs, at := g.signalsTo(c1), g.signalTimes(c1)
			if !slices.Equal(sigs, tc.want) {
				t.Fatalf("container 1 was signalled %v, want %v", sigs, tc.want)
			}
			if len(tc.want) < 2 {
				return
			}
			gap := at[1].Sub(at[0])
			if tc.minGap > 0 && gap < tc.minGap {
				t.Errorf("SIGKILL followed SIGTERM after %v, inside the %v grace", gap, tc.minGap)
			}
			if tc.maxGap > 0 && gap > tc.maxGap {
				t.Errorf("SIGKILL followed SIGTERM after %v, want an escalation within %v", gap, tc.maxGap)
			}
		})
	}
}

// TestDeletePodSparesAnExitedMain pins that DeletePod never signals the
// process group of a main whose process is already Done: one that exited on
// its own, as a completed Job container does, with no StopContainer claiming
// it. Once its leader is reaped the pgid may name an unrelated process, and the
// daemon is privileged. Its tree is the pod-tree sweep's (sweepPodTrees), which
// signals only members proven ours by exact instance. The sibling main still
// running is stopped as before. The groups ignore every signal
// (liveGroups.deaf), so each signal recorded is the stop's own decision.
func TestDeletePodSparesAnExitedMain(t *testing.T) {
	const (
		exited  = 3001 // c1: exits 0 as it is spawned
		running = 3002 // c2: runs until the stop
	)
	cases := []struct {
		name string
		// grace is the DeletePod request's grace_period_seconds.
		grace int64
		// want is every signal the running main's group gets, in order.
		want []os.Signal
	}{
		{name: "immediate-kill", grace: 0, want: []os.Signal{killSignal}},
		{name: "graceful-stop", grace: 1, want: []os.Signal{termSignal, killSignal}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLiveGroups(t)
			g.deaf = true
			rt := newTestRuntime(t, Deps{Spawner: g, Waiter: g, SignalGroup: g.signal, ProcGroup: g.procGroup})
			rt.drainGrace = 50 * time.Millisecond
			rt.exitObsGrace = 50 * time.Millisecond
			// Registered after the runtime, so it runs before rt.Close.
			t.Cleanup(g.exitAll)
			const podID = "pod-delete-exited-main"
			box := hostBinBox(rt, podID)
			box.Containers = []*runtimev1.Container{
				{Name: "c1", Image: NativeImage, Command: []string{"/bin/sleep", markExitZero}},
				{Name: "c2", Image: "/bin/sleep"},
			}
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil || resp.GetError() != nil {
				t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
			}
			if got := g.spawned(); got != 2 {
				t.Fatalf("%d groups spawned, want 2", got)
			}
			// The fixture's premise: c1's process is Done and nothing claimed it.
			g.awaitExitedObserved()
			rt.mu.Lock()
			p := rt.pods[podID]
			rt.mu.Unlock()
			if p == nil {
				t.Fatal("created pod is not registered")
			}
			p.mu.Lock()
			var c1Done, c1Stopped bool
			for _, cp := range p.containers {
				if cp.name == "c1" && cp.proc != nil {
					c1Done, c1Stopped = procDone(cp.proc), cp.stopped
				}
			}
			p.mu.Unlock()
			if !c1Done || c1Stopped {
				t.Fatalf("c1 before the delete: done=%v stopped=%v, want done and unclaimed", c1Done, c1Stopped)
			}

			if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: podID, GracePeriodSeconds: tc.grace}); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			if sigs := g.signalsTo(exited); len(sigs) > 0 {
				t.Errorf("pgid %d exited on its own before the delete but was signalled %v", exited, sigs)
			}
			if sigs := g.signalsTo(running); !slices.Equal(sigs, tc.want) {
				t.Errorf("running main pgid %d was signalled %v, want %v", running, sigs, tc.want)
			}
		})
	}
}
