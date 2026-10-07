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
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Literal pbi_flags policy values from <sys/proc_info.h>, spelled out here so
// the tests do not borrow the implementation's own constants.
const (
	testPCNone     uint32 = 0x000
	testPCThrottle uint32 = 0x200
	testPCSusp     uint32 = 0x400
	testPCKill     uint32 = 0x600
)

// spawnSleepWith starts /bin/sleep 60 through the production spawner s and
// returns its pid, registering a SIGKILL+reap cleanup.
func spawnSleepWith(t *testing.T, s PosixSpawner) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	p := NewProcess(s, KqueueReaper{},
		SpawnSpec{Path: "/bin/sleep", Argv: []string{"/bin/sleep", "60"}, Env: []string{}}, nil)
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := p.PID()
	t.Cleanup(func() {
		_ = unix.Kill(pid, unix.SIGKILL)
		_, _, _ = p.Wait(ctx)
	})
	return pid
}

// TestPodSpawnMarkedPcontrolKill proves a pod process leaves PosixSpawner
// carrying the pcontrol-KILL policy when, and only when, PressureKill is set:
// the plan decision, the fail-soft retry decision, and a real spawn read back
// through proc_pidinfo. The unmarked real spawn is the control that shows the
// bit comes from this spawner and not from the test host.
func TestPodSpawnMarkedPcontrolKill(t *testing.T) {
	t.Run("plan", func(t *testing.T) {
		dir := t.TempDir()
		cases := []struct {
			name         string
			spec         SpawnSpec
			pressureKill bool
			want         spawnPlan
		}{
			{"marked-no-dir", SpawnSpec{Path: "/bin/sleep"}, true, spawnPlan{PControl: pcontrolKill}},
			{"unmarked-no-dir", SpawnSpec{Path: "/bin/sleep"}, false, spawnPlan{PControl: pcontrolNone}},
			{"marked-with-dir", SpawnSpec{Path: "/bin/sleep", Dir: dir}, true, spawnPlan{ChangeDir: dir, PControl: pcontrolKill}},
			{"unmarked-with-dir", SpawnSpec{Path: "/bin/sleep", Dir: dir}, false, spawnPlan{ChangeDir: dir, PControl: pcontrolNone}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := planSpawn(tc.spec, tc.pressureKill)
				if err != nil {
					t.Fatalf("planSpawn: %v", err)
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Errorf("plan = %+v, want %+v", got, tc.want)
				}
			})
		}
	})

	t.Run("retry", func(t *testing.T) {
		marked := spawnPlan{ChangeDir: "/private/tmp", PControl: pcontrolKill}
		unmarked := spawnPlan{ChangeDir: "/private/tmp", PControl: pcontrolNone}
		cases := []struct {
			name      string
			plan      spawnPlan
			setRC     int
			spawnErr  error
			wantPlan  spawnPlan
			wantRetry bool
		}{
			{"setpcontrol-failed-already-unmarked", marked, int(unix.EINVAL), unix.EINVAL, marked, false},
			{"einval-marked-retries-unmarked", marked, 0, unix.EINVAL, unmarked, true},
			{"eperm-no-retry", marked, 0, unix.EPERM, marked, false},
			{"enoent-no-retry", marked, 0, unix.ENOENT, marked, false},
			{"einval-unmarked-no-retry", unmarked, 0, unix.EINVAL, unmarked, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, retry := pcontrolRetry(tc.plan, tc.setRC, tc.spawnErr)
				if retry != tc.wantRetry {
					t.Errorf("retry = %v, want %v", retry, tc.wantRetry)
				}
				if !reflect.DeepEqual(got, tc.wantPlan) {
					t.Errorf("plan = %+v, want %+v", got, tc.wantPlan)
				}
			})
		}
	})

	t.Run("real-spawn-marked", func(t *testing.T) {
		before := UnmarkedSpawns()
		pid := spawnSleepWith(t, PosixSpawner{PressureKill: true})
		flags, err := pcontrolFlags(pid)
		if err != nil {
			t.Fatalf("pcontrolFlags: %v", err)
		}
		if flags&testPCKill != testPCKill {
			t.Fatalf("pbi_flags = 0x%x, policy bits 0x%x; want pcontrol-KILL (0x%x)", flags, flags&testPCKill, testPCKill)
		}
		if got := UnmarkedSpawns(); got != before {
			t.Errorf("UnmarkedSpawns moved %d -> %d on a spawn that carried the mark", before, got)
		}
	})

	t.Run("real-spawn-unmarked-control", func(t *testing.T) {
		pid := spawnSleepWith(t, PosixSpawner{PressureKill: false})
		flags, err := pcontrolFlags(pid)
		if err != nil {
			t.Fatalf("pcontrolFlags: %v", err)
		}
		if flags&testPCKill == testPCKill {
			t.Fatalf("pbi_flags = 0x%x carries pcontrol-KILL without PressureKill; the bit does not come from the spawner", flags)
		}
	})
}

// TestPcontrolCanary proves the startup self-check passes on this host and that
// the verdict function reads the two-bit policy field by full-mask compare.
func TestPcontrolCanary(t *testing.T) {
	t.Run("verify-on-host", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := VerifyPressureKill(ctx); err != nil {
			t.Fatalf("VerifyPressureKill: %v", err)
		}
	})

	t.Run("verdict", func(t *testing.T) {
		cases := []struct {
			name  string
			flags uint32
			want  bool
		}{
			{"none", testPCNone, false},
			{"throttle-only", testPCThrottle, false},
			{"suspend-only", testPCSusp, false},
			{"kill", testPCKill, true},
			{"kill-with-unrelated-bits", testPCKill | 0x1 | 0x10, true},
			{"unrelated-bits-only", 0x1 | 0x10 | 0x800, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := pcontrolIsKill(tc.flags); got != tc.want {
					t.Errorf("pcontrolIsKill(0x%x) = %v, want %v", tc.flags, got, tc.want)
				}
			})
		}
	})
}
