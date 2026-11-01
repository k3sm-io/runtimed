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

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
)

// spawnRecorder is the injected leaf writer, OOM arm and forker of
// limitThenFork: it records every call in order, fails the write to one file
// when failOn names it, and models a leaf without the memory controller when
// noMemory is set: every memory interface file is absent, so a write fails
// the way opening a missing file does.
type spawnRecorder struct {
	failOn   string
	noMemory bool
	calls    []string
	files    map[string]string
}

func (r *spawnRecorder) write(path, value string) error {
	name := filepath.Base(path)
	if r.noMemory && strings.HasPrefix(name, "memory.") {
		return fmt.Errorf("open %s: %w", path, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist})
	}
	if name == r.failOn {
		return errors.New("injected write failure")
	}
	r.calls = append(r.calls, name+"="+value)
	if r.files == nil {
		r.files = map[string]string{}
	}
	r.files[name] = value
	return nil
}

func (r *spawnRecorder) arm(container string) { r.calls = append(r.calls, "arm "+container) }

func (r *spawnRecorder) fork() (int, error) {
	r.calls = append(r.calls, "fork")
	return 42, nil
}

func (r *spawnRecorder) spawn(leaf string, cp guestinit.ContainerPlan) (int, error) {
	return limitThenFork(slog.New(slog.DiscardHandler), leaf, cp, r.write, r.arm, r.fork)
}

// TestSpawnAppliesMemoryLimitsBeforeFork is the B1140 gate: spawn's start
// order, through the same limitThenFork the linux spawn calls with the real
// leaf writer and ForkExec. The limits are written max, then high, then
// oom.group, all before the fork places the child in its leaf; a failed write
// means no fork; and a reused leaf whose new spec leaves a limit unset gets
// "max" written, so a stale bound from an earlier instance does not survive.
func TestSpawnAppliesMemoryLimitsBeforeFork(t *testing.T) {
	const leaf = "/sys/fs/cgroup/k3sm/app"
	plan := func(limit, high int64) guestinit.ContainerPlan {
		return guestinit.ContainerPlan{Name: "app", MemoryMaxBytes: limit, MemoryHighBytes: high}
	}

	t.Run("max, then high, then oom.group, then the fork", func(t *testing.T) {
		r := &spawnRecorder{}
		pid, err := r.spawn(leaf, plan(1<<30, 966367641))
		if err != nil || pid != 42 {
			t.Fatalf("spawn = %d, %v; want 42, nil", pid, err)
		}
		want := []string{
			guestagent.MemoryMaxFile + "=1073741824",
			guestagent.MemoryHighFile + "=966367641",
			guestagent.MemoryOOMGroupFile + "=1",
			"arm app",
			"fork",
		}
		if !reflect.DeepEqual(r.calls, want) {
			t.Errorf("calls = %q\nwant    %q", r.calls, want)
		}
	})

	t.Run("a failed write means no fork", func(t *testing.T) {
		for _, f := range []string{guestagent.MemoryMaxFile, guestagent.MemoryHighFile, guestagent.MemoryOOMGroupFile} {
			r := &spawnRecorder{failOn: f}
			if _, err := r.spawn(leaf, plan(1<<30, 966367641)); err == nil {
				t.Errorf("%s failing: spawn succeeded, want the start to fail", f)
			}
			for _, c := range r.calls {
				if c == "fork" {
					t.Errorf("%s failing: the container was forked: calls %q", f, r.calls)
				}
			}
		}
		r := &spawnRecorder{}
		if _, err := r.spawn("", plan(1<<30, 0)); err == nil || len(r.calls) != 0 {
			t.Errorf("a limit with no leaf: err %v, calls %q; want an error and no fork", err, r.calls)
		}
	})

	t.Run("an unset limit on a reused leaf is written as max", func(t *testing.T) {
		// The earlier instance left memory.max and memory.high set; the new
		// spec sets only one of them each time.
		for _, tc := range []struct {
			name         string
			limit, high  int64
			wantMax, wHi string
		}{
			{"high only", 0, 1 << 29, "max", "536870912"},
			{"max only", 1 << 30, 0, "1073741824", "max"},
		} {
			r := &spawnRecorder{files: map[string]string{
				guestagent.MemoryMaxFile:  "2147483648",
				guestagent.MemoryHighFile: "1932735283",
			}}
			if _, err := r.spawn(leaf, plan(tc.limit, tc.high)); err != nil {
				t.Fatalf("%s: spawn: %v", tc.name, err)
			}
			if got := r.files[guestagent.MemoryMaxFile]; got != tc.wantMax {
				t.Errorf("%s: memory.max = %q, want %q", tc.name, got, tc.wantMax)
			}
			if got := r.files[guestagent.MemoryHighFile]; got != tc.wHi {
				t.Errorf("%s: memory.high = %q, want %q", tc.name, got, tc.wHi)
			}
			if n := len(r.calls); n == 0 || r.calls[n-1] != "fork" {
				t.Errorf("%s: calls %q, want the fork last", tc.name, r.calls)
			}
		}
	})

	t.Run("no limit resets the leaf, then forks", func(t *testing.T) {
		r := &spawnRecorder{}
		if _, err := r.spawn(leaf, plan(0, 0)); err != nil {
			t.Fatalf("spawn: %v", err)
		}
		want := []string{
			guestagent.MemoryMaxFile + "=max",
			guestagent.MemoryHighFile + "=max",
			guestagent.MemoryOOMGroupFile + "=0",
			"arm app",
			"fork",
		}
		if !reflect.DeepEqual(r.calls, want) {
			t.Errorf("calls = %q, want %q", r.calls, want)
		}
	})
}

// TestSpawnResetsStaleLimitsOnReusedLeaf is the B1160 gate: a restart reuses
// the container's leaf, so when the new spec sets no memory limit the leaf
// still holds the earlier instance's memory.max, memory.high and
// memory.oom.group = 1. Spawn writes max, max and 0 over them before the fork,
// so an unbounded container does not run bounded and group-killed; and a
// failed reset write means no fork, the same as a failed limit write.
func TestSpawnResetsStaleLimitsOnReusedLeaf(t *testing.T) {
	const leaf = "/sys/fs/cgroup/k3sm/app"
	unset := guestinit.ContainerPlan{Name: "app"}
	prior := func() map[string]string {
		return map[string]string{
			guestagent.MemoryMaxFile:      "1073741824",
			guestagent.MemoryHighFile:     "966367641",
			guestagent.MemoryOOMGroupFile: "1",
		}
	}

	r := &spawnRecorder{files: prior()}
	pid, err := r.spawn(leaf, unset)
	if err != nil || pid != 42 {
		t.Fatalf("spawn = %d, %v; want 42, nil", pid, err)
	}
	want := []string{
		guestagent.MemoryMaxFile + "=max",
		guestagent.MemoryHighFile + "=max",
		guestagent.MemoryOOMGroupFile + "=0",
		"arm app",
		"fork",
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Errorf("calls = %q\nwant    %q", r.calls, want)
	}
	for f, v := range map[string]string{
		guestagent.MemoryMaxFile:      "max",
		guestagent.MemoryHighFile:     "max",
		guestagent.MemoryOOMGroupFile: "0",
	} {
		if got := r.files[f]; got != v {
			t.Errorf("%s = %q after the reset, want %q", f, got, v)
		}
	}

	for _, f := range []string{guestagent.MemoryMaxFile, guestagent.MemoryHighFile, guestagent.MemoryOOMGroupFile} {
		r := &spawnRecorder{failOn: f, files: prior()}
		if _, err := r.spawn(leaf, unset); err == nil {
			t.Errorf("%s reset failing: spawn succeeded, want the start to fail", f)
		}
		for _, c := range r.calls {
			if c == "fork" {
				t.Errorf("%s reset failing: the container was forked: calls %q", f, r.calls)
			}
		}
	}
}

// TestSpawnStartsUnmeteredWithoutMemoryController covers a leaf the memory
// controller was never enabled in (EnableSubtreeControllers is best effort, and
// a kernel may lack the controller): it has no memory.max, so no bound can be
// stale. A spec with no limit skips the reset and forks; a spec with a limit
// still fails the start, since the bound it asked for cannot be applied.
func TestSpawnStartsUnmeteredWithoutMemoryController(t *testing.T) {
	const leaf = "/sys/fs/cgroup/k3sm/app"

	t.Run("no limit forks with no write", func(t *testing.T) {
		r := &spawnRecorder{noMemory: true}
		pid, err := r.spawn(leaf, guestinit.ContainerPlan{Name: "app"})
		if err != nil || pid != 42 {
			t.Fatalf("spawn = %d, %v; want 42, nil", pid, err)
		}
		if want := []string{"arm app", "fork"}; !reflect.DeepEqual(r.calls, want) {
			t.Errorf("calls = %q, want %q", r.calls, want)
		}
	})

	t.Run("a limit still fails the start", func(t *testing.T) {
		for _, cp := range []guestinit.ContainerPlan{
			{Name: "app", MemoryMaxBytes: 1 << 30},
			{Name: "app", MemoryHighBytes: 1 << 29},
		} {
			r := &spawnRecorder{noMemory: true}
			if _, err := r.spawn(leaf, cp); err == nil {
				t.Errorf("max %d high %d: spawn succeeded, want the start to fail", cp.MemoryMaxBytes, cp.MemoryHighBytes)
			}
			for _, c := range r.calls {
				if c == "fork" {
					t.Errorf("max %d high %d: the container was forked: calls %q", cp.MemoryMaxBytes, cp.MemoryHighBytes, r.calls)
				}
			}
		}
	})
}
