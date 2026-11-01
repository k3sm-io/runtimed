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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"

	guestv1 "k3sm.io/apis/guest/v1"
)

// fakeLeaf makes a directory carrying the memory interface files a delegated
// cgroup2 leaf has, empty, so what the guest writes is exactly what is read
// back. cgroupfs files always exist; the writer opens them without O_CREATE.
func fakeLeaf(t *testing.T, events string) string {
	t.Helper()
	leaf := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{guestagent.MemoryMaxFile, guestagent.MemoryHighFile, guestagent.MemoryOOMGroupFile} {
		if err := os.WriteFile(filepath.Join(leaf, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	setEvents(t, leaf, events)
	return leaf
}

func setEvents(t *testing.T, leaf, events string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(leaf, guestagent.MemoryEventsFile), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readLeafFile(t *testing.T, leaf, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(leaf, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func memSpec(limit, high int64) *guestv1.GuestSpec {
	return &guestv1.GuestSpec{
		Hostname: "p", AgentPort: 1024,
		Containers: []*guestv1.GuestContainer{{
			Name: "app", RootfsTag: "k3sm.rootfs", Command: []string{"/bin/sh"},
			MemoryLimitBytes: limit, MemoryHighBytes: high,
		}},
	}
}

const eventsZero = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"

// TestGuestInitSetsMemoryMaxAndHigh is the M21.9 gate: a GuestContainer's
// memory_limit_bytes and memory_high_bytes reach the container's cgroup2
// memory.max and memory.high (with memory.oom.group = 1) through the same
// plan-then-apply path the linux spawn takes, an unset limit writes nothing,
// a forbidden pair is refused at plan time, and an OOM kill counted in
// memory.events after the container started is reported as oom_killed.
func TestGuestInitSetsMemoryMaxAndHigh(t *testing.T) {
	const limit = int64(1 << 30)
	const high = limit * 9 / 10 // the host's default, 90% of the limit

	plan := func(t *testing.T, spec *guestv1.GuestSpec) guestinit.ContainerPlan {
		t.Helper()
		bp, err := guestinit.Plan(spec, guestinit.Options{})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		return bp.Containers[0]
	}

	t.Run("both limits are written before the container runs", func(t *testing.T) {
		leaf := fakeLeaf(t, eventsZero)
		if err := applyContainerMemory(leaf, plan(t, memSpec(limit, high))); err != nil {
			t.Fatalf("applyContainerMemory: %v", err)
		}
		if got := readLeafFile(t, leaf, guestagent.MemoryMaxFile); got != "1073741824" {
			t.Errorf("memory.max = %q, want 1073741824", got)
		}
		if got := readLeafFile(t, leaf, guestagent.MemoryHighFile); got != "966367641" {
			t.Errorf("memory.high = %q, want 966367641", got)
		}
		if got := readLeafFile(t, leaf, guestagent.MemoryOOMGroupFile); got != "1" {
			t.Errorf("memory.oom.group = %q, want 1", got)
		}
	})

	t.Run("no limit writes nothing", func(t *testing.T) {
		leaf := fakeLeaf(t, eventsZero)
		if err := applyContainerMemory(leaf, plan(t, memSpec(0, 0))); err != nil {
			t.Fatalf("applyContainerMemory: %v", err)
		}
		for _, f := range []string{guestagent.MemoryMaxFile, guestagent.MemoryHighFile, guestagent.MemoryOOMGroupFile} {
			if got := readLeafFile(t, leaf, f); got != "" {
				t.Errorf("%s = %q, want untouched", f, got)
			}
		}
	})

	t.Run("a limit with no leaf fails closed", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent")
		if err := applyContainerMemory(missing, plan(t, memSpec(limit, high))); err == nil {
			t.Fatal("a limit that could not be written must fail the start")
		}
		if err := applyContainerMemory("", plan(t, memSpec(limit, 0))); err == nil {
			t.Fatal("a limit with no cgroup leaf must fail the start")
		}
		if err := applyContainerMemory("", plan(t, memSpec(0, 0))); err != nil {
			t.Fatalf("no limit and no leaf is the unmetered case, not an error: %v", err)
		}
	})

	t.Run("a forbidden pair is refused at plan time", func(t *testing.T) {
		for name, spec := range map[string]*guestv1.GuestSpec{
			"negative limit":     memSpec(-1, 0),
			"negative high":      memSpec(0, -1),
			"high above the max": memSpec(limit, limit+1),
		} {
			if _, err := guestinit.Plan(spec, guestinit.Options{}); !errors.Is(err, guestinit.ErrInvalidSpec) {
				t.Errorf("%s: Plan err = %v, want ErrInvalidSpec", name, err)
			}
		}
		if _, err := guestinit.Plan(memSpec(0, high), guestinit.Options{}); err != nil {
			t.Errorf("memory.high alone is allowed: %v", err)
		}
	})

	t.Run("the spec fields decode from proto-JSON", func(t *testing.T) {
		spec, err := decodeSpec([]byte(`{"hostname":"p","agentPort":1024,"containers":[{"name":"app",` +
			`"rootfsTag":"k3sm.rootfs","command":["/bin/sh"],"memoryLimitBytes":"1073741824","memoryHighBytes":"966367641"}]}`))
		if err != nil {
			t.Fatalf("decodeSpec: %v", err)
		}
		cp := plan(t, spec)
		if cp.MemoryMaxBytes != limit || cp.MemoryHighBytes != high {
			t.Errorf("plan memory = %d/%d, want %d/%d", cp.MemoryMaxBytes, cp.MemoryHighBytes, limit, high)
		}
	})

	t.Run("an OOM kill after the start is reported", func(t *testing.T) {
		root := t.TempDir()
		leaf := filepath.Join(root, "app")
		if err := os.MkdirAll(leaf, 0o755); err != nil {
			t.Fatal(err)
		}
		// A previous instance of the same container was OOM-killed once: a
		// restart reuses the leaf, so the counter is cumulative.
		setEvents(t, leaf, strings.Replace(eventsZero, "oom_kill 0", "oom_kill 1", 1))
		w := newOOMWatch(root)
		w.arm("app")
		if w.killed("app") {
			t.Fatal("an exit with no new oom_kill must not be OOMKilled")
		}
		w.arm("app")
		setEvents(t, leaf, "low 0\nhigh 7\nmax 3\noom 1\noom_kill 2\n")
		if !w.killed("app") {
			t.Fatal("a new oom_kill since the start must be OOMKilled")
		}
	})

	t.Run("an unreadable counter is never OOMKilled", func(t *testing.T) {
		w := newOOMWatch(t.TempDir())
		w.arm("app")
		if w.killed("app") {
			t.Fatal("no memory.events must not prove an OOM kill")
		}
		if w.killed("never-armed") {
			t.Fatal("an unarmed container must not be OOMKilled")
		}
	})
}
