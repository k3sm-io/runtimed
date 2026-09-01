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

package guestagent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestCgroup2Parsers pins the readers that turn a guest's cgroup2 files into the
// numbers `kubectl top` shows. They are the only place a mis-read becomes a wrong
// figure, and they are pure — which is exactly why they live here rather than in
// the linux executor, where no darwin test could reach them.
func TestCgroup2Parsers(t *testing.T) {
	// A real cpu.stat, including the fields a newer kernel adds.
	const cpuStat = `usage_usec 1234567
user_usec 900000
system_usec 334567
nr_periods 0
nr_throttled 0
throttled_usec 0
`
	t.Run("cpu-usage-usec", func(t *testing.T) {
		got, err := CPUUsageUsec(cpuStat)
		if err != nil {
			t.Fatalf("CPUUsageUsec: %v", err)
		}
		if got != 1234567 {
			t.Errorf("usage_usec = %d, want 1234567", got)
		}
	})

	t.Run("unknown-fields-are-skipped-not-rejected", func(t *testing.T) {
		// The kernel adds counters over time. An agent that refused to read
		// cpu.stat because a newer kernel grew a field would report nothing at all.
		withNew := cpuStat + "some_future_counter 42\n"
		if _, err := CPUUsageUsec(withNew); err != nil {
			t.Errorf("a cpu.stat with an unknown field was rejected: %v", err)
		}
	})

	t.Run("an-absent-field-is-absent-not-zero", func(t *testing.T) {
		_, err := CPUUsageUsec("user_usec 1\nsystem_usec 2\n")
		if !errors.Is(err, ErrCgroupFieldAbsent) {
			t.Errorf("err = %v, want ErrCgroupFieldAbsent; a zero counter is a different fact from an unreadable one", err)
		}
	})

	t.Run("a-non-numeric-value-is-an-error", func(t *testing.T) {
		if _, err := CPUUsageUsec("usage_usec lots\n"); err == nil {
			t.Error("a non-numeric usage_usec was accepted")
		}
	})

	t.Run("single-value-files", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			content string
			want    uint64
			wantErr bool
		}{
			{name: "plain", content: "4194304\n", want: 4194304},
			{name: "no-trailing-newline", content: "17", want: 17},
			{name: "empty-is-absent", content: "\n", wantErr: true},
			// "max" appears in the LIMIT files and means "no limit". Mapping it to
			// 0 or MaxUint64 would be a lie in one direction or the other.
			{name: "max-is-absent-not-a-number", content: "max\n", wantErr: true},
			{name: "garbage", content: "n/a\n", wantErr: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := ParseSingleUint(tc.content)
				if tc.wantErr {
					if err == nil {
						t.Errorf("ParseSingleUint(%q) = %d, want an error", tc.content, got)
					}
					return
				}
				if err != nil {
					t.Fatalf("ParseSingleUint(%q): %v", tc.content, err)
				}
				if got != tc.want {
					t.Errorf("ParseSingleUint(%q) = %d, want %d", tc.content, got, tc.want)
				}
			})
		}
	})

	t.Run("working-set-subtracts-inactive-file", func(t *testing.T) {
		// The subtraction IS the kubelet's definition, not an approximation: page
		// cache is charged to the cgroup, so memory.current alone would report a
		// container that merely READ a large file as holding all of it live.
		const memStat = "anon 500\ninactive_file 4000\nactive_file 100\n"
		got, err := WorkingSet("10000\n", memStat)
		if err != nil {
			t.Fatalf("WorkingSet: %v", err)
		}
		if got != 6000 {
			t.Errorf("working set = %d, want 6000 (10000 - 4000)", got)
		}
	})

	t.Run("working-set-saturates-instead-of-wrapping", func(t *testing.T) {
		// The two numbers come from two files at two instants, so a guest that
		// faulted pages in between can legitimately produce inactive_file >
		// current. An unsigned subtraction there wraps to ~16 exabytes, which is
		// worse than reporting zero.
		got, err := WorkingSet("1000\n", "inactive_file 4000\n")
		if err != nil {
			t.Fatalf("WorkingSet: %v", err)
		}
		if got != 0 {
			t.Errorf("working set = %d, want 0; an unsigned subtraction must not wrap", got)
		}
	})

	t.Run("a-memory-stat-without-inactive-file-has-no-sample", func(t *testing.T) {
		// Not "the container uses no page cache" — a kernel this code does not
		// know. Reporting memory.current would overstate the working set by
		// exactly the amount the field exists to remove.
		if _, err := WorkingSet("1000\n", "anon 10\n"); !errors.Is(err, ErrCgroupFieldAbsent) {
			t.Errorf("err = %v, want ErrCgroupFieldAbsent", err)
		}
	})
}

// TestLogRingBoundsAndSelection pins the retained-output buffer: its two bounds,
// its filter order, and the guarantee that a slow follower never blocks the
// container that is writing.
func TestLogRingBoundsAndSelection(t *testing.T) {
	base := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	entry := func(i int, line string) LogEntry {
		return LogEntry{At: base.Add(time.Duration(i) * time.Second), Line: []byte(line)}
	}

	t.Run("the-entry-bound-evicts-oldest-first", func(t *testing.T) {
		r := NewRing(3, 1<<20)
		for i := 0; i < 5; i++ {
			r.Append(entry(i, string(rune('a'+i))))
		}
		got := r.Snapshot(Selector{})
		if len(got) != 3 {
			t.Fatalf("retained %d entries, want 3", len(got))
		}
		if string(got[0].Line) != "c" || string(got[2].Line) != "e" {
			t.Errorf("retained %q..%q, want the LAST three", got[0].Line, got[2].Line)
		}
		if r.Dropped() != 2 {
			t.Errorf("Dropped() = %d, want 2; a reader must be told the log starts mid-stream", r.Dropped())
		}
	})

	t.Run("the-byte-bound-is-independent-of-the-entry-bound", func(t *testing.T) {
		// Neither bound implies the other: an entry cap alone lets a container
		// hold a gigabyte in a thousand enormous lines.
		r := NewRing(1000, 32)
		for i := 0; i < 4; i++ {
			r.Append(entry(i, strings.Repeat("x", 20)))
		}
		if got := r.Snapshot(Selector{}); len(got) > 2 {
			t.Errorf("retained %d entries of 20 bytes under a 32-byte cap; the byte bound did not bite", len(got))
		}
	})

	t.Run("appended-bytes-are-copied", func(t *testing.T) {
		// The caller is a read pump reusing one buffer. Retaining the slice would
		// make every stored entry alias whatever that buffer last held — the
		// classic form of this bug, where old log lines mutate.
		r := NewRing(10, 1<<20)
		buf := []byte("first")
		r.Append(LogEntry{At: base, Line: buf})
		copy(buf, "SECON")
		if got := string(r.Snapshot(Selector{})[0].Line); got != "first" {
			t.Errorf("retained entry = %q after the caller reused its buffer, want %q", got, "first")
		}
	})

	t.Run("since-time-narrows-before-tail-lines", func(t *testing.T) {
		// The order is upstream's and is not interchangeable. Tail-then-since
		// would return the last N overall and then drop the ones before
		// since_time, which for a container that went quiet returns nothing where
		// upstream returns its last N lines since that time.
		r := NewRing(100, 1<<20)
		for i := 0; i < 10; i++ {
			r.Append(entry(i, string(rune('0'+i))))
		}
		got := r.Snapshot(Selector{SinceTime: base.Add(2 * time.Second), TailLines: 3})
		if len(got) != 3 {
			t.Fatalf("got %d entries, want 3", len(got))
		}
		if string(got[0].Line) != "7" || string(got[2].Line) != "9" {
			t.Errorf("got %q..%q, want the last three at or after since_time", got[0].Line, got[2].Line)
		}
	})

	t.Run("tail-lines-larger-than-the-buffer-returns-everything", func(t *testing.T) {
		r := NewRing(100, 1<<20)
		r.Append(entry(0, "only"))
		if got := r.Snapshot(Selector{TailLines: 50}); len(got) != 1 {
			t.Errorf("got %d entries, want 1", len(got))
		}
	})

	t.Run("a-follower-that-stops-reading-never-blocks-the-writer", func(t *testing.T) {
		// In a guest the writer is the pod's own output pump. A blocked writer is
		// a blocked workload.
		r := NewRing(10000, 1<<30)
		_, unsubscribe := r.Subscribe(1)
		defer unsubscribe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 5000; i++ {
				r.Append(entry(i, "line"))
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Append blocked on a follower that stopped reading; a slow log reader must never stall the workload")
		}
	})

	t.Run("close-ends-every-follower", func(t *testing.T) {
		r := NewRing(10, 1<<20)
		ch, unsubscribe := r.Subscribe(4)
		defer unsubscribe()
		r.Close()
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("a follower received an entry after Close")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a follower did not see end-of-stream after Close; it would hang on a container that will never write again")
		}
	})

	t.Run("subscribing-after-close-does-not-hang", func(t *testing.T) {
		r := NewRing(10, 1<<20)
		r.Close()
		ch, unsubscribe := r.Subscribe(1)
		defer unsubscribe()
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("a post-Close subscriber received an entry")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a post-Close subscriber hung")
		}
	})
}

// TestEventsFanOutDropsRatherThanBlocks pins the property PID 1 depends on: the
// reaper publishes exits from its only reaping loop, so a subscriber that stopped
// reading must never be able to stall it. A stalled reaper means unreaped zombies
// and, in a pid namespace, no other process to inherit them.
func TestEventsFanOutDropsRatherThanBlocks(t *testing.T) {
	t.Run("delivers-to-every-subscriber", func(t *testing.T) {
		e := NewEvents(8)
		a, b := e.Subscribe(), e.Subscribe()
		defer a.Close()
		defer b.Close()
		e.Publish(ContainerEvent{Container: "app", Started: &ContainerStarted{PID: 7}})
		for i, sub := range []*Subscription{a, b} {
			select {
			case ev := <-sub.C():
				if ev.Container != "app" || ev.Started == nil || ev.Started.PID != 7 {
					t.Errorf("subscriber %d got %+v", i, ev)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("subscriber %d received nothing", i)
			}
		}
	})

	t.Run("a-full-queue-drops-and-marks-rather-than-blocking", func(t *testing.T) {
		e := NewEvents(1)
		sub := e.Subscribe()
		defer sub.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 100; i++ {
				e.Publish(ContainerEvent{Container: "app"})
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Publish blocked on a full subscriber queue; that would stall PID 1's reap loop and leave zombies nothing can inherit")
		}
		if !sub.Lossy() {
			t.Error("the subscriber was not marked lossy after events were dropped; a dropped ContainerEvent can be the pod's only OOMKilled notice, so the loss must be reportable")
		}
	})

	t.Run("an-unsubscribed-consumer-stops-receiving", func(t *testing.T) {
		e := NewEvents(4)
		sub := e.Subscribe()
		sub.Close()
		sub.Close() // idempotent: a stream can end from either side
		e.Publish(ContainerEvent{Container: "app"})
		select {
		case ev, ok := <-sub.C():
			if ok {
				t.Errorf("an unsubscribed consumer received %+v", ev)
			}
		default:
		}
	})

	t.Run("close-ends-every-subscription", func(t *testing.T) {
		e := NewEvents(4)
		sub := e.Subscribe()
		defer sub.Close()
		e.Close()
		select {
		case _, ok := <-sub.C():
			if ok {
				t.Error("a subscriber received an event after Close")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a subscriber did not see end-of-stream after Close; a host watching ContainerEvents would hang")
		}
	})
}

// TestExecHelpers pins the two exec facts a consumer can observe: what is refused
// before a fork, and how a signalled process's exit code is reported.
func TestExecHelpers(t *testing.T) {
	t.Run("rejects-what-must-not-be-forked", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			spec ExecSpec
		}{
			{"no-container", ExecSpec{Argv: []string{"/bin/sh"}}},
			// execve with no program is not a no-op, and upstream requires a
			// command; rejecting here makes the failure name itself.
			{"empty-argv", ExecSpec{Container: "app"}},
			{"empty-argv0", ExecSpec{Container: "app", Argv: []string{""}}},
			{"too-many-args", ExecSpec{Container: "app", Argv: make([]string, maxExecArgv+1)}},
			{"argv-too-large", ExecSpec{Container: "app", Argv: []string{"/bin/sh", strings.Repeat("x", maxExecArgBytes)}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := ValidateExec(tc.spec); !errors.Is(err, ErrExecInvalid) {
					t.Errorf("err = %v, want ErrExecInvalid", err)
				}
			})
		}
	})

	t.Run("accepts-an-ordinary-command", func(t *testing.T) {
		if err := ValidateExec(ExecSpec{Container: "app", Argv: []string{"/bin/sh", "-c", "echo hi"}}); err != nil {
			t.Errorf("ValidateExec: %v", err)
		}
	})

	t.Run("a-signalled-process-exits-128-plus-n", func(t *testing.T) {
		// The same convention the host-process path uses. A
		// `kubectl exec … ; echo $?` must not report a different number depending
		// on whether the pod was a host process or a guest.
		for _, tc := range []struct {
			sig  int
			want int32
		}{
			{0, 0},
			{-1, 0},
			{9, 137},  // SIGKILL, the one an operator reads by sight
			{15, 143}, // SIGTERM
		} {
			if got := ExitCodeForSignal(tc.sig); got != tc.want {
				t.Errorf("ExitCodeForSignal(%d) = %d, want %d", tc.sig, got, tc.want)
			}
		}
	})
}

// TestPodIDFromCmdline pins how the guest learns the identity it asserts every
// request against — the workaround for guest/v1's GuestSpec carrying no pod_id.
func TestPodIDFromCmdline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmdline string
		want    string
		wantErr error
	}{
		{
			name:    "plain",
			cmdline: "console=hvc0 quiet " + PodIDCmdlineKey + "=abc-123",
			want:    "abc-123",
		},
		{
			name:    "only-parameter",
			cmdline: PodIDCmdlineKey + "=abc-123\n",
			want:    "abc-123",
		},
		{
			// The kernel's own rule for a repeated parameter is last-wins, so a
			// reader that took the first would disagree with the kernel about
			// which value actually took effect.
			name:    "repeated-takes-the-last",
			cmdline: PodIDCmdlineKey + "=first " + PodIDCmdlineKey + "=second",
			want:    "second",
		},
		{
			name:    "absent",
			cmdline: "console=hvc0 quiet",
			wantErr: ErrPodIDAbsent,
		},
		{
			name:    "empty-value-is-an-absence",
			cmdline: PodIDCmdlineKey + "=",
			wantErr: ErrPodIDAbsent,
		},
		{
			// A prefix match would accept this and adopt a wrong identity.
			name:    "a-longer-key-is-not-this-key",
			cmdline: PodIDCmdlineKey + "_extra=abc",
			wantErr: ErrPodIDAbsent,
		},
		{
			name:    "empty-cmdline",
			cmdline: "",
			wantErr: ErrPodIDAbsent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PodIDFromCmdline(tc.cmdline)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("PodIDFromCmdline: %v", err)
			}
			if got != tc.want {
				t.Errorf("pod id = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("rejects-a-malformed-id", func(t *testing.T) {
		// A malformed id would be compared against every incoming pod_id, turning
		// a boot-time typo into a pod that can never be reached.
		if _, err := PodIDFromCmdline(PodIDCmdlineKey + "=" + strings.Repeat("p", 254)); err == nil {
			t.Error("an over-length pod id was accepted")
		}
	})
}
