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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/sysvipc"
)

const (
	sweepUID = 279 // the service account's uid in these fakes
	otherUID = 501
	podSID   = 4000
	hostPID  = 777 // a live process outside every pod
	podPID   = 4001
	deadPID  = 9999
	// unknownPID is a creator getsid answers EPERM for: liveness unknown.
	unknownPID = 5555
	sweepNowS  = 1_800_000_000
)

// fakeIPC is an in-memory host table. stats counts IPC_STAT calls per id, and
// mutate, when set, runs after the first stat of an id (to model a change
// between the verdict and the re-read).
type fakeIPC struct {
	objs    map[sysvipc.Ref]sysvipc.Object
	removed []sysvipc.Ref
	stats   map[sysvipc.Ref]int
	mutate  func(r sysvipc.Ref, o *sysvipc.Object)
}

func (f *fakeIPC) sweeper() *sysvSweeper {
	now := time.Unix(sweepNowS, 0)
	return &sysvSweeper{
		uid:   sweepUID,
		grace: sysvSweepGrace,
		now:   func() time.Time { return now },
		list: func(context.Context) ([]sysvipc.Ref, error) {
			var refs []sysvipc.Ref
			for r := range f.objs {
				refs = append(refs, r)
			}
			return refs, nil
		},
		stat: func(r sysvipc.Ref) (sysvipc.Object, error) {
			o, ok := f.objs[r]
			if !ok {
				return sysvipc.Object{}, sysvipc.ErrGone
			}
			f.stats[r]++
			if f.stats[r] == 1 && f.mutate != nil {
				c := o
				f.mutate(r, &c)
				f.objs[r] = c
			}
			return o, nil
		},
		remove: func(r sysvipc.Ref) error {
			delete(f.objs, r)
			f.removed = append(f.removed, r)
			return nil
		},
		sessions: func() map[int]bool { return map[int]bool{podSID: true} },
		sidOf: func(pid int) (int, error) {
			switch pid {
			case hostPID:
				return 1, nil
			case podPID:
				return podSID, nil
			case unknownPID:
				return 0, unix.EPERM
			}
			return 0, unix.ESRCH
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// leak is an object exactly as a pod leaves one: the service account's,
// never used, created well before the grace period.
func leak(kind sysvipc.Kind, id int) sysvipc.Object {
	o := sysvipc.Object{Ref: sysvipc.Ref{Kind: kind, ID: id}, Key: 0, UID: sweepUID, CUID: sweepUID,
		Ctime: time.Unix(sweepNowS, 0).Add(-10 * time.Minute)}
	if kind == sysvipc.Shm {
		o.CPID = deadPID
	}
	return o
}

func TestSysVSweepVerdicts(t *testing.T) {
	young := leak(sysvipc.Shm, 1)
	young.Ctime = time.Unix(sweepNowS, 0).Add(-sysvSweepGrace + time.Second)
	for _, tc := range []struct {
		name   string
		obj    func() sysvipc.Object
		remove bool
	}{
		{"a pod's unused segment, creator gone", func() sysvipc.Object { return leak(sysvipc.Shm, 1) }, true},
		{"a pod's unused semaphore set", func() sysvipc.Object { return leak(sysvipc.Sem, 2) }, true},
		{"an unused message queue: reported, never removed", func() sysvipc.Object { return leak(sysvipc.Msg, 3) }, false},
		{"a semaphore set a process is blocked on", func() sysvipc.Object {
			o := leak(sysvipc.Sem, 11)
			o.Waiters = 1
			return o
		}, false},
		{"a segment whose creator's liveness is unknown (not ESRCH)", func() sysvipc.Object {
			o := leak(sysvipc.Shm, 12)
			o.CPID = unknownPID
			return o
		}, false},
		{"a segment whose creator is still a live pod process", func() sysvipc.Object {
			o := leak(sysvipc.Shm, 4)
			o.CPID = podPID
			return o
		}, true},
		{"another user's object", func() sysvipc.Object {
			o := leak(sysvipc.Shm, 5)
			o.UID, o.CUID = otherUID, otherUID
			return o
		}, false},
		{"owned by the service account but created by another user", func() sysvipc.Object {
			o := leak(sysvipc.Sem, 6)
			o.CUID = otherUID
			return o
		}, false},
		{"a root object", func() sysvipc.Object {
			o := leak(sysvipc.Shm, 7)
			o.UID, o.CUID = 0, 0
			return o
		}, false},
		{"an attached segment", func() sysvipc.Object {
			o := leak(sysvipc.Shm, 8)
			o.Nattch = 1
			return o
		}, false},
		{"a used semaphore set", func() sysvipc.Object {
			o := leak(sysvipc.Sem, 9)
			o.Used = true
			return o
		}, false},
		{"an object inside the grace period", func() sysvipc.Object { return young }, false},
		{"a segment whose creator is a live non-pod process", func() sysvipc.Object {
			o := leak(sysvipc.Shm, 10)
			o.CPID = hostPID
			return o
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.obj()
			f := &fakeIPC{objs: map[sysvipc.Ref]sysvipc.Object{o.Ref: o}, stats: map[sysvipc.Ref]int{}}
			got := f.sweeper().sweepOnce(context.Background())
			if (len(got) == 1) != tc.remove || (len(f.removed) == 1) != tc.remove {
				t.Errorf("removed %v, want removal=%v", f.removed, tc.remove)
			}
		})
	}
}

// TestSysVSweepRereadsBeforeRemove pins the id-reuse guard: an object whose
// identity or state changed between the verdict and the re-read is kept.
func TestSysVSweepRereadsBeforeRemove(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(sysvipc.Ref, *sysvipc.Object)
	}{
		{"the id now names a new object (ctime)", func(_ sysvipc.Ref, o *sysvipc.Object) { o.Ctime = o.Ctime.Add(time.Hour) }},
		{"the id now names a new object (key)", func(_ sysvipc.Ref, o *sysvipc.Object) { o.Key = 42 }},
		{"it was attached meanwhile", func(_ sysvipc.Ref, o *sysvipc.Object) { o.Nattch = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := leak(sysvipc.Shm, 1)
			f := &fakeIPC{objs: map[sysvipc.Ref]sysvipc.Object{o.Ref: o}, stats: map[sysvipc.Ref]int{}, mutate: tc.mutate}
			f.sweeper().sweepOnce(context.Background())
			if len(f.removed) != 0 {
				t.Errorf("removed %v after a change between the two reads", f.removed)
			}
		})
	}
}

// TestSysVSweepReportsAKeptQueueOnce pins rule 5's report: a queue a pod may
// have left is logged once, not every scan, and again only if the id is reused.
func TestSysVSweepReportsAKeptQueueOnce(t *testing.T) {
	var buf bytes.Buffer
	o := leak(sysvipc.Msg, 3)
	f := &fakeIPC{objs: map[sysvipc.Ref]sysvipc.Object{o.Ref: o}, stats: map[sysvipc.Ref]int{}}
	s := f.sweeper()
	s.log = slog.New(slog.NewTextHandler(&buf, nil))
	s.sweepOnce(context.Background())
	s.sweepOnce(context.Background())
	if n := strings.Count(buf.String(), "kept an unused System V message queue"); n != 1 {
		t.Fatalf("queue reported %d times over two scans, want 1:\n%s", n, buf.String())
	}
	o.Ctime = o.Ctime.Add(time.Second)
	f.objs[o.Ref] = o
	s.sweepOnce(context.Background())
	if n := strings.Count(buf.String(), "kept an unused System V message queue"); n != 2 {
		t.Errorf("a reused queue id reported %d times in all, want 2", n)
	}
	if len(f.removed) != 0 {
		t.Errorf("removed %v; a queue is never removed", f.removed)
	}
}

func TestSysVSweepListFailureRemovesNothing(t *testing.T) {
	f := &fakeIPC{objs: map[sysvipc.Ref]sysvipc.Object{}, stats: map[sysvipc.Ref]int{}}
	s := f.sweeper()
	s.list = func(context.Context) ([]sysvipc.Ref, error) { return nil, errors.New("ipcs failed") }
	if got := s.sweepOnce(context.Background()); len(got) != 0 {
		t.Errorf("a failed list removed %v", got)
	}
}

func TestSysVSweepEligibleUser(t *testing.T) {
	for _, tc := range []struct {
		uid  uint32
		name string
		want bool
	}{
		{279, "_k3sm", true},
		{0, "_k3sm", false},
		{0, "root", false},
		{501, "miko", false},
		{279, "_k3smx", false},
	} {
		if got := sysvSweepEligibleUser(tc.uid, tc.name); got != tc.want {
			t.Errorf("sysvSweepEligibleUser(%d, %q) = %v, want %v", tc.uid, tc.name, got, tc.want)
		}
	}
}
