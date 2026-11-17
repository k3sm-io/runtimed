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

package runtime

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/sysvipc"
)

// sysvHelperEnv makes TestSysVSweepHelperProcess, re-run as a child, create
// one segment, print its id and exit, so the segment's creator is a pid that is
// gone by the time the sweep runs: the shape a pod's leaked segment has once
// the pod's process exits.
const sysvHelperEnv = "K3SM_SYSV_SWEEP_HELPER"

func TestSysVSweepHelperProcess(t *testing.T) {
	if os.Getenv(sysvHelperEnv) != "1" {
		t.Skip("helper process for TestSysVSweepRealKernel")
	}
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|0o600)
	if err != nil {
		os.Exit(3)
	}
	os.Stdout.WriteString("SHMID=" + strconv.Itoa(id) + "\n")
	os.Exit(0)
}

// TestSysVSweepRealKernel runs the sweeper end to end against the real kernel
// seams (List, Stat, Remove, getsid), with this process's uid as the swept uid
// and no grace period. It removes exactly the objects a pod could leave and
// keeps every in-use shape beside them. The list is restricted to the objects
// this test made, so nothing else on the host is ever a candidate.
func TestSysVSweepRealKernel(t *testing.T) {
	semget := func() int {
		t.Helper()
		r, _, e := unix.Syscall(unix.SYS_SEMGET, unix.IPC_PRIVATE, 1, unix.IPC_CREAT|0o600)
		if e != 0 {
			t.Fatalf("semget: %v", e)
		}
		return int(r)
	}
	var mine []sysvipc.Ref
	track := func(r sysvipc.Ref) sysvipc.Ref {
		mine = append(mine, r)
		t.Cleanup(func() { _ = sysvipc.Remove(r) })
		return r
	}

	// What a pod leaves: an untouched set, and a segment whose creator is gone.
	leakSet := track(sysvipc.Ref{Kind: sysvipc.Sem, ID: semget()})
	cmd := exec.Command(os.Args[0], "-test.run=^TestSysVSweepHelperProcess$")
	cmd.Env = append(os.Environ(), sysvHelperEnv+"=1")
	out, err := cmd.Output()
	idS, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "SHMID=")
	if !ok {
		t.Fatalf("helper: %v, %q", err, out)
	}
	shmID, err := strconv.Atoi(strings.Fields(idS)[0])
	if err != nil {
		t.Fatalf("helper id %q: %v", idS, err)
	}
	leakSeg := track(sysvipc.Ref{Kind: sysvipc.Shm, ID: shmID})

	// What a live user holds: a set initialised with SETVAL and left idle, a
	// set operated on, and a segment whose creator (this process) is alive
	// outside every pod.
	setval := track(sysvipc.Ref{Kind: sysvipc.Sem, ID: semget()})
	if _, _, e := unix.Syscall6(unix.SYS_SEMCTL, uintptr(setval.ID), 0, 8 /* SETVAL */, 1, 0, 0); e != 0 {
		t.Fatalf("semctl SETVAL: %v", e)
	}
	operated := track(sysvipc.Ref{Kind: sysvipc.Sem, ID: semget()})
	up := struct{ num, op, flg int16 }{0, 1, unix.IPC_NOWAIT}
	if _, _, e := unix.Syscall(unix.SYS_SEMOP, uintptr(operated.ID), uintptr(unsafe.Pointer(&up)), 1); e != 0 {
		t.Fatalf("semop: %v", e)
	}
	liveSeg, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|0o600)
	if err != nil {
		t.Fatalf("shmget: %v", err)
	}
	liveCreator := track(sysvipc.Ref{Kind: sysvipc.Shm, ID: liveSeg})

	s := &sysvSweeper{
		uid:   uint32(os.Geteuid()),
		grace: 0,
		now:   func() time.Time { return time.Now().Add(time.Second) },
		list: func(ctx context.Context) ([]sysvipc.Ref, error) {
			all, err := sysvipc.List(ctx)
			if err != nil {
				return nil, err
			}
			return slices.DeleteFunc(all, func(r sysvipc.Ref) bool { return !slices.Contains(mine, r) }), nil
		},
		stat:     sysvipc.Stat,
		remove:   sysvipc.Remove,
		sessions: func() map[int]bool { return map[int]bool{} },
		sidOf:    unix.Getsid,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	var removed []sysvipc.Ref
	for _, o := range s.sweepOnce(context.Background()) {
		removed = append(removed, o.Ref)
	}
	for _, c := range []struct {
		name string
		ref  sysvipc.Ref
		gone bool
	}{
		{"an untouched semaphore set", leakSet, true},
		{"a segment whose creator exited", leakSeg, true},
		{"a set initialised with SETVAL and left idle", setval, false},
		{"a set operated on", operated, false},
		{"a segment whose creator is alive outside every pod", liveCreator, false},
	} {
		if got := slices.Contains(removed, c.ref); got != c.gone {
			t.Errorf("%s (%s %d): removed=%v, want %v", c.name, c.ref.Kind, c.ref.ID, got, c.gone)
		}
		if _, err := sysvipc.Stat(c.ref); (err != nil) != c.gone {
			t.Errorf("%s (%s %d): after the sweep stat err=%v, want gone=%v", c.name, c.ref.Kind, c.ref.ID, err, c.gone)
		}
	}
}
