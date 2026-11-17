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

package sysvipc

import (
	"context"
	"errors"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// semBuf is struct sembuf (sem_num, sem_op, sem_flg).
type semBuf struct {
	num uint16
	op  int16
	flg int16
}

// TestStatReadsUseAndIdentity measures, on the real kernel, the fields the
// sweeper decides on: a fresh object reads unused with this uid as owner and
// creator, and a used one reads used. It creates two objects and removes them.
func TestStatReadsUseAndIdentity(t *testing.T) {
	uid := uint32(os.Geteuid())
	shm, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|0o600)
	if err != nil {
		t.Fatalf("shmget: %v", err)
	}
	semR, _, errno := unix.Syscall(unix.SYS_SEMGET, unix.IPC_PRIVATE, 1, unix.IPC_CREAT|0o600)
	if errno != 0 {
		_ = Remove(Ref{Shm, shm})
		t.Fatalf("semget: %v", errno)
	}
	sem := int(semR)
	rs, rm := Ref{Shm, shm}, Ref{Sem, sem}
	t.Cleanup(func() { _ = Remove(rs); _ = Remove(rm) })

	refs, err := List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(refs, rs) || !slices.Contains(refs, rm) {
		t.Fatalf("List lacks the test's objects %v, %v", rs, rm)
	}
	for _, r := range []Ref{rs, rm} {
		o, err := Stat(r)
		if err != nil {
			t.Fatal(err)
		}
		if o.UID != uid || o.CUID != uid || o.Used || o.Nattch != 0 || o.Waiters != 0 || o.Ctime.IsZero() {
			t.Errorf("fresh %s: %+v", r.Kind, o)
		}
		if r.Kind == Shm && o.CPID != os.Getpid() {
			t.Errorf("fresh segment's creator %d, want this process %d", o.CPID, os.Getpid())
		}
	}
	// A process blocked in semop has completed no operation, so the set
	// still reads unused; Waiters is what shows it.
	blocked := make(chan syscall.Errno, 1)
	go func() {
		down := semBuf{num: 0, op: -1}
		_, _, e := unix.Syscall(unix.SYS_SEMOP, uintptr(sem), uintptr(unsafe.Pointer(&down)), 1)
		blocked <- e
	}()
	// Poll by count, not by clock: each Stat is itself a few system calls, so
	// the bound is generous for a goroutine that only has to enter semop.
	var waiting Object
	for range 1_000_000 {
		if waiting, err = Stat(rm); err != nil || waiting.Waiters > 0 {
			break
		}
		runtime.Gosched()
	}
	if err != nil || waiting.Waiters != 1 || waiting.Used {
		t.Errorf("set with a blocked semop reads %+v, %v; want Waiters 1, not Used", waiting, err)
	}
	b, err := unix.SysvShmAttach(shm, 0, 0)
	if err != nil {
		t.Fatalf("shmat: %v", err)
	}
	if err := unix.SysvShmDetach(b); err != nil {
		t.Fatalf("shmdt: %v", err)
	}
	op := semBuf{num: 0, op: 1, flg: unix.IPC_NOWAIT}
	if _, _, errno := unix.Syscall(unix.SYS_SEMOP, uintptr(sem), uintptr(unsafe.Pointer(&op)), 1); errno != 0 {
		t.Fatalf("semop: %v", errno)
	}
	if e := <-blocked; e != 0 {
		t.Fatalf("the blocked semop: %v", e)
	}
	for _, r := range []Ref{rs, rm} {
		if o, err := Stat(r); err != nil || !o.Used {
			t.Errorf("used %s reads %+v, %v; want Used", r.Kind, o, err)
		}
	}
	if err := Remove(rs); err != nil {
		t.Fatal(err)
	}
	if _, err := Stat(rs); !errors.Is(err, ErrGone) {
		t.Errorf("removed segment: %v, want ErrGone", err)
	}
	if err := Remove(rs); !errors.Is(err, ErrGone) {
		t.Errorf("second remove: %v, want ErrGone", err)
	}
}
