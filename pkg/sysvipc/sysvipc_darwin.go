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

/*
#include <errno.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <unistd.h>

// k3sm_ipc_stat is the flat view of one object that IPC_STAT returns. The
// wrappers below fill it so Go never touches the three kernel structs or the
// variadic semctl.
typedef struct {
	long long key;
	unsigned int uid, cuid;
	int cpid, nattch, used, waiters;
	long long ctime;
} k3sm_ipc_stat;

static int k3sm_shm_stat(int id, k3sm_ipc_stat *out) {
	struct shmid_ds ds;
	if (shmctl(id, IPC_STAT, &ds) != 0) {
		return errno;
	}
	out->key = (long long)ds.shm_perm._key;
	out->uid = ds.shm_perm.uid;
	out->cuid = ds.shm_perm.cuid;
	out->cpid = ds.shm_cpid;
	out->nattch = (int)ds.shm_nattch;
	out->used = ds.shm_atime != 0 || ds.shm_dtime != 0;
	out->ctime = (long long)ds.shm_ctime;
	out->waiters = 0;
	return 0;
}

static int k3sm_sem_stat(int id, k3sm_ipc_stat *out) {
	struct semid_ds ds;
	union semun arg;
	arg.buf = &ds;
	if (semctl(id, 0, IPC_STAT, arg) != 0) {
		return errno;
	}
	out->key = (long long)ds.sem_perm._key;
	out->uid = ds.sem_perm.uid;
	out->cuid = ds.sem_perm.cuid;
	out->cpid = 0;
	out->nattch = 0;
	out->used = ds.sem_otime != 0;
	out->ctime = (long long)ds.sem_ctime;
	// A process blocked in semop has not completed an operation, so sem_otime
	// is still 0; the per-semaphore wait counts are what show it. A set that
	// was initialised with SETVAL or SETALL also leaves sem_otime 0, so any
	// nonzero value counts as use: a pod can do neither, so a set a pod left
	// always reads all zero.
	out->waiters = 0;
	// The per-semaphore reads cost three calls per semaphore (a set may hold
	// tens of thousands), so they run only for a set that could still be a
	// removal candidate: never operated on, and this process's own. For any
	// other set the values and waiters decide nothing.
	if (out->used || out->uid != geteuid() || out->cuid != geteuid()) {
		return 0;
	}
	for (int i = 0; i < (int)ds.sem_nsems; i++) {
		int v = semctl(id, i, GETVAL);
		if (v < 0) {
			return errno;
		}
		if (v != 0) {
			out->used = 1;
		}
		int n = semctl(id, i, GETNCNT);
		if (n < 0) {
			return errno;
		}
		int z = semctl(id, i, GETZCNT);
		if (z < 0) {
			return errno;
		}
		out->waiters += n + z;
	}
	return 0;
}

static int k3sm_msg_stat(int id, k3sm_ipc_stat *out) {
	struct msqid_ds ds;
	if (msgctl(id, IPC_STAT, &ds) != 0) {
		return errno;
	}
	out->key = (long long)ds.msg_perm._key;
	out->uid = ds.msg_perm.uid;
	out->cuid = ds.msg_perm.cuid;
	out->cpid = 0;
	out->nattch = 0;
	out->used = ds.msg_stime != 0 || ds.msg_rtime != 0 || ds.msg_qnum != 0;
	out->ctime = (long long)ds.msg_ctime;
	out->waiters = 0;
	return 0;
}

static int k3sm_shm_rmid(int id) { return shmctl(id, IPC_RMID, NULL) == 0 ? 0 : errno; }
static int k3sm_sem_rmid(int id) { return semctl(id, 0, IPC_RMID) == 0 ? 0 : errno; }
static int k3sm_msg_rmid(int id) { return msgctl(id, IPC_RMID, NULL) == 0 ? 0 : errno; }
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// ipcsPath is the system ipcs; an absolute path, so no PATH entry decides it.
const ipcsPath = "/usr/bin/ipcs"

// List returns every System V IPC object on the host, by class and id.
func List(ctx context.Context) ([]Ref, error) {
	cmd := exec.CommandContext(ctx, ipcsPath, "-m", "-s", "-q")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sysvipc: %s: %w", ipcsPath, err)
	}
	return parseIpcs(out)
}

// Stat reads r with IPC_STAT. ErrGone means r names no live object.
func Stat(r Ref) (Object, error) {
	var st C.k3sm_ipc_stat
	var rc C.int
	switch r.Kind {
	case Shm:
		rc = C.k3sm_shm_stat(C.int(r.ID), &st)
	case Sem:
		rc = C.k3sm_sem_stat(C.int(r.ID), &st)
	case Msg:
		rc = C.k3sm_msg_stat(C.int(r.ID), &st)
	default:
		return Object{}, fmt.Errorf("sysvipc: unknown kind %d", r.Kind)
	}
	if err := errnoErr(rc); err != nil {
		return Object{}, fmt.Errorf("sysvipc: stat %s %d: %w", r.Kind, r.ID, err)
	}
	return Object{
		Ref:     r,
		Key:     int64(st.key),
		UID:     uint32(st.uid),
		CUID:    uint32(st.cuid),
		CPID:    int(st.cpid),
		Nattch:  int(st.nattch),
		Used:    st.used != 0,
		Waiters: int(st.waiters),
		Ctime:   time.Unix(int64(st.ctime), 0),
	}, nil
}

// Remove removes r with IPC_RMID. ErrGone means it was already gone.
func Remove(r Ref) error {
	var rc C.int
	switch r.Kind {
	case Shm:
		rc = C.k3sm_shm_rmid(C.int(r.ID))
	case Sem:
		rc = C.k3sm_sem_rmid(C.int(r.ID))
	case Msg:
		rc = C.k3sm_msg_rmid(C.int(r.ID))
	default:
		return fmt.Errorf("sysvipc: unknown kind %d", r.Kind)
	}
	if err := errnoErr(rc); err != nil {
		return fmt.Errorf("sysvipc: remove %s %d: %w", r.Kind, r.ID, err)
	}
	return nil
}

// errnoErr maps a wrapper's errno to an error; EINVAL and EIDRM become
// ErrGone alongside the errno.
func errnoErr(rc C.int) error {
	if rc == 0 {
		return nil
	}
	e := syscall.Errno(rc)
	if e == syscall.EINVAL || e == syscall.EIDRM {
		return errors.Join(ErrGone, e)
	}
	return e
}
