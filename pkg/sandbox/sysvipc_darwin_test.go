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

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"k3sm.io/runtimed/pkg/sysvipc"
)

// TestNativePodSysVIPCIsConsistent is the B1788 gate. It applies a pod's REAL
// generated profile to a helper (sandbox_init in the child) and measures System
// V IPC and POSIX shared memory there, with and without the path-rebase shim:
//
//   - the profile grants no ipc-sysv operation and no ipc-posix-shm (static);
//   - with the shim, shmget, semget and msgget fail with ENOSYS and create
//     nothing, so create and use agree: neither works;
//   - without the shim, the kernel still lets the create calls through (the
//     ceiling the profile cannot close), every use of the object is EPERM, and
//     the object is exactly what the runtime's sweeper removes: owned and
//     created by this uid, never used, nothing attached. The test removes it
//     with the sweeper's own seam (sysvipc.Remove) and checks it is gone;
//   - shm_open is EPERM on both paths.
//
// Red before B1788: the shim let the creates through, so the shimmed path
// created an object nothing in the pod could ever remove.
func TestNativePodSysVIPCIsConsistent(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("SKIP: clang not on PATH, the SysV helper cannot be built: %v", err)
	}
	helper := filepath.Join(t.TempDir(), "sysvhelper")
	if out, err := exec.Command(clang, "-o", helper, filepath.Join("testdata", "sysvhelper.c")).CombinedOutput(); err != nil {
		t.Fatalf("build sysvhelper: %v\n%s", err, out)
	}
	shim := buildSemTestShim(t)
	prof, prefix := semPodProfile(t, randomPodUID(t))
	for _, op := range []string{"ipc-sysv", "ipc-posix-shm"} {
		if strings.Contains(prof, op) {
			t.Fatalf("the generated pod profile mentions %s; it must grant neither", op)
		}
	}
	pf := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(pf, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	shmName := prefix + "shm" + randomHex(t, 3)

	run := func(env ...string) map[string]string {
		t.Helper()
		cmd := exec.Command(helper, pf, shmName)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sysvhelper: %v\n%s", err, out)
		}
		res := map[string]string{}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if op, r, ok := strings.Cut(l, " "); ok {
				res[op] = r
			}
		}
		return res
	}
	errno := func(e syscall.Errno) string { return "err " + strconv.Itoa(int(e)) }

	t.Run("with the shim, create is refused and nothing is left", func(t *testing.T) {
		res := run("DYLD_INSERT_LIBRARIES="+shim, "K3SM_SEM_PREFIX="+prefix)
		for _, op := range []string{"shmget", "semget", "msgget"} {
			if res[op] != errno(syscall.ENOSYS) {
				t.Errorf("%s under the shim: %q, want %q (ENOSYS)", op, res[op], errno(syscall.ENOSYS))
			}
			if id, ok := strings.CutPrefix(res[op], "id "); ok {
				t.Cleanup(func() { removeOwn(t, op, id) })
			}
		}
		if res["shm_open"] != errno(syscall.EPERM) {
			t.Errorf("shm_open under the shim: %q, want EPERM", res["shm_open"])
		}
	})

	t.Run("without the shim, create gets through but every use is EPERM and the sweeper's seam removes it", func(t *testing.T) {
		res := run()
		for _, c := range []struct {
			create string
			kind   sysvipc.Kind
			uses   []string
		}{
			{"shmget", sysvipc.Shm, []string{"shmat", "shmctl-stat", "shmctl-rmid"}},
			{"semget", sysvipc.Sem, []string{"semop", "semctl-rmid"}},
			{"msgget", sysvipc.Msg, []string{"msgctl-rmid"}},
		} {
			idS, ok := strings.CutPrefix(res[c.create], "id ")
			if !ok {
				t.Errorf("%s without the shim: %q; the kernel ceiling changed (create no longer gets through)", c.create, res[c.create])
				continue
			}
			id, _ := strconv.Atoi(idS)
			ref := sysvipc.Ref{Kind: c.kind, ID: id}
			t.Cleanup(func() { _ = sysvipc.Remove(ref) })
			for _, u := range c.uses {
				if res[u] != errno(syscall.EPERM) {
					t.Errorf("%s on the pod's own %s: %q, want EPERM", u, c.kind, res[u])
				}
			}
			o, err := sysvipc.Stat(ref)
			if err != nil {
				t.Fatalf("stat the pod's %s %d unconfined: %v", c.kind, id, err)
			}
			uid := uint32(os.Geteuid())
			if o.UID != uid || o.CUID != uid || o.Nattch != 0 || o.Used {
				t.Errorf("the pod's %s %d is %+v; the sweeper keys on owner=creator=%d, unused, unattached", c.kind, id, o, uid)
			}
			if c.kind == sysvipc.Shm && o.CPID <= 0 {
				t.Errorf("the pod's segment records no creator pid: %+v", o)
			}
			if err := sysvipc.Remove(ref); err != nil {
				t.Fatalf("remove the pod's %s %d: %v", c.kind, id, err)
			}
			if _, err := sysvipc.Stat(ref); !errors.Is(err, sysvipc.ErrGone) {
				t.Errorf("the pod's %s %d survived its removal: %v", c.kind, id, err)
			}
		}
		if res["shm_open"] != errno(syscall.EPERM) {
			t.Errorf("shm_open without the shim: %q, want EPERM", res["shm_open"])
		}
	})
}

// removeOwn removes an object a failing case left, so a red run leaks nothing.
func removeOwn(t *testing.T, op, id string) {
	t.Helper()
	n, err := strconv.Atoi(id)
	if err != nil {
		return
	}
	kind := map[string]sysvipc.Kind{"shmget": sysvipc.Shm, "semget": sysvipc.Sem, "msgget": sysvipc.Msg}[op]
	_ = sysvipc.Remove(sysvipc.Ref{Kind: kind, ID: n})
}
