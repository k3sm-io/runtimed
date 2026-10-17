//go:build darwin

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
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestVMHostControlRoundTrip drives the helper's control socket end to end: the
// answer the helper serves, and the kernel's peer pid the daemon reads beside
// it.
func TestVMHostControlRoundTrip(t *testing.T) {
	// A short directory: a unix socket path is capped near 104 bytes.
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, VMHostControlSocketName)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- ServeVMHostControl(lis, VMHostVersion{Protocol: 7, Pid: 4242}) }()

	ctx, cancel := context.WithTimeout(context.Background(), vmAdoptProbeTimeout)
	defer cancel()
	ans, err := dialVMHostVersion(ctx, socket)
	if err != nil {
		t.Fatalf("dialVMHostVersion: %v", err)
	}
	if ans.Protocol != 7 || ans.Pid != 4242 {
		t.Errorf("answer = %+v, want what the helper serves", ans.VMHostVersion)
	}
	if ans.PeerPid != os.Getpid() {
		t.Errorf("peer pid = %d, want the serving process %d (LOCAL_PEERPID)", ans.PeerPid, os.Getpid())
	}
	_ = lis.Close()
	if err := <-served; err != nil {
		t.Errorf("ServeVMHostControl after close = %v, want nil", err)
	}
	if _, err := dialVMHostVersion(ctx, socket); err == nil {
		t.Error("a closed control socket still answered")
	}
}

// TestWatchAdoptedHelperExit pins the adopted exit edge: it closes when the
// process exits, at once when the process is already gone or fails the
// identity check made after the watch is armed, and not at all on cancel.
func TestWatchAdoptedHelperExit(t *testing.T) {
	start := func(t *testing.T) *exec.Cmd {
		t.Helper()
		cmd := exec.Command("/bin/sleep", "30")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		return cmd
	}
	closedWithin := func(ch <-chan struct{}, d time.Duration) bool {
		select {
		case <-ch:
			return true
		case <-time.After(d):
			return false
		}
	}

	t.Run("the exit closes the edge", func(t *testing.T) {
		cmd := start(t)
		done, err := watchAdoptedHelperExit(context.Background(), cmd.Process.Pid, func() bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		if closedWithin(done, 50*time.Millisecond) {
			t.Fatal("the edge closed for a live process")
		}
		_ = cmd.Process.Kill()
		if !closedWithin(done, 5*time.Second) {
			t.Fatal("the edge never closed after the process exited")
		}
	})
	t.Run("a failed identity check after arming reads as exited", func(t *testing.T) {
		cmd := start(t)
		done, err := watchAdoptedHelperExit(context.Background(), cmd.Process.Pid, func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if !closedWithin(done, time.Second) {
			t.Fatal("a process that is not the recorded instance was watched as if it were")
		}
	})
	t.Run("a process already gone reads as exited", func(t *testing.T) {
		cmd := start(t)
		pid := cmd.Process.Pid
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		done, err := watchAdoptedHelperExit(context.Background(), pid, func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if !closedWithin(done, time.Second) {
			t.Fatal("a reaped pid was watched as live")
		}
	})
	t.Run("cancel ends the watch without claiming an exit", func(t *testing.T) {
		cmd := start(t)
		ctx, cancel := context.WithCancel(context.Background())
		done, err := watchAdoptedHelperExit(ctx, cmd.Process.Pid, func() bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if closedWithin(done, 200*time.Millisecond) {
			t.Fatal("a cancelled watch closed the edge; nothing exited")
		}
	})
}
