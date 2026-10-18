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
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// TestDialVMHostVersionSurvivesAnEarlyClose pins adoption's version call
// against a helper that writes its version line and closes at once: the
// kernel's peer pid can then be gone before it is read (ENOTCONN), and that
// must not refuse a healthy helper. The retry never weakens the identity rule:
// every answer carries a pid the kernel named, a helper that closes first on
// every attempt is still refused, and a gone one is refused without a retry.
func TestDialVMHostVersionSurvivesAnEarlyClose(t *testing.T) {
	listen := func(t *testing.T) (net.Listener, string) {
		t.Helper()
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
		t.Cleanup(func() { _ = lis.Close() })
		return lis, socket
	}
	banner := []byte(`{"protocol":7,"pid":4242}` + "\n")
	// serve answers each connection with the banner; the first earlyCloses
	// connections are closed at once and reported on closed, every later one
	// is held until the client closes it, as k3sm-vmhost does.
	serve := func(lis net.Listener, earlyCloses int, closed chan<- struct{}, accepted *atomic.Int32) {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			n := int(accepted.Add(1))
			_, _ = conn.Write(banner)
			if n <= earlyCloses {
				_ = conn.Close()
				closed <- struct{}{}
				continue
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}
	// afterClose reads the peer only once the helper has closed the
	// connection, for as many connections as the helper closes early.
	afterClose := func(closed <-chan struct{}, early int) func(net.Conn) (int, error) {
		var reads atomic.Int32
		return func(conn net.Conn) (int, error) {
			if int(reads.Add(1)) <= early {
				<-closed
			}
			return controlPeerPid(conn)
		}
	}
	probeCtx := func(t *testing.T) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), vmAdoptProbeTimeout)
		t.Cleanup(cancel)
		return ctx
	}

	t.Run("a banner-and-close helper answers every call with the kernel's peer", func(t *testing.T) {
		lis, socket := listen(t)
		go func() { _ = ServeVMHostControl(lis, VMHostVersion{Protocol: 7, Pid: 4242}) }()
		for i := range 50 {
			ans, err := dialVMHostVersion(probeCtx(t), socket)
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
			if ans.PeerPid != os.Getpid() || ans.Pid != 4242 {
				t.Fatalf("call %d: answer %+v, want peer %d (LOCAL_PEERPID) saying pid 4242", i, ans, os.Getpid())
			}
		}
	})
	t.Run("an early close is dialled again and the answer names the kernel's peer", func(t *testing.T) {
		lis, socket := listen(t)
		const early = vmAdoptPeerAttempts - 1
		closed := make(chan struct{}, vmAdoptPeerAttempts)
		var accepted atomic.Int32
		go serve(lis, early, closed, &accepted)
		ans, err := dialVMHostVersionWith(probeCtx(t), socket, afterClose(closed, early))
		if err != nil {
			t.Fatalf("a helper that closed first %d times was refused: %v", early, err)
		}
		if ans.PeerPid != os.Getpid() || ans.Pid != 4242 || ans.Protocol != 7 {
			t.Errorf("answer = %+v, want peer %d saying protocol 7, pid 4242", ans, os.Getpid())
		}
		if got := accepted.Load(); got != vmAdoptPeerAttempts {
			t.Errorf("connections = %d, want %d", got, vmAdoptPeerAttempts)
		}
	})
	t.Run("a helper that closes first on every attempt is refused", func(t *testing.T) {
		lis, socket := listen(t)
		closed := make(chan struct{}, vmAdoptPeerAttempts+1)
		var accepted atomic.Int32
		go serve(lis, vmAdoptPeerAttempts+1, closed, &accepted)
		ans, err := dialVMHostVersionWith(probeCtx(t), socket, afterClose(closed, vmAdoptPeerAttempts+1))
		if err == nil {
			t.Fatalf("answer %+v accepted from a peer the kernel never named", ans)
		}
		if !errors.Is(err, errVMHostPeerGone) || !errors.Is(err, unix.ENOTCONN) {
			t.Errorf("err = %v, want the peer-gone ENOTCONN", err)
		}
		if got := accepted.Load(); got != vmAdoptPeerAttempts {
			t.Errorf("connections = %d, want the bound %d", got, vmAdoptPeerAttempts)
		}
	})
	t.Run("a gone helper is refused without a retry", func(t *testing.T) {
		lis, socket := listen(t)
		_ = lis.Close()
		_, err := dialVMHostVersion(probeCtx(t), socket)
		if err == nil {
			t.Fatal("a socket with no helper behind it answered")
		}
		if errors.Is(err, errVMHostPeerGone) {
			t.Errorf("err = %v, a dial failure is not a peer that closed first", err)
		}
	})
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
		done, err := watchAdoptedHelperExit(context.Background(), cmd.Process.Pid, func() bool { return true }, nil)
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
		done, err := watchAdoptedHelperExit(context.Background(), cmd.Process.Pid, func() bool { return false }, nil)
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
		done, err := watchAdoptedHelperExit(context.Background(), pid, func() bool { return false }, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !closedWithin(done, time.Second) {
			t.Fatal("a reaped pid was watched as live")
		}
	})
	t.Run("a failed kevent wait is not an exit: the identity is polled until it is gone", func(t *testing.T) {
		wait, interval := adoptedExitWait, adoptedExitPollInterval
		adoptedExitWait = func(int, []unix.Kevent_t) (int, error) { return 0, unix.EBADF }
		adoptedExitPollInterval = 10 * time.Millisecond
		t.Cleanup(func() { adoptedExitWait, adoptedExitPollInterval = wait, interval })

		cmd := start(t)
		var alive atomic.Bool
		alive.Store(true)
		done, err := watchAdoptedHelperExit(context.Background(), cmd.Process.Pid, alive.Load, nil)
		if err != nil {
			t.Fatal(err)
		}
		if closedWithin(done, 200*time.Millisecond) {
			t.Fatal("a broken kevent wait closed the edge while the recorded instance was alive")
		}
		alive.Store(false)
		if !closedWithin(done, 2*time.Second) {
			t.Fatal("the poll never closed the edge once the recorded instance was gone")
		}
	})
	t.Run("cancel ends the watch without claiming an exit", func(t *testing.T) {
		cmd := start(t)
		ctx, cancel := context.WithCancel(context.Background())
		done, err := watchAdoptedHelperExit(ctx, cmd.Process.Pid, func() bool { return true }, nil)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if closedWithin(done, 200*time.Millisecond) {
			t.Fatal("a cancelled watch closed the edge; nothing exited")
		}
	})
}
