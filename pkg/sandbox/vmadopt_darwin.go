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
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// adoptCancelIdent is the EVFILT_USER ident the adopted-exit watch registers
// for its cancellation wakeup; idents are per (kqueue, filter), so it cannot
// collide with the EVFILT_PROC registration, whose ident is the pid.
const adoptCancelIdent = 1

// watchAdoptedHelperExit returns an edge closed when pid exits, for a helper
// this daemon did not spawn (so there is no wait4 to collect it, and no status
// to report).
//
// REGISTER, THEN VERIFY. EVFILT_PROC/NOTE_EXIT is armed first and verify — the
// recorded-identity check — runs after it. Verifying first would leave a window
// in which the helper exits and its pid is recycled before the registration,
// and the watch would then follow an unrelated process. With the order
// reversed, a registration that lands on a recycled pid fails verify, and ESRCH
// at registration means the helper is already gone; both close the edge at
// once: the helper is treated as exited, status unknown.
//
// The watch ends on the exit, or silently on ctx (DetachVMs, or an adoption
// that was refused after the watch was armed): a cancelled watch does not
// close the edge, because nothing exited.
func watchAdoptedHelperExit(ctx context.Context, pid int, verify func() bool) (<-chan struct{}, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("refusing to watch pid %d (must be > 1)", pid)
	}
	done := make(chan struct{})
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("kqueue: %w", err)
	}
	evs := []unix.Kevent_t{
		{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT},
		{Ident: adoptCancelIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR},
	}
	if _, err := unix.Kevent(kq, evs[:1], nil, nil); err != nil {
		_ = unix.Close(kq)
		if errors.Is(err, unix.ESRCH) {
			close(done)
			return done, nil
		}
		return nil, fmt.Errorf("kevent register pid %d: %w", pid, err)
	}
	if !verify() {
		_ = unix.Close(kq)
		close(done)
		return done, nil
	}
	if _, err := unix.Kevent(kq, evs[1:], nil, nil); err != nil {
		_ = unix.Close(kq)
		return nil, fmt.Errorf("kevent register the cancel wakeup for pid %d: %w", pid, err)
	}

	go func() {
		defer func() { _ = unix.Close(kq) }()
		stop := make(chan struct{})
		gone := make(chan struct{})
		go func() {
			defer close(gone)
			select {
			case <-ctx.Done():
			case <-stop:
				return
			}
			trigger := unix.Kevent_t{Ident: adoptCancelIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}
			_, _ = unix.Kevent(kq, []unix.Kevent_t{trigger}, nil, nil)
		}()
		// The trigger goroutine is joined before the kqueue is closed, so it can
		// never fire into a descriptor number the kernel has handed elsewhere.
		defer func() {
			close(stop)
			<-gone
		}()
		out := make([]unix.Kevent_t, 2)
		for {
			n, err := unix.Kevent(kq, nil, out, nil)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				// The watch cannot continue. Closing the edge reads as an exit,
				// which is the fail-safe reading: the pod is reported gone and
				// recreated rather than left watched by nothing.
				close(done)
				return
			}
			for _, ev := range out[:n] {
				if ev.Filter == unix.EVFILT_PROC {
					close(done)
					return
				}
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	return done, nil
}

// bootSessionID returns the running boot's kern.bootsessionuuid: a fresh value
// on every boot, so a record stamped with it cannot be adopted after a reboot.
func bootSessionID() (string, error) {
	s, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return "", fmt.Errorf("read kern.bootsessionuuid: %w", err)
	}
	if s == "" {
		return "", errors.New("kern.bootsessionuuid is empty")
	}
	return s, nil
}

// dialVMHostVersion asks the helper behind socket for its version and reads,
// from the kernel, which process answered (LOCAL_PEERPID). ctx bounds the dial
// and the read.
func dialVMHostVersion(ctx context.Context, socket string) (vmHostAnswer, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return vmHostAnswer{}, fmt.Errorf("dial %s: %w", socket, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(vmAdoptProbeTimeout))
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return vmHostAnswer{}, fmt.Errorf("dial %s: not a unix socket connection", socket)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return vmHostAnswer{}, fmt.Errorf("peer of %s: %w", socket, err)
	}
	peer := 0
	var perr error
	if cerr := raw.Control(func(fd uintptr) {
		peer, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); cerr != nil {
		return vmHostAnswer{}, fmt.Errorf("peer of %s: %w", socket, cerr)
	}
	if perr != nil {
		return vmHostAnswer{}, fmt.Errorf("peer pid of %s: %w", socket, perr)
	}
	v, err := decodeVMHostVersion(conn)
	if err != nil {
		return vmHostAnswer{}, err
	}
	return vmHostAnswer{VMHostVersion: v, PeerPid: peer}, nil
}
