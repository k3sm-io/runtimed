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
	"log/slog"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// adoptCancelIdent is the EVFILT_USER ident the adopted-exit watch registers
// for its cancellation wakeup; idents are per (kqueue, filter), so it cannot
// collide with the EVFILT_PROC registration, whose ident is the pid.
const adoptCancelIdent = 1

// adoptedExitWait is the blocking kevent the adopted-exit watch waits in. A
// variable only so a test can make it fail.
var adoptedExitWait = func(kq int, out []unix.Kevent_t) (int, error) {
	return unix.Kevent(kq, nil, out, nil)
}

// adoptedExitPollInterval is how often the watch re-checks the helper's
// identity once kqueue can no longer tell it about the exit (pollAdoptedExit).
// A variable only so a test can shorten it.
var adoptedExitPollInterval = 2 * time.Second

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
func watchAdoptedHelperExit(ctx context.Context, pid int, verify func() bool, log *slog.Logger) (<-chan struct{}, error) {
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
			n, err := adoptedExitWait(kq, out)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				// kqueue can no longer report the exit. That is NOT an exit:
				// closing the edge here would report a running guest dead and
				// have the pod recreated beside it. Fall back to polling the
				// recorded identity, and close the edge only once the recorded
				// instance is proven gone.
				pollAdoptedExit(ctx, pid, verify, done, err, log)
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

// pollAdoptedExit is the adopted-exit watch's fallback once kevent fails: it
// re-runs verify (the recorded-identity predicate) every
// adoptedExitPollInterval and closes done once verify reports the recorded
// instance gone. It returns on ctx without closing done, as the kqueue watch
// does. The exit is then noticed up to one interval late, which is the price of
// never mistaking a broken watch for an exit.
func pollAdoptedExit(ctx context.Context, pid int, verify func() bool, done chan<- struct{}, cause error, log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log.Warn("the kqueue exit watch of an adopted vm host helper failed; polling its identity instead",
		"pid", pid, "interval", adoptedExitPollInterval, "err", cause)
	t := time.NewTicker(adoptedExitPollInterval)
	defer t.Stop()
	for {
		if !verify() {
			close(done)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
	peer, err := controlPeerPid(conn)
	if err != nil {
		return vmHostAnswer{}, fmt.Errorf("peer of %s: %w", socket, err)
	}
	v, err := decodeVMHostVersion(conn)
	if err != nil {
		return vmHostAnswer{}, err
	}
	return vmHostAnswer{VMHostVersion: v, PeerPid: peer}, nil
}

// controlPeerPid reads, from the kernel, the pid of the process serving the
// other end of a unix socket connection (LOCAL_PEERPID).
func controlPeerPid(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	peer := 0
	var perr error
	if cerr := raw.Control(func(fd uintptr) {
		peer, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); cerr != nil {
		return 0, cerr
	}
	if perr != nil {
		return 0, fmt.Errorf("LOCAL_PEERPID: %w", perr)
	}
	return peer, nil
}

// controlPeerUID reads, from the kernel, the effective uid of the process at
// the other end of a unix socket connection (LOCAL_PEERCRED).
func controlPeerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var perr error
	if cerr := raw.Control(func(fd uintptr) {
		cred, perr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); cerr != nil {
		return 0, cerr
	}
	if perr != nil {
		return 0, fmt.Errorf("LOCAL_PEERCRED: %w", perr)
	}
	return cred.Uid, nil
}
