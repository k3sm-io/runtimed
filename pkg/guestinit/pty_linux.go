//go:build linux

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

package guestinit

import (
	"fmt"
	"os"
	"path"
	"strconv"

	"golang.org/x/sys/unix"
)

// OpenPTY allocates a pseudoterminal pair from the devpts instance ptmxPath
// belongs to, and returns the master and the slave.
//
// It is the ONE function in this package that performs a syscall, and the one
// place a linux-only build tag appears outside a test. It earns the exception by
// having no decision in it: which instance to allocate from is decided by the
// pure ExecPTYOrigin, the wiring around it by the pure PlanExecIO, and what is
// left here is the fixed four-call devpts dance with no branch a table could
// cover. The !linux stub fails closed so the package still builds and tests on
// darwin, where the rest of it is exercised.
//
// ptsDir is passed rather than derived from ptmxPath because the two are NOT in
// a fixed relation: the guest's multiplexer is /dev/ptmx with slaves in
// /dev/pts, while a container's is /dev/pts/ptmx with slaves alongside it.
//
// # Both descriptors are O_CLOEXEC, and that is load-bearing
//
// PID 1 forks every container and every other exec in this pod. A master left
// without FD_CLOEXEC would be inherited by all of them, which means (a) the
// kernel would never return EIO on the master when the exec'd process exits,
// because a descriptor on the pair would still be open somewhere, so the exec
// would hang instead of ending; and (b) an unrelated container would hold a
// live handle on another exec session's terminal. This is the same discipline
// the vsock listener already applies for the same reason.
//
// The caller owns closing both files; PlanExecIO says when each is closed.
func OpenPTY(ptmxPath, ptsDir string) (master, slave *os.File, err error) {
	m, err := os.OpenFile(ptmxPath, os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open the pty multiplexer %s: %w", ptmxPath, err)
	}
	fd := int(m.Fd())
	// TIOCSPTLCK(0) unlocks the slave. A slave opened while still locked fails
	// with EIO, and Linux locks it at allocation precisely so a racing opener
	// cannot get in before the allocator has set the ownership it wants.
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("unlock the pty slave of %s: %w", ptmxPath, err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("read the pty index of %s: %w", ptmxPath, err)
	}
	name := path.Join(ptsDir, strconv.Itoa(n))
	s, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("open the pty slave %s: %w", name, err)
	}
	return m, s, nil
}

// SetWinsize applies a terminal size to a pty.
//
// It is called on the MASTER: the kernel propagates the size to the pair and
// sends SIGWINCH to the slave's foreground process group, which is the whole
// mechanism by which a `kubectl exec -it` window resize reaches the program
// inside the container.
func SetWinsize(f *os.File, sz WinSize) error {
	ws := &unix.Winsize{Row: sz.Rows, Col: sz.Cols}
	if err := unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		return fmt.Errorf("set the terminal size to %dx%d: %w", sz.Rows, sz.Cols, err)
	}
	return nil
}

// ChownTTY gives the pty slave to the identity the exec'd process runs as.
//
// devpts creates a slave owned by whoever opened the multiplexer — PID 1, root —
// with mode 0620. The exec'd process inherits its three descriptors already
// open, so it can read and write the terminal regardless; what it could NOT do
// is open the terminal AGAIN by name, which is what /dev/tty, `script`, `sudo`,
// an ssh-agent prompt and every program that reopens its controlling terminal
// do. This is grantpt(3)'s job, performed here because there is no libc in the
// loop.
func ChownTTY(slave *os.File, uid, gid int) error {
	if err := unix.Fchown(int(slave.Fd()), uid, gid); err != nil {
		return fmt.Errorf("give the pty slave to %d:%d: %w", uid, gid, err)
	}
	return nil
}
