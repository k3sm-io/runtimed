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

package runtime

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY allocates a pseudoterminal master/slave pair on macOS for a tty exec.
// golang.org/x/sys/unix has no posix_openpt(3) binding, so it uses the BSD path:
// open the /dev/ptmx clone device, grant + unlock the slave (TIOCPTYGRANT /
// TIOCPTYUNLK), resolve the slave node name (TIOCPTYGNAME), then open it
// O_NOCTTY. This is the minimal in-tree pty without a third-party dependency or
// cgo (the ioctls go through golang.org/x/sys/unix), isolated here per the darwin
// SPI discipline; the !darwin stub fails closed.
//
// The caller wires the returned slave to the exec'd command's stdin/stdout/stderr
// (with Setsid+Setctty so the slave becomes its controlling tty) and reads/writes
// the master. The caller owns closing both files.
func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	fd := int(m.Fd())
	if err := ptyVoidIoctl(fd, unix.TIOCPTYGRANT); err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("grant pty: %w", err)
	}
	if err := ptyVoidIoctl(fd, unix.TIOCPTYUNLK); err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("unlock pty: %w", err)
	}
	name, err := ptySlaveName(fd)
	if err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("open pty slave %s: %w", name, err)
	}
	return m, s, nil
}

// setWinsize applies a kubectl terminal-resize (TIOCSWINSZ) to the pty so a tty
// exec's window size tracks the client. width/height are columns/rows.
func setWinsize(f *os.File, width, height uint16) error {
	ws := &unix.Winsize{Row: height, Col: width}
	if err := unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		return fmt.Errorf("set winsize: %w", err)
	}
	return nil
}

// ptyVoidIoctl issues a no-argument (_IO) pty ioctl on fd.
func ptyVoidIoctl(fd int, req uint) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), 0); errno != 0 {
		return errno
	}
	return nil
}

// ptySlaveName resolves the slave device path via TIOCPTYGNAME, which writes a
// NUL-terminated path into a 128-byte buffer.
func ptySlaveName(fd int) (string, error) {
	var buf [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", fmt.Errorf("resolve pty slave name: %w", errno)
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n]), nil
}
