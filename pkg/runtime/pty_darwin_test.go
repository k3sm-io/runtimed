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
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpenPTYAllocatesTTY exercises the darwin pty allocation + resize path
// directly (the tty-exec plumbing): openPTY returns a usable master/slave pair,
// the slave is a real terminal, and setWinsize round-trips through the master.
func TestOpenPTYAllocatesTTY(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Fatalf("openPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	// The slave must be a terminal (only ttys have a termios).
	if _, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TIOCGETA); err != nil {
		t.Errorf("slave is not a tty: %v", err)
	}

	if err := setWinsize(master, 120, 40); err != nil {
		t.Fatalf("setWinsize: %v", err)
	}
	ws, err := unix.IoctlGetWinsize(int(master.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		t.Fatalf("get winsize: %v", err)
	}
	if ws.Col != 120 || ws.Row != 40 {
		t.Errorf("winsize = %dx%d (colxrow), want 120x40", ws.Col, ws.Row)
	}
}
