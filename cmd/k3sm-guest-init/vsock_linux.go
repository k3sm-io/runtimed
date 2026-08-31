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

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// The AF_VSOCK listener the guest agent is served on.
//
// NO NEW DEPENDENCY. golang.org/x/sys/unix is already a dependency of this module
// and carries the whole AF_VSOCK surface (SockaddrVM, the CID constants,
// Accept4) — so the transport that makes the guest reachable costs the initramfs
// nothing it was not already carrying.
//
// WHY THE ADAPTERS BELOW EXIST, given the standard library already wraps fds:
// net.FileListener and net.FileConn REFUSE a socket family they do not recognize
// (they switch on the address family and return "unknown network"), and AF_VSOCK
// is not among them. So the fds cannot be handed to net directly.
//
// What CAN be reused is os.NewFile, which registers a non-blocking fd with the
// runtime's network poller. That is the whole reason to go through os.File rather
// than raw unix.Read/unix.Write: it keeps deadlines working (SetReadDeadline on an
// os.File backed by the poller), keeps a blocked goroutine parked instead of
// pinning an OS thread, and makes Close unblock a parked reader — every property
// gRPC's transport assumes of a net.Conn. The adapters are thin because everything
// hard is already done by the poller.

// vsockAddr is a net.Addr for an AF_VSOCK endpoint.
type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("vsock:%d:%d", a.cid, a.port) }

// listenVsock binds and listens on the given vsock port, for any CID.
//
// VMADDR_CID_ANY is correct rather than lax: the only peer that can reach a guest's
// vsock is its own hypervisor, so binding to a specific CID would buy no isolation
// and would break when the host CID differs from the one this code guessed.
//
// The socket is created NON-BLOCKING with CLOEXEC. Non-blocking is what lets
// os.NewFile attach it to the runtime poller (see the file comment); CLOEXEC keeps
// the listener out of every container this init forks, which matters because those
// processes are the tenant's.
func listenVsock(port uint32, backlog int) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind vsock port %d: %w", port, err)
	}
	if err := unix.Listen(fd, backlog); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("listen vsock port %d: %w", port, err)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d", port))
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("vsock: could not adopt the listening descriptor")
	}
	return &vsockListener{f: f, addr: vsockAddr{cid: unix.VMADDR_CID_ANY, port: port}}, nil
}

// vsockListener is a net.Listener over a poller-registered AF_VSOCK listening fd.
type vsockListener struct {
	f    *os.File
	addr vsockAddr
}

// Accept waits for the next connection.
//
// The wait goes through SyscallConn().Read, which is the runtime poller's
// "readable" wait: the callback returns false to mean "not ready, park me", and the
// poller reschedules the goroutine when the fd becomes readable. That is what makes
// a parked Accept cost a goroutine rather than an OS thread, and what makes Close
// wake it.
func (l *vsockListener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		nfd     int
		peer    unix.Sockaddr
		acceptE error
	)
	ctrlErr := rc.Read(func(fd uintptr) bool {
		nfd, peer, acceptE = unix.Accept4(int(fd), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if errors.Is(acceptE, unix.EAGAIN) || errors.Is(acceptE, unix.EWOULDBLOCK) {
			return false // not ready: park until the poller says otherwise
		}
		return true
	})
	if ctrlErr != nil {
		return nil, ctrlErr
	}
	if acceptE != nil {
		if errors.Is(acceptE, unix.EINTR) || errors.Is(acceptE, unix.ECONNABORTED) {
			// Both are retryable and neither is a listener failure: a signal
			// arrived, or a peer went away between the SYN and the accept.
			// Reporting them would tear down the agent for a non-event.
			return nil, unix.EINTR
		}
		return nil, fmt.Errorf("vsock accept: %w", acceptE)
	}
	f := os.NewFile(uintptr(nfd), "vsock-conn")
	if f == nil {
		_ = unix.Close(nfd)
		return nil, errors.New("vsock: could not adopt an accepted descriptor")
	}
	return &vsockConn{f: f, local: l.addr, remote: peerAddr(peer)}, nil
}

// Close closes the listener, unblocking a parked Accept.
func (l *vsockListener) Close() error { return l.f.Close() }

// Addr returns the listening address.
func (l *vsockListener) Addr() net.Addr { return l.addr }

// peerAddr renders an accepted peer's address, falling back to a zero vsock
// address for a family this build does not expect.
func peerAddr(sa unix.Sockaddr) vsockAddr {
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		return vsockAddr{cid: vm.CID, port: vm.Port}
	}
	return vsockAddr{}
}

// vsockConn is a net.Conn over a poller-registered AF_VSOCK stream fd.
//
// Every method delegates to os.File, which is where the deadline and cancellation
// behaviour actually comes from — see the file comment. Writing these by hand over
// unix.Read/unix.Write would mean reimplementing all of it, badly.
type vsockConn struct {
	f             *os.File
	local, remote vsockAddr
}

func (c *vsockConn) Read(b []byte) (int, error)  { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error) { return c.f.Write(b) }
func (c *vsockConn) Close() error                { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr         { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr        { return c.remote }

func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// Ensure the adapters satisfy the net interfaces gRPC's transport requires.
var (
	_ net.Listener = (*vsockListener)(nil)
	_ net.Conn     = (*vsockConn)(nil)
)
