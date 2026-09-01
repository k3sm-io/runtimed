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

// Command vmsmokeguest is the LAB GUEST for the M11.2-d9 vm-boot smoke: a
// minimal linux/arm64 PID 1 that brings up AF_VSOCK and serves exactly one
// guest/v1 RPC — Health.
//
// # Why this is not k3sm-guest-init
//
// The smoke's subject is the HOST-side SPINE: write the machine description,
// spawn the entitled helper, attach, boot, and complete the agent handshake over
// the runtimed-private agent.sock. The real guest init answers a different
// question (does the guest compose its pod correctly), and it cannot run here
// yet for a concrete reason: its first act is to mount the k3sm.spec virtiofs
// share, and neither pinned lab kernel has virtiofs built in — it ships as
// virtiofs.ko, which a PID 1 that has not yet read its spec cannot know to load.
// Pointing the smoke at it would test the guest artifacts (M11.2-d3), not the
// spine, and would fail for a reason the spine did not cause.
//
// So this guest is deliberately the SMALLEST thing that can prove the host end:
// if it answers Health over agent.sock, then the spec was accepted, the machine
// was built, the kernel booted, the vsock device attached, the guest agent bound,
// and the helper's proxy relayed the call. Every one of those is host-side.
//
// # It lives in testdata, and is built by the test, never committed as a binary
//
// The initramfs is composed at test time from this source (cross-compiled
// GOOS=linux GOARCH=arm64 CGO_ENABLED=0) plus whatever kernel modules the lab
// declares. Committing a built initramfs would put a ~16 MB opaque blob in the
// repo that nobody could review and that would silently drift from guest/v1.
//
// # What it deliberately does not do
//
// It never powers off, and it ignores SIGTERM — it has no workload to terminate
// and no filesystem to sync. That is a FEATURE of the smoke rather than a
// shortcut: it forces the daemon's teardown down its ESCALATION arm (SIGTERM to
// the helper, the helper's guest-stop attempt going unanswered, the grace budget
// expiring, the machine halted hard), which is the arm a well-behaved guest would
// never exercise and therefore the one most likely to be wrong.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	guestv1 "k3sm.io/apis/guest/v1"
)

// agentPort must equal sandbox.VMAgentVsockPort, which is what the host writes
// into VMHostSpec.agent_vsock_port and what the helper's proxy dials. It is a
// literal here because this file is built as its own program by the test and
// links nothing from pkg/sandbox; the smoke fails loudly (no Health, then the
// boot deadline) if the two ever drift.
const agentPort = 1024

// modulesDir is where the test stages the kernel modules it was told to load.
// Every .ko found there is insmod'd in LEXICAL order, which is why the test names
// them with a numeric prefix: vsock's virtio transport depends on the common
// layer, which depends on the core, and finit_module does no dependency
// resolution.
const modulesDir = "/mods"

// agent serves the one RPC the smoke needs. Everything else stays unimplemented:
// answering more would invite the smoke to grow into a guest-behaviour test,
// which is a different deliverable's gate.
type agent struct {
	guestv1.UnimplementedGuestAgentServer
}

func (agent) Health(context.Context, *guestv1.HealthRequest) (*guestv1.HealthResponse, error) {
	return &guestv1.HealthResponse{Ready: true, ApiVersion: "guest.v1"}, nil
}

func main() {
	// /proc first: nothing has run before PID 1, so every later diagnostic read
	// would fail for a reason that has nothing to do with the boot.
	_ = os.MkdirAll("/proc", 0o555)
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")
	fmt.Println("K3SM_SMOKE_GUEST_INIT_EXEC")
	if b, err := os.ReadFile("/proc/cmdline"); err == nil {
		// Echoes the host-appended k3sm.pod_id, so the console log shows the
		// guest received the identity FromSpec put on the command line.
		fmt.Printf("K3SM_SMOKE_GUEST_CMDLINE=%s", string(b))
	}

	loadModules()

	lis, err := listenVsock(agentPort)
	if err != nil {
		// Printed, then hang: a PID 1 that exits panics the kernel, which the
		// host would see as an opaque machine death instead of this line.
		fmt.Printf("K3SM_SMOKE_GUEST_LISTEN_ERR=%v\n", err)
		hang()
	}
	fmt.Printf("K3SM_SMOKE_GUEST_AGENT_LISTENING port=%d\n", agentPort)

	s := grpc.NewServer()
	guestv1.RegisterGuestAgentServer(s, agent{})
	go func() {
		if err := s.Serve(lis); err != nil {
			fmt.Printf("K3SM_SMOKE_GUEST_SERVE_ERR=%v\n", err)
		}
	}()
	hang()
}

// loadModules insmods every module the test staged, in lexical order.
//
// AF_VSOCK IS A MODULE ON the STOCK LAB KERNELS. Without this the socket(2) call
// below fails with "address family not supported by protocol" and the smoke
// reports a boot that reached userspace and then could not be reached — a
// confusing shape for a missing kernel option. A kernel with vsock built in
// simply has an empty modules dir and this is a no-op.
func loadModules() {
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		return // no modules staged: the kernel is expected to have vsock built in
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".ko") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := modulesDir + "/" + name
		if err := insmod(path); err != nil {
			fmt.Printf("K3SM_SMOKE_GUEST_INSMOD_ERR mod=%s err=%v\n", name, err)
			continue
		}
		fmt.Printf("K3SM_SMOKE_GUEST_INSMOD_OK mod=%s\n", name)
	}
}

// insmod loads one kernel module via finit_module(2).
func insmod(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return unix.FinitModule(int(f.Fd()), "", 0)
}

// hang parks PID 1 forever. It never powers off — see the package doc for why
// that is the smoke's teardown subject rather than an omission.
func hang() {
	select {}
}

// --- AF_VSOCK adapters ------------------------------------------------------
//
// net.FileListener and net.FileConn refuse AF_VSOCK (they switch on the address
// family), so the fds cannot be handed to net directly. What IS reused is
// os.NewFile, which registers a non-blocking fd with the runtime's network
// poller — that is what keeps deadlines working, keeps a blocked goroutine parked
// instead of pinning a thread, and makes Close unblock a parked reader, all of
// which gRPC's transport assumes of a net.Conn. These mirror
// cmd/k3sm-guest-init/vsock_linux.go, which cannot be imported: this file is
// built as a standalone program and that one is package main.

type vsockAddr struct{ cid, port uint32 }

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("vsock:%d:%d", a.cid, a.port) }

type vsockListener struct {
	f    *os.File
	addr vsockAddr
}

func (l *vsockListener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		nfd int
		ae  error
	)
	if cerr := rc.Read(func(fd uintptr) bool {
		nfd, _, ae = unix.Accept4(int(fd), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		return !(ae == unix.EAGAIN || ae == unix.EWOULDBLOCK)
	}); cerr != nil {
		return nil, cerr
	}
	if ae != nil {
		return nil, ae
	}
	return &vsockConn{f: os.NewFile(uintptr(nfd), "vsock-conn"), a: l.addr}, nil
}

func (l *vsockListener) Close() error   { return l.f.Close() }
func (l *vsockListener) Addr() net.Addr { return l.addr }

type vsockConn struct {
	f *os.File
	a vsockAddr
}

func (c *vsockConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *vsockConn) Close() error                       { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr                { return c.a }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.a }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// listenVsock binds and listens on port for any CID: the only peer that can reach
// a guest's vsock is its own hypervisor, so a specific CID would buy no isolation
// and would break whenever the host CID differed from the guessed one.
func listenVsock(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind vsock port %d: %w", port, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("listen vsock port %d: %w", port, err)
	}
	return &vsockListener{
		f:    os.NewFile(uintptr(fd), "vsock"),
		addr: vsockAddr{cid: unix.VMADDR_CID_ANY, port: port},
	}, nil
}
