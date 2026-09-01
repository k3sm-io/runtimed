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

package vmhost

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeGuestEnd is the far side of one relayed connection: the conn the proxy's
// dialer handed back, plus the peer a test drives.
type fakeGuestEnd struct {
	peer net.Conn
}

// newTestProxy starts a proxy on a unix socket in a temp dir, dialing an
// in-process net.Pipe for the "guest". It returns the socket path, a channel of
// guest ends (one per accepted connection), a cancel func, and a func that blocks
// until Serve has returned.
//
// The guest side is a net.Pipe deliberately: it has no CloseWrite, exactly like a
// real vsock connection, so the half-close behaviour the relay must degrade to is
// the one under test rather than a unix-socket best case.
func newTestProxy(t *testing.T, dialErr error) (string, <-chan fakeGuestEnd, context.CancelFunc, func() error) {
	t.Helper()
	sock := shortSocketPath(t)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ends := make(chan fakeGuestEnd, 8)
	dial := func(ctx context.Context) (net.Conn, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		a, b := net.Pipe()
		ends <- fakeGuestEnd{peer: b}
		return a, nil
	}

	p := NewProxy(lis, dial, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx) }()

	// Serve sends exactly one value, and both the cleanup and a subtest may want
	// it — so the receive happens once and the result is memoised. Handing out two
	// independent receivers of a one-shot channel deadlocks whichever arrives
	// second, which reads as a hung package rather than as the harness bug it is.
	//
	// The wait is bounded for the same reason: a future regression that genuinely
	// wedges Serve should fail here with a message naming it, not stall until the
	// package timeout.
	var once sync.Once
	var serveErr error
	settle := func() error {
		once.Do(func() {
			select {
			case serveErr = <-served:
			case <-time.After(30 * time.Second):
				serveErr = errors.New("Serve did not return within 30s; a relay goroutine is still parked")
			}
		})
		return serveErr
	}
	t.Cleanup(func() {
		cancel()
		if err := settle(); err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return sock, ends, cancel, settle
}

// TestProxyRelayShutdown is B227's proxy gate. The agent proxy is the only path
// between the daemon and a guest, and it runs inside the one k3sm binary carrying
// com.apple.security.virtualization — so what it must get right is relaying bytes
// faithfully and then GOING AWAY COMPLETELY, leaving no goroutine holding a vsock
// connection into a machine the lifecycle is about to halt.
//
// every assertion is a t.Run subtest of this one function on purpose: the gate runs
// `go test -run '^TestProxyRelayShutdown$'`, so a sibling top-level Test* would be
// silently filtered out and never run.
//
// Hermetic: a unix socket in a temp dir and an in-process net.Pipe. No VM, no
// vsock, no gRPC — which is itself the point, because the proxy must not know what
// gRPC is.
func TestProxyRelayShutdown(t *testing.T) {
	t.Run("relays-bytes-in-both-directions", func(t *testing.T) {
		sock, ends, _, _ := newTestProxy(t, nil)

		client, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = client.Close() }()

		guest := (<-ends).peer
		defer func() { _ = guest.Close() }()

		// client -> guest
		go func() { _, _ = client.Write([]byte("hello guest")) }()
		if got := readN(t, guest, len("hello guest")); got != "hello guest" {
			t.Errorf("guest received %q, want %q", got, "hello guest")
		}
		// guest -> client
		go func() { _, _ = guest.Write([]byte("hello host")) }()
		if got := readN(t, client, len("hello host")); got != "hello host" {
			t.Errorf("client received %q, want %q", got, "hello host")
		}
	})

	t.Run("relays-a-payload-larger-than-one-buffer", func(t *testing.T) {
		// A byte pump that framed or truncated would pass the small case above and
		// fail here — and an exec stream is exactly this shape.
		sock, ends, _, _ := newTestProxy(t, nil)
		client, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = client.Close() }()
		guest := (<-ends).peer
		defer func() { _ = guest.Close() }()

		payload := make([]byte, 256<<10)
		for i := range payload {
			payload[i] = byte(i)
		}
		go func() {
			_, _ = client.Write(payload)
			_ = client.(*net.UnixConn).CloseWrite()
		}()
		got, err := io.ReadAll(guest)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(got) != len(payload) {
			t.Fatalf("guest received %d bytes, want %d", len(got), len(payload))
		}
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("payload differs at byte %d", i)
			}
		}
	})

	t.Run("propagates-the-client-half-close-as-guest-EOF", func(t *testing.T) {
		// A gRPC client that half-closes its request stream is saying "no more
		// requests, keep sending responses" — `kubectl exec` with stdin closed is
		// exactly that. A relay that propagated nothing would leave the guest
		// waiting forever for a request that will never come.
		sock, ends, _, _ := newTestProxy(t, nil)
		client, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = client.Close() }()
		guest := (<-ends).peer
		defer func() { _ = guest.Close() }()

		if _, err := client.Write([]byte("last")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := client.(*net.UnixConn).CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		if got := readN(t, guest, 4); got != "last" {
			t.Errorf("guest received %q, want %q", got, "last")
		}
		_ = guest.SetReadDeadline(time.Now().Add(5 * time.Second))
		var buf [1]byte
		if _, err := guest.Read(buf[:]); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("guest read after the client half-close = %v, want EOF", err)
		}
	})

	t.Run("propagates-the-guest-EOF-to-the-client", func(t *testing.T) {
		sock, ends, _, _ := newTestProxy(t, nil)
		client, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = client.Close() }()
		guest := (<-ends).peer

		if _, err := guest.Write([]byte("bye")); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = guest.Close()

		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(client)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != "bye" {
			t.Errorf("client received %q, want %q", got, "bye")
		}
	})

	t.Run("Serve-returns-only-after-every-relay-has-drained", func(t *testing.T) {
		// The load-bearing shutdown property. Serve's return has to MEAN "no relay
		// goroutine of this proxy is alive", because the lifecycle halts the
		// machine right after — and a goroutine still holding a vsock connection
		// into a machine being torn down is the race this drain exists to remove.
		sock, ends, cancel, wait := newTestProxy(t, nil)

		const conns = 8
		clients := make([]net.Conn, 0, conns)
		guests := make([]net.Conn, 0, conns)
		for i := 0; i < conns; i++ {
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatalf("dial %d: %v", i, err)
			}
			clients = append(clients, c)
			guests = append(guests, (<-ends).peer)
		}
		// Every relay is parked in Read on both sides — the state a shutdown
		// actually finds them in.
		cancel()

		if err := wait(); err != nil {
			t.Fatalf("Serve: %v — cancellation is a normal end, and a Serve that has not returned means a relay goroutine is still parked, which is exactly the leak the drain exists to prevent", err)
		}

		// Serve has returned, so both ends of every relay must already be closed.
		for i, c := range clients {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			var buf [1]byte
			if _, err := c.Read(buf[:]); err == nil {
				t.Errorf("client %d is still readable after Serve returned; its relay was not torn down", i)
			}
		}
		for _, g := range guests {
			_ = g.Close()
		}
	})

	t.Run("a-dial-failure-fails-only-that-connection", func(t *testing.T) {
		// One unreachable guest must not take the listener down: the daemon opens
		// a connection per RPC, so a transient failure has to cost one RPC, not
		// the pod's whole control channel.
		sock, _, _, _ := newTestProxy(t, errors.New("vsock: connection refused"))

		for i := 0; i < 3; i++ {
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatalf("dial %d: %v", i, err)
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(c); err != nil {
				t.Fatalf("read %d: %v", i, err)
			}
			_ = c.Close()
		}
	})

	t.Run("a-closed-listener-ends-Serve-without-an-error", func(t *testing.T) {
		sock := shortSocketPath(t)
		lis, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		p := NewProxy(lis, func(context.Context) (net.Conn, error) { return nil, errors.New("unused") }, quietLogger())
		var wg sync.WaitGroup
		var serveErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveErr = p.Serve(context.Background())
		}()
		// Give the accept loop a moment to park, then take the listener away.
		time.Sleep(20 * time.Millisecond)
		_ = lis.Close()
		wg.Wait()
		if serveErr != nil {
			t.Errorf("Serve = %v, want nil on a closed listener", serveErr)
		}
	})
}

// readN reads exactly n bytes under a deadline, failing the test on error.
func readN(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return string(buf)
}

// shortSocketPath returns a unix-socket path short ENOUGH TO BIND. A darwin
// sockaddr_un carries 104 bytes, and t.TempDir() builds its name from the full
// subtest path — which for a table of long, descriptive subtest names overflows it
// and reports the confusing "bind: invalid argument". Rooting the socket at /tmp
// with a pid-and-counter suffix keeps every case under the limit while staying
// unique across parallel runs.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "k3sm-vmhost-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}
