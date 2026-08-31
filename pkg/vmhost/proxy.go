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
	"log/slog"
	"net"
	"sync"
)

// vsockDialer opens ONE connection to the guest agent's vsock port. It is the
// transport seam of the agent proxy: production is the VZ socket device's Connect
// (vz_darwin.go), and a test injects a dialer backed by an in-process pipe so the
// whole relay — accept, both copy directions, half-close, shutdown — runs with no
// VM anywhere.
type vsockDialer func(ctx context.Context) (net.Conn, error)

// Proxy relays a runtimed-PRIVATE unix socket to the guest agent's vsock port, one
// vsock connection per accepted unix connection.
//
// IT NEVER PARSES A BYTE OF THE PAYLOAD. What crosses is guest/v1 gRPC, and this
// process is the one holding com.apple.security.virtualization — the single most
// privileged binary k3sm ships. Teaching it to decode protobuf from a guest would
// put an attacker-reachable parser inside the entitled process for no benefit
// whatever: the daemon on the other end already speaks gRPC, applies its own
// receive bounds, and treats everything from the guest as untrusted. So this is a
// byte pump, deliberately, and that is a security property rather than a
// simplification.
//
// The unix socket is NOT in the pod directory. The pod dir is the one tree a pod's
// own confinement can reach, so an agent socket there would put the pod's control
// channel inside the pod's reach; it lives under the daemon's private run tree
// instead (see pkg/runtime's guestAgentSocket).
//
// The zero value is not usable; construct one with NewProxy.
type Proxy struct {
	lis  net.Listener
	dial vsockDialer
	log  *slog.Logger

	wg sync.WaitGroup
}

// NewProxy builds a proxy relaying lis to the guest agent reached through dial.
func NewProxy(lis net.Listener, dial vsockDialer, log *slog.Logger) *Proxy {
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{lis: lis, dial: dial, log: log}
}

// Serve accepts and relays until ctx is cancelled or the listener fails, then
// DRAINS: it closes the listener, waits for every in-flight relay goroutine to
// finish, and only then returns.
//
// The drain is why Serve's return is a meaningful statement. A proxy that returned
// while relays were still running would leave goroutines holding a vsock
// connection into a machine the lifecycle is about to halt — and the helper's exit
// would race them. Because Serve returns only after wg.Wait(), "Serve returned"
// means "no relay goroutine of this proxy is alive", which is exactly what the
// shutdown sequence needs to be able to assume.
//
// A cancelled ctx is a normal end and reports nil, not ctx.Err(): shutdown is not
// a proxy failure.
func (p *Proxy) Serve(ctx context.Context) error {
	// Closing the listener is how a blocked Accept is unblocked — net.Listener has
	// no ctx-aware Accept — so the closer goroutine is the ctx bridge.
	closed := make(chan struct{})
	var closeOnce sync.Once
	closeListener := func() { closeOnce.Do(func() { _ = p.lis.Close(); close(closed) }) }

	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		select {
		case <-ctx.Done():
			closeListener()
		case <-stop:
		}
	}()

	err := p.acceptLoop(ctx)

	close(stop)
	watcher.Wait()
	closeListener()
	p.wg.Wait()

	select {
	case <-ctx.Done():
		return nil // cancellation is a normal end, not a failure
	default:
	}
	return err
}

// acceptLoop accepts connections and hands each to its own relay goroutine.
func (p *Proxy) acceptLoop(ctx context.Context) error {
	for {
		conn, err := p.lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.relay(ctx, conn)
		}()
	}
}

// relay bridges one accepted client connection to one fresh guest-agent
// connection.
//
// ONE VSOCK CONNECTION PER CLIENT CONNECTION, never a shared or pooled one: the
// daemon opens a connection per RPC (see pkg/runtime's dialGuest), streams on it,
// and closes it, so multiplexing here would add a state machine whose only job
// would be to undo that.
func (p *Proxy) relay(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	guest, err := p.dial(ctx)
	if err != nil {
		p.log.Warn("could not reach the guest agent for a relayed connection", "err", err)
		return
	}
	defer func() { _ = guest.Close() }()

	// A cancelled ctx must tear the relay down even though both copies are blocked
	// in Read. Closing both ends is the only portable way to do that; the copies
	// then return with a use-of-closed error, which copyHalf treats as a normal
	// end.
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var closer sync.WaitGroup
	closer.Add(1)
	go func() {
		defer closer.Done()
		<-relayCtx.Done()
		_ = client.Close()
		_ = guest.Close()
	}()

	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); copyHalf(guest, client) }()
	go func() { defer copies.Done(); copyHalf(client, guest) }()
	copies.Wait()

	cancel()
	closer.Wait()
}

// halfCloser is the optional half-close capability. *net.UnixConn and *net.TCPConn
// have it; a vsock connection may not.
type halfCloser interface{ CloseWrite() error }

// copyHalf copies src into dst and PROPAGATES THE HALF-CLOSE: when src reaches EOF
// it shuts down dst's write side, so the far end sees a clean end-of-stream while
// its own direction stays open.
//
// This matters for exactly the traffic that crosses here. A gRPC client that
// half-closes its request stream is telling the server "no more requests, but keep
// sending responses" — a `kubectl exec` with stdin closed and output still flowing
// is precisely that. A proxy that tore the whole connection down on first EOF
// would truncate the response; one that propagated nothing would leave the server
// waiting forever for a request that will never come.
//
// WHERE dst OFFERS NO CloseWrite it is closed OUTRIGHT instead. A vsock connection
// is that case. The alternative — leaving the direction open — is not "degraded but
// safe": the opposite copy would then stay blocked in Read on a peer that has been
// told nothing and will never speak again, and the relay goroutine would live until
// the whole machine was torn down. A connection that cannot express half-close
// cannot distinguish that state from a leak, so the honest end is a full close.
func copyHalf(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if hc, ok := dst.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = dst.Close()
}
