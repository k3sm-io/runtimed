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

package guestagent

import (
	"errors"
	"io"
	"sync"
)

// The two reasons an attach cannot do what it was asked to do. They are
// SENTINELS rather than strings because the server maps each onto a different
// gRPC code and a different remedy, and because guest.proto forbids the third
// option: "Stdin is never silently dropped: a client that believes it is typing
// into a process must be told when it is not."
var (
	// ErrNoStdin reports that a container retains no stdin endpoint, so nothing
	// a client types can reach it. It is the container's spawn-time shape
	// (GuestContainer.stdin false), not a transient condition — reattaching
	// will not change it, and only recreating the pod with `stdin: true` can.
	ErrNoStdin = errors.New("guestagent: this container retains no stdin endpoint")

	// ErrNoTTY reports that a container holds no pseudo-terminal, so a window
	// size has nothing to be applied to. guest.proto makes tty ADVISORY on
	// attach — it was decided at spawn — so this is not an error the client
	// sees: the server logs it and drops the frame.
	ErrNoTTY = errors.New("guestagent: this container has no pseudo-terminal")
)

// AttachEndpoints are one running container's RETAINED stdio endpoints — the
// half of a container's plumbing that outlives its spawn because `kubectl
// attach` needs it later.
//
// Both members are nil-able, and the two nils mean different things a client
// must be able to tell apart. A nil Stdin means the container was spawned
// without one (docker's `-i` absent), so there is nothing to write to and the
// attach is refused. A nil Resize means the container holds no pty (docker's
// `-t` absent), so a resize frame is inert — which is not a refusal, because
// guest.proto makes tty advisory on attach.
type AttachEndpoints struct {
	// Stdin is the retained write side of the container's standard input: the
	// pty MASTER for a tty container, the stdin pipe's write end otherwise. It
	// is nil when the container was spawned without stdin.
	//
	// It is an io.WriteCloser rather than an io.Writer because the endpoint's
	// LIFETIME is the container's, and Release — called from the guest's
	// container-exit watcher and from nowhere else — is what ends it. An attach
	// that closed it would kill the next attach's input (and, on a tty, hang the
	// container's session up with SIGHUP), which is exactly the "detach is not
	// kill" property guest.proto states.
	Stdin io.WriteCloser

	// Resize applies a window size to the container's terminal. It is nil when
	// the container holds no pty.
	Resize func(rows, cols uint16) error

	// TTY reports whether the container was spawned on a pseudo-terminal. It is
	// the fact `kubectl attach -t` is asking about, and it is decided at spawn:
	// an attach cannot make a container that has no terminal acquire one.
	TTY bool
}

// AttachHub maps a container name to its retained stdio endpoints.
//
// It is the piece that makes `kubectl attach` mean anything at all. Before it,
// a container's stdin write end and its pty master were local variables in the
// spawn path: they went out of scope the moment the fork returned, so the only
// process that could ever write to a running container was the one that had
// started it. The hub is where those descriptors are kept for the life of the
// container so a client arriving minutes later can reach them.
//
// # It is CONCRETE, and it is in Deps, exactly as Events is
//
// It is not a seam onto the guest: it holds no policy, performs no syscall of
// its own, and its two verbs are a write and a callback. Like Events it is a
// bounded registry this package owns and tests directly — which is what lets
// the whole attach handler run under `go test -race` on darwin with an
// io.Writer and a closure standing in for a pty master.
//
// # Locking discipline
//
// mu guards m and nothing else. WriteStdin and Resize copy the endpoint out
// under the lock and then call it with the lock RELEASED: the endpoints are a
// pipe write and a TIOCSWINSZ ioctl on a live terminal, and holding a mutex
// across either would let one wedged container's blocked writer stall every
// other container's attach, its exit-time Release, and the spawn of the pod's
// remaining containers.
//
// The zero value is not usable; construct one with NewAttachHub.
type AttachHub struct {
	mu sync.Mutex
	m  map[string]AttachEndpoints
}

// NewAttachHub returns an empty hub.
func NewAttachHub() *AttachHub {
	return &AttachHub{m: map[string]AttachEndpoints{}}
}

// Register records a container's retained endpoints. It is called by the spawn
// path immediately after the fork — after, because the endpoints only exist
// once the child holds the other side of them, and a hub entry for a container
// that failed to start would offer an attach a descriptor nothing reads.
//
// A second Register for the same container REPLACES the first. That is the
// restart case and it is the only correct answer: the previous entry's
// descriptors belong to a process that no longer exists.
func (h *AttachHub) Register(container string, ep AttachEndpoints) {
	h.mu.Lock()
	h.m[container] = ep
	h.mu.Unlock()
}

// Release deregisters a container and closes its retained stdin endpoint.
//
// It is called from the guest's CONTAINER-EXIT watcher and from nowhere else.
// Attach teardown must never call it: several clients may be attached at once
// (guest.proto: "Concurrent attaches are ALLOWED"), so one client detaching
// would otherwise take the others' input with it — and on a tty, closing the
// master hangs the session up with SIGHUP, turning a detach into a kill.
//
// It is idempotent, and the close error is discarded: this runs on the reap
// path, where the container is already gone and there is nothing left to do
// about a descriptor that will not close.
func (h *AttachHub) Release(container string) {
	h.mu.Lock()
	ep, ok := h.m[container]
	delete(h.m, container)
	h.mu.Unlock()
	if ok && ep.Stdin != nil {
		_ = ep.Stdin.Close()
	}
}

// Endpoints returns a container's retained endpoints. The false return means
// the container has none — it was never registered, or it has already exited
// and been released.
func (h *AttachHub) Endpoints(container string) (AttachEndpoints, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ep, ok := h.m[container]
	return ep, ok
}

// WriteStdin writes p to the container's retained stdin endpoint.
//
// It returns ErrNoStdin — never a silent success — when the container has no
// such endpoint, whether because it was spawned without stdin or because it has
// already exited. Several attached clients may call this concurrently and their
// writes INTERLEAVE in arrival order; the hub arbitrates nothing, because
// guest.proto says sorting out interleaved input is the operator's affair and
// that the alternative is silently dropping a client's keystrokes.
func (h *AttachHub) WriteStdin(container string, p []byte) error {
	h.mu.Lock()
	ep, ok := h.m[container]
	h.mu.Unlock()
	if !ok || ep.Stdin == nil {
		return ErrNoStdin
	}
	if len(p) == 0 {
		return nil
	}
	_, err := ep.Stdin.Write(p)
	return err
}

// Resize applies a window size to the container's terminal.
//
// It returns ErrNoTTY when the container holds no pty. The server DROPS that
// rather than failing the stream: guest.proto makes tty advisory on attach, so
// a client that asked for a terminal against a container that has none is
// wrong about the terminal, not wrong to be attached.
func (h *AttachHub) Resize(container string, rows, cols uint16) error {
	h.mu.Lock()
	ep, ok := h.m[container]
	h.mu.Unlock()
	if !ok || ep.Resize == nil {
		return ErrNoTTY
	}
	return ep.Resize(rows, cols)
}
