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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"
)

// Shortening a helper's stop before it begins.
//
// A SIGTERM carries no number, so a helper spawned with a pod's long grace
// spends that grace when it is signalled, and a stopper with a shorter bound
// (StopAllVMs, the node teardown of a full stop or an uninstall) can only
// SIGKILL it at the bound: the guest still believes it has its whole grace and
// is power-cut partway through. The shorten request closes that gap. Sent on
// the helper's control socket BEFORE the SIGTERM, it carries the stopper's
// bound B and asks the helper to START its stop with
//
//	grace' = max(1 s, min(grace, B - VMHelperStopMargin))   (ShortenedStopGrace)
//
// through the same single shutdown path SIGTERM takes, so the guest's own
// SIGTERM and SIGKILL phases fit the time the stopper will actually give it.
//
// It is ADDITIVE on the control socket and VMHostProtocolVersion is unchanged:
// the helper still writes its version line first, to every connection, and a
// client that sends nothing (adoption's version call) sees exactly what it saw
// before. A request line after the banner is the new part. The compatibility
// window is the helper that predates it: it closes the connection after the
// banner, the client reads that as VMHostShortenUnsupported, and the stopper
// sends its SIGTERM and waits as it always did.

// VMHostMinShortenBound is the smallest stop bound a shorten request may
// carry: the helper's stop margin plus the one-second floor of the grace. A
// bound below it leaves the guest less than a second, so the request is
// refused and the stopper's plain SIGTERM decides.
const VMHostMinShortenBound = VMHelperStopMargin + time.Second

// vmHostShortenTimeout bounds one shorten exchange, dial to reply. The helper
// answers from its accept loop under one mutex and never touches the guest to
// do it, so a healthy helper answers at once; the bound is for a wedged one,
// and it is short because it is spent inside the stopper's own bound.
const vmHostShortenTimeout = time.Second

// vmHostControlLineMax bounds one line on the control socket, either way.
const vmHostControlLineMax = 4096

// vmHostOpShortenStop is the one request the control socket understands.
const vmHostOpShortenStop = "shorten-stop"

// The reply results on the wire.
const (
	vmHostReplyShortened       = "shortened"
	vmHostReplyAlreadyStopping = "already-stopping"
	vmHostReplyRefused         = "refused"
	vmHostReplyUnknown         = "unknown-request"
)

// ErrVMHostShortenBound reports a stop bound below VMHostMinShortenBound.
var ErrVMHostShortenBound = errors.New("sandbox: the stop bound is below the shorten floor")

// ShortenedStopGrace is the grace a helper spawned with grace starts its stop
// with when its stopper will wait at most bound from the request:
// max(1 s, min(grace, bound - VMHelperStopMargin)). The margin stays behind it
// for the guest's sync reserve, the hard stop and the helper's exit, exactly as
// for an uncut stop (VMHelperStopWait). A bound below VMHostMinShortenBound is
// refused with ErrVMHostShortenBound.
//
// It is the one formula: the helper applies it to its own grace, and a stopper
// uses it to tell whether a helper's grace would be cut at all (the result is
// less than the grace). It never extends a grace a caller applies it to, except
// to the one-second floor, which the helper's own guard (it never extends)
// absorbs.
func ShortenedStopGrace(grace, bound time.Duration) (time.Duration, error) {
	if bound < VMHostMinShortenBound {
		return 0, fmt.Errorf("%w: bound %s, floor %s", ErrVMHostShortenBound, bound, VMHostMinShortenBound)
	}
	return max(time.Second, min(grace, bound-VMHelperStopMargin)), nil
}

// VMHostStopShortener is the helper's stop as its control socket drives it.
// pkg/vmhost's Lifecycle satisfies it; it is defined here, at the consumer,
// because pkg/vmhost never imports this package.
type VMHostStopShortener interface {
	// ShortenGrace starts the stop with a grace no longer than shorten returns
	// for the current one, and reports the grace before and after. It reports
	// alreadyStopping, changing nothing, when the stop has begun; an error from
	// shorten starts nothing.
	ShortenGrace(shorten func(current time.Duration) (time.Duration, error)) (from, to time.Duration, alreadyStopping bool, err error)
}

// VMHostControl is what a helper's control socket serves: its version banner,
// and the stop a shorten request drives.
type VMHostControl struct {
	// Version is the banner written to every connection.
	Version VMHostVersion
	// Stop is the stop a shorten request drives; nil answers every request as
	// unknown, which is how a banner-only helper looks to a client.
	Stop VMHostStopShortener
	// PodID names the pod in the helper's log lines.
	PodID string
	// Logger receives the shortenings; nil means slog.Default.
	Logger *slog.Logger

	// peerUID reads a connection's peer uid (LOCAL_PEERCRED); nil means
	// controlPeerUID. A field so a test can stand in a foreign peer.
	peerUID func(conn net.Conn) (uint32, error)
}

// ServeVMHostControlStop serves c on lis: every connection gets the version
// banner first, exactly as ServeVMHostControl writes it, and then one request
// line, if the client sends one within vmAdoptProbeTimeout, is answered with
// one reply line. A client that sends nothing is left with the banner alone.
// It returns nil once lis is closed.
//
// Each connection is served on its own goroutine, bounded by its deadline, so
// a client that holds a connection open cannot delay another's banner.
func ServeVMHostControlStop(lis net.Listener, c VMHostControl) error {
	banner, err := json.Marshal(c.Version)
	if err != nil {
		return fmt.Errorf("marshal the vm host version: %w", err)
	}
	banner = append(banner, '\n')
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept on the vm host control socket: %w", err)
		}
		go c.serveConn(conn, banner)
	}
}

// serveConn writes the banner to conn, then answers at most one request line.
func (c VMHostControl) serveConn(conn net.Conn, banner []byte) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(vmAdoptProbeTimeout))
	if _, err := conn.Write(banner); err != nil {
		return
	}
	line, err := readControlLine(bufio.NewReaderSize(conn, vmHostControlLineMax))
	if err != nil {
		// A banner-only client (EOF), or one that sent nothing in time.
		return
	}
	rep := c.answer(line, func() error { return c.peerMayStop(conn) })
	reply, err := json.Marshal(rep)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(reply, '\n'))
}

// peerMayStop reports, as an error, a peer that may not change this helper's
// stop: only root or this helper's own uid may. The socket is already
// owner-only (0600 in a 0700 dir); this is the second layer, so a socket that
// was somehow reachable by another uid still cannot shorten a guest's grace.
func (c VMHostControl) peerMayStop(conn net.Conn) error {
	read := c.peerUID
	if read == nil {
		read = controlPeerUID
	}
	uid, err := read(conn)
	if err != nil {
		return fmt.Errorf("the peer's uid cannot be read: %w", err)
	}
	if uid != 0 && int(uid) != os.Geteuid() {
		return fmt.Errorf("peer uid %d may not shorten this helper's stop (only root or uid %d)", uid, os.Geteuid())
	}
	return nil
}

// answer decides one request line. peerOK is consulted only for a well-formed
// shorten request, before the stop is touched.
func (c VMHostControl) answer(line []byte, peerOK func() error) vmHostReply {
	var req vmHostRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Op != vmHostOpShortenStop || c.Stop == nil {
		return vmHostReply{Result: vmHostReplyUnknown}
	}
	bound := time.Duration(req.BoundNanos)
	if err := peerOK(); err != nil {
		c.Logger.Warn("refused a request to shorten the guest's stop from a peer that may not make it", "pod", c.PodID, "bound", bound, "err", err)
		return vmHostReply{Result: vmHostReplyRefused, Error: err.Error()}
	}
	from, to, stopping, err := c.Stop.ShortenGrace(func(current time.Duration) (time.Duration, error) {
		return ShortenedStopGrace(current, bound)
	})
	switch {
	case err != nil:
		c.Logger.Warn("refused a request to shorten the guest's stop", "pod", c.PodID, "bound", bound, "err", err)
		return vmHostReply{Result: vmHostReplyRefused, Error: err.Error()}
	case stopping:
		c.Logger.Info("a request to shorten the guest's stop came after the stop began; nothing changed",
			"pod", c.PodID, "grace", from, "bound", bound)
		return vmHostReply{Result: vmHostReplyAlreadyStopping, FromNanos: int64(from), ToNanos: int64(to)}
	case to < from:
		c.Logger.Warn("shortening the guest's stop grace to fit the stopper's bound",
			"pod", c.PodID, "original_grace", from, "new_grace", to, "bound", bound)
	default:
		c.Logger.Info("starting the guest's stop at its full grace, which fits the stopper's bound",
			"pod", c.PodID, "grace", to, "bound", bound)
	}
	return vmHostReply{Result: vmHostReplyShortened, FromNanos: int64(from), ToNanos: int64(to)}
}

// vmHostRequest is one request line on the control socket.
type vmHostRequest struct {
	Op         string `json:"op"`
	BoundNanos int64  `json:"boundNanos,omitempty"`
}

// vmHostReply is one reply line on the control socket.
type vmHostReply struct {
	Result    string `json:"result"`
	FromNanos int64  `json:"fromNanos,omitempty"`
	ToNanos   int64  `json:"toNanos,omitempty"`
	Error     string `json:"error,omitempty"`
}

// readControlLine reads one newline-terminated line of at most
// vmHostControlLineMax bytes.
func readControlLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	return line, nil
}

// VMHostShortenResult is what a shorten request came to.
type VMHostShortenResult int

// The shorten results.
const (
	// VMHostShortenUnsupported means the helper did not take the request: its
	// control socket could not be reached, or it answered with its banner alone
	// (a helper that predates the request), or it did not know the request. The
	// stopper's SIGTERM-and-wait decides, as before.
	VMHostShortenUnsupported VMHostShortenResult = iota
	// VMHostShortened means the helper began its stop with the grace in To.
	VMHostShortened
	// VMHostAlreadyStopping means the helper's stop had already begun, with
	// the grace it was sent then; the request changed nothing.
	VMHostAlreadyStopping
)

// String renders a result for logs.
func (r VMHostShortenResult) String() string {
	switch r {
	case VMHostShortenUnsupported:
		return "unsupported"
	case VMHostShortened:
		return "shortened"
	case VMHostAlreadyStopping:
		return "already-stopping"
	default:
		return fmt.Sprintf("unknown(%d)", int(r))
	}
}

// VMHostShortenOutcome is a shorten request's result, the helper's grace
// before and after it, and, for an unsupported one, why.
type VMHostShortenOutcome struct {
	Result VMHostShortenResult
	From   time.Duration
	To     time.Duration
	Reason string
}

// ShortenVMHostStop asks the helper serving socket, which must be the process
// pid, to start its stop with the grace bound leaves it (ShortenedStopGrace).
//
// The peer is proven before anything is sent: the kernel's LOCAL_PEERPID and
// the banner's pid must both be pid, as adoption requires, so a request never
// reaches a process other than the recorded helper. A socket that cannot be
// reached, a banner-only helper and an unknown request are
// VMHostShortenUnsupported with a nil error; a peer that is not pid, a refused
// bound, a malformed exchange or a timeout after the request was sent are
// errors. Either way the caller's SIGTERM is still what follows: on a
// shortened stop it is redundant, and on anything else it is the stop.
//
// A helper that predates the request writes its banner and closes at once, so
// it can be gone before the kernel is asked for the peer: LOCAL_PEERPID then
// fails with ENOTCONN. That is the banner-only helper, not a failure, and it
// is VMHostShortenUnsupported; the identity rule still holds, because nothing
// is ever sent to a peer the kernel did not name.
func ShortenVMHostStop(ctx context.Context, socket string, pid int, bound time.Duration) (VMHostShortenOutcome, error) {
	return shortenVMHostStop(ctx, socket, pid, bound, controlPeerPid)
}

// shortenVMHostStop is ShortenVMHostStop with the peer-pid read as a parameter,
// so a test can order the read after the helper has closed the connection.
func shortenVMHostStop(ctx context.Context, socket string, pid int, bound time.Duration, peerPid func(net.Conn) (int, error)) (VMHostShortenOutcome, error) {
	if pid <= 1 {
		return VMHostShortenOutcome{}, fmt.Errorf("shorten the vm host stop: no helper pid (%d)", pid)
	}
	if bound < VMHostMinShortenBound {
		return VMHostShortenOutcome{}, fmt.Errorf("shorten the vm host stop: %w: bound %s, floor %s", ErrVMHostShortenBound, bound, VMHostMinShortenBound)
	}
	ctx, cancel := context.WithTimeout(ctx, vmHostShortenTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return VMHostShortenOutcome{Reason: fmt.Sprintf("the control socket cannot be reached: %v", err)}, nil
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	peer, err := peerPid(conn)
	if errors.Is(err, syscall.ENOTCONN) {
		return VMHostShortenOutcome{Reason: "the helper closed the connection before its peer could be read, as one that predates the request does"}, nil
	}
	if err != nil {
		return VMHostShortenOutcome{}, fmt.Errorf("peer of %s: %w", socket, err)
	}
	if peer != pid {
		return VMHostShortenOutcome{}, fmt.Errorf("the control socket %s is served by pid %d, not the helper %d; nothing sent", socket, peer, pid)
	}
	r := bufio.NewReaderSize(conn, vmHostControlLineMax)
	line, err := readControlLine(r)
	if err != nil {
		return VMHostShortenOutcome{}, fmt.Errorf("read the vm host banner on %s: %w", socket, err)
	}
	v, err := decodeVMHostVersion(bytes.NewReader(line))
	if err != nil {
		return VMHostShortenOutcome{}, err
	}
	if v.Pid != pid {
		return VMHostShortenOutcome{}, fmt.Errorf("the control socket %s names pid %d, not the helper %d; nothing sent", socket, v.Pid, pid)
	}
	if v.Protocol != VMHostProtocolVersion {
		return VMHostShortenOutcome{Reason: fmt.Sprintf("the helper speaks protocol %d, this build %d", v.Protocol, VMHostProtocolVersion)}, nil
	}
	req, err := json.Marshal(vmHostRequest{Op: vmHostOpShortenStop, BoundNanos: int64(bound)})
	if err != nil {
		return VMHostShortenOutcome{}, fmt.Errorf("marshal the shorten request: %w", err)
	}
	if _, err := conn.Write(append(req, '\n')); err != nil {
		if helperHungUp(err) {
			return VMHostShortenOutcome{Reason: "the helper closed the connection after its banner"}, nil
		}
		return VMHostShortenOutcome{}, fmt.Errorf("send the shorten request on %s: %w", socket, err)
	}
	line, err = readControlLine(r)
	if err != nil {
		if helperHungUp(err) {
			return VMHostShortenOutcome{Reason: "the helper answered with its banner only"}, nil
		}
		return VMHostShortenOutcome{}, fmt.Errorf("read the shorten reply on %s: %w", socket, err)
	}
	var rep vmHostReply
	if err := json.Unmarshal(line, &rep); err != nil {
		return VMHostShortenOutcome{}, fmt.Errorf("decode the shorten reply on %s: %w", socket, err)
	}
	out := VMHostShortenOutcome{From: time.Duration(rep.FromNanos), To: time.Duration(rep.ToNanos)}
	switch rep.Result {
	case vmHostReplyShortened:
		out.Result = VMHostShortened
		return out, nil
	case vmHostReplyAlreadyStopping:
		out.Result = VMHostAlreadyStopping
		return out, nil
	case vmHostReplyUnknown:
		return VMHostShortenOutcome{Reason: "the helper does not know the request"}, nil
	case vmHostReplyRefused:
		return VMHostShortenOutcome{}, fmt.Errorf("the helper refused to shorten its stop: %s", rep.Error)
	default:
		return VMHostShortenOutcome{}, fmt.Errorf("the helper answered the shorten request with %q", rep.Result)
	}
}

// helperHungUp reports whether err is the peer closing the connection: what a
// helper that predates the shorten request does after its banner.
func helperHungUp(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}
