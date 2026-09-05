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
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/image"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The runtimed-PRIVATE guest-agent socket layout: <Root>/run/vm/<pod>/agent.sock.
//
// It is deliberately not in the pod dir. The pod dir is
// the one tree a pod's own confinement can reach — the SBPL re-allow tier is
// built from it — so an agent.sock placed there would put the pod's own control
// channel inside the pod's reach: a workload could then speak GuestAgent for its
// own VM (and, with a guessable neighbour path, ask the daemon to dial a socket a
// neighbour planted). Keeping it under <Root>/run, which no generated profile
// ever re-allows, makes "no pod SBPL allows any agent.sock" a property of the
// LAYOUT rather than of every future profile edit. guestAgentSocketOutsidePodTree
// (guest_test.go) pins it.
const (
	guestRunDirName      = "run"
	guestVMDirName       = "vm"
	guestAgentSocketName = "agent.sock"
)

// maxGuestFrameBytes bounds a single message read from a guest agent.
//
// Everything the agent sends is GUEST-CONTROLLED DATA (guest.proto §TRUST): the
// workload runs in that guest, so a compromised one shapes these frames. The
// bound is applied as the gRPC client's MaxCallRecvMsgSize, which rejects an
// oversized frame before its bytes are buffered — the only placement that
// actually bounds the read. Truncating after receipt would not: the allocation
// has already happened by the time a handler could trim it.
//
// 1 MiB is far above any legitimate frame (a guest streams exec output in the
// same ~32 KiB chunks the host pump uses, and a log entry is one line), and an
// over-bound frame ends that one pod's stream with a legible ResourceExhausted —
// it never touches the daemon or another pod.
const maxGuestFrameBytes = 1 << 20

// maxGuestMessageBytes bounds guest-authored TEXT that is relayed into a
// host-side status or exec result (an agent's error message). The frame bound
// above already caps what arrives; this caps what is quoted onward, so a guest
// cannot use the daemon as an amplifier for a megabyte of attacker-chosen text
// in an operator's terminal or the node's logs.
const maxGuestMessageBytes = 1024

// GuestDialer dials one vm pod's guest-agent socket. It is the transport seam of
// the vm Exec/Logs route: production dials the unix socket the per-pod vmhost
// proxies to the guest's vsock port (dialGuestUnix), and tests inject a dialer
// backed by an in-process listener so the full gRPC round trip — client conn,
// codec, streams — runs against a fake GuestAgent with no VM anywhere.
//
// addr is the socket path guestAgentSocket derived for the pod; a dialer must
// treat it as the address to reach and never as a path to create.
type GuestDialer func(ctx context.Context, addr string) (net.Conn, error)

// dialGuestUnix is the production GuestDialer: a plain unix-domain connection to
// the vmhost-proxied agent socket.
func dialGuestUnix(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

// isVM reports whether this pod runs under the vm backend, i.e. whether its
// verbs route to a guest agent instead of to host processes. It reads the
// RESOLVED backend createPod recorded (pod.backend), never the requested one,
// and that field is immutable after create — so no lock is taken or needed.
//
// The vm route is reachable exactly when a pod carries SANDBOX_BACKEND_VM here;
// createVMPod records it when it assembles a running vm pod via the live-boot
// path — until it succeeds it fails before assembling one, so a pod that
// never booted a guest is false for this predicate.
func (p *pod) isVM() bool {
	return p.backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM
}

// lookupPod resolves a pod by id without touching its containers. Exec's route
// dispatch needs it because a vm pod's containers live in the GUEST and have no
// host containerProc, so the host-process lookupContainer cannot answer for one.
func (r *Runtime) lookupPod(podID string) (*pod, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pods[podID]
	return p, ok
}

// guestAgentSocket returns the runtimed-private guest-agent socket path for
// podID under root (see the layout constants above).
//
// The id is parsed, not interpolated: like every other pod-path derivation in
// this daemon the layout is unreachable without validation having run, so no
// caller can build an agent-socket path — and then dial it — from an identifier
// that was never checked.
func guestAgentSocket(root, podID string) (string, error) {
	id, err := image.ParsePodID(podID)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, guestRunDirName, guestVMDirName, id.String(), guestAgentSocketName), nil
}

// dialGuest returns a gRPC client connection to podID's guest agent over the
// injected transport seam.
//
// One connection per RPC, closed by the caller: a vm-pod exec or log stream is
// an operator action, not a hot path, and a per-call conn means no reconnect
// state machine, no cache to invalidate when a pod is deleted, and no way for
// one pod's dead socket to hold resources against another's. grpc.NewClient is
// lazy, so a missing socket surfaces as Unavailable on the first RPC rather than
// here.
func (r *Runtime) dialGuest(podID string) (*grpc.ClientConn, error) {
	addr, err := guestAgentSocket(r.cfg.Root, podID)
	if err != nil {
		return nil, err
	}
	// passthrough:// hands the address to the dialer verbatim — the seam, not a
	// gRPC name resolver, decides what "this pod's agent socket" connects to.
	return grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(r.guestDialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGuestFrameBytes)),
	)
}

// vmContainerName resolves which of the pod's declared containers a vm-pod verb
// selects, mirroring the host-process rule (findContainer): an empty name picks
// the sole container, otherwise the name must be one the box declares.
//
// It resolves against the PodBox rather than live containerProcs because a vm
// pod has none — its containers are guest processes. Resolving host-side anyway
// (instead of forwarding whatever the client sent) keeps container selection a
// host decision: the name that crosses to the guest is one this node declared,
// so a selector the pod never had cannot be smuggled through the daemon.
func vmContainerName(box *runtimev1.PodBox, requested string) (string, error) {
	declared := make([]string, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	for _, c := range box.GetInitContainers() {
		declared = append(declared, c.GetName())
	}
	for _, c := range box.GetContainers() {
		declared = append(declared, c.GetName())
	}
	if requested == "" && len(declared) == 1 {
		return declared[0], nil
	}
	for _, name := range declared {
		if name == requested {
			return name, nil
		}
	}
	return "", status.Errorf(codes.NotFound, "container %s not found in pod %s", requested, box.GetPodId())
}

// execGuest is Exec's vm route: it proxies the client's exec stream to the pod's
// guest agent and relays the guest's stdout/stderr/exit back, preserving the two
// properties `kubectl exec` is built on — the stdout/stderr split stays
// demultiplexed byte for byte, and the command's exit code round-trips
// faithfully (a shell's `kubectl exec … && …` is exactly that code).
//
// The PARAMETERS come from the first frame alone and are re-stamped with the
// pod id this route resolved, which is what the agent's single-pod check
// (guest.proto: "the agent must reject a pod_id that is not the pod it booted")
// is asserting against. Subsequent frames are narrowed to stdin + resize by
// forwardExecInput, so no later frame can re-aim the stream.
func (r *Runtime) execGuest(stream runtimev1.Runtime_ExecServer, p *pod, first *runtimev1.ExecRequest) error {
	podID := p.box.GetPodId()
	if len(first.GetCommand()) == 0 {
		return status.Error(codes.InvalidArgument, "exec: command is required")
	}
	container, err := vmContainerName(p.box, first.GetContainer())
	if err != nil {
		return err
	}
	if first.GetTty() {
		// Only a tty exec needs negotiating: a plain exec has been served by
		// every initramfs this daemon has ever paired with, and gating it would
		// refuse working pods for nothing.
		if err := r.requireGuestCapability("exec", guestagent.CapabilityTTYExec, p); err != nil {
			return err
		}
	}

	// Cancelling on return tears down the guest stream (and with it the guest-side
	// process) when the client goes away mid-exec.
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	conn, err := r.dialGuest(podID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "exec: %v", err)
	}
	defer func() { _ = conn.Close() }()

	agent, err := guestv1.NewGuestAgentClient(conn).Exec(ctx)
	if err != nil {
		return guestStreamError("exec", podID, err)
	}
	// A Send that races the agent's rejection returns io.EOF, whose real status is
	// only readable from Recv — so an EOF here falls through to the relay loop
	// below, which reports the agent's actual code (that is how a pod_id-mismatch
	// rejection reaches the client as the agent's own error).
	if err := agent.Send(&runtimev1.ExecRequest{
		PodId:     podID,
		Container: container,
		Command:   first.GetCommand(),
		Tty:       first.GetTty(),
		Stdin:     first.GetStdin(),
		Stdout:    first.GetStdout(),
		Stderr:    first.GetStderr(),
	}); err != nil && !errors.Is(err, io.EOF) {
		return guestStreamError("exec", podID, err)
	}

	// Detached, exactly as the host-process runExec stdin pump is: a client that
	// holds stdin open must not block teardown, and the handler's return cancels
	// ctx, which unblocks this goroutine's Recv.
	go forwardExecInput(stream, agent)

	for {
		resp, rerr := agent.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil // the guest closed the stream after its terminal frame
			}
			return guestStreamError("exec", podID, rerr)
		}
		if serr := stream.Send(relayExecResponse(resp)); serr != nil {
			return serr
		}
	}
}

// forwardExecInput pumps the client's post-parameter frames to the guest agent
// and propagates the client's half-close as the guest's stdin EOF.
//
// It forwards only stdin bytes and tty resizes. pod_id, container and command
// are read once, from the first frame, so a later frame naming another pod or
// another command is inert — the stream stays bound to the pod the route
// resolved, and re-targeting is impossible rather than merely rejected.
func forwardExecInput(stream runtimev1.Runtime_ExecServer, agent guestv1.GuestAgent_ExecClient) {
	for {
		req, err := stream.Recv()
		if err != nil {
			// Client half-close (io.EOF) or stream teardown: close the send side so
			// the guest's process sees stdin EOF and can flush and exit.
			_ = agent.CloseSend()
			return
		}
		data, resize := req.GetStdinData(), req.GetResize()
		if len(data) == 0 && resize == nil {
			continue
		}
		fwd := &runtimev1.ExecRequest{StdinData: data}
		if resize != nil {
			fwd.Resize = &runtimev1.TerminalSize{Width: resize.GetWidth(), Height: resize.GetHeight()}
		}
		if err := agent.Send(fwd); err != nil {
			return
		}
	}
}

// relayExecResponse rebuilds the client-facing ExecResponse from the guest's,
// field by named field.
//
// Rebuilding rather than forwarding the received message is the untrusted-data
// discipline: only the fields this route means to relay cross to the client, so
// a field a future agent sets — deliberately or not — cannot ride through
// unexamined. The exit code is relayed verbatim (it is the conformance-bearing
// value, and the guest legitimately owns it: it ran the process). The agent's
// structured error is relayed as code + a length-bounded message, dropping its
// details: the provider reads that error as "the command could not run", which
// is worth keeping, while an Any-typed detail payload from a guest is not.
func relayExecResponse(resp *runtimev1.ExecResponse) *runtimev1.ExecResponse {
	out := &runtimev1.ExecResponse{Stdout: resp.GetStdout(), Stderr: resp.GetStderr()}
	if ex := resp.GetExit(); ex != nil {
		out.Exit = &runtimev1.ExecResult{ExitCode: ex.GetExitCode()}
		if st := ex.GetError(); st != nil {
			out.Exit.Error = rpcStatus(codes.Code(st.GetCode()), "%s", boundGuestMessage(st.GetMessage()))
		}
	}
	return out
}

// maxGuestCapabilityTokens bounds how many advertised tokens one Health
// response is scanned for.
//
// The frame bound already caps what arrives, so this is not what stops a flood;
// it caps the WORK a hostile agent can make the poll do on every tick, forever,
// on a node running many pods. A real agent advertises a handful.
const maxGuestCapabilityTokens = 64

// knownGuestCapability reports whether tok is a capability this daemon
// understands.
//
// It is an ALLOWLIST, and the filter is what makes the recorded set safe: only
// tokens from this package's own vocabulary are retained, so no guest-chosen
// string is ever stored on a pod, logged, or compared. An unknown token is
// ignored exactly as guest.proto says it should be.
func knownGuestCapability(tok string) bool {
	switch tok {
	case guestagent.CapabilityTTYExec, guestagent.CapabilityAttach:
		return true
	}
	return false
}

// guestCapVerdict is what the recorded capability state says about one token.
type guestCapVerdict int

// The three verdicts. They are three and not two because "the guest says it
// cannot" and "nobody has asked the guest yet" call for opposite behaviour, and
// collapsing them either refuses working pods or hides an unsupported pairing
// behind a bare Unimplemented.
const (
	// guestCapUnobserved means no Health response has been read for this pod
	// yet. The request proceeds: refusing on the strength of never having asked
	// would fail every verb issued before the first poll landed.
	guestCapUnobserved guestCapVerdict = iota
	// guestCapPresent means the agent advertised the token.
	guestCapPresent
	// guestCapAbsent means the agent answered and did NOT advertise it — a
	// positive statement, which an older initramfs makes by advertising nothing
	// at all.
	guestCapAbsent
)

// classifyGuestCapability is the verdict function, kept pure so the three-state
// rule is pinned by a table rather than by reading the two call sites.
func classifyGuestCapability(observed bool, caps map[string]struct{}, token string) guestCapVerdict {
	if !observed {
		return guestCapUnobserved
	}
	if _, ok := caps[token]; ok {
		return guestCapPresent
	}
	return guestCapAbsent
}

// setGuestCapabilities records the tokens an agent advertised, filtered to the
// ones this daemon knows. See the pod's guestCaps fields for the three states
// it maintains.
func (r *Runtime) setGuestCapabilities(p *pod, advertised []string) {
	caps := map[string]struct{}{}
	for i, tok := range advertised {
		if i >= maxGuestCapabilityTokens {
			break
		}
		if knownGuestCapability(tok) {
			caps[tok] = struct{}{}
		}
	}
	p.mu.Lock()
	p.guestCaps = caps
	p.guestCapsObserved = true
	p.mu.Unlock()
}

// requireGuestCapability refuses a verb the pod's guest agent has said it
// cannot serve, with a message that names the fix.
//
// the POINT IS the DIAGNOSTIC. Without it, a daemon paired with an older
// initramfs answers `kubectl attach` with "method Attach not implemented" and
// `kubectl exec -it` with a terminal refusal from inside the guest — both
// technically true and both indistinguishable, to the operator reading them,
// from a bug in this daemon. Compat is lockstep via the in-code initramfs
// sha256 pin (guest.proto §COMPAT POSTURE), so the only reachable way to be
// here is the dev-lab --guest-artifacts-dir override, and that is what the
// message says.
func (r *Runtime) requireGuestCapability(verb, token string, p *pod) error {
	p.mu.Lock()
	observed, caps := p.guestCapsObserved, p.guestCaps
	p.mu.Unlock()
	if classifyGuestCapability(observed, caps, token) != guestCapAbsent {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s: the guest initramfs booted for pod %s does not advertise the %q capability, so it cannot serve this verb; "+
			"recreate the pod so it boots the initramfs this daemon pins (a --guest-artifacts-dir override is unsupported skew)",
		verb, p.box.GetPodId(), token)
}

// attachGuest is Attach's vm route: it bridges the client's attach stream to
// the pod's guest agent, which holds the container's RETAINED stdio.
//
// It mirrors execGuest — same first-frame re-stamp, same detached input pump,
// same field-by-field relay — with one difference that is the whole point of
// the verb: this route STARTS NOTHING and ENDS NOTHING. execGuest's ctx cancel
// on handler return tears down a guest-side process the client asked to run;
// the same cancel here tears down only the stream, because the agent's Attach
// never signals the container, never closes its endpoints, and never forwards a
// client half-close as stdin EOF (guest.proto: "DETACH IS NOT KILL"). A client
// that disconnects has unsubscribed, and the workload does not notice.
//
// The PARAMETERS come from the first frame alone and are re-stamped with the
// pod id and container name this route resolved host-side — the same
// narrowing execGuest applies, so no later frame can re-aim the stream.
func (r *Runtime) attachGuest(stream runtimev1.Runtime_AttachServer, p *pod, first *runtimev1.AttachRequest) error {
	podID := p.box.GetPodId()
	container, err := vmContainerName(p.box, first.GetContainer())
	if err != nil {
		return err
	}
	if err := r.requireGuestCapability("attach", guestagent.CapabilityAttach, p); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	conn, err := r.dialGuest(podID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "attach: %v", err)
	}
	defer func() { _ = conn.Close() }()

	agent, err := guestv1.NewGuestAgentClient(conn).Attach(ctx)
	if err != nil {
		return guestStreamError("attach", podID, err)
	}
	// A Send that races the agent's rejection returns io.EOF, whose real status
	// is only readable from Recv — so an EOF here falls through to the relay
	// loop, which reports the agent's actual code (that is how the
	// no-retained-stdin FailedPrecondition reaches the client as the agent's own
	// error rather than as a bare stream failure).
	if err := agent.Send(&runtimev1.AttachRequest{
		PodId:     podID,
		Container: container,
		Stdin:     first.GetStdin(),
		Stdout:    first.GetStdout(),
		Stderr:    first.GetStderr(),
		Tty:       first.GetTty(),
	}); err != nil && !errors.Is(err, io.EOF) {
		return guestStreamError("attach", podID, err)
	}

	// Detached, exactly as the exec input pump is: a client holding stdin open
	// must not block teardown, and the handler's return cancels ctx, which
	// unblocks this goroutine's Recv.
	go forwardAttachInput(stream, agent)

	for {
		resp, rerr := agent.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil // the guest closed the stream after its terminal frame
			}
			return guestStreamError("attach", podID, rerr)
		}
		if serr := stream.Send(relayAttachResponse(resp)); serr != nil {
			return serr
		}
	}
}

// forwardAttachInput pumps the client's post-parameter frames to the guest
// agent, forwarding ONLY stdin bytes and terminal resizes.
//
// pod_id and container are read once, from the first frame, so a later frame
// naming another pod or another container is inert — the stream stays bound to
// what the route resolved, and re-targeting is impossible rather than merely
// rejected.
//
// The client's half-close ends the send side of the GUEST stream, and that is
// all it does. It is deliberately NOT the exec path's meaning: there,
// CloseSend gives the exec'd process stdin EOF so a filter can flush and exit.
// Here the far end's own input pump simply stops, and the container's stdin
// endpoint stays open for the next client — because the container is going to
// outlive this attach.
func forwardAttachInput(stream runtimev1.Runtime_AttachServer, agent guestv1.GuestAgent_AttachClient) {
	for {
		req, err := stream.Recv()
		if err != nil {
			_ = agent.CloseSend()
			return
		}
		data, resize := req.GetStdinData(), req.GetResize()
		if len(data) == 0 && resize == nil {
			continue
		}
		fwd := &runtimev1.AttachRequest{StdinData: data}
		if resize != nil {
			fwd.Resize = &runtimev1.TerminalSize{Width: resize.GetWidth(), Height: resize.GetHeight()}
		}
		if err := agent.Send(fwd); err != nil {
			return
		}
	}
}

// relayAttachResponse rebuilds the client-facing AttachResponse from the
// guest's, field by named field — the same untrusted-data discipline
// relayExecResponse applies, and for the same reason: only the fields this
// route means to relay cross to the client, so a field a future agent sets
// cannot ride through unexamined.
func relayAttachResponse(resp *runtimev1.AttachResponse) *runtimev1.AttachResponse {
	out := &runtimev1.AttachResponse{Stdout: resp.GetStdout(), Stderr: resp.GetStderr()}
	if ex := resp.GetExit(); ex != nil {
		out.Exit = &runtimev1.ExecResult{ExitCode: ex.GetExitCode()}
		if st := ex.GetError(); st != nil {
			out.Exit.Error = rpcStatus(codes.Code(st.GetCode()), "%s", boundGuestMessage(st.GetMessage()))
		}
	}
	return out
}

// getLogsGuest is GetLogs's vm route: the guest agent holds the pod's output, so
// the SELECTION options (follow, tail_lines, since_time, previous) are forwarded
// to it — only the guest can apply them — while the PRESENTATION options
// (timestamps, limit_bytes) are applied HOST-side by the same logEmitter the
// host-process path uses.
//
// That split is the bounded-read posture, not a tidiness preference: an agent
// that ignores limit_bytes and streams forever must not be able to flood the
// client, so the byte budget is spent and enforced here, on this side of the
// boundary. Timestamps are rendered here for the same reason the budget is
// counted here — the two are one option set, and rendering guest-side would
// double-prefix every line.
func (r *Runtime) getLogsGuest(req *runtimev1.GetLogsRequest, stream grpc.ServerStreamingServer[runtimev1.LogEntry], p *pod) error {
	podID := p.box.GetPodId()
	container, err := vmContainerName(p.box, req.GetContainer())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	conn, err := r.dialGuest(podID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "logs: %v", err)
	}
	defer func() { _ = conn.Close() }()

	fwd := &runtimev1.GetLogsRequest{
		PodId:     podID,
		Container: container,
		Follow:    req.GetFollow(),
		TailLines: req.GetTailLines(),
		// previous is FORWARDED rather than refused as it is on the host-process
		// path: there the answer is knowably "not retained" (runtimed buffers only
		// the live container), whereas the guest owns whatever it retained, so the
		// honest reply is the agent's.
		Previous: req.GetPrevious(),
	}
	if ts := req.GetSinceTime(); ts.IsValid() {
		fwd.SinceTime = timestamppb.New(ts.AsTime())
	}
	agent, err := guestv1.NewGuestAgentClient(conn).Logs(ctx, fwd)
	if err != nil {
		return guestStreamError("logs", podID, err)
	}

	em := newLogEmitter(stream, req)
	for {
		ent, rerr := agent.Recv()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return guestStreamError("logs", podID, rerr)
		}
		if serr := em.sendEntry(logLine{at: ent.GetTimestamp().AsTime(), line: ent.GetLine()}, relayLogStream(ent.GetStream())); serr != nil {
			if errors.Is(serr, errLogLimitReached) {
				return nil // the client's byte budget is spent: a normal end of stream
			}
			return serr
		}
	}
}

// relayLogStream narrows a guest-reported stream label to the two values the
// runtime/v1 contract defines, defaulting anything else to stdout — the same
// label the host-process path emits for its combined buffer. A guest is free to
// send an enum value this build does not know; it is not free to have that value
// reach a client as an unmapped number.
func relayLogStream(s runtimev1.LogStream) runtimev1.LogStream {
	if s == runtimev1.LogStream_LOG_STREAM_STDERR {
		return runtimev1.LogStream_LOG_STREAM_STDERR
	}
	return runtimev1.LogStream_LOG_STREAM_STDOUT
}

// guestStreamError maps a guest-agent stream failure onto the status the client
// sees, keeping the agent's own code (so a pod_id mismatch stays the agent's
// InvalidArgument and an unreachable socket stays Unavailable) and quoting its
// message under the guest-text bound.
//
// An oversized frame is named explicitly: gRPC reports the receive-bound refusal
// as ResourceExhausted, which on its own reads like a host resource problem when
// it is in fact this route refusing to buffer what the guest sent.
func guestStreamError(verb, podID string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return status.Errorf(codes.Unavailable, "%s: guest agent for pod %s: %v", verb, podID, err)
	}
	if st.Code() == codes.ResourceExhausted {
		return status.Errorf(codes.ResourceExhausted,
			"%s: guest agent for pod %s sent a frame over the %d-byte bound: %s",
			verb, podID, maxGuestFrameBytes, boundGuestMessage(st.Message()))
	}
	return status.Errorf(st.Code(), "%s: guest agent for pod %s: %s", verb, podID, boundGuestMessage(st.Message()))
}

// boundGuestMessage trims guest-authored text to maxGuestMessageBytes on a rune
// boundary (utf8HeadBytes), so relayed text stays bounded and stays valid UTF-8.
func boundGuestMessage(msg string) string {
	return string(utf8HeadBytes([]byte(msg), maxGuestMessageBytes))
}
