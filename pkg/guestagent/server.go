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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// maxStopGraceSeconds clamps the grace the host asks for.
//
// guest.proto says the host clamps before sending "so the guest can treat it as
// already-budgeted" — and this is the guest declining to take that on trust. A
// grace the guest honours is a grace during which PID 1 will not power off, so a
// bad or hostile value here is a VM that outlives its pod and can only be reaped by
// the daemon's own timeout.
const maxStopGraceSeconds = 300

// ErrNotFound reports that a named container is not one this guest is running. It
// is separate from a pod-id mismatch: one is "wrong guest", the other "no such
// container here".
var ErrNotFound = errors.New("guestagent: no such container")

// Status is the guest's readiness and identity, as Health reports it.
type Status struct {
	// Ready is true once boot has completed far enough to accept the other RPCs.
	Ready bool
	// GuestIP is the address the guest's DHCP client leased on eth0, empty until
	// the lease is held. this IS the single LIVE-ADDRESS AUTHORITY for a vm pod:
	// the host does not re-derive it from the network attachment, so a lease
	// change is observable as a change in this field and nowhere else.
	GuestIP string
	// RosettaRegistered is true when binfmt_misc registration for the linux/amd64
	// interpreter succeeded. false IS not AN ERROR — a guest booted without the
	// Rosetta share is the normal case, which is every guest this build produces.
	RosettaRegistered bool
	// Capabilities are optional feature tokens. They exist so an additive change
	// can be negotiated without an APIVersion bump; an unknown token is ignored by
	// the host.
	Capabilities []string
}

// ContainerSample is one container's cgroup2 resource sample.
type ContainerSample struct {
	// CPUUsageUsec is cumulative CPU time in microseconds (cgroup2 cpu.stat
	// usage_usec).
	CPUUsageUsec uint64
	// MemoryWorkingSetBytes is the working set as WorkingSet computes it.
	MemoryWorkingSetBytes uint64
}

// The five consumer seams. Each is the smallest thing the server needs from the
// running guest, defined here at the consumer and implemented once, in the linux
// executor (cmd/k3sm-guest-init). Keeping them small and separate is what lets the
// whole service run under `go test -race` on darwin with no VM: a test supplies
// five fakes and the real handler code — the pod-id enforcement, the bounds, the
// stream shapes — is what runs.

// Runner is the guest's container roster and its shutdown verb.
type Runner interface {
	// Containers returns the pod's container names in declared order. The order
	// is part of the contract: it is what the host reports back, and a set
	// reordered per call makes a stats table jump between scrapes.
	Containers() []string
	// Stop terminates every container within grace, then syncs and powers the
	// machine off. It does not return on success.
	Stop(ctx context.Context, grace time.Duration) error
}

// Sampler reads one container's cgroup2 sample.
type Sampler interface {
	// Sample returns the container's current sample, or an error if none can be
	// read. An error means the container is omitted from the response — absence
	// is the only honest encoding of "unknown" (guest.proto), because a zero
	// sample is indistinguishable from an idle container.
	Sample(ctx context.Context, container string) (ContainerSample, error)
}

// Logs supplies a container's retained and live output.
type Logs interface {
	// Stream returns a channel of the container's entries matching sel, closed
	// when the stream ends, plus a cancel func the caller must call.
	Stream(ctx context.Context, container string, sel Selector) (<-chan LogEntry, func(), error)
}

// RawOutput supplies a container's retained and live output as RAW BYTES.
//
// It is a SECOND seam onto the same output rather than a method on Logs, and
// the split is the point: `kubectl logs` wants LINES and `kubectl attach` wants
// BYTES, and one source cannot honestly serve both. A line source holds a
// newline-less write — which is every shell prompt, every password query, and
// every keystroke a pty echoes back — until a delimiter arrives that an
// interactive session may never send, so attach served from it looks wedged
// exactly when the user is typing. A byte source, used for logs, would make
// `--tail=10` mean "the last ten reads the pump happened to make".
type RawOutput interface {
	// RawStream returns a subscription over the container's raw output. The
	// caller MUST send the subscription's snapshot before draining its channel,
	// and MUST Close it when the stream ends.
	RawStream(container string) (*ByteSubscription, error)
}

// Execer runs one command inside a container.
type Execer interface {
	// Exec runs spec with the given plumbing and returns its terminal result.
	Exec(ctx context.Context, spec ExecSpec, io ExecIO) (ExecResult, error)
}

// Statusr reports the guest's readiness and identity.
type Statusr interface {
	// Status returns the guest's current status.
	Status(ctx context.Context) Status
}

// Deps are the server's six seams plus its two concrete registries.
type Deps struct {
	Runner  Runner
	Sampler Sampler
	Logs    Logs
	Execer  Execer
	Status  Statusr
	// RawOutput is the byte-granular half of a container's output, which
	// `kubectl attach` streams from. It is separate from Logs; see RawOutput.
	// A nil one makes attach report Unavailable with that stated reason rather
	// than silently serving nothing.
	RawOutput RawOutput
	// Events is the ContainerEvents fan-out the guest's reaper publishes to. It
	// is CONCRETE rather than an interface because it is not a seam onto the
	// guest — it is a bounded fan-out this package owns and tests directly.
	Events *Events
	// Attach is the retained-stdio registry the guest's spawn path registers
	// each container in. It is concrete for the SAME reason Events is: it holds
	// no policy and performs no syscall of its own, so it is a registry this
	// package owns and tests directly rather than a sixth seam onto the guest.
	// A nil one is replaced with an empty hub, which makes every attach that
	// asks for stdin fail with the stated FailedPrecondition rather than panic.
	Attach *AttachHub
	// Logger receives the agent's narration; nil means slog.Default.
	Logger *slog.Logger
}

// Server implements guest/v1's GuestAgent for the one pod this guest booted.
//
// single-POD, ASSERTED not ASSUMED. Every RPC that carries pod_id checks it
// against the booted pod and rejects any other with InvalidArgument. The id is not
// a selector — there is nothing to select among — it is the caller's assertion that
// it reached the guest it meant to reach, and the check is what makes a
// mis-addressed request a loud error instead of a silent answer about the wrong
// pod. `container` is the real selector, and it is resolved against the roster the
// pod actually declared, so a name the pod never had is NotFound rather than
// something the guest goes looking for.
//
// The zero value is not usable; construct one with NewServer.
type Server struct {
	guestv1.UnimplementedGuestAgentServer

	podID string
	deps  Deps
	log   *slog.Logger
}

// Ensure the server satisfies the generated service interface.
var _ guestv1.GuestAgentServer = (*Server)(nil)

// NewServer builds the agent for podID over deps.
func NewServer(podID string, deps Deps) *Server {
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}
	if deps.Events == nil {
		deps.Events = NewEvents(0)
	}
	if deps.Attach == nil {
		deps.Attach = NewAttachHub()
	}
	return &Server{podID: podID, deps: deps, log: log}
}

// Register attaches the agent to a gRPC server.
func (s *Server) Register(srv *grpc.Server) { guestv1.RegisterGuestAgentServer(srv, s) }

// checkPod enforces the single-pod assertion. See the type doc.
func (s *Server) checkPod(verb, got string) error {
	if got != s.podID {
		return status.Errorf(codes.InvalidArgument,
			"%s: pod_id %q is not the pod this guest booted (%q)", verb, got, s.podID)
	}
	return nil
}

// checkContainer resolves a container name against the pod's declared roster.
func (s *Server) checkContainer(verb, name string) error {
	for _, c := range s.deps.Runner.Containers() {
		if c == name {
			return nil
		}
	}
	return status.Errorf(codes.NotFound, "%s: container %q is not running in pod %s", verb, name, s.podID)
}

// Health reports readiness, the leased guest address, Rosetta registration, and
// the api_version handshake.
//
// It takes no pod_id (the request is empty by contract), so there is nothing to
// assert here — the handshake IS the assertion, one level up: a host that reads an
// api_version it does not speak fails the pod with that stated reason instead of
// proceeding into streams it cannot parse.
func (s *Server) Health(ctx context.Context, _ *guestv1.HealthRequest) (*guestv1.HealthResponse, error) {
	st := s.deps.Status.Status(ctx)
	return &guestv1.HealthResponse{
		Ready:             st.Ready,
		GuestIp:           st.GuestIP,
		RosettaRegistered: st.RosettaRegistered,
		ApiVersion:        APIVersion,
		Capabilities:      advertisedCapabilities(st.Capabilities),
	}, nil
}

// advertisedCapabilities merges the tokens this BUILD implements with whatever
// the status seam adds, dropping duplicates and keeping the build's own order
// first.
//
// The build's set leads because the tokens name verbs this package serves —
// Attach is in server.go, the tty exec is in the executor the same initramfs
// ships — so the agent, not the guest's boot state, is the authority on whether
// they exist. The seam can still add a token for something only the running
// guest knows, which is what HealthResponse.capabilities is for.
func advertisedCapabilities(extra []string) []string {
	out := Capabilities()
	seen := make(map[string]struct{}, len(out)+len(extra))
	for _, c := range out {
		seen[c] = struct{}{}
	}
	for _, c := range extra {
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// ContainerEvents streams the booted pod's lifecycle transitions until the client
// goes away or the guest shuts down.
//
// LIST then WATCH. The stream opens with a SNAPSHOT — one event per container the
// guest has seen, replayed verbatim — and only then streams live transitions. That
// is not an optimization: this guest starts its containers before it serves the
// agent (the agent's Health is the host's boot probe, so it must not answer before
// there is a pod to answer about), so a live-only stream delivered every
// ContainerStarted to nobody. The host's fold then never learned a container was
// running and a demonstrably running pod reported Pending with no container
// statuses. The snapshot also closes the same hole on every RESUBSCRIBE: the host
// re-establishes this stream after a transient drop, and without a replay it would
// never re-learn state it had already been told once.
//
// The snapshot is sent BEFORE the live loop is entered, so a live event cannot
// overtake the retained state it supersedes. Events makes the boundary exact — no
// event is both replayed and delivered live, and none falls between the two (see
// SubscribeWithSnapshot).
//
// A lossy subscription ends the stream with a stated reason. The fan-out drops
// rather than blocks (see Events), because blocking would stall PID 1's reap loop
// and leave zombies nothing can inherit — but a dropped ContainerEvent can be the
// pod's only OOMKilled notice, and silently continuing would let a killed container
// look like a clean exit. So the drop is reported.
func (s *Server) ContainerEvents(req *guestv1.ContainerEventsRequest, stream grpc.ServerStreamingServer[guestv1.ContainerEvent]) error {
	if err := s.checkPod("events", req.GetPodId()); err != nil {
		return err
	}
	snapshot, sub := s.deps.Events.SubscribeWithSnapshot()
	defer sub.Close()
	for _, ev := range snapshot {
		if err := stream.Send(eventProto(ev)); err != nil {
			return err
		}
	}

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-sub.C():
			if !ok {
				return nil // the guest is shutting down
			}
			if err := stream.Send(eventProto(ev)); err != nil {
				return err
			}
			if sub.Lossy() {
				return status.Errorf(codes.ResourceExhausted,
					"events: this subscriber fell behind and lifecycle transitions were dropped; "+
						"the stream is ending rather than continuing with a gap that could hide an OOM kill")
			}
		}
	}
}

// eventProto renders one event as its guest/v1 message.
func eventProto(ev ContainerEvent) *guestv1.ContainerEvent {
	out := &guestv1.ContainerEvent{
		Container: ev.Container,
		Timestamp: timestamppb.New(ev.At),
	}
	if ev.Started != nil {
		out.Started = &guestv1.ContainerStarted{Pid: ev.Started.PID}
	}
	if ev.Exited != nil {
		out.Exited = &guestv1.ContainerExited{
			ExitCode:  ev.Exited.ExitCode,
			Signal:    ev.Exited.Signal,
			OomKilled: ev.Exited.OOMKilled,
		}
	}
	return out
}

// Stats returns one on-demand cgroup2 sample per container.
//
// ON demand, never ON A TICK: the host asks when it needs a sample and runs no
// sampling loop against a guest, because the vm path has no OOM race to poll for
// (the hypervisor memory ceiling is enforced by the VM, and an OOM arrives as a
// ContainerEvent). The walk is over the pod's declared roster, so the response is
// bounded by the pod's own container count.
//
// A container whose sample cannot be read is omitted. See Sampler.
func (s *Server) Stats(ctx context.Context, req *guestv1.StatsRequest) (*guestv1.StatsResponse, error) {
	if err := s.checkPod("stats", req.GetPodId()); err != nil {
		return nil, err
	}
	names := s.deps.Runner.Containers()
	out := &guestv1.StatsResponse{
		Timestamp:  timestamppb.New(time.Now()),
		Containers: make([]*guestv1.GuestContainerStats, 0, len(names)),
	}
	for _, name := range names {
		sample, err := s.deps.Sampler.Sample(ctx, name)
		if err != nil {
			s.log.Debug("no cgroup2 sample for a container", "container", name, "err", err)
			continue
		}
		out.Containers = append(out.Containers, &guestv1.GuestContainerStats{
			Container:             name,
			CpuUsageUsec:          sample.CPUUsageUsec,
			MemoryWorkingSetBytes: sample.MemoryWorkingSetBytes,
		})
	}
	return out, nil
}

// Logs streams a container's output, applying the SELECTION options only.
//
// follow / tail_lines / since_time / previous are answered here because only the
// guest holds the output. timestamps and limit_bytes are not applied: the host
// applies them on its own side, precisely so an agent that ignored limit_bytes
// could not flood a client. The entry's timestamp is carried so the host can
// render it; the byte budget is the host's to spend.
func (s *Server) Logs(req *runtimev1.GetLogsRequest, stream grpc.ServerStreamingServer[runtimev1.LogEntry]) error {
	if err := s.checkPod("logs", req.GetPodId()); err != nil {
		return err
	}
	if err := s.checkContainer("logs", req.GetContainer()); err != nil {
		return err
	}
	sel := Selector{
		TailLines: req.GetTailLines(),
		Follow:    req.GetFollow(),
		Previous:  req.GetPrevious(),
	}
	if ts := req.GetSinceTime(); ts.IsValid() {
		sel.SinceTime = ts.AsTime()
	}

	ctx := stream.Context()
	entries, cancel, err := s.deps.Logs.Stream(ctx, req.GetContainer(), sel)
	if err != nil {
		return status.Errorf(codes.Unavailable, "logs: %v", err)
	}
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-entries:
			if !ok {
				return nil
			}
			if err := stream.Send(&runtimev1.LogEntry{
				Line:      e.Line,
				Timestamp: timestamppb.New(e.At),
				Stream:    logStreamProto(e.Stream),
			}); err != nil {
				return err
			}
		}
	}
}

// logStreamProto maps the agent's stream kind onto the runtime/v1 enum. stdout is
// the default for anything unrecognized, matching what the host does with a value
// it does not know.
func logStreamProto(k LogStreamKind) runtimev1.LogStream {
	if k == StreamStderr {
		return runtimev1.LogStream_LOG_STREAM_STDERR
	}
	return runtimev1.LogStream_LOG_STREAM_STDOUT
}

// Exec runs a command in a guest container, reusing the runtime/v1 exec stream
// messages verbatim.
//
// the PARAMETERS COME from the FIRST FRAME alone. Later frames are narrowed to
// stdin bytes and tty resizes, so a frame naming another pod, another container or
// another command is inert — the stream stays bound to what the first frame
// selected, and re-targeting is impossible rather than merely rejected. That
// mirrors the host's own forwardExecInput, and the two must agree: this is the end
// that would actually run the smuggled command.
func (s *Server) Exec(stream grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "exec: the stream closed before the parameter frame")
		}
		return err
	}
	if err := s.checkPod("exec", first.GetPodId()); err != nil {
		return err
	}
	if err := s.checkContainer("exec", first.GetContainer()); err != nil {
		return err
	}
	spec := ExecSpec{
		Container: first.GetContainer(),
		Argv:      first.GetCommand(),
		TTY:       first.GetTty(),
		Stdin:     first.GetStdin(),
	}
	if err := ValidateExec(spec); err != nil {
		return status.Errorf(codes.InvalidArgument, "exec: %v", err)
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	stdinR, stdinW := io.Pipe()
	resize := make(chan TerminalSize, 4)
	// The input pump is detached, exactly as the host's is: a client holding stdin
	// open must not block teardown, and the handler's return cancels ctx and
	// closes the pipe, which unblocks it.
	go func() {
		defer func() { _ = stdinW.Close() }()
		defer close(resize)
		forwardExecInput(stream, stdinW, resize)
	}()

	res, err := s.deps.Execer.Exec(ctx, spec, ExecIO{
		Stdin:  stdinR,
		Stdout: &execWriter{stream: stream, stderr: false},
		Stderr: &execWriter{stream: stream, stderr: true},
		Resize: resize,
	})
	_ = stdinR.Close()
	if err != nil {
		// The exit frame carries the failure so the client sees the agent's own
		// code rather than a bare stream error: `kubectl exec` reports it, and a
		// shell's `&&` reads the code.
		return stream.Send(&runtimev1.ExecResponse{
			Exit: &runtimev1.ExecResult{
				ExitCode: 1,
				Error:    status.Convert(err).Proto(),
			},
		})
	}
	return stream.Send(&runtimev1.ExecResponse{
		Exit: &runtimev1.ExecResult{ExitCode: res.ExitCode},
	})
}

// forwardExecInput pumps post-parameter frames into the exec's stdin and resize
// channel, propagating the client's half-close as stdin EOF.
func forwardExecInput(stream grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse], stdin io.WriteCloser, resize chan<- TerminalSize) {
	for {
		req, err := stream.Recv()
		if err != nil {
			return // half-close or teardown: the deferred Close gives stdin EOF
		}
		if data := req.GetStdinData(); len(data) > 0 {
			if _, werr := stdin.Write(data); werr != nil {
				return
			}
		}
		if r := req.GetResize(); r != nil {
			select {
			case resize <- TerminalSize{Width: r.GetWidth(), Height: r.GetHeight()}:
			default:
				// A resize is a hint about a window that has already changed; the
				// next one supersedes it. Dropping beats blocking the input pump.
			}
		}
	}
}

// execWriter turns one of the exec's output streams into gRPC frames, keeping
// stdout and stderr DEMULTIPLEXED byte for byte — the property `kubectl exec` is
// built on, and one a merge here could not be undone downstream.
type execWriter struct {
	stream grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]
	stderr bool
}

// Write sends p as one frame. It never returns a short write: gRPC either sent the
// frame or it did not.
func (w *execWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	resp := &runtimev1.ExecResponse{}
	// The bytes are COPIED: the caller is a read pump reusing one buffer, and a
	// proto message handed to gRPC is serialized asynchronously.
	buf := make([]byte, len(p))
	copy(buf, p)
	if w.stderr {
		resp.Stderr = buf
	} else {
		resp.Stdout = buf
	}
	if err := w.stream.Send(resp); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Attach bridges a client to an ALREADY-RUNNING container's retained stdio
// (`kubectl attach`), reusing the runtime/v1 attach stream messages verbatim.
//
// # It starts nothing, and DETACH IS NOT KILL
//
// guest.proto states the property and this handler is where it is kept: the
// container is running before the first frame and keeps running after the last.
// The teardown path unsubscribes from the output stream and does nothing else —
// it never closes a hub endpoint (AttachHub.Release is the exit watcher's, and
// nobody else's), never signals the container, and never forwards the client's
// stdin half-close as EOF to the container's input. Each of those three would
// turn "the operator pressed ^]" into "the workload died", and the second and
// third would do it silently.
//
// # Concurrent attaches, and why nothing arbitrates them
//
// Several clients may be attached at once. Each gets its OWN output
// subscription, so each sees the same bytes, and all of their stdin lands in
// the one retained endpoint interleaved in arrival order. That is the contract:
// the alternative is silently dropping a client's keystrokes, and an operator
// who has two terminals open on one process already knows it.
//
// # The parameters come from the FIRST FRAME alone
//
// pod_id, container, stdin, stdout, stderr and tty are read once. Later frames
// are narrowed to stdin bytes and resizes (forwardAttachInput), so a frame
// naming another pod or another container is inert — the stream stays bound to
// what the first frame selected, exactly as Exec does.
//
// # tty is ADVISORY here
//
// Tty-ness was decided when the container was spawned and an attach cannot
// change it. The field states what the client expects; a resize takes effect
// only when the container actually holds a pty, and is dropped with a debug
// line when it does not.
func (s *Server) Attach(stream grpc.BidiStreamingServer[runtimev1.AttachRequest, runtimev1.AttachResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "attach: the stream closed before the parameter frame")
		}
		return err
	}
	if err := s.checkPod("attach", first.GetPodId()); err != nil {
		return err
	}
	container := first.GetContainer()
	if err := s.checkContainer("attach", container); err != nil {
		return err
	}

	// The retained endpoints, read ONCE, for one question: does the stdin this
	// client asked for exist at all. The container's tty-ness is deliberately
	// NOT consulted for output — the raw source passes bytes through verbatim,
	// so a pty's CRLFs are already in them and a pipe's are correctly absent.
	ep, haveEndpoints := s.deps.Attach.Endpoints(container)
	if first.GetStdin() && (!haveEndpoints || ep.Stdin == nil) {
		// FAIL, never DROP. guest.proto: "Stdin is never silently dropped: a
		// client that believes it is typing into a process must be told when it
		// is not." The message names the fix because the condition is not
		// transient — the container was spawned this way, so reattaching will
		// produce the identical refusal.
		return status.Errorf(codes.FailedPrecondition,
			"attach: container %q in pod %s retains no stdin endpoint, so nothing typed here can reach it; "+
				"set stdin: true on that container and recreate the pod (`kubectl run --stdin`), "+
				"or use `kubectl exec -i` to start a new process that does read input",
			container, s.podID)
	}

	ctx := stream.Context()

	// The BYTE source, not the line ring. An attached client is a terminal:
	// its shell prompt, its password query and every keystroke the pty echoes
	// back arrive with no newline behind them, and a line-granular source holds
	// exactly those until a delimiter that an interactive session may never
	// send. `kubectl logs` keeps the line ring, unchanged — see RawOutput for
	// why one source cannot honestly serve both.
	if s.deps.RawOutput == nil {
		return status.Error(codes.Unavailable,
			"attach: this guest captures no raw container output, so there is nothing to bridge a client to")
	}
	sub, err := s.deps.RawOutput.RawStream(container)
	if err != nil {
		return status.Errorf(codes.Unavailable, "attach: %v", err)
	}
	// The ONLY teardown. See the type doc for the three things it deliberately
	// is not.
	defer sub.Close()

	if first.GetStdin() {
		// Detached, exactly as the exec input pump is: a client holding stdin
		// open must not block teardown, and the handler's return cancels the
		// stream context, which unblocks this goroutine's Recv.
		go s.forwardAttachInput(stream, container)
	}

	// SNAPSHOT FIRST, always. ByteRing.Subscribe registered this client and
	// read the retained bytes in ONE critical section, so no byte can fall
	// between the two and none is delivered twice — but the retained bytes
	// PRECEDE the live ones, and draining the channel first would hand the
	// client's terminal the session out of order.
	for _, chunk := range sub.Snapshot() {
		resp, want := attachFrame(chunk, first.GetStdout(), first.GetStderr())
		if !want {
			continue
		}
		if serr := stream.Send(resp); serr != nil {
			return serr
		}
	}

	reported := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case chunk, ok := <-sub.C():
			if !ok {
				// The container's output stream ended, which the guest does when
				// the container exits (Capture.Close on the reap path).
				return s.sendAttachExit(stream, container)
			}
			// A client that fell behind lost BYTES, and a gap in a terminal
			// stream is a half-drawn screen with no way for the reader to know
			// it. Say so, once per new loss, before the bytes that follow the
			// gap — the notice is visible noise and it is the cheaper mistake.
			if now := sub.DroppedBytes(); now > reported {
				if serr := stream.Send(&runtimev1.AttachResponse{
					Stdout: attachDropNotice(now - reported)}); serr != nil {
					return serr
				}
				reported = now
			}
			resp, want := attachFrame(chunk, first.GetStdout(), first.GetStderr())
			if !want {
				continue
			}
			if serr := stream.Send(resp); serr != nil {
				return serr
			}
		}
	}
}

// forwardAttachInput pumps a client's post-parameter frames into the
// container's retained endpoints.
//
// It runs ONLY when the first frame asked for stdin, so stdin bytes on a stream
// that never requested it are inert rather than quietly delivered — the same
// narrowing the first-frame rule applies to every other parameter.
//
// The client's half-close is NOT propagated. On the exec path a half-close
// closes the child's stdin so a filter can flush and exit; here the endpoint
// belongs to a container that is going to outlive this attach, and closing it
// would give the workload an unrecoverable EOF (and, on a tty, SIGHUP) because
// an operator detached.
func (s *Server) forwardAttachInput(stream grpc.BidiStreamingServer[runtimev1.AttachRequest, runtimev1.AttachResponse], container string) {
	for {
		req, err := stream.Recv()
		if err != nil {
			return // half-close or teardown: nothing to propagate, by design
		}
		if data := req.GetStdinData(); len(data) > 0 {
			if werr := s.deps.Attach.WriteStdin(container, data); werr != nil {
				// The endpoint is gone (the container exited under us) or the
				// write failed. Either way there is nothing further to deliver,
				// and the output loop is about to end the stream with the exit
				// frame that explains it.
				s.log.Debug("attach stdin could not be delivered",
					"container", container, "err", werr)
				return
			}
		}
		if r := req.GetResize(); r != nil {
			// runtime/v1 TerminalSize is width x height; a winsize is rows x
			// cols. The transposition is the same one the exec resize pump does,
			// and getting it backwards is invisible until a curses program lays
			// itself out sideways.
			if rerr := s.deps.Attach.Resize(container, uint16(r.GetHeight()), uint16(r.GetWidth())); rerr != nil {
				// DROPPED, not fatal: tty is advisory on attach, so a resize
				// against a container with no terminal is a client expectation
				// that was wrong, not a stream that should end.
				s.log.Debug("attach resize dropped",
					"container", container, "rows", r.GetHeight(), "cols", r.GetWidth(), "err", rerr)
			}
		}
	}
}

// sendAttachExit ends the stream with the container's terminal status, read from
// the event fan-out's retained state.
//
// The fan-out is the right source and the only one: the reaper publishes each
// container's exit there, and it RETAINS the last transition per container — so
// an attach that arrived after the container had already exited reads the same
// answer as one that watched it happen. The signal convention is Exec's
// (128+n), because a consumer must not read a different number for the same
// death depending on which verb it used to watch it.
//
// A stream that ends with NO recorded exit ends silently. That is the guest
// shutting down (Capture.CloseAll) rather than the container exiting, and
// inventing an exit code for it would tell the client the workload finished
// when in fact the machine went away underneath it.
func (s *Server) sendAttachExit(stream grpc.BidiStreamingServer[runtimev1.AttachRequest, runtimev1.AttachResponse], container string) error {
	ev, ok := s.deps.Events.Latest(container)
	if !ok || ev.Exited == nil {
		return nil
	}
	code := ev.Exited.ExitCode
	if ev.Exited.Signal != 0 {
		code = ExitCodeForSignal(int(ev.Exited.Signal))
	}
	return stream.Send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: code}})
}

// attachFrame renders one raw chunk as the client-facing frame, or reports that
// the client did not ask for that stream.
//
// The bytes are passed through VERBATIM: nothing is added, nothing is stripped,
// nothing is re-chunked. That is the whole difference from the logs path, where
// the line writer strips the delimiter and the host's logEmitter puts one back.
// An attached client is a terminal, so its escape sequences, its CRLFs and its
// partial writes have to arrive exactly as the program emitted them — a
// reconstructed delimiter would be a guess about output that was never
// line-shaped to begin with.
//
// # One residual, and it is cosmetic
//
// The retained buffer is bounded and evicted oldest-bytes-first, so a client
// attaching to a busy full-screen program can begin MID-ESCAPE-SEQUENCE: the
// first few bytes it receives may be the tail of a cursor-positioning code
// whose introducer was evicted, which the terminal renders as a stray
// character or two. There is no honest fix inside a bounded buffer — the
// alternative is retaining the whole session — and the recovery is the one
// every terminal user already has: ^L redraws. The same applies after a
// drop notice.
func attachFrame(chunk ByteChunk, wantStdout, wantStderr bool) (*runtimev1.AttachResponse, bool) {
	if len(chunk.Data) == 0 {
		return nil, false
	}
	if chunk.Stream == StreamStderr {
		if !wantStderr {
			return nil, false
		}
		return &runtimev1.AttachResponse{Stderr: chunk.Data}, true
	}
	if !wantStdout {
		return nil, false
	}
	return &runtimev1.AttachResponse{Stdout: chunk.Data}, true
}

// attachDropNotice is the in-band line a client gets when the bounds cost it
// bytes — the Capture truncationNotice idiom, restated for a terminal.
//
// It is CRLF-wrapped and names ^L because its reader is a terminal that has
// just been handed a discontinuity: without the notice, a half-drawn screen and
// a program that has genuinely gone quiet look identical, and they call for
// opposite operator actions.
func attachDropNotice(dropped int) []byte {
	return []byte(fmt.Sprintf(
		"\r\n[k3sm-guest] attach dropped %d bytes: this client fell behind. Redraw with ^L.\r\n",
		dropped))
}

// Stop begins guest shutdown: SIGTERM to every container, SIGKILL to what remains
// after grace, then sync and poweroff.
//
// It RETURNS before the GUEST IS GONE, on purpose. guest.proto says shutdown is
// acknowledged by the call returning and the guest powers off immediately after —
// so the shutdown runs detached and the acknowledgement is sent first. The
// alternative is a call that can never return successfully, because a poweroff
// takes the transport with it, and the host would read every clean shutdown as a
// failure.
func (s *Server) Stop(ctx context.Context, req *guestv1.StopRequest) (*guestv1.StopResponse, error) {
	grace := clampGrace(req.GetGraceSeconds())
	s.log.Info("the host asked the guest to shut down", "grace", grace)
	go func() {
		// Background, not the RPC's ctx: the RPC returns immediately (see above),
		// which would cancel the very shutdown it just acknowledged.
		if err := s.deps.Runner.Stop(context.Background(), grace); err != nil {
			s.log.Error("guest shutdown failed", "err", err)
		}
	}()
	return &guestv1.StopResponse{}, nil
}

// clampGrace turns the host's requested grace into a duration the guest will
// honour. See maxStopGraceSeconds for why the guest clamps a value the host has
// already clamped.
func clampGrace(seconds int32) time.Duration {
	if seconds <= 0 {
		return 0
	}
	if seconds > maxStopGraceSeconds {
		return maxStopGraceSeconds * time.Second
	}
	return time.Duration(seconds) * time.Second
}
