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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/mount"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- in-process guest agent ----------------------------------------------

// fakeGuestAgent is a SCRIPTABLE guest/v1 GuestAgent server, reached over a real
// gRPC connection on a bufconn listener. Nothing about the route is stubbed: the
// daemon's own client conn, codec, and stream plumbing run end to end — only the
// SOCKET is replaced, which is the whole point of the GuestDialer seam (there is
// no VM, no vmhost, and no vsock anywhere in this file).
//
// It is scriptable BY DESIGN, and that is now its only job: it can be made to
// misbehave in ways a correct agent never would — an oversized frame, a stream
// that ends mid-exec, an undeclared container name — which is what these tests are
// about, and which the shipped agent cannot be asked to do.
//
// The complementary assertion, that the daemon's routes and the shipped
// k3sm.io/runtimed/pkg/guestagent server agree about the contract, is
// TestGuestAgentServesTheHostRoutes (guestagent_fullstack_test.go). Until that
// existed this file's fakes were the only far end anywhere, so the routes were
// verified only against a double written to satisfy them; they no longer are.
//
// bootedPod is the single pod this guest "booted": every request whose pod_id is
// not that id is rejected, exactly as guest.proto requires ("the agent must
// reject a pod_id that is not the pod it booted").
type fakeGuestAgent struct {
	guestv1.UnimplementedGuestAgentServer

	bootedPod string
	// exec is the scripted body run after the first frame is accepted; logs and
	// attach are its GetLogs and Attach counterparts. A nil body ends the stream
	// immediately.
	exec   func(gs guestv1.GuestAgent_ExecServer) error
	logs   func(req *runtimev1.GetLogsRequest, gs guestv1.GuestAgent_LogsServer) error
	attach func(gs guestv1.GuestAgent_AttachServer) error

	mu           sync.Mutex
	execFrames   []*runtimev1.ExecRequest
	attachFrames []*runtimev1.AttachRequest
	logsReq      *runtimev1.GetLogsRequest
	sawStdinEOF  bool
}

// recordAttach keeps every attach frame the guest was sent, which is what pins
// the route's first-frame re-stamp and its refusal to forward anything but
// stdin bytes and resizes.
func (f *fakeGuestAgent) recordAttach(req *runtimev1.AttachRequest) {
	f.mu.Lock()
	f.attachFrames = append(f.attachFrames, req)
	f.mu.Unlock()
}

func (f *fakeGuestAgent) attachSeen() []*runtimev1.AttachRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*runtimev1.AttachRequest(nil), f.attachFrames...)
}

// Attach mirrors Exec: it enforces the single-pod contract on the first frame,
// then runs the scripted body.
func (f *fakeGuestAgent) Attach(gs guestv1.GuestAgent_AttachServer) error {
	first, err := gs.Recv()
	if err != nil {
		return err
	}
	f.recordAttach(first)
	if first.GetPodId() != f.bootedPod {
		return status.Errorf(codes.InvalidArgument,
			"attach: pod_id %q is not the pod this guest booted (%q)", first.GetPodId(), f.bootedPod)
	}
	if f.attach == nil {
		return nil
	}
	return f.attach(gs)
}

func (f *fakeGuestAgent) record(req *runtimev1.ExecRequest) {
	f.mu.Lock()
	f.execFrames = append(f.execFrames, req)
	f.mu.Unlock()
}

func (f *fakeGuestAgent) frames() []*runtimev1.ExecRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*runtimev1.ExecRequest(nil), f.execFrames...)
}

func (f *fakeGuestAgent) stdinEOF() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawStdinEOF
}

func (f *fakeGuestAgent) noteStdinEOF() {
	f.mu.Lock()
	f.sawStdinEOF = true
	f.mu.Unlock()
}

func (f *fakeGuestAgent) Exec(gs guestv1.GuestAgent_ExecServer) error {
	first, err := gs.Recv()
	if err != nil {
		return err
	}
	f.record(first)
	if first.GetPodId() != f.bootedPod {
		return status.Errorf(codes.InvalidArgument,
			"exec: pod_id %q is not the pod this guest booted (%q)", first.GetPodId(), f.bootedPod)
	}
	if f.exec == nil {
		return nil
	}
	return f.exec(gs)
}

func (f *fakeGuestAgent) Logs(req *runtimev1.GetLogsRequest, gs guestv1.GuestAgent_LogsServer) error {
	f.mu.Lock()
	f.logsReq = req
	f.mu.Unlock()
	if req.GetPodId() != f.bootedPod {
		return status.Errorf(codes.InvalidArgument,
			"logs: pod_id %q is not the pod this guest booted (%q)", req.GetPodId(), f.bootedPod)
	}
	if f.logs == nil {
		return nil
	}
	return f.logs(req, gs)
}

func (f *fakeGuestAgent) logsRequest() *runtimev1.GetLogsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logsReq
}

// startFakeGuestAgent serves agent on an in-process bufconn listener and returns
// a GuestDialer reaching it plus an accessor for the addresses the daemon asked
// to dial. The addresses are what pins the Resolution 7 socket invariant AT the
// ROUTE (guestAgentSocket's own shape is pinned separately, below): the route
// must ask for the runtimed-private path, never a pod-dir one.
func startFakeGuestAgent(t *testing.T, agent guestv1.GuestAgentServer) (GuestDialer, func() []string) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	guestv1.RegisterGuestAgentServer(srv, agent)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		<-served
		_ = lis.Close()
	})

	var mu sync.Mutex
	var dialed []string
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return lis.DialContext(ctx)
	}
	return dial, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), dialed...)
	}
}

// addVMPod registers a running vm-backend pod in rt's pod table.
//
// It builds the pod directly instead of going through CreatePod because the vm
// pod ASSEMBLY is a different deliverable: createVMPod still fails at the
// lab-gated CreateVM (sandbox.ErrVMBootNotImplemented), so no CreatePod call can
// produce one yet — the machine builder (pkg/vmhost, cmd/k3sm-vmhost) exists, but
// the runtime spine that spawns it is a later wave. What the route keys off — pod.backend == SANDBOX_BACKEND_VM, the
// resolved backend createVMPod records when it assembles a running pod — is set
// here exactly as that assembly will set it.
func addVMPod(t *testing.T, rt *Runtime, podID string, containers ...string) *pod {
	t.Helper()
	box := hostBinBox(rt, podID)
	box.Containers = nil
	for _, name := range containers {
		box.Containers = append(box.Containers, &runtimev1.Container{Name: name, Image: "docker.io/library/busybox:latest"})
	}
	// The pod-lifetime supervision context is set exactly as createPod sets it:
	// it is what every per-pod goroutine (and, on the host spine, the memory
	// sampler) is rooted at, so a stand-in without one would make an arm attempt
	// panic instead of being refused — which would hide the very refusal B107's
	// no-ticker assertion is about.
	podCtx, podCancel := context.WithCancel(context.Background())
	t.Cleanup(podCancel)
	p := &pod{
		box:     box,
		backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
		phase:   runtimev1.PodPhase_POD_PHASE_RUNNING,
		supCtx:  podCtx,
		cancel:  podCancel,
	}
	rt.mu.Lock()
	rt.pods[podID] = p
	rt.mu.Unlock()
	return p
}

// execOutput is what a client saw on an exec stream.
type execOutput struct {
	stdout []byte
	stderr []byte
	exit   *runtimev1.ExecResult
	frames int
}

// drainExec collects everything already buffered on the fake stream. It is
// called after the handler returned, so the buffer is complete and the drain is
// non-blocking — an assertion about what did not arrive (an oversized frame, a
// terminal exit after a refusal) needs that determinism.
func drainExec(st *fakeExecStream) execOutput {
	var out execOutput
	for {
		select {
		case resp := <-st.out:
			out.frames++
			out.stdout = append(out.stdout, resp.GetStdout()...)
			out.stderr = append(out.stderr, resp.GetStderr()...)
			if ex := resp.GetExit(); ex != nil {
				out.exit = ex
			}
		default:
			return out
		}
	}
}

// TestVMPodExecRoutesToGuestAgent is the B101 gate. It asserts the
// CONFORMANCE-BEARING properties of the vm exec route, not merely that a dial
// happened: exit-code fidelity in both directions of the `kubectl exec … && …`
// decision, byte-exact stdout/stderr demultiplexing, EOF propagation both ways,
// the single-pod pod_id contract, the host-process path's total isolation from
// this route, and the untrusted-guest read bound.
func TestVMPodExecRoutesToGuestAgent(t *testing.T) {
	t.Run("exit-code-round-trip-and-stream-demux", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			code int32
		}{
			{"zero", 0},
			{"nonzero", 7},
			{"signal-mapped", 137},
		} {
			t.Run(tc.name, func(t *testing.T) {
				agent := &fakeGuestAgent{bootedPod: "pod-vm"}
				agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
					// Interleaved so a route that merged the two streams, or
					// reordered within one, cannot pass.
					for _, resp := range []*runtimev1.ExecResponse{
						{Stdout: []byte("out-a")},
						{Stderr: []byte("err-1")},
						{Stdout: []byte("out-b")},
						{Stderr: []byte("err-2")},
					} {
						if err := gs.Send(resp); err != nil {
							return err
						}
					}
					return gs.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: tc.code}})
				}
				dial, dialed := startFakeGuestAgent(t, agent)
				rt := newTestRuntime(t, Deps{GuestDialer: dial})
				addVMPod(t, rt, "pod-vm", "app")

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				st := newFakeExecStream(ctx)
				st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/sh", "-c", "true"}})
				st.closeSend()
				if err := rt.Exec(st); err != nil {
					t.Fatalf("Exec: %v", err)
				}
				out := drainExec(st)
				if got, want := string(out.stdout), "out-aout-b"; got != want {
					t.Errorf("stdout = %q, want %q (stderr must not leak into it)", got, want)
				}
				if got, want := string(out.stderr), "err-1err-2"; got != want {
					t.Errorf("stderr = %q, want %q (stdout must not leak into it)", got, want)
				}
				if out.exit == nil {
					t.Fatal("no terminal exit frame reached the client")
				}
				if out.exit.GetExitCode() != tc.code {
					t.Errorf("exit code = %d, want %d (kubectl exec's && depends on this)", out.exit.GetExitCode(), tc.code)
				}
				// The route dialed the pod's own private agent socket.
				want, err := guestAgentSocket(rt.cfg.Root, "pod-vm")
				if err != nil {
					t.Fatal(err)
				}
				if got := dialed(); len(got) != 1 || got[0] != want {
					t.Errorf("dialed = %v, want exactly [%s]", got, want)
				}
				// The pod id the guest was asked for is the pod the route
				// resolved, and the container selector was resolved host-side.
				frames := agent.frames()
				if len(frames) == 0 {
					t.Fatal("the guest agent received no frame")
				}
				if frames[0].GetPodId() != "pod-vm" {
					t.Errorf("forwarded pod_id = %q, want %q", frames[0].GetPodId(), "pod-vm")
				}
				if frames[0].GetContainer() != "app" {
					t.Errorf("forwarded container = %q, want the pod's sole declared container %q", frames[0].GetContainer(), "app")
				}
			})
		}
	})

	t.Run("close-semantics-eof-both-directions", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
			// Echo stdin until the CLIENT's half-close reaches the guest as EOF
			// (direction 1), then send the terminal frame and return, which
			// closes the guest stream (direction 2).
			for {
				req, err := gs.Recv()
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
					agent.noteStdinEOF()
					break
				}
				if d := req.GetStdinData(); len(d) > 0 {
					if err := gs.Send(&runtimev1.ExecResponse{Stdout: d}); err != nil {
						return err
					}
				}
			}
			return gs.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/cat"}, Stdin: true})
		st.feed(&runtimev1.ExecRequest{StdinData: []byte("ping\n")})
		st.closeSend()

		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec: %v", err)
		}
		out := drainExec(st)
		if got := string(out.stdout); got != "ping\n" {
			t.Errorf("echoed stdout = %q, want %q (client stdin must reach the guest)", got, "ping\n")
		}
		if !agent.stdinEOF() {
			t.Error("the guest never saw stdin EOF: the client half-close was not propagated")
		}
		if out.exit == nil || out.exit.GetExitCode() != 0 {
			t.Errorf("exit = %v, want a terminal frame with code 0 (the guest's stream close must end the client's)", out.exit)
		}
	})

	t.Run("pod-id-mismatch-rejected", func(t *testing.T) {
		// The guest booted a different pod than the one being exec'd — the
		// unsupported-skew case the single-pod contract exists to catch.
		agent := &fakeGuestAgent{bootedPod: "pod-other"}
		agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
			t.Error("the scripted body ran: a pod_id mismatch must be rejected before it")
			return nil
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/sh"}})
		st.closeSend()

		err := rt.Exec(st)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("Exec error = %v (code %v), want the agent's InvalidArgument rejection", err, status.Code(err))
		}
		if out := drainExec(st); out.exit != nil {
			t.Errorf("a terminal exit frame (%v) reached the client after a rejection; a rejected exec must never look like a completed one", out.exit)
		}
	})

	t.Run("later-frame-cannot-retarget-the-stream", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
			for {
				req, err := gs.Recv()
				if err != nil {
					break
				}
				agent.record(req)
			}
			return gs.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/cat"}, Stdin: true})
		// A hostile second frame: another pod, another command, riding stdin.
		st.feed(&runtimev1.ExecRequest{PodId: "pod-victim", Container: "other", Command: []string{"/bin/sh", "-c", "id"}, StdinData: []byte("x")})
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec: %v", err)
		}

		frames := agent.frames()
		if len(frames) < 2 {
			t.Fatalf("the guest saw %d frames, want the params frame plus the forwarded stdin", len(frames))
		}
		for _, f := range frames[1:] {
			if f.GetPodId() != "" || f.GetContainer() != "" || len(f.GetCommand()) != 0 {
				t.Errorf("a post-params frame carried parameters (pod_id=%q container=%q command=%v); only stdin/resize may be forwarded",
					f.GetPodId(), f.GetContainer(), f.GetCommand())
			}
		}
		if got := string(frames[1].GetStdinData()); got != "x" {
			t.Errorf("forwarded stdin = %q, want %q", got, "x")
		}
	})

	t.Run("host-process-pod-never-touches-the-guest-route", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
			return gs.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
		}
		dial, dialed := startFakeGuestAgent(t, agent)
		be := &recordingExecBackend{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{GuestDialer: dial, Backend: be, Waiter: w})
		// One host-process pod and one vm pod on the same daemon: dispatch is
		// per pod, so a mis-keyed route shows up as the wrong one being used.
		mustCreatePod(t, rt, hostBinBox(rt, "pod-host"))
		defer w.release(1001)
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-host", Command: []string{"/bin/echo", "hello"}})
		st.closeSend()
		if err := rt.Exec(st); err != nil {
			t.Fatalf("Exec: %v", err)
		}
		out := drainExec(st)
		if !strings.Contains(string(out.stdout), "hello") {
			t.Errorf("host-process exec stdout = %q, want it to contain %q", out.stdout, "hello")
		}
		if out.exit == nil || out.exit.GetExitCode() != 0 {
			t.Errorf("host-process exec exit = %v, want code 0", out.exit)
		}
		if got := dialed(); len(got) != 0 {
			t.Errorf("the host-process exec dialed a guest agent (%v); it must never reach the guest route", got)
		}
		if len(agent.frames()) != 0 {
			t.Errorf("the guest agent saw %d frames from a host-process exec, want 0", len(agent.frames()))
		}
		// It really did go through the host confinement seam.
		if argv := be.lastArgv(); len(argv) == 0 || argv[0] != "/bin/echo" {
			t.Errorf("host-process exec argv through WrapCommand = %v, want it to start with /bin/echo", argv)
		}
	})

	t.Run("oversized-guest-frame-is-refused-not-relayed", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.exec = func(gs guestv1.GuestAgent_ExecServer) error {
			if err := gs.Send(&runtimev1.ExecResponse{Stdout: []byte("head")}); err != nil {
				return err
			}
			// One byte over the bound: a hostile/broken guest trying to make the
			// daemon buffer whatever it likes.
			if err := gs.Send(&runtimev1.ExecResponse{Stdout: bytes.Repeat([]byte("x"), maxGuestFrameBytes+1)}); err != nil {
				return err
			}
			return gs.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/sh"}})
		st.closeSend()

		err := rt.Exec(st)
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("Exec error = %v (code %v), want ResourceExhausted for an over-bound guest frame", err, status.Code(err))
		}
		out := drainExec(st)
		if string(out.stdout) != "head" {
			t.Errorf("client stdout = %d bytes, want exactly the %q that preceded the over-bound frame", len(out.stdout), "head")
		}
		if out.exit != nil {
			t.Errorf("an exit frame (%v) was relayed after the bound was hit; the refusal must end the stream", out.exit)
		}
	})

	t.Run("unknown-container-not-found", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		dial, dialed := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app", "sidecar")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Container: "nope", Command: []string{"/bin/sh"}})
		st.closeSend()
		if err := rt.Exec(st); status.Code(err) != codes.NotFound {
			t.Errorf("Exec(undeclared container) code = %v, want NotFound", status.Code(err))
		}
		if got := dialed(); len(got) != 0 {
			t.Errorf("an undeclared container selector reached the dial step (%v); resolve host-side first", got)
		}
	})

	t.Run("unreachable-agent-is-unavailable", func(t *testing.T) {
		dialErr := errors.New("no such file or directory")
		rt := newTestRuntime(t, Deps{GuestDialer: func(context.Context, string) (net.Conn, error) { return nil, dialErr }})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm", Command: []string{"/bin/sh"}})
		st.closeSend()

		err := rt.Exec(st)
		if status.Code(err) != codes.Unavailable {
			t.Errorf("Exec(unreachable agent) code = %v, want Unavailable", status.Code(err))
		}
		if out := drainExec(st); out.exit != nil {
			t.Errorf("exit frame %v reached the client for an unreachable agent", out.exit)
		}
	})

	t.Run("command-is-required", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		dial, dialed := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeExecStream(ctx)
		st.feed(&runtimev1.ExecRequest{PodId: "pod-vm"})
		st.closeSend()
		if err := rt.Exec(st); status.Code(err) != codes.InvalidArgument {
			t.Errorf("Exec(no command) code = %v, want InvalidArgument (same as the host-process path)", status.Code(err))
		}
		if got := dialed(); len(got) != 0 {
			t.Errorf("an empty command reached the dial step (%v)", got)
		}
	})
}

// TestVMPodLogsRouteToGuestAgent pins the GetLogs half of the route: SELECTION
// options cross to the guest (only it holds the buffer), PRESENTATION options
// are applied HOST-side over untrusted guest data, the guest's stdout/stderr
// labelling survives, and a host-process pod is untouched.
func TestVMPodLogsRouteToGuestAgent(t *testing.T) {
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	t.Run("selection-forwarded-presentation-host-side", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.logs = func(req *runtimev1.GetLogsRequest, gs guestv1.GuestAgent_LogsServer) error {
			for _, ent := range []*runtimev1.LogEntry{
				{Line: []byte("one"), Timestamp: timestamppb.New(at), Stream: runtimev1.LogStream_LOG_STREAM_STDOUT},
				{Line: []byte("two"), Timestamp: timestamppb.New(at), Stream: runtimev1.LogStream_LOG_STREAM_STDERR},
			} {
				if err := gs.Send(ent); err != nil {
					return err
				}
			}
			return nil
		}
		dial, dialed := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeLogStream(ctx)
		err := rt.GetLogs(&runtimev1.GetLogsRequest{
			PodId:      "pod-vm",
			TailLines:  5,
			SinceTime:  timestamppb.New(at.Add(-time.Hour)),
			Timestamps: true,
		}, st)
		if err != nil {
			t.Fatalf("GetLogs: %v", err)
		}

		want, derr := guestAgentSocket(rt.cfg.Root, "pod-vm")
		if derr != nil {
			t.Fatal(derr)
		}
		if got := dialed(); len(got) != 1 || got[0] != want {
			t.Errorf("dialed = %v, want exactly [%s]", got, want)
		}
		fwd := agent.logsRequest()
		if fwd == nil {
			t.Fatal("the guest agent received no Logs request")
		}
		if fwd.GetPodId() != "pod-vm" || fwd.GetContainer() != "app" {
			t.Errorf("forwarded (pod_id, container) = (%q, %q), want (%q, %q)", fwd.GetPodId(), fwd.GetContainer(), "pod-vm", "app")
		}
		if fwd.GetTailLines() != 5 || !fwd.GetSinceTime().IsValid() {
			t.Errorf("selection options were not forwarded: tail_lines=%d since_time=%v", fwd.GetTailLines(), fwd.GetSinceTime())
		}
		if fwd.GetTimestamps() || fwd.GetLimitBytes() != 0 {
			t.Errorf("presentation options were forwarded (timestamps=%v limit_bytes=%d); they are applied host-side",
				fwd.GetTimestamps(), fwd.GetLimitBytes())
		}

		st.mu.Lock()
		entries := append([]*runtimev1.LogEntry(nil), st.entries...)
		st.mu.Unlock()
		if len(entries) != 2 {
			t.Fatalf("client got %d entries, want 2", len(entries))
		}
		if got := string(entries[0].GetLine()); !strings.HasSuffix(got, " one") {
			t.Errorf("entry 0 = %q, want the host-rendered RFC3339 prefix + %q", got, "one")
		}
		if entries[0].GetStream() != runtimev1.LogStream_LOG_STREAM_STDOUT ||
			entries[1].GetStream() != runtimev1.LogStream_LOG_STREAM_STDERR {
			t.Errorf("stream labels = (%v, %v), want (STDOUT, STDERR): the guest's demux must survive the relay",
				entries[0].GetStream(), entries[1].GetStream())
		}
	})

	t.Run("limit-bytes-enforced-host-side", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		agent.logs = func(req *runtimev1.GetLogsRequest, gs guestv1.GuestAgent_LogsServer) error {
			// A guest that ignores the budget entirely (it was not even told).
			for range 100 {
				if err := gs.Send(&runtimev1.LogEntry{Line: []byte("flood"), Timestamp: timestamppb.New(at)}); err != nil {
					return err
				}
			}
			return nil
		}
		dial, _ := startFakeGuestAgent(t, agent)
		rt := newTestRuntime(t, Deps{GuestDialer: dial})
		addVMPod(t, rt, "pod-vm", "app")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeLogStream(ctx)
		if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-vm", LimitBytes: 12}, st); err != nil {
			t.Fatalf("GetLogs: %v", err)
		}
		st.mu.Lock()
		var total int
		for _, e := range st.entries {
			total += len(e.GetLine()) + 1
		}
		st.mu.Unlock()
		if total > 12 {
			t.Errorf("client received %d bytes for limit_bytes=12: a guest that ignores the budget must not flood the client", total)
		}
		if total == 0 {
			t.Error("client received nothing; the budget should have carried at least one line")
		}
	})

	t.Run("host-process-pod-never-touches-the-guest-route", func(t *testing.T) {
		agent := &fakeGuestAgent{bootedPod: "pod-vm"}
		dial, dialed := startFakeGuestAgent(t, agent)
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{GuestDialer: dial, Waiter: w})
		mustCreatePod(t, rt, hostBinBox(rt, "pod-host"))
		defer w.release(1001)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := newFakeLogStream(ctx)
		if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-host"}, st); err != nil {
			t.Fatalf("GetLogs: %v", err)
		}
		if got := dialed(); len(got) != 0 {
			t.Errorf("host-process GetLogs dialed a guest agent (%v)", got)
		}
	})
}

// TestGuestAgentSocketIsRuntimedPrivate pins the runtimed-private socket placement as a property
// of the LAYOUT: the agent socket lives under <Root>/run, never inside the pod
// tree a pod's own SBPL re-allow is built from — so "no pod profile allows any
// agent.sock" cannot be broken by a future profile edit.
func TestGuestAgentSocketIsRuntimedPrivate(t *testing.T) {
	const root = "/var/lib/k3sm"
	rt := newTestRuntime(t, Deps{})

	t.Run("derived-shape", func(t *testing.T) {
		got, err := guestAgentSocket(root, "pod-vm")
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(root, "run", "vm", "pod-vm", "agent.sock"); got != want {
			t.Errorf("guestAgentSocket = %q, want %q", got, want)
		}
	})

	t.Run("outside-the-pod-tree", func(t *testing.T) {
		sock, err := guestAgentSocket(rt.cfg.Root, "pod-vm")
		if err != nil {
			t.Fatal(err)
		}
		podsRoot := rt.cache.PodsRoot()
		if mount.IsStrictlyUnder(sock, podsRoot) {
			t.Errorf("agent socket %q is under the pods root %q: a pod's own profile could reach its control channel", sock, podsRoot)
		}
		podDir, err := rt.podDir("pod-vm")
		if err != nil {
			t.Fatal(err)
		}
		if mount.IsStrictlyUnder(sock, podDir) || sock == podDir {
			t.Errorf("agent socket %q is inside the pod dir %q (the private-placement contract forbids it)", sock, podDir)
		}
	})

	t.Run("hostile-pod-ids-refused", func(t *testing.T) {
		for _, id := range []string{"", "../../etc", "a/b", "POD", ".hidden"} {
			if got, err := guestAgentSocket(root, id); err == nil {
				t.Errorf("guestAgentSocket(%q) = %q, want an error: no socket path may be derived from an unvalidated id", id, got)
			}
		}
	})

	t.Run("fits-in-sun_path", func(t *testing.T) {
		// A darwin sockaddr_un carries 104 bytes of sun_path including the
		// terminator, and bind(2) reports an over-long path as the famously
		// unhelpful EINVAL — not ENAMETOOLONG. The derived path is
		// <Root>/run/vm/<podID>/agent.sock, so a long pod id can overflow it on a
		// real node, and the failure would look like a broken helper rather than a
		// path-length problem.
		//
		// The pod id is a kube UID (36 characters), so the production path has
		// generous headroom; the assertion is against a future layout change that
		// spends it — a deeper run tree, a longer socket name, an id scheme with
		// namespace and name in it.
		const sunPathMax = 104
		longestID := strings.Repeat("a", 63) // the longest label ParsePodID accepts
		sock, err := guestAgentSocket(root, longestID)
		if err != nil {
			t.Fatalf("guestAgentSocket(%q): %v", longestID, err)
		}
		if len(sock)+1 > sunPathMax {
			t.Errorf("the derived agent socket is %d bytes (%q); with the NUL terminator that exceeds sun_path's %d, "+
				"and bind(2) would fail with EINVAL rather than naming the length", len(sock), sock, sunPathMax)
		}
	})
}
